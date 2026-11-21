package sh.tinfoil

import kotlinx.coroutines.CancellationException
import okhttp3.HttpUrl
import sh.tinfoil.internal.RouterDiscovery
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.internal.transport.Urls
import sh.tinfoil.internal.verification.DocumentFetcher
import java.io.IOException

/**
 * Obtains the attestation document of an enclave for a challenge nonce, in
 * place of the client's direct fetch from the enclave: the
 * [fetchAttestation][EnclaveOptions.fetchAttestation] option of the enclave
 * and router clients. [AttestationRelay] fetches through a relay; a
 * function of the caller's can do anything else.
 *
 * A fetcher is not trusted. The client verifies whatever it returns as it
 * verifies a document that it fetched itself: the document must answer the
 * nonce, and pass the trust and the policy. So a fetcher can make
 * verification fail, but it cannot make an enclave pass that would not pass
 * otherwise. An attestation document is not tied to the host that serves
 * it: a fetcher that returns another enclave's valid document passes
 * verification, and the first request then fails, because the host does
 * not hold the verified key.
 *
 * A client calls it for every verification: when it is created, whenever it
 * verifies again after an expiry or a key rotation, and, on the router
 * route, for each router that discovery tries and for the fallback.
 *
 * It runs in a coroutine that ends after 30 seconds. That coroutine is not
 * any one caller's, since one verification can serve many requests: a
 * caller's cancellation ends only that caller's wait. What it throws is
 * reported as a [NetworkException] that keeps it as its cause, unless it is
 * a [TinfoilException], which keeps its category; that includes the end of
 * its coroutine after 30 seconds, since that timeout is the client's. A
 * [ConfigurationException] that it throws is not tried again. It may be
 * called from several threads at once, and must not call back into the
 * client.
 */
public fun interface AttestationFetcher {
    /**
     * The attestation document of [host], an enclave's host with an
     * optional port, for [nonce], the challenge that it must answer.
     */
    @Throws(Exception::class)
    public suspend fun fetchAttestation(host: String, nonce: ByteArray): ByteArray
}

/**
 * An [AttestationFetcher] that fetches documents through a relay, such as
 * an endpoint on the application's own origin that forwards each request to
 * the enclave that it names, so that a client reaches only that origin.
 *
 * It sends `GET <url>/.well-known/tinfoil-attestation?nonce=<nonce>&enclave=<host>`,
 * where `nonce` is the challenge in lowercase hex and `host` is the
 * enclave's host, with its port, encoded as a query value, with the SDK
 * identity headers (`Tinfoil-SDK`, `Tinfoil-SDK-Version`) that a direct
 * fetch sends, and nothing that identifies the caller. A `2xx` response's
 * body is the document. It applies the bounds of a direct fetch: 30
 * seconds, 32 MiB, and no redirect to a URL that is not HTTPS. A failure to
 * fetch, an error status or an oversized response is a [NetworkException].
 * The relay is not trusted; see [AttestationFetcher].
 *
 * A relay forwards the request to
 * `https://<host>/.well-known/tinfoil-attestation?nonce=<nonce>` and returns
 * the body unchanged. It should forward only to the enclave hosts that the
 * application expects, so that it is not an open proxy.
 *
 * @param url The relay's URL. Its path, if any, is where the relay is
 *   mounted: the request path joins under it, whether or not it ends with
 *   `/`. It must use HTTPS; `http://` is accepted only when its host is
 *   `localhost` or a loopback IP address, and on Android cleartext HTTP also
 *   has to be permitted by the app's network security configuration.
 * @throws ConfigurationException for a URL that is empty, not absolute, of
 *   another scheme, or that has user information, a query or a fragment,
 *   even an empty one.
 */
public class AttestationRelay(url: String) : AttestationFetcher {
    /** The relay's URL, ending with `/`. */
    public val url: HttpUrl = Urls.routeUrl(url, "attestation relay URL")

    /**
     * Fetches the document through the relay, on connections of its own; a
     * client that is given this relay fetches through it on the client's
     * connections instead.
     */
    @Throws(IOException::class, CancellationException::class)
    override suspend fun fetchAttestation(host: String, nonce: ByteArray): ByteArray {
        val fetcher = DocumentFetcher(HttpSettings())
        try {
            return fetcher.fetch(documentUrl(host, nonce), allowLoopbackHttp = true)
        } finally {
            fetcher.close()
        }
    }

    /** Where the document of [host] for [nonce] is fetched from. */
    @JvmSynthetic
    internal fun documentUrl(host: String, nonce: ByteArray): HttpUrl {
        Urls.enclaveUrl(host)
        return url.newBuilder()
            .encodedPath(url.encodedPath + ".well-known/tinfoil-attestation")
            .addQueryParameter("nonce", nonce.joinToString("") { "%02x".format(it) })
            .addQueryParameter("enclave", host)
            .build()
    }

    override fun equals(other: Any?): Boolean = this === other || (other is AttestationRelay && url == other.url)

    override fun hashCode(): Int = url.hashCode()

    override fun toString(): String = "AttestationRelay(url=$url)"
}

/**
 * Obtains the candidate routers for router discovery, in place of the
 * client's fetch of Tinfoil's list from `https://atc.tinfoil.sh/routers`:
 * the [fetchRouterList][RouterOptions.fetchRouterList] option of the router
 * client. [RouterListRelay] fetches through a relay; a function of the
 * caller's can do anything else.
 *
 * The list is not trusted: it only proposes hosts. Discovery shuffles a
 * copy of it, verifies each router that it tries, tries them for at most 30
 * seconds in all, and falls back to `inference.tinfoil.sh` when none
 * passes. Anything that it throws, or a list that it returns with no valid
 * host, counts as an empty list.
 *
 * An attestation document does not name the host that serves it, so the
 * list's source is trusted not to name a host that would relay another
 * router's attestation: with [Transport.Ehbp] through a proxy, such a host
 * would receive the request headers, the API key included, although not
 * the sealed bodies.
 *
 * It runs in the coroutine of the caller of `create`, so it ends when that
 * caller is cancelled, or once discovery's 30 seconds are over.
 */
public fun interface RouterListFetcher {
    /** The hosts of the candidate routers, each with an optional port. */
    @Throws(Exception::class)
    public suspend fun fetchRouterList(): List<String>
}

/**
 * A [RouterListFetcher] that fetches the router list through a relay, such
 * as an endpoint on the application's own origin that forwards the request
 * to `https://atc.tinfoil.sh/routers`.
 *
 * It sends `GET <url>/routers`, with the query parameters that a direct
 * fetch sends, of which this client sends none, and reads the response as a
 * direct fetch's: a JSON array of host strings, of at most 1 MiB, fetched
 * within 30 seconds and with no redirect to a URL that is not HTTPS. A
 * failure to fetch it is a [NetworkException], and a response that is not
 * such an array is an empty list.
 *
 * @param url The relay's URL, under the rules of [AttestationRelay]'s.
 * @throws ConfigurationException for a URL that [AttestationRelay] would
 *   refuse.
 */
public class RouterListRelay(url: String) : RouterListFetcher {
    /** The relay's URL, ending with `/`. */
    public val url: HttpUrl = Urls.routeUrl(url, "router list relay URL")

    /**
     * Fetches the list through the relay, on connections of its own; a
     * client that is given this relay fetches through it on the client's
     * connections instead.
     */
    @Throws(IOException::class, CancellationException::class)
    override suspend fun fetchRouterList(): List<String> {
        val fetcher = RouterDiscovery.listFetcher(HttpSettings())
        try {
            return RouterDiscovery.parse(fetcher.fetch(listUrl, allowLoopbackHttp = true))
        } finally {
            fetcher.close()
        }
    }

    /** Where the list is fetched from. */
    @get:JvmSynthetic
    internal val listUrl: HttpUrl
        get() = url.newBuilder().encodedPath(url.encodedPath + "routers").build()

    override fun equals(other: Any?): Boolean = this === other || (other is RouterListRelay && url == other.url)

    override fun hashCode(): Int = url.hashCode()

    override fun toString(): String = "RouterListRelay(url=$url)"
}
