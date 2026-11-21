package sh.tinfoil

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.internal.EnclaveConnection
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.RouteSettings
import sh.tinfoil.internal.RouterDiscovery
import sh.tinfoil.internal.requireNotEmpty
import sh.tinfoil.internal.transport.AttestedCall
import sh.tinfoil.internal.transport.Urls
import sh.tinfoil.internal.transport.UserCacheSecret
import sh.tinfoil.internal.verification.AttestationFetcher
import sh.tinfoil.internal.verification.VerifierInputs
import java.io.IOException
import kotlin.coroutines.coroutineContext

/**
 * An HTTP client whose requests reach only the attested Tinfoil router that
 * it chose when it was created.
 *
 * Tinfoil's routers are enclaves that forward inference requests to the
 * models. [create] picks one, verifies it and returns a client that is bound
 * to it. From then on the client behaves as an [EnclaveHttpClient] for that
 * router: every request waits for a verification that is valid at that
 * moment, goes out under the keys that the verification endorses, and the
 * client verifies the same router again by itself when a verification
 * reaches its freshness deadline or the router stops holding the verified
 * key. A client never moves to another router; to choose again, create
 * another client.
 *
 * Send requests with [execute], or hand the client, which is an OkHttp
 * [Call.Factory], to a library that is built on OkHttp.
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 */
public class RouterHttpClient private constructor(
    private val connection: EnclaveConnection,
) : AttestedHttpClient {
    /**
     * The router that the client chose and verifies: its host, with a port
     * when the router list gave one.
     */
    public val enclave: String get() = connection.enclave

    /**
     * The URL that requests are sent under: the router's own origin,
     * `https://<enclave>/`, or the proxy that the client was created with.
     * Resolve request paths against it, as in `baseUrl.resolve("v1/models")`.
     */
    override val baseUrl: HttpUrl get() = connection.baseUrl

    /** How the client protects its requests, as it was created with. */
    public val transport: Transport get() = connection.transport

    /**
     * The last successful verification, without checking it. It may have
     * expired or been rejected since; use [ensureVerified] for one that is
     * valid.
     */
    public val current: Verification? get() = connection.current

    /**
     * Returns a verification of the router that is valid now, verifying
     * first only if the last one has reached its freshness deadline or the
     * router has rejected its key. It behaves as
     * [EnclaveHttpClient.ensureVerified] does, and is safe to call from the
     * main thread.
     *
     * @throws ConfigurationException if the client is closed.
     * @throws NetworkException if the attestation document cannot be fetched.
     * @throws AttestationException if the router is not to be trusted.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun ensureVerified(): Verification = connection.ensureVerified()

    /**
     * Verifies the same router again, even if the last verification is still
     * valid, and returns the new verification. It behaves as
     * [EnclaveHttpClient.reverify] does: a failure does not withdraw a
     * verification that is still valid, and does not make the client choose
     * another router. It is safe to call from the main thread.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun reverify(): Verification = connection.reverify()

    /**
     * Sends [request] to the router and returns the response as soon as its
     * headers arrive. The body streams as it is read, and the caller closes
     * the response. It is safe to call from the main thread; reading the
     * response's body, or closing it unread, is not.
     *
     * The rules are those of [EnclaveHttpClient.execute]: the request must be
     * on [baseUrl]'s origin, without credentials in its URL or a `Host`
     * header; it waits for a valid verification; redirects are not followed;
     * and the HTTP client may send a request again by itself unless its body
     * can be written only once or is sealed. With [Transport.Tls] it is
     * written only to a connection that carries the attested key. With
     * [Transport.Ehbp] only its body is sealed, to the attested HPKE
     * key: its method, URL and headers are not, nor is a request without a
     * body or the response to it; see [EnclaveHttpClient.execute] for all
     * that this mode changes. One thing is stricter here than there: the
     * caller did not choose the router's host, so a connection that goes
     * to the router itself, and not to a proxy, must present the attested
     * TLS key in this mode too, and a router that presents another key is
     * verified again and then refused, exactly as with [Transport.Tls].
     * Through a proxy, the connection is the proxy's, and is validated as
     * any HTTPS connection is.
     *
     * The client's user cache secret is added to the body of a `POST` whose
     * path ends in `/chat/completions`, `/completions` or `/responses`, as
     * the member `user_cache_secret`, if the body is one JSON object in
     * which that member is absent or the empty string, before the body is
     * sealed. The rest of the body is sent byte for byte as it was given,
     * and the request's `Content-Length` is that of the new body. Only a
     * member with exactly that name counts: one whose name differs from it
     * only by case, such as `User_Cache_Secret`, is left as it was written,
     * and the client's member is added beside it. A non-empty
     * `user_cache_secret` string in the body is the request's own scope and
     * is kept, so a server can give each of its users a cache of their own.
     * Any other body is sent unchanged: one that is not a JSON object in
     * UTF-8, one that names the member more than once or with a value that
     * is not a string, and a body of more than 64 MiB that declares its
     * length or can be written again, which a router refuses for its size.
     * To decide, the body is read into memory before the request is sent:
     * it is written once, then, and what it wrote is what is sent. A
     * request to one of those paths whose body cannot be examined is
     * refused with a [ConfigurationException] before anything is sent, so
     * that it does not land in the cache that the API key's other clients
     * share: a duplex body, and a body that declares no length, can be
     * written only once and is longer than 64 MiB.
     *
     * @throws ConfigurationException for a request that is refused.
     * @throws NetworkException if the router has to be verified again and
     *   its attestation document cannot be fetched.
     * @throws AttestationException if the router is not to be trusted, or
     *   does not hold the verified key.
     * @throws IOException for any other failure to exchange the request,
     *   as the HTTP client reports it.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun execute(request: Request): Response = connection.send(request)

    /**
     * Sends [request] as [execute] does, and returns the response together
     * with its session recovery token: the key material that can open this
     * one response again later, without this client. It behaves as
     * [EnclaveHttpClient.executeRecoverable] does: it requires
     * [Transport.Ehbp], and the token, which is secret key material, is
     * null for a response that is not sealed.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun executeRecoverable(request: Request): RecoverableResponse = connection.sendRecoverable(request)

    /**
     * Prepares [request] as a call that follows the rules of [execute], for
     * code that is written against OkHttp. Nothing is checked or sent until
     * the call is executed or enqueued. It behaves as
     * [EnclaveHttpClient.newCall] does: a blocking [Call.execute] is never
     * for the main thread.
     */
    override fun newCall(request: Request): Call = AttestedCall(connection, request)

    /**
     * Closes the client. Later requests and verifications fail with a
     * [ConfigurationException], a verification in progress and the requests
     * in flight are cancelled, and every connection is closed. Closing again
     * does nothing.
     *
     * It is safe to call from any thread, the main thread included, and
     * returns at once: the client refuses requests from then on, and the
     * cancelling and the closing of connections follow on a background
     * thread.
     */
    override fun close() {
        connection.close()
    }

    public companion object {
        /**
         * Creates a client for one of Tinfoil's routers, verified before
         * this returns.
         *
         * The router is the first on Tinfoil's router list that verifies
         * and holds its attested TLS key. The list is only a proposal, and
         * is not trusted. Each router on it is verified against Tinfoil's
         * router by name, exactly as an enclave that the caller names would
         * be. A host could pass that by handing on a genuine router's
         * attestation document, so it must also present the TLS key that
         * the document endorses, on a connection that is opened to check
         * that and carries no request. The client's later connections to
         * the router are pinned to that key in both transport modes. So
         * whatever the list says, no request, header or body is written to
         * a host that does not hold a verified router's TLS key; a forged
         * list can only cost time, or decide which genuine router is
         * chosen.
         *
         * Routers are tried in the order of the list, one at a time and
         * once each, for at most 30 seconds in all, the fetch of the list
         * included. A router that cannot be reached, does not verify, does
         * not present its attested key or is rejected by
         * the [verification check][RouterOptions.verificationCheck] is
         * passed over. If no router is chosen,
         * because the list could not be fetched or is empty, none passed
         * or the time ran out, the client uses `inference.tinfoil.sh`,
         * which is verified in the same way, with one more attempt if the
         * first fails; if that fails too, this fails with its error. Its
         * connections are pinned to its attested key like any router's.
         *
         * With a [base URL][RouterOptions.baseUrl], which is a proxy, or an
         * [attestation relay][RouterOptions.attestationRelay], the list is
         * not fetched and the client uses `inference.tinfoil.sh`.
         *
         * Everything is an option, set in the block that [options] is and
         * described by [RouterOptions]:
         *
         * ```
         * val client = RouterHttpClient.create { userCacheSecret = secret }
         * ```
         *
         * Every option is checked before any network I/O. Each call
         * chooses anew.
         *
         * It is safe to call from the main thread. [options] runs once, on
         * the calling thread, before anything else, and what it set is
         * copied as it returns; what it throws is thrown from here as it
         * is, and nothing is contacted. The options are then checked, which
         * loads the native verifier library the first time, and everything
         * is fetched and verified on background threads. A caller that is
         * cancelled just as the client is made does not receive it, and
         * the client is closed.
         *
         * @param options Sets the options; see [RouterOptions]. Without it,
         *   every option has its default.
         * @throws ConfigurationException if an option is invalid.
         * @throws NetworkException if no router on the list was chosen and
         *   the attestation document of `inference.tinfoil.sh` cannot be
         *   fetched.
         * @throws AttestationException if no router on the list was chosen
         *   and `inference.tinfoil.sh` is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(options: RouterOptions.() -> Unit = {}): RouterHttpClient =
            create(Internals(), options)

        /** [create] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun create(internals: Internals, options: RouterOptions.() -> Unit): RouterHttpClient =
            create(routerSettings(options), internals)

        /** [create] with options that were read already. */
        @JvmSynthetic
        internal suspend fun create(settings: RouteSettings, internals: Internals): RouterHttpClient = Background.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            val transport = settings.transport
            val verificationCheck = settings.verificationCheck
            val onVerificationResult = settings.onVerificationResult
            // Everything down to the fallback's connection is checked
            // before any I/O.
            val proxy = (transport as? Transport.Ehbp)?.proxyUrl?.also { Urls.routeUrl(it, "proxy URL") }
            // The router's config trust is Tinfoil's public registry.
            val verifier = internals.newVerifier(null, VerifierInputs.policy(settings.policy))
            val relay = requireNotEmpty(settings.attestationRelay, "attestationRelay")
            val secret = UserCacheSecret.resolve(settings.userCacheSecret, internals.processSecret)
            val open = { host: String ->
                EnclaveConnection.create(
                    host, RouterDiscovery.ROUTER_PIN, transport, relay, verifier, secret, verificationCheck,
                    onVerificationResult, internals,
                    // The caller named no host, so a direct connection to
                    // the router is pinned in both transport modes.
                    proposed = true,
                )
            }
            val fallback = open(internals.discovery.fallback)

            // A proxy forwards each request, with its headers, to the host
            // that the request names, over a connection that only the proxy
            // sees. A listed host could not be held to its attested key
            // there, so none is used.
            val discovered = try {
                if (relay == null && proxy == null) discover(open, internals) else null
            } catch (e: Throwable) {
                fallback.close()
                throw e
            }
            val connection = if (discovered == null) {
                fallback
            } else {
                fallback.close()
                discovered
            }
            try {
                // A caller that gave up while routers were tried gets no
                // client. A discovered router is verified already, and the
                // fallback is verified here.
                coroutineContext.ensureActive()
                connection.ensureVerified()
            } catch (e: Throwable) {
                connection.close()
                throw e
            }
            return@creating RouterHttpClient(connection)
        }

        private suspend fun discover(open: (String) -> EnclaveConnection, internals: Internals): EnclaveConnection? {
            // The list is fetched as attestation documents are: over HTTPS
            // only, within a time and a size, on connections of its own.
            val fetcher = AttestationFetcher(
                internals.http,
                timeout = RouterDiscovery.LIST_TIMEOUT,
                maxBodyBytes = RouterDiscovery.MAX_LIST_BYTES,
            )
            try {
                return RouterDiscovery(internals.discovery, fetcher::fetch).discover(open)
            } finally {
                fetcher.close()
            }
        }
    }
}
