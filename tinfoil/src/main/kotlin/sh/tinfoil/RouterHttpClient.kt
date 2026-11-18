package sh.tinfoil

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.internal.EnclaveConnection
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.RouterDiscovery
import sh.tinfoil.internal.nullIfEmpty
import sh.tinfoil.internal.transport.AttestedCall
import sh.tinfoil.internal.transport.Urls
import sh.tinfoil.internal.transport.UserCacheSecret
import sh.tinfoil.internal.verification.AttestationFetcher
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
 * moment, goes out only on a connection whose TLS certificate carries the
 * attested key, and the client verifies the same router again by itself when
 * a verification reaches its freshness deadline or the router stops
 * presenting the verified key. A client never moves to another router; to
 * choose again, create another client.
 *
 * Send requests with [execute], or hand the client, which is an OkHttp
 * [Call.Factory], to a library that is built on OkHttp.
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 */
public class RouterHttpClient private constructor(
    private val connection: EnclaveConnection,
) : Call.Factory, AutoCloseable {
    /**
     * The router that the client chose and verifies: its host, with a port
     * when the router list gave one.
     */
    public val enclave: String get() = connection.enclave

    /** What the router is verified against: Tinfoil's router, by name. */
    public val pin: Pin get() = connection.pin

    /**
     * The URL that requests are sent under: the router's own origin,
     * `https://<enclave>/`. Resolve request paths against it, as in
     * `baseUrl.resolve("v1/models")`.
     */
    public val baseUrl: HttpUrl get() = connection.baseUrl

    /** How the client protects its requests. */
    public val transportMode: TransportMode get() = connection.transportMode

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
     * [EnclaveHttpClient.ensureVerified] does.
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
     * another router.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun reverify(): Verification = connection.reverify()

    /**
     * Sends [request] to the router and returns the response as soon as its
     * headers arrive. The body streams as it is read, and the caller closes
     * the response.
     *
     * The rules are those of [EnclaveHttpClient.execute]: the request must be
     * on [baseUrl]'s origin, over HTTPS, without credentials in its URL or a
     * `Host` header; it waits for a valid verification and is written only
     * to a connection that carries the attested key; redirects are not
     * followed; and the HTTP client may send a request again by itself
     * unless its body can be written only once.
     *
     * The client's user cache secret is added to the body of a `POST` whose
     * path ends in `/chat/completions`, `/completions` or `/responses`, as
     * the member `user_cache_secret`, if the body is one JSON object in
     * which that member is absent or the empty string. The rest of the body
     * is sent byte for byte as it was given. A non-empty `user_cache_secret`
     * string in the body is the request's own scope and is kept, so a server
     * can give each of its users a cache of their own. Any other body is
     * sent unchanged, without the client's secret; see
     * [EnclaveHttpClient.execute] for which.
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
     * Prepares [request] as a call that follows the rules of [execute], for
     * code that is written against OkHttp. Nothing is checked or sent until
     * the call is executed or enqueued. It behaves as
     * [EnclaveHttpClient.newCall] does.
     */
    override fun newCall(request: Request): Call = AttestedCall(connection, request)

    /**
     * Closes the client. Later requests and verifications fail with a
     * [ConfigurationException], a verification in progress and the requests
     * in flight are cancelled, and every connection is closed. Closing again
     * does nothing.
     */
    override fun close() {
        connection.close()
    }

    public companion object {
        /**
         * Creates a client for one of Tinfoil's routers, verified before
         * this returns.
         *
         * The router is the first on Tinfoil's router list that verifies.
         * The list is only a proposal: each router on it is verified against
         * Tinfoil's router by name, exactly as an enclave that the caller
         * names would be, and nothing is sent to one that does not verify.
         * Routers are tried in the order of the list, one at a time and
         * once each, for at most 30 seconds in all, the fetch of the list
         * included. A router that cannot be reached, does not verify or is
         * rejected by [verificationCheck] is passed over. If no router is
         * chosen, because the list could not be fetched or is empty, none
         * verified or the time ran out, the client uses
         * `inference.tinfoil.sh`, which is verified in the same way, with
         * one more attempt if the first fails; if that fails too, this
         * fails with its error.
         *
         * Every argument is checked before any network I/O. Each call
         * chooses anew.
         *
         * @param transportMode How requests are protected. Only
         *   [TransportMode.Tls] is available in this version.
         * @param baseUrl A proxy to send requests through. The router is not
         *   known before it is chosen, so a base URL cannot be on its origin,
         *   and a pinned TLS connection cannot pass through a proxy: it
         *   requires [TransportMode.Ehbp], and is refused in this version.
         * @param attestationRelay A host, with an optional port, that fetches
         *   attestation documents on the client's behalf. It is not trusted:
         *   a document is verified whoever delivers it. With a relay the
         *   router list is not consulted: the client uses
         *   `inference.tinfoil.sh`, verified through the relay.
         * @param verifier The trust policy. Null selects the defaults. A
         *   verifier that supplies or authorizes configs by itself, with an
         *   embedded config or a config authorizer, is refused: it needs an
         *   enclave that the caller names, so use [EnclaveHttpClient].
         * @param userCacheSecret The prompt-cache scope of the client's
         *   requests; see [execute]. Requests with the same secret, under the
         *   same API key, share cached prompt prefixes. Null or empty selects
         *   a random secret that is generated once in each process, kept
         *   only in memory, and shared by every client in the process that
         *   is given none. Pass one to keep the scope across processes or
         *   devices. Use an opaque random value, not a user ID or an API
         *   key.
         * @param verificationCheck Called with each verification that passes
         *   [verifier], before the router's keys are used: for each router
         *   that is tried here, and whenever the client verifies again. It
         *   throws to reject the router; here, the next router is then
         *   tried. It must not call back into the client.
         * @param onVerificationResult Called with the outcome of every
         *   verification of the router that the client uses, here and later:
         *   the verification, or the [TinfoilException] that it failed with.
         *   The routers that were tried and passed over are not reported. It
         *   only observes, so anything that it throws is ignored. It is
         *   called once the verification is over, on a thread of the
         *   client's, and may be called from several threads.
         * @throws ConfigurationException if an argument is invalid.
         * @throws NetworkException if no router on the list was chosen and
         *   the attestation document of `inference.tinfoil.sh` cannot be
         *   fetched.
         * @throws AttestationException if no router on the list was chosen
         *   and `inference.tinfoil.sh` is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            transportMode: TransportMode = TransportMode.Tls,
            baseUrl: String? = null,
            attestationRelay: String? = null,
            verifier: Verifier? = null,
            userCacheSecret: String? = null,
            verificationCheck: VerificationCheck? = null,
            onVerificationResult: ((Result<Verification>) -> Unit)? = null,
        ): RouterHttpClient = create(
            transportMode, baseUrl, attestationRelay, verifier, userCacheSecret, verificationCheck,
            onVerificationResult, Internals(),
        )

        /** [create] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun create(
            transportMode: TransportMode,
            baseUrl: String?,
            attestationRelay: String?,
            verifier: Verifier?,
            userCacheSecret: String?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            internals: Internals,
        ): RouterHttpClient {
            // Everything down to the fallback's connection is checked
            // before any I/O.
            val base = baseUrl.nullIfEmpty()?.let(Urls::baseUrl)
            if (transportMode != TransportMode.Tls) {
                throw ConfigurationException("TransportMode.$transportMode is not available in this version of the SDK")
            }
            if (base != null) {
                throw ConfigurationException(
                    "a base URL is a proxy when the router is discovered, which requires TransportMode.Ehbp",
                )
            }
            val policy = verifier ?: Verifier()
            if (policy.backend.callerAuthorizesConfig) {
                throw ConfigurationException(
                    "a verifier that authorizes configs itself needs an explicit enclave: use EnclaveHttpClient",
                )
            }
            val relay = attestationRelay.nullIfEmpty()
            val secret = UserCacheSecret.orProcessDefault(userCacheSecret)
            val open = { host: String ->
                EnclaveConnection.create(
                    host, RouterDiscovery.ROUTER_PIN, transportMode, null, relay, policy, secret, verificationCheck,
                    onVerificationResult, internals,
                )
            }
            val fallback = open(internals.discovery.fallback)

            val discovered = try {
                if (relay == null) discover(open, internals) else null
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
            return RouterHttpClient(connection)
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
