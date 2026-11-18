package sh.tinfoil

import kotlinx.coroutines.CancellationException
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.gateway.GatewayCatalog
import sh.tinfoil.internal.gateway.GatewayRouter
import sh.tinfoil.internal.transport.AttestedCall
import java.io.IOException

/**
 * An HTTP client for Tinfoil inference through Tinfoil's gateway, which
 * routes each request to an enclave that serves the model that the request
 * names: a replica of that model.
 *
 * **Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.**
 *
 * The gateway is not trusted with what a request says. Before a request is
 * sent, the client picks a replica of its model, verifies that replica's
 * attestation, and seals the request's body to the HPKE key that the
 * verification endorses, as [TransportMode.Ehbp] does; the response's body
 * is sealed in turn. The gateway forwards what it cannot read.
 *
 * What the gateway does see is everything that is not a body: the method,
 * the URL and the headers of every request, the API key among them, the
 * model that each request names, and the whole of a request that has no
 * body and of the response to it. Do not put in a URL or a header what only
 * the model may read. Protocol upgrades, such as WebSockets, and `CONNECT`
 * are refused, because sealing cannot protect them.
 *
 * What a replica is verified against depends on the model. A model with a
 * [ModelPin] is verified against that pin, under the pin's trust policy. Any
 * other model is verified against the repository that the gateway's catalog
 * names for it, which must be one of Tinfoil's, `tinfoilsh/<name>`: for such
 * a model the client is assured that the request is sealed to an enclave
 * that runs a release of one of Tinfoil's repositories, and trusts Tinfoil
 * for which of them serves the model. Pin the models for which that is not
 * enough, and set `pinnedModelsOnly` to serve no other.
 *
 * Send requests with [execute], or hand the client, which is an OkHttp
 * [Call.Factory], to a library that is built on OkHttp.
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 */
@ExperimentalTinfoilApi
public class GatewayHttpClient private constructor(
    private val router: GatewayRouter,
) : Call.Factory, AutoCloseable {
    /**
     * The gateway's base URL, which requests are sent under. Resolve request
     * paths against it, as in `baseUrl.resolve("chat/completions")`.
     */
    public val baseUrl: HttpUrl get() = router.baseUrl

    /**
     * The last successful verification of each replica that the client has
     * used and still keeps, without checking them: any may have expired or
     * been rejected since. They are sorted by host. Use [ensureVerified]
     * for a verification that is valid.
     */
    public val current: List<ReplicaVerification> get() = router.current

    /**
     * The models that the client serves: those of the gateway's catalog
     * that the client's pins and `pinnedModelsOnly` allow, sorted. No
     * replica is verified for this, so a model that is listed can still
     * fail to verify.
     *
     * The catalog is fetched again if the last fetch is more than 10
     * seconds old; a fetch that fails keeps the last catalog, so only the
     * first fetch can fail this.
     *
     * @throws ConfigurationException if the client is closed.
     * @throws NetworkException if there is no catalog yet and it cannot be
     *   fetched.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun models(): List<String> = router.models()

    /**
     * Returns a verification, valid now, of a replica that serves [model],
     * verifying a replica first only if that is needed. Replicas are tried
     * in an order that is fixed for the model, so calling this again
     * returns the same replica's verification while it stays valid. A
     * request for the model may still go to another replica, which is
     * verified in the same way before anything is sealed to it.
     *
     * @throws ConfigurationException if the client is closed or does not
     *   serve [model]: it is not in the catalog, or it is not pinned and
     *   only pinned models are served.
     * @throws NetworkException if no replica's attestation document can be
     *   fetched.
     * @throws AttestationException if no replica of the model is to be
     *   trusted, or the catalog names another repository for a pinned model
     *   than its pin does.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun ensureVerified(model: String): Verification = router.ensureVerified(model)

    /**
     * Sends [request] through the gateway, sealed to a verified replica of
     * the model that it names, and returns the response as soon as its
     * headers arrive. The body streams as it is read, and the caller closes
     * the response.
     *
     * The request must be on [baseUrl]'s origin, without credentials in its
     * URL and without a `Host` header, an `Ehbp-` header or
     * `X-Tinfoil-Enclave-Url`. Redirects are not followed.
     *
     * **The model.** A request names its model in one of three ways: the
     * `model` member of a JSON object body, when it is a `POST` with the
     * content type `application/json`; the one `model` field of a
     * `multipart/form-data` upload; or the header `X-Tinfoil-Model`, which
     * wins over both and which every other request needs. The client copies
     * the name into that header for the gateway. A request that names no
     * model, such as `GET /v1/models`, is refused: use [models].
     *
     * To find the model, a JSON body is read into memory here, before
     * anything is sent, and so is an upload that has no `X-Tinfoil-Model`
     * header; at most 64 MiB are read, and a larger body is refused. An
     * upload with the header is streamed as it is.
     *
     * **Repeated members.** A JSON object body that names `model`,
     * `user_cache_secret` or `cache_salt` more than once at its top level,
     * in any spelling, is refused before anything is sent: a server could
     * read another of the repeats than the client did, and so serve another
     * model than the one whose replica was verified. An upload with more
     * than one `model` field, or one that cannot be read strictly, is
     * refused for the same reason. With the `X-Tinfoil-Model` header, the
     * client verifies a replica of the model that the header names, and
     * does not compare it with the body.
     *
     * **The prompt cache.** On a `POST` whose path ends in
     * `/chat/completions`, `/completions` or `/responses`, with a JSON
     * object body, the member `user_cache_secret` is removed from the body,
     * and `cache_salt` is set to a salt that is derived on this device from
     * that secret, or from the client's when the body has none or an empty
     * one, and from the request's bearer token. The secret itself is sent
     * to no one. The header `X-Tinfoil-Cache-Prefix`, which the gateway
     * reads to keep a conversation on one replica, is set to a keyed hash
     * of the start of the prompt. These edits rewrite only those members in
     * the body's text: every other byte is sent as it was given, so a
     * number keeps all its digits. Any other body is sealed and sent
     * unchanged, without a cache scope.
     *
     * **Replicas.** The model's replicas are tried in an order that the
     * cache prefix fixes, or in a random order for a request without one,
     * and the first that verifies is used; one that cannot be verified, or
     * that the client's verification check rejects, is passed over, for at
     * most 16 replicas. If the gateway answers that it routed the request
     * to another replica, which cannot open it, that replica is verified in
     * the same way and the request is sealed to it and sent again, up to 3
     * times; and a request is sent once more after a replica turns out not
     * to hold its attested key and has been verified again. So one call can
     * send a request up to 8 times, each time sealed to a replica that
     * verified, and only if its body can be written again; a JSON body
     * always can, since it is read into memory. Cancel the coroutine to
     * stop that.
     *
     * The client keeps the verifications and the connections of the 256
     * replicas that it used last. When it lets one go, a request that is
     * still in flight to that replica is cancelled.
     *
     * A response without a body of its own to seal is not authenticated:
     * an error status that the gateway answers by itself is returned as it
     * is.
     *
     * @throws ConfigurationException for a request that is refused, a
     *   model that the client does not serve, and a closed client.
     * @throws NetworkException if no replica's attestation document can be
     *   fetched, or the gateway keeps routing the request away from the
     *   replica that it was sealed to.
     * @throws AttestationException if no replica of the model is to be
     *   trusted, the catalog names another repository for a pinned model
     *   than its pin does, or the replica does not hold the verified key.
     * @throws IOException for any other failure to exchange the request,
     *   as the HTTP client reports it.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun execute(request: Request): Response = router.send(request)

    /**
     * Sends [request] as [execute] does, and returns the response together
     * with its session recovery token: the key material that can open this
     * one response again later, without this client. The token is that of
     * the request that was answered, if the request was sent more than
     * once, and is null for a response that is not sealed; see
     * [RecoverableResponse].
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun executeRecoverable(request: Request): RecoverableResponse = router.sendRecoverable(request)

    /**
     * Prepares [request] as a call that follows the rules of [execute], for
     * code that is written against OkHttp. Nothing is checked or sent until
     * the call is executed or enqueued; the call's failures are
     * [IOException]s, and its timeout spans everything from the fetch of
     * the catalog to the last byte of the response body.
     */
    override fun newCall(request: Request): Call = AttestedCall(router, request)

    /**
     * Closes the client. Later requests and verifications fail with a
     * [ConfigurationException], verifications in progress and the requests
     * in flight are cancelled, and every connection is closed. Nothing of
     * the client runs afterwards. Closing again does nothing.
     */
    override fun close() {
        router.close()
    }

    /** Names the gateway, and nothing that is secret. */
    override fun toString(): String = "GatewayHttpClient(baseUrl=$baseUrl)"

    public companion object {
        /** The base URL of Tinfoil's gateway, which a client uses unless it is given another. */
        public const val DEFAULT_BASE_URL: String = GatewayRouter.DEFAULT_BASE_URL

        /**
         * Creates a client for the gateway and fetches the gateway's
         * catalog before this returns, so that a gateway that cannot be
         * reached fails here and not at the first request.
         *
         * Every argument is checked before any network I/O. No replica is
         * verified here: a model's replicas are verified when a request
         * first needs them, so the pins may name models that the catalog
         * does not list, and a request for such a model fails.
         *
         * @param modelPins The repository that each of these models must
         *   run, by the model's name as requests give it, and optionally a
         *   trust policy for the model. The map is copied.
         * @param pinnedModelsOnly Whether to serve only the models in
         *   [modelPins], which must then name at least one.
         * @param baseUrl The gateway's base URL. Null selects Tinfoil's
         *   gateway, [DEFAULT_BASE_URL]. It must be an absolute `https` URL
         *   without user information, a query or a fragment. Attestation
         *   documents and the catalog are fetched from its host.
         * @param verifier The trust policy for the models that are not
         *   pinned, and for the pins without a policy of their own. Null
         *   selects the defaults. A verifier that supplies or authorizes
         *   configs by itself, with an embedded config or a config
         *   authorizer, is refused: replicas are verified against
         *   repositories, so use [EnclaveHttpClient] for an enclave that
         *   needs one.
         * @param userCacheSecret The prompt-cache scope of the client's
         *   requests; see [execute]. Requests with the same secret, under
         *   the same API key, share cached prompt prefixes. A non-empty
         *   `user_cache_secret` string in a request's body is used in its
         *   place, so a server can give each of its users a cache of their
         *   own. Null or empty selects a random secret that is generated
         *   once in each process, kept only in memory, and shared by every
         *   client in the process that is given none. Pass one to keep the
         *   scope across processes or devices. Use an opaque random value,
         *   not a user ID or an API key: the gateway sees a cache prefix
         *   that is keyed on it, and could test guesses of a secret that
         *   can be guessed, and then of the prompt.
         * @param verificationCheck Called with each replica's verification
         *   that passes its trust policy, for pinned models and others,
         *   before the replica's key is used, and whenever a replica is
         *   verified again. It throws to reject the replica, and the next
         *   replica of the model is then tried. It must not call back into
         *   the client.
         * @param onVerificationResult Called with the outcome of every
         *   verification of a replica: the verification, or the
         *   [TinfoilException] that it failed with. It only observes, so
         *   anything that it throws is ignored. It is called once the
         *   verification is over, on a thread of the client's, and may be
         *   called from several threads.
         * @param catalog Called for every request, and by [models] and
         *   [ensureVerified], in place of the gateway's catalog, which is
         *   then never fetched. It must be fast and safe to call from
         *   several threads. Its entries are held to the same rule as the
         *   gateway's: a model whose repository is not `tinfoilsh/<name>`,
         *   or that has no replicas, is not served. Null fetches the
         *   gateway's catalog here, and again whenever the client is used
         *   and the last fetch is more than 10 seconds old; a fetch that
         *   fails keeps the last catalog. Nothing is fetched while the
         *   client is idle.
         * @throws ConfigurationException if an argument is invalid.
         * @throws NetworkException if the catalog cannot be fetched or
         *   read.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            modelPins: Map<String, ModelPin> = emptyMap(),
            pinnedModelsOnly: Boolean = false,
            baseUrl: String? = null,
            verifier: Verifier? = null,
            userCacheSecret: String? = null,
            verificationCheck: VerificationCheck? = null,
            onVerificationResult: ((Result<Verification>) -> Unit)? = null,
            catalog: (() -> Catalog)? = null,
        ): GatewayHttpClient = create(
            modelPins, pinnedModelsOnly, baseUrl, verifier, userCacheSecret, verificationCheck, onVerificationResult,
            catalog, Internals(),
        )

        /** [create] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun create(
            modelPins: Map<String, ModelPin>,
            pinnedModelsOnly: Boolean,
            baseUrl: String?,
            verifier: Verifier?,
            userCacheSecret: String?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            catalog: (() -> Catalog)?,
            internals: Internals,
        ): GatewayHttpClient {
            val client = unverified(
                modelPins, pinnedModelsOnly, baseUrl, verifier, userCacheSecret, verificationCheck,
                onVerificationResult, catalog, internals,
            )
            try {
                // Reads the catalog, which is the fetch of it when the
                // caller supplied none.
                client.router.models()
            } catch (e: Throwable) {
                client.close()
                throw e
            }
            return client
        }

        /**
         * A client that is checked but has fetched no catalog. Every
         * argument is checked here, and nothing here performs I/O.
         */
        @JvmSynthetic
        internal fun unverified(
            modelPins: Map<String, ModelPin>,
            pinnedModelsOnly: Boolean,
            baseUrl: String?,
            verifier: Verifier?,
            userCacheSecret: String?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            catalog: (() -> Catalog)?,
            internals: Internals,
        ): GatewayHttpClient = GatewayHttpClient(
            GatewayRouter.create(
                modelPins, pinnedModelsOnly, baseUrl, verifier, userCacheSecret, verificationCheck,
                onVerificationResult, catalog, internals,
            ),
        )

        /**
         * Fetches the catalog of the gateway at [host], a host with an
         * optional port, and returns the models in it that a client can be
         * routed to: those whose replicas run a repository of Tinfoil's,
         * `tinfoilsh/<name>`, named without a tag or a digest, and that
         * have at least one replica.
         *
         * The catalog is fetched over HTTPS only, redirects included,
         * within 10 seconds and 2 MiB, and it is not trusted: it says where
         * replicas are, and proves nothing about them.
         *
         * @throws ConfigurationException if [host] is not a host.
         * @throws NetworkException if the catalog cannot be fetched or
         *   read.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun fetchCatalog(host: String): Catalog = fetchCatalog(host, Internals())

        /** [fetchCatalog] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun fetchCatalog(host: String, internals: Internals): Catalog {
            GatewayCatalog.url(host)
            val fetcher = GatewayCatalog.fetcher(internals.http)
            try {
                return GatewayCatalog.fetch(host, fetcher)
            } finally {
                fetcher.close()
            }
        }
    }
}
