package sh.tinfoil

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.GatewaySettings
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
 * verification endorses, as [Transport.Ehbp] does; the response's body
 * is sealed in turn. The gateway forwards what it cannot read.
 *
 * What the gateway does see is everything that is not a body: the method,
 * the URL and the headers of every request, the API key among them, the
 * model that each request names, and the whole of a request that has no
 * body and of the response to it. Do not put in a URL or a header what only
 * the model may read. Protocol upgrades, such as WebSockets, and `CONNECT`
 * are refused, because sealing cannot protect them.
 *
 * The client serves only the models that it has a [ModelPin] for, and
 * needs at least one. A model's replicas are verified against its pin,
 * under the pin's trust policy, and the gateway's catalog must name the
 * pin's repository for the model. A request for any other model, one that
 * the catalog lists included, fails with a [ConfigurationException] before
 * any replica is contacted.
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
) : AttestedHttpClient {
    /**
     * The gateway's base URL, which requests are sent under. Resolve request
     * paths against it, as in `baseUrl.resolve("chat/completions")`.
     */
    override val baseUrl: HttpUrl get() = router.baseUrl

    /**
     * Returns one entry for each replica that the client has tried to
     * verify and still keeps, failed replicas included, sorted by host,
     * without any I/O. An entry's [current][ReplicaVerification.current]
     * follows the rule of [EnclaveHttpClient.currentVerification] for that
     * replica: the report of the verification that its requests are sent
     * under now, while it is fresh and has not been withdrawn, and null
     * otherwise. Its [lastAttempt][ReplicaVerification.lastAttempt] is the
     * replica's most recent attempt, as
     * [EnclaveHttpClient.lastVerificationAttempt] describes: a failed
     * attempt replaces an earlier success there, though `current` keeps
     * that success while the failure leaves it valid.
     */
    public fun replicas(): List<ReplicaVerification> = router.replicaVerifications

    /**
     * The models that the client serves: those of the gateway's catalog
     * that the client has pins for, whose repository the catalog names,
     * sorted. No replica is verified for this, so a model that is listed
     * can still fail to verify.
     *
     * The catalog is fetched again if the last fetch is more than 10
     * seconds old; a fetch that fails keeps the last catalog, so only the
     * first fetch can fail this. It is safe to call from the main thread.
     *
     * @throws ConfigurationException if the client is closed.
     * @throws NetworkException if there is no catalog yet and it cannot be
     *   fetched.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun models(): List<String> = router.models()

    /**
     * Returns the report of a verification, valid now, of a replica that
     * serves [model], verifying a replica first only if that is needed.
     * Replicas are tried in an order that is fixed for the model, so
     * calling this again returns the same replica's report while it stays
     * valid. A request for the model may still go to another replica, which
     * is verified in the same way before anything is sealed to it. It is
     * safe to call from the main thread.
     *
     * @throws ConfigurationException if the client is closed or does not
     *   serve [model]: it is not pinned, which is checked before the
     *   catalog is read, or it is not in the catalog.
     * @throws NetworkException if no replica's attestation document can be
     *   fetched.
     * @throws AttestationException if no replica of the model is to be
     *   trusted, or the catalog names another repository for the model than
     *   its pin does.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun ensureVerified(model: String): VerificationReport = router.ensureVerified(model)

    /**
     * Verifies again the replica that [ensureVerified] would return for
     * [model], even if its verification is still valid, and returns the new
     * report. It tries the model's replicas in the order that
     * [ensureVerified] tries them, verifying each again, and stops at the
     * first that passes. Each failure follows the rule that
     * [EnclaveHttpClient.reverify] describes, for its replica: an
     * [AttestationException] withdraws the replica's verification, so this
     * moves on to the next replica, as [ensureVerified] then does, and
     * passes over a replica that had no verification in the same way. A
     * failure of any other kind, such as a [NetworkException], keeps the
     * replica's verification while it is valid, and requests for [model]
     * still go to that replica, so this stops there and throws that
     * failure. When no replica passes or keeps a valid verification, it
     * throws the last failure. The replicas after the one that it stops at
     * are not verified. It is safe to call from the main thread.
     *
     * @throws ConfigurationException if the client is closed or does not
     *   serve [model]: it is not pinned, which is checked before the
     *   catalog is read and before any replica is verified, or it is not in
     *   the catalog.
     * @throws NetworkException as described above, or if the catalog
     *   cannot be fetched.
     * @throws AttestationException if no replica of the model is to be
     *   trusted, or the catalog names another repository for the model than
     *   its pin does.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun reverify(model: String): VerificationReport = router.reverify(model)

    /**
     * Sends [request] through the gateway, sealed to a verified replica of
     * the model that it names, and returns the response as soon as its
     * headers arrive. The body streams as it is read, and the caller closes
     * the response. It is safe to call from the main thread: the request's
     * body is read, examined and sealed on background threads. Reading the
     * response's body, or closing it unread, is network I/O, and is not.
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
     * model, such as `GET /v1/models`, is refused before anything is looked
     * up for it: use [models].
     *
     * To find the model, a JSON body is read into memory here, before
     * anything is sent, and so is an upload that has no `X-Tinfoil-Model`
     * header; at most 64 MiB are read, and a larger body is refused. An
     * upload with the header is streamed as it is.
     *
     * **Bodies that could be read in two ways.** The client routes a
     * request by the model that it reads, and the server reads the body
     * for itself, so a body in which the two could find different things
     * is refused before anything is sent, with or without the header:
     * - a JSON body that is not exactly one JSON value in UTF-8, by the
     *   strict grammar: no byte order mark, no other encoding, no `NaN`,
     *   comments or trailing commas;
     * - a JSON object that names `model`, `user_cache_secret` or
     *   `cache_salt` more than once at its top level, in any spelling;
     * - a JSON object with a top-level member whose name differs from one
     *   of those three only by case, such as `Model`, which a server that
     *   ignores case would take for it; and
     * - an upload that does not have exactly one `model` field, that is
     *   not written strictly, or whose `model` field carries a header that
     *   says how it is encoded.
     *
     * A JSON body that is valid and is not an object, such as an array,
     * names no model; with the header, it is sealed and sent as it is. With
     * the header, the client verifies a replica of the model that the
     * header names, and does not compare it with the body.
     *
     * **The prompt cache.** On a `POST` with the content type
     * `application/json` whose path ends in `/chat/completions`,
     * `/completions` or `/responses` and whose body is a JSON object, the
     * member `user_cache_secret` is removed from the body, and `cache_salt`
     * is set to a salt that is derived on this device from that secret, or
     * from the client's when the body has none or an empty one, and from
     * the request's bearer token. On those requests no secret leaves the
     * device. The header `X-Tinfoil-Cache-Prefix`, which the gateway reads
     * to keep a conversation on one replica, is set to a keyed hash of the
     * start of the prompt. These edits rewrite only those members in the
     * body's text: every other byte is sent as it was given, so a number
     * keeps all its digits.
     *
     * Every other request is sealed and sent as it was given, without a
     * cache scope: any other path, method or content type, and a JSON body
     * that is not an object. The client's own secret is never added to
     * such a request. A `user_cache_secret` member that the caller put in
     * such a body is not removed: it is sent as written, inside the sealed
     * body, to the verified replica and to no one else.
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
     * replicas that it used last, and of any other that is in use: a
     * replica is in use until the response of every request to it is
     * closed, so close each response.
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
     *   trusted, the catalog names another repository for the model than
     *   its pin does, or the replica does not hold the verified key.
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
     * the catalog to the last byte of the response body. A blocking
     * [Call.execute] blocks its thread for all of that, so it is never for
     * the main thread.
     */
    override fun newCall(request: Request): Call = AttestedCall(router, request)

    /**
     * Closes the client. Later requests and verifications fail with a
     * [ConfigurationException], verifications in progress and the requests
     * in flight are cancelled, and every connection is closed. Nothing of
     * the client runs afterwards. Closing again does nothing.
     *
     * It is safe to call from any thread, the main thread included, and
     * returns at once: the client refuses requests from then on, and the
     * cancelling and the closing of connections follow on a background
     * thread.
     */
    override fun close() {
        router.close()
    }

    /** Names the gateway, and nothing that is secret. */
    override fun toString(): String = "GatewayHttpClient(baseUrl=$baseUrl)"

    public companion object {
        /** The base URL of Tinfoil's gateway, which a client uses unless it is given another. */
        // Not a `const`: the compiler would copy a constant's value into
        // the code that reads it, which would then keep the URL that it was
        // compiled against.
        public val DEFAULT_URL: String = GatewayRouter.DEFAULT_URL

        /**
         * Creates a client for the gateway and fetches the gateway's
         * catalog before this returns, so that a gateway that cannot be
         * reached fails here and not at the first request.
         *
         * Everything is an option, set in the block that [options] is and
         * described by [GatewayOptions]:
         *
         * ```
         * val client = GatewayHttpClient.create {
         *     modelPins = mapOf("a-model" to ModelPin("tinfoilsh/a-model"))
         * }
         * ```
         *
         * Every option is checked before any network I/O. No replica is
         * verified here: a model's replicas are verified when a request
         * first needs them, so the pins may name models that the catalog
         * does not list, and a request for such a model fails.
         *
         * It is safe to call from the main thread. [options] runs once, on
         * the calling thread, before anything else, and what it set is
         * copied as it returns; what it throws is thrown from here as it
         * is, and nothing is contacted. The options are then checked, which
         * loads the native verifier library the first time, and everything
         * is fetched on background threads. A caller that is cancelled just
         * as the client is made does not receive it, and the client is
         * closed.
         *
         * @param options Sets the options; see [GatewayOptions]. Without
         *   it, every option has its default.
         * @throws ConfigurationException if an option is invalid.
         * @throws NetworkException if the catalog cannot be fetched or
         *   read.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(options: GatewayOptions.() -> Unit = {}): GatewayHttpClient =
            create(Internals(), options)

        /** [create] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun create(internals: Internals, options: GatewayOptions.() -> Unit): GatewayHttpClient =
            create(gatewaySettings(options), internals)

        /** [create] with options that were read already. */
        @JvmSynthetic
        internal suspend fun create(settings: GatewaySettings, internals: Internals): GatewayHttpClient = Background.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            val client = unverified(settings, internals)
            try {
                // Reads the catalog, which is the fetch of it when the
                // caller supplied none.
                client.router.models()
            } catch (e: Throwable) {
                client.close()
                throw e
            }
            return@creating client
        }

        /**
         * A client that is checked but has fetched no catalog. Every
         * option is checked here, and nothing here performs I/O.
         */
        @JvmSynthetic
        internal fun unverified(settings: GatewaySettings, internals: Internals): GatewayHttpClient = GatewayHttpClient(
            GatewayRouter.create(
                settings.modelPins, settings.url, settings.policy,
                settings.userCacheSecret, settings.verificationCheck, settings.onVerificationAttempt, settings.catalog,
                internals,
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
         * replicas are, and proves nothing about them. It is safe to call
         * from the main thread.
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
            // The fetch, the reading of what it returns and the closing of
            // its connections run on a background thread.
            return withContext(Background.dispatcher) {
                val fetcher = GatewayCatalog.fetcher(internals.http)
                try {
                    GatewayCatalog.fetch(host, fetcher)
                } finally {
                    fetcher.close()
                }
            }
        }
    }
}
