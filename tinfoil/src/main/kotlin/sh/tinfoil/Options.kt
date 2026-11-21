package sh.tinfoil

import sh.tinfoil.internal.GatewaySettings
import sh.tinfoil.internal.RouteSettings

/**
 * Marks the receivers of the options blocks that the clients' `create`
 * functions take, so that a block that is nested in another, such as the
 * `openAI { }` of the OpenAI clients, sets only its own options: inside it,
 * an option of the outer block is a compile error unless it is named with
 * its receiver.
 */
@DslMarker
@Target(AnnotationTarget.CLASS, AnnotationTarget.TYPE)
public annotation class TinfoilOptionsDsl

/**
 * The options of [EnclaveHttpClient.create], which are set in the block that
 * it takes:
 *
 * ```
 * val client = EnclaveHttpClient.create("enclave.example.com", Trust.RepoPin("org/repo")) {
 *     transport = Transport.Ehbp(proxyUrl = "https://proxy.example.com/")
 * }
 * ```
 *
 * An option that the block does not set keeps its default. The block runs
 * once, on the thread that called `create`, before anything is checked or
 * contacted, and what it set is copied as it returns: the client is made
 * from those copies, so a change to this object after the block has returned
 * changes nothing. The object is for the block alone and is not safe to
 * share between threads.
 *
 * For the string options, only null means that the option is not set: an
 * empty string is refused by `create`, with a [ConfigurationException],
 * before anything is contacted.
 */
@TinfoilOptionsDsl
@SubclassOptInRequired(InternalTinfoilApi::class)
public abstract class EnclaveOptions @InternalTinfoilApi protected constructor() {
    /**
     * How requests are protected: [Transport.Tls], the default, protects
     * the whole exchange on a direct connection; [Transport.Ehbp] protects
     * only bodies, and works through a proxy, its
     * [proxyUrl][Transport.Ehbp.proxyUrl], which must not be on the
     * enclave's own origin.
     */
    public var transport: Transport = Transport.Tls

    /**
     * A host, with an optional port, that fetches the enclave's attestation
     * document on the client's behalf. It is not trusted: the document is
     * verified whoever delivers it.
     */
    public var attestationRelay: String? = null

    /**
     * The checks that apply on top of the trust argument of
     * [EnclaveHttpClient.create]: register pins, the freshness bound and
     * who vouches for the runtime and platform artifacts. The default keeps
     * every default; see [Policy].
     */
    public var policy: Policy = Policy()

    /**
     * The prompt-cache scope of the client's requests, for an enclave that
     * is one of Tinfoil's routers; other enclaves do not read it. Null
     * sends none. It is added to the JSON body of a `POST` to a chat,
     * completions or responses path, and such a request is refused if its
     * body cannot be examined; see [EnclaveHttpClient.execute]. Use an
     * opaque random value, not a user ID or an API key.
     */
    public var userCacheSecret: String? = null

    /**
     * Called with each verification that passes the trust argument and
     * [policy], before the enclave's keys are used; it throws to reject the enclave. It must not
     * call back into the client.
     */
    public var verificationCheck: VerificationCheck? = null

    /**
     * Called with the outcome of every verification that the client runs,
     * in `create` and later: the verification, or the [TinfoilException]
     * that it failed with. It only observes, so anything that it throws is
     * ignored. It is called once the verification is over, on a thread of
     * the client's: requests that waited for the verification, and `create`
     * itself, may already have gone on by then. It may call back into the
     * client, and may be called from several threads.
     */
    public var onVerificationResult: ((Result<Verification>) -> Unit)? = null

    /** The options as they are now, copied. */
    @JvmSynthetic
    internal fun snapshot(): RouteSettings = RouteSettings(
        transport, attestationRelay, policy, userCacheSecret, verificationCheck, onVerificationResult,
    )
}

/**
 * The options of [RouterHttpClient.create], which are set in the block that
 * it takes:
 *
 * ```
 * val client = RouterHttpClient.create { userCacheSecret = secret }
 * ```
 *
 * An option that the block does not set keeps its default. The block runs
 * once, on the thread that called `create`, before anything is checked or
 * contacted, and what it set is copied as it returns: the client is made
 * from those copies, so a change to this object after the block has returned
 * changes nothing. The object is for the block alone and is not safe to
 * share between threads.
 *
 * For the string options, only null means that the option is not set: an
 * empty string is refused by `create`, with a [ConfigurationException],
 * before anything is contacted.
 */
@TinfoilOptionsDsl
@SubclassOptInRequired(InternalTinfoilApi::class)
public abstract class RouterOptions @InternalTinfoilApi protected constructor() {
    /**
     * How requests are protected: [Transport.Tls], the default, protects
     * the whole exchange on a direct connection; [Transport.Ehbp] protects
     * only bodies, and works through a proxy, its
     * [proxyUrl][Transport.Ehbp.proxyUrl], which forwards each request to
     * the router that the request's `X-Tinfoil-Enclave-Url` header names.
     * With a proxy the router list is not consulted, and the router is
     * always `inference.tinfoil.sh`: the proxy opens the connection to the
     * host that the header names and passes it every header, the API key
     * included, and this SDK cannot hold that connection to the attested
     * key, so the header never names a host that an untrusted list
     * proposed. The router is still verified directly, or through
     * [attestationRelay], and not through the proxy.
     */
    public var transport: Transport = Transport.Tls

    /**
     * A host, with an optional port, that fetches attestation documents on
     * the client's behalf. It is not trusted: a document is verified whoever
     * delivers it. With a relay the router list is not consulted: the client
     * uses `inference.tinfoil.sh`, verified through the relay.
     */
    public var attestationRelay: String? = null

    /**
     * The checks that apply on top of the router's fixed trust, its
     * repository `tinfoilsh/confidential-model-router`: register pins, the
     * freshness bound and who vouches for the runtime and platform
     * artifacts. The default keeps every default; see [Policy].
     */
    public var policy: Policy = Policy()

    /**
     * The prompt-cache scope of the client's requests. It is added to the
     * JSON body of a `POST` to a chat, completions or responses path, and
     * such a request is refused if its body cannot be examined; see
     * [RouterHttpClient.execute]. Requests with the same secret, under the
     * same API key, share cached prompt prefixes. Null selects a
     * random secret that is generated once in each process, kept only in
     * memory, and shared by every client in the process that is given none.
     * Set one to keep the scope across processes or devices. Use an opaque
     * random value, not a user ID or an API key.
     */
    public var userCacheSecret: String? = null

    /**
     * Called with each verification that passes [policy], before the
     * router's keys are used: for each router that is tried in `create`,
     * and whenever the client verifies again. It throws to reject the
     * router; in `create`, the next router is then tried. It must not call
     * back into the client.
     */
    public var verificationCheck: VerificationCheck? = null

    /**
     * Called with the outcome of every verification of the router that the
     * client uses, in `create` and later: the verification, or the
     * [TinfoilException] that it failed with. The routers that were tried
     * and passed over are not reported. It only observes, so anything that
     * it throws is ignored. It is called once the verification is over, on
     * a thread of the client's, and may be called from several threads.
     */
    public var onVerificationResult: ((Result<Verification>) -> Unit)? = null

    /** The options as they are now, copied. */
    @JvmSynthetic
    internal fun snapshot(): RouteSettings = RouteSettings(
        transport, attestationRelay, policy, userCacheSecret, verificationCheck, onVerificationResult,
    )
}

/**
 * The options of [GatewayHttpClient.create], which are set in the block
 * that it takes:
 *
 * ```
 * val client = GatewayHttpClient.create {
 *     modelPins = mapOf("a-model" to ModelPin("tinfoilsh/a-model"))
 *     pinnedModelsOnly = true
 * }
 * ```
 *
 * **Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.**
 *
 * An option that the block does not set keeps its default. The block runs
 * once, on the thread that called `create`, before anything is checked or
 * contacted, and what it set is copied as it returns: the client is made
 * from those copies, so a change to this object, or to a map that it was
 * given, after the block has returned changes nothing. The object is for
 * the block alone and is not safe to share between threads.
 *
 * For the string options, only null means that the option is not set: an
 * empty string is refused by `create`, with a [ConfigurationException],
 * before anything is contacted.
 */
@ExperimentalTinfoilApi
@TinfoilOptionsDsl
@SubclassOptInRequired(InternalTinfoilApi::class)
public abstract class GatewayOptions @InternalTinfoilApi protected constructor() {
    /**
     * The repository that each of these models must run, by the model's
     * name as requests give it, and optionally a trust policy for the
     * model. None by default. The map is copied when the block returns.
     */
    public var modelPins: Map<String, ModelPin> = emptyMap()

    /**
     * Whether to serve only the models in [modelPins], which must then name
     * at least one. False by default.
     */
    public var pinnedModelsOnly: Boolean = false

    /**
     * The gateway's base URL. Null selects Tinfoil's gateway,
     * [GatewayHttpClient.DEFAULT_BASE_URL]. It must be an absolute `https`
     * URL without user information, a query or a fragment. Attestation
     * documents and the catalog are fetched from its host.
     */
    public var baseUrl: String? = null

    /**
     * The checks that apply to the replicas of the models that are not
     * pinned, and of the pins without a policy of their own, on top of the
     * repository that each is verified against. The default keeps every
     * default; see [Policy].
     */
    public var policy: Policy = Policy()

    /**
     * The prompt-cache scope of the client's requests; see
     * [GatewayHttpClient.execute]. Requests with the same secret, under the
     * same API key, share cached prompt prefixes. A non-empty
     * `user_cache_secret` string in a request's body is used in its place,
     * so a server can give each of its users a cache of their own. Null
     * selects a random secret that is generated once in each process,
     * kept only in memory, and shared by every client in the process that
     * is given none. Set one to keep the scope across processes or devices.
     * Use an opaque random value, not a user ID or an API key: the gateway
     * sees a cache prefix that is keyed on it, and could test guesses of a
     * secret that can be guessed, and then of the prompt.
     */
    public var userCacheSecret: String? = null

    /**
     * Called with each replica's verification that passes its trust policy,
     * for pinned models and others, before the replica's key is used, and
     * whenever a replica is verified again. It throws to reject the
     * replica, and the next replica of the model is then tried. It must not
     * call back into the client.
     */
    public var verificationCheck: VerificationCheck? = null

    /**
     * Called with the outcome of every verification of a replica: the
     * verification, or the [TinfoilException] that it failed with. It only
     * observes, so anything that it throws is ignored. It is called once
     * the verification is over, on a thread of the client's, and may be
     * called from several threads.
     */
    public var onVerificationResult: ((Result<Verification>) -> Unit)? = null

    /**
     * Called for every request, and by [GatewayHttpClient.models] and
     * [GatewayHttpClient.ensureVerified], in place of the gateway's
     * catalog, which is then never fetched. It is called on the thread that
     * makes the request, so it must be fast, and safe to call from several
     * threads. Its entries are held to the same rule as the gateway's: a
     * model whose repository is not `tinfoilsh/<name>`, or that has no
     * replicas, is not served. Null fetches the gateway's catalog in
     * `create`, and again whenever the client is used and the last fetch is
     * more than 10 seconds old; a fetch that fails keeps the last catalog.
     * Nothing is fetched while the client is idle.
     */
    public var catalog: (() -> Catalog)? = null

    /** The options as they are now, copied. */
    @JvmSynthetic
    internal fun snapshot(): GatewaySettings = GatewaySettings(
        LinkedHashMap(modelPins), pinnedModelsOnly, baseUrl, policy, userCacheSecret, verificationCheck,
        onVerificationResult, catalog,
    )
}

// The objects that the blocks receive. They are private, and extending the
// types above is for this SDK's own artifacts alone, which the marker on
// their constructors says: a `create` function takes a block and never an
// options object, so an object that someone else made reaches no client.

private class PlainEnclaveOptions : EnclaveOptions()

private class PlainRouterOptions : RouterOptions()

@ExperimentalTinfoilApi
private class PlainGatewayOptions : GatewayOptions()

// Each of these runs the caller's block once, on the calling thread, and
// returns copies of what it set. Whatever the block throws is the caller's
// own failure, and passes through.

@JvmSynthetic
internal fun enclaveSettings(options: EnclaveOptions.() -> Unit): RouteSettings =
    PlainEnclaveOptions().apply(options).snapshot()

@JvmSynthetic
internal fun routerSettings(options: RouterOptions.() -> Unit): RouteSettings =
    PlainRouterOptions().apply(options).snapshot()

@ExperimentalTinfoilApi
@JvmSynthetic
internal fun gatewaySettings(options: GatewayOptions.() -> Unit): GatewaySettings =
    PlainGatewayOptions().apply(options).snapshot()
