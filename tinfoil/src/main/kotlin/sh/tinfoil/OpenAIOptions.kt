@file:OptIn(InternalTinfoilApi::class)

package sh.tinfoil

import com.openai.core.ClientOptions
import sh.tinfoil.internal.CrossArtifact
import sh.tinfoil.internal.GatewaySettings
import sh.tinfoil.internal.OpenAISettings
import sh.tinfoil.internal.RouteSettings

/**
 * The options of the OpenAI client that this SDK puts over an attested
 * client. [Client.create] takes them alone, in its block; the `create`
 * functions of the OpenAI clients that name their route take them together
 * with the route's options, in one block:
 *
 * ```
 * val client = Client.create(apiKey) {
 *     tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH)
 *     openAI { maxRetries(0) }
 * }
 * ```
 *
 * An option that the block does not set keeps its default. The block runs
 * once, on the thread that called `create`, before anything is checked or
 * contacted, and what it set is copied as it returns: the client is made
 * from those copies, so a change to this object, or to a set that it was
 * given, after the block has returned changes nothing. The object is for
 * the block alone and is not safe to share between threads.
 */
@TinfoilOptionsDsl
public sealed interface OpenAIOptions {
    /**
     * The progress events to ask for, with the `X-Tinfoil-Events` header of
     * every request; see [TinfoilEvent]. None by default, which sends no
     * header. A request, or [openAI], that sets that header itself keeps
     * its own value. The set is copied when the block returns.
     */
    public var tinfoilEvents: Set<TinfoilEvent>

    /**
     * Sets any other option of the OpenAI client, such as `maxRetries`,
     * `timeout` or default headers, on the OpenAI SDK's own options
     * builder, which is the receiver of [configure].
     *
     * [configure] does not run now. It is kept, and runs once, in `create`,
     * before any network I/O, on a background thread; what it throws is
     * thrown by `create`. If this is called more than once, each
     * [configure] runs, in the order of the calls, on the same builder.
     * Inside [configure], the options of the block around it are out of
     * scope: they were copied before it runs, so setting one there would
     * change nothing, and does not compile.
     *
     * An HTTP client or a base URL that it sets is replaced by this
     * client's. A credential that it sets with the builder's `apiKey` or
     * `credential` replaces the API key that `create` was given, and one
     * of another kind, such as a workload identity, is refused together
     * with that key, with a [ConfigurationException] before any network
     * I/O. Logging is off unless it is turned on here; the builder's
     * `fromEnv()`, if called here, reads the environment as the OpenAI SDK
     * documents.
     */
    public fun openAI(configure: (@TinfoilOptionsDsl ClientOptions.Builder).() -> Unit)
}

/**
 * The options of [sh.tinfoil.openai.EnclaveOpenAIClient.create]: those of
 * the [EnclaveHttpClient] that the client sends through, which
 * [EnclaveOptions] describes, and those of the OpenAI client, which
 * [OpenAIOptions] describes, all set in the one block that `create` takes:
 *
 * ```
 * val client = EnclaveOpenAIClient.create("enclave.example.com", pin, apiKey) {
 *     transportMode = TransportMode.EHBP
 *     tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH)
 *     openAI { maxRetries(0) }
 * }
 * ```
 *
 * Two options mean more here than [EnclaveOptions] says. [baseUrl] is also
 * where the OpenAI client's requests are sent, used as it is given: the
 * OpenAI API's paths, such as `chat/completions`, are joined under it. Null
 * selects `https://<enclave>/v1/`. [userCacheSecret] is added to the chat,
 * completions and responses requests that the OpenAI client sends; a
 * request that sets `user_cache_secret` itself, as an additional body
 * property, keeps its own.
 */
public sealed class EnclaveOpenAIOptions : EnclaveOptions(), OpenAIOptions

/**
 * The options of [sh.tinfoil.openai.RouterOpenAIClient.create]: those of
 * the [RouterHttpClient] that the client sends through, which
 * [RouterOptions] describes, and those of the OpenAI client, which
 * [OpenAIOptions] describes, all set in the one block that `create` takes:
 *
 * ```
 * val client = RouterOpenAIClient.create(apiKey) {
 *     userCacheSecret = secret
 *     openAI { maxRetries(0) }
 * }
 * ```
 *
 * Two options mean more here than [RouterOptions] says. [baseUrl], a proxy,
 * which requires [TransportMode.EHBP], is also where the OpenAI client's
 * requests are sent, used as it is given: the OpenAI API's paths, such as
 * `chat/completions`, are joined under it. Null selects the router's
 * `https://<router>/v1/`. [userCacheSecret] is added to the chat,
 * completions and responses requests that the OpenAI client sends; a
 * request that sets `user_cache_secret` itself, as an additional body
 * property, keeps its own, so a server can give each of its users a prompt
 * cache of their own.
 */
public sealed class RouterOpenAIOptions : RouterOptions(), OpenAIOptions

/**
 * The options of [sh.tinfoil.openai.GatewayOpenAIClient.create]: those of
 * the [GatewayHttpClient] that the client sends through, which
 * [GatewayOptions] describes, and those of the OpenAI client, which
 * [OpenAIOptions] describes, all set in the one block that `create` takes:
 *
 * ```
 * val client = GatewayOpenAIClient.create(apiKey) {
 *     modelPins = mapOf("a-model" to ModelPin("tinfoilsh/a-model"))
 *     openAI { maxRetries(0) }
 * }
 * ```
 *
 * **Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.**
 *
 * Two options mean more here than [GatewayOptions] says. [baseUrl], the
 * gateway's base URL, is also where the OpenAI client's requests are sent,
 * used as it is given: the OpenAI API's paths, such as `chat/completions`,
 * are joined under it. Null selects Tinfoil's gateway. [userCacheSecret]
 * scopes the prompt cache of the chat, completions and responses requests
 * that the OpenAI client sends; a request that sets `user_cache_secret`
 * itself, as an additional body property, is scoped by its own, so a server
 * can give each of its users a prompt cache of their own.
 */
@ExperimentalTinfoilApi
public sealed class GatewayOpenAIOptions : GatewayOptions(), OpenAIOptions

// The objects that the blocks receive. They are private, and the types
// above are sealed, so that only this file makes one.

private class PlainOpenAIOptions : OpenAIOptions {
    override var tinfoilEvents: Set<TinfoilEvent> = emptySet()

    private val configure = ArrayList<ClientOptions.Builder.() -> Unit>()

    override fun openAI(configure: (@TinfoilOptionsDsl ClientOptions.Builder).() -> Unit) {
        this.configure += configure
    }

    fun snapshot(): OpenAISettings = OpenAISettings(LinkedHashSet(tinfoilEvents), ArrayList(configure))
}

private class PlainEnclaveOpenAIOptions(
    val openAI: PlainOpenAIOptions = PlainOpenAIOptions(),
) : EnclaveOpenAIOptions(), OpenAIOptions by openAI

private class PlainRouterOpenAIOptions(
    val openAI: PlainOpenAIOptions = PlainOpenAIOptions(),
) : RouterOpenAIOptions(), OpenAIOptions by openAI

@ExperimentalTinfoilApi
private class PlainGatewayOpenAIOptions(
    val openAI: PlainOpenAIOptions = PlainOpenAIOptions(),
) : GatewayOpenAIOptions(), OpenAIOptions by openAI

// Each of these runs the caller's block once, on the calling thread, and
// returns copies of what it set. Whatever the block throws is the caller's
// own failure, and passes through.

@JvmSynthetic
internal fun openAISettings(options: OpenAIOptions.() -> Unit): OpenAISettings =
    PlainOpenAIOptions().apply(options).snapshot()

@JvmSynthetic
internal fun enclaveOpenAISettings(options: EnclaveOpenAIOptions.() -> Unit): Pair<RouteSettings, OpenAISettings> =
    PlainEnclaveOpenAIOptions().apply(options).let { CrossArtifact.snapshot(it) to it.openAI.snapshot() }

@JvmSynthetic
internal fun routerOpenAISettings(options: RouterOpenAIOptions.() -> Unit): Pair<RouteSettings, OpenAISettings> =
    PlainRouterOpenAIOptions().apply(options).let { CrossArtifact.snapshot(it) to it.openAI.snapshot() }

@ExperimentalTinfoilApi
@JvmSynthetic
internal fun gatewayOpenAISettings(options: GatewayOpenAIOptions.() -> Unit): Pair<GatewaySettings, OpenAISettings> =
    PlainGatewayOpenAIOptions().apply(options).let { CrossArtifact.snapshot(it) to it.openAI.snapshot() }
