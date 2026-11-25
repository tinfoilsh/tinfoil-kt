package sh.tinfoil.openai

import com.openai.core.ClientOptions
import sh.tinfoil.ConfigurationException
import sh.tinfoil.TinfoilOptionsDsl
import sh.tinfoil.openai.internal.OpenAISettings

/**
 * The options of [Client], which its `create` functions take in a block:
 *
 * ```
 * val client = Client.create(httpClient, apiKey) {
 *     apiPath = "/openai/v1/"
 *     tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH)
 *     openAI { maxRetries(0) }
 * }
 * ```
 *
 * Where requests go on the network is the HTTP client's configuration: its
 * transport and proxy, or the gateway's URL. These options choose only the
 * path of the API on the server, and configure the OpenAI SDK.
 *
 * An option that the block does not set keeps its default. The block runs
 * once, on the thread that called `create`, before anything is checked, and
 * what it set is copied as it returns: the client is made from those
 * copies, so a change to this object, or to a set that it was given, after
 * the block has returned changes nothing. The object is for the block alone
 * and is not safe to share between threads.
 */
@TinfoilOptionsDsl
public class OpenAIOptions internal constructor() {
    /**
     * The path of the API under the HTTP client's base URL: the proxy URL,
     * the enclave's origin or the gateway's URL. Null selects `/v1/`; to
     * keep the default, leave it null, since an empty string is refused. It
     * must be an absolute path, as RFC 3986 defines `path-absolute`: it
     * starts with `/` but not `//`, holds only path characters and escapes,
     * and has no query or fragment. It must not have a `.` or `..` segment,
     * plain or percent-encoded, nor an encoded `/` or `\` (`%2F`, `%5C`).
     * The base URL that it makes ends with `/`. Anything that is refused is
     * a [ConfigurationException] from `create`.
     */
    public var apiPath: String? = null

    /**
     * The progress events to ask for, with the `X-Tinfoil-Events` header of
     * every request; see [TinfoilEvent]. None by default, which sends no
     * header. A request, or [openAI], that sets that header itself keeps
     * its own value. The set is copied when the block returns.
     */
    public var tinfoilEvents: Set<TinfoilEvent> = emptySet()

    private val configure = ArrayList<ClientOptions.Builder.() -> Unit>()

    /**
     * Sets any other option of the OpenAI client, such as `maxRetries`,
     * `timeout` or default headers, on the OpenAI SDK's own options
     * builder, which is the receiver of [configure].
     *
     * [configure] does not run now. It is kept, and runs once, in `create`,
     * on a background thread; what it throws is thrown by `create`. If this
     * is called more than once, each [configure] runs, in the order of the
     * calls, on the same builder. Inside [configure], the options of the
     * block around it are out of scope: they were copied before it runs, so
     * setting one there would change nothing, and does not compile.
     *
     * An HTTP client or a base URL that it sets is replaced by this
     * client's; choose the path with [apiPath]. A credential that it sets
     * with the builder's `apiKey` or `credential` replaces the API key that
     * `create` was given, and one of another kind, such as a workload
     * identity, is refused together with that key, with a
     * [ConfigurationException]. Logging is off unless it is turned on here;
     * the builder's `fromEnv()`, if called here, reads the environment as
     * the OpenAI SDK documents, and the base URL that it reads has no
     * effect.
     */
    public fun openAI(configure: (@TinfoilOptionsDsl ClientOptions.Builder).() -> Unit) {
        this.configure += configure
    }

    /** The options as they are now, copied. */
    internal fun snapshot(): OpenAISettings = OpenAISettings(apiPath, LinkedHashSet(tinfoilEvents), ArrayList(configure))
}

/**
 * Runs the caller's block once, on the calling thread, and returns copies
 * of what it set. Whatever the block throws is the caller's own failure, and
 * passes through.
 */
@JvmSynthetic
internal fun openAISettings(options: OpenAIOptions.() -> Unit): OpenAISettings = OpenAIOptions().apply(options).snapshot()
