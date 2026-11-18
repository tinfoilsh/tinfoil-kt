package sh.tinfoil.openai

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import com.openai.core.ClientOptions
import kotlinx.coroutines.CancellationException
import sh.tinfoil.Catalog
import sh.tinfoil.ConfigurationException
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.ModelPin
import sh.tinfoil.NetworkException
import sh.tinfoil.TinfoilEvent
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import sh.tinfoil.Verifier
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.OpenAIOptions
import java.io.IOException

/**
 * An OpenAI client whose requests go through Tinfoil's gateway, each sealed
 * to a verified replica of the model that it names.
 *
 * **Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.**
 *
 * [openAI] is the OpenAI SDK's own client, to use as that SDK documents.
 * Every request that it makes goes through [httpClient], a
 * [GatewayHttpClient], and through nothing else, under the gateway's base
 * URL as it was given. [GatewayHttpClient] says what the gateway can and
 * cannot see: it reads the API key and every other header, and no body.
 *
 * A request has to name a model, so the calls of the OpenAI SDK that send
 * none, such as listing models, are refused; use [GatewayHttpClient.models].
 *
 * How failures of this SDK reach the caller of [openAI], which timeouts and
 * cancellations apply, and what a client made with `withOptions` can
 * bypass, are as [EnclaveOpenAIClient] describes them. A request can be
 * sent more often here: each of the OpenAI SDK's attempts can send it up to
 * 8 times, as [GatewayHttpClient.execute] describes.
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 */
@ExperimentalTinfoilApi
public class GatewayOpenAIClient private constructor(
    /** The gateway client that every request of [openAI] goes through. */
    public val httpClient: GatewayHttpClient,
    /**
     * The OpenAI SDK's client, with blocking calls. Its calls block while
     * a replica is verified, too, so they are never for the main thread;
     * [openAIAsync] is.
     */
    public val openAI: OpenAIClient,
) : AutoCloseable {
    /**
     * The same client with calls that return a `CompletableFuture`, which a
     * coroutine awaits with `kotlinx.coroutines.future.await`, and streams
     * that [asFlow] turns into flows. It shares everything with [openAI].
     */
    public val openAIAsync: OpenAIClientAsync get() = openAI.async()

    /**
     * Closes the OpenAI client and [httpClient]: later requests fail,
     * requests in flight are cancelled, and every connection is closed.
     * Closing again does nothing. Close this client rather than [openAI]
     * alone, which would leave the HTTP client open.
     * It is safe to call from any thread, the main thread included.
     */
    override fun close() {
        try {
            openAI.close()
        } finally {
            httpClient.close()
        }
    }

    /** Names the gateway, and nothing that is secret. */
    override fun toString(): String = "GatewayOpenAIClient(baseUrl=${httpClient.baseUrl})"

    public companion object {
        /**
         * Creates a [GatewayHttpClient], which fetches the gateway's
         * catalog before this returns, and an OpenAI client over it.
         *
         * Every argument is checked before any network I/O, the OpenAI
         * options included.
         *
         * It is safe to call from the main thread: the OpenAI options are
         * prepared, the other options are checked, which loads the native
         * verifier library the first time, and everything is fetched on
         * background threads.
         *
         * The parameters from [modelPins] to [catalog] are those of
         * [GatewayHttpClient.create], which describes them. Its
         * `userCacheSecret` scopes the prompt cache of the chat,
         * completions and responses requests that the OpenAI client sends;
         * a request that sets `user_cache_secret` itself, as an additional
         * body property, is scoped by its own, so a server can give each of
         * its users a prompt cache of their own.
         *
         * @param baseUrl The gateway's base URL, which the OpenAI client
         *   uses as it is given: the OpenAI API's paths, such as
         *   `chat/completions`, are joined under it. Null selects Tinfoil's
         *   gateway.
         * @param apiKey The API key, sent as a bearer token with every
         *   request. The gateway reads it. It is required, unless
         *   [configure] sets a credential. It is never read from the
         *   environment.
         * @param tinfoilEvents The progress events to ask for, with the
         *   `X-Tinfoil-Events` header of every request; see [TinfoilEvent].
         *   None by default, which sends no header. A request, or
         *   [configure], that sets that header itself keeps its own value.
         * @param configure Sets any other option of the OpenAI client, such
         *   as `maxRetries`, `timeout` or default headers, on the OpenAI
         *   SDK's own options builder. It runs once, here, before any
         *   network I/O, on a background thread. An HTTP client or a base
         *   URL that it sets is replaced by this client's. Logging is off
         *   unless it is turned on here; the builder's `fromEnv()`, if
         *   called here, reads the environment as the OpenAI SDK documents.
         * @throws ConfigurationException if an argument is invalid, or the
         *   OpenAI options name no credential.
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
            apiKey: String? = null,
            tinfoilEvents: Set<TinfoilEvent> = emptySet(),
            configure: (ClientOptions.Builder.() -> Unit)? = null,
        ): GatewayOpenAIClient = create(
            modelPins, pinnedModelsOnly, baseUrl, verifier, userCacheSecret, verificationCheck, onVerificationResult,
            catalog, apiKey, tinfoilEvents, configure, Internals(),
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
            apiKey: String?,
            tinfoilEvents: Set<TinfoilEvent>,
            configure: (ClientOptions.Builder.() -> Unit)?,
            internals: Internals,
        ): GatewayOpenAIClient = Background.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            val options = OpenAIOptions.prepare(apiKey, tinfoilEvents, configure)
            val httpClient = try {
                GatewayHttpClient.create(
                    modelPins, pinnedModelsOnly, baseUrl, verifier, userCacheSecret, verificationCheck,
                    onVerificationResult, catalog, internals,
                )
            } catch (e: Throwable) {
                options.discard()
                throw e
            }
            val openAI = try {
                // The gateway's base URL is the API's, as it is.
                options.bind(httpClient, httpClient.baseUrl)
            } catch (e: Throwable) {
                options.discard()
                httpClient.close()
                throw e
            }
            return@creating GatewayOpenAIClient(httpClient, openAI)
        }
    }
}
