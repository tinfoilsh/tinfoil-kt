@file:OptIn(InternalTinfoilApi::class)

package sh.tinfoil.openai

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import kotlinx.coroutines.CancellationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.InternalTinfoilApi
import sh.tinfoil.NetworkException
import sh.tinfoil.internal.CrossArtifact
import sh.tinfoil.internal.GatewaySettings
import sh.tinfoil.openai.internal.OpenAISettings
import sh.tinfoil.openai.internal.PreparedOpenAIOptions
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
 * 8 times, as [GatewayHttpClient.execute] describes, so with the OpenAI
 * SDK's default of two retries one call can send a request up to 24 times,
 * each time sealed to a replica that verified.
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
         * Everything but the API key is an option, set in the one block
         * that [options] is and described by [GatewayOpenAIOptions]:
         *
         * ```
         * val client = GatewayOpenAIClient.create(apiKey) {
         *     modelPins = mapOf("a-model" to ModelPin("tinfoilsh/a-model"))
         *     openAI { maxRetries(0) }
         * }
         * ```
         *
         * Every argument and option is checked before any network I/O, the
         * OpenAI options included.
         *
         * It is safe to call from the main thread. [options] runs once, on
         * the calling thread, before anything else, and what it set is
         * copied as it returns; what it throws is thrown from here as it
         * is, and nothing is contacted. The block that it gave to
         * `openAI { }` runs later, once, on a background thread, where the
         * OpenAI options are prepared and the other options are checked,
         * which loads the native verifier library the first time, and
         * where everything is fetched.
         *
         * @param apiKey The API key, sent as a bearer token with every
         *   request. The gateway reads it. It must not be empty or blank.
         *   It is never read from the environment.
         * @param options Sets the options; see [GatewayOpenAIOptions].
         *   Without it, every option has its default.
         * @throws ConfigurationException if an argument or an option is
         *   invalid: [apiKey] is empty or blank, or the OpenAI options do
         *   not make a client. Its message never repeats the key.
         * @throws NetworkException if the catalog cannot be fetched or
         *   read.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            apiKey: String,
            options: GatewayOpenAIOptions.() -> Unit = {},
        ): GatewayOpenAIClient = create(apiKey, CrossArtifact::gatewayHttpClient, options)

        /**
         * [create] with [connect] in place of what makes the HTTP client,
         * which tests replace. Whatever it returns is a gateway client.
         */
        @JvmSynthetic
        internal suspend fun create(
            apiKey: String,
            connect: suspend (settings: GatewaySettings) -> GatewayHttpClient,
            options: GatewayOpenAIOptions.() -> Unit,
        ): GatewayOpenAIClient {
            val (route, openAISettings) = gatewayOpenAISettings(options)
            return create(apiKey, route, openAISettings, connect)
        }

        /** [create] with options that were read already. */
        @JvmSynthetic
        internal suspend fun create(
            apiKey: String,
            route: GatewaySettings,
            openAISettings: OpenAISettings,
            connect: suspend (settings: GatewaySettings) -> GatewayHttpClient,
        ): GatewayOpenAIClient = CrossArtifact.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            val prepared = PreparedOpenAIOptions.prepare(apiKey, openAISettings)
            val httpClient = try {
                connect(route)
            } catch (e: Throwable) {
                prepared.discard()
                throw e
            }
            val openAI = try {
                // The gateway's base URL is the API's, as it is.
                prepared.bind(httpClient, httpClient.baseUrl)
            } catch (e: Throwable) {
                prepared.discard()
                httpClient.close()
                throw e
            }
            return@creating GatewayOpenAIClient(httpClient, openAI)
        }
    }
}
