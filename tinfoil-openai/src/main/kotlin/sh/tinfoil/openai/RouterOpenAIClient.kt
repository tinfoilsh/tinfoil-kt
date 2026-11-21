@file:OptIn(InternalTinfoilApi::class)

package sh.tinfoil.openai

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import kotlinx.coroutines.CancellationException
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.InternalTinfoilApi
import sh.tinfoil.NetworkException
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.internal.CrossArtifact
import sh.tinfoil.internal.RouteSettings
import sh.tinfoil.openai.internal.OpenAISettings
import sh.tinfoil.openai.internal.PreparedOpenAIOptions
import java.io.IOException

/**
 * An OpenAI client whose requests reach only the attested Tinfoil router
 * that it chose when it was created.
 *
 * [openAI] is the OpenAI SDK's own client, to use as that SDK documents.
 * Every request that it makes, the API key included, goes through
 * [httpClient], a [RouterHttpClient], and through nothing else: it waits for
 * a verification of the router that is valid at that moment, goes out under
 * the keys that the verification endorses, and is refused if it is addressed
 * to any other origin.
 *
 * Requests are sent under the router's own `https://<router>/v1/` or, when
 * the client was created with a base URL, which is a proxy's, under that.
 *
 * How failures of this SDK reach the caller of [openAI], how often a request
 * can be sent again, which timeouts and cancellations apply, and what a
 * client made with `withOptions` can bypass, are as [EnclaveOpenAIClient]
 * describes them.
 *
 * It exists for as long as a router is Tinfoil's route to its models. For
 * inference that does not depend on the route, use [Client].
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 */
public class RouterOpenAIClient private constructor(
    /** The attested HTTP client that every request of [openAI] goes through. */
    public val httpClient: RouterHttpClient,
    /**
     * The OpenAI SDK's client, with blocking calls. Its calls block while
     * the router is verified, too, so they are never for the main thread;
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

    /** Names the router, and nothing that is secret. */
    override fun toString(): String = "RouterOpenAIClient(enclave=${httpClient.enclave})"

    public companion object {
        /**
         * Creates a [RouterHttpClient], which chooses and verifies a router
         * before this returns, and an OpenAI client over it.
         *
         * Everything but the API key is an option, set in the one block
         * that [options] is and described by [RouterOpenAIOptions]:
         *
         * ```
         * val client = RouterOpenAIClient.create(apiKey) {
         *     userCacheSecret = secret
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
         * where everything is fetched and verified.
         *
         * @param apiKey The API key, sent as a bearer token with every
         *   request, to the router only, or to the proxy in front of it.
         *   It must not be empty or blank. It is never read from the
         *   environment.
         * @param options Sets the options; see [RouterOpenAIOptions].
         *   Without it, every option has its default.
         * @throws ConfigurationException if an argument or an option is
         *   invalid: [apiKey] is empty or blank, or the OpenAI options do
         *   not make a client. Its message never repeats the key.
         * @throws NetworkException if no router on the list was chosen and
         *   the attestation document of the fallback router cannot be
         *   fetched.
         * @throws AttestationException if no router on the list was chosen
         *   and the fallback router is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            apiKey: String,
            options: RouterOpenAIOptions.() -> Unit = {},
        ): RouterOpenAIClient = create(apiKey, CrossArtifact::routerHttpClient, options)

        /**
         * [create] with [connect] in place of what makes the HTTP client,
         * which tests replace. Whatever it returns is an attested client.
         */
        @JvmSynthetic
        internal suspend fun create(
            apiKey: String,
            connect: suspend (settings: RouteSettings) -> RouterHttpClient,
            options: RouterOpenAIOptions.() -> Unit,
        ): RouterOpenAIClient {
            val (route, openAISettings) = routerOpenAISettings(options)
            return create(apiKey, route, openAISettings, connect)
        }

        /** [create] with options that were read already. */
        @JvmSynthetic
        internal suspend fun create(
            apiKey: String,
            route: RouteSettings,
            openAISettings: OpenAISettings,
            connect: suspend (settings: RouteSettings) -> RouterHttpClient,
        ): RouterOpenAIClient = CrossArtifact.creating {
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
                prepared.bind(httpClient, PreparedOpenAIOptions.apiUrl(httpClient.baseUrl))
            } catch (e: Throwable) {
                prepared.discard()
                httpClient.close()
                throw e
            }
            return@creating RouterOpenAIClient(httpClient, openAI)
        }
    }
}
