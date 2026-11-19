@file:OptIn(InternalTinfoilApi::class)

package sh.tinfoil

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import kotlinx.coroutines.CancellationException
import okhttp3.Call
import okhttp3.HttpUrl
import sh.tinfoil.internal.CrossArtifact
import sh.tinfoil.internal.PreparedOpenAIOptions
import sh.tinfoil.internal.RouteSettings
import sh.tinfoil.openai.EnclaveOpenAIClient
import sh.tinfoil.openai.RouterOpenAIClient
import java.io.IOException

/**
 * An OpenAI client for inference on Tinfoil's recommended route.
 *
 * [openAI] is the OpenAI SDK's own client, to use as that SDK documents.
 * Every request that it makes, the API key included, goes to a service that
 * was verified before the client was returned and is verified again as its
 * verification expires or its key changes, and to nothing else.
 *
 * The client takes only options of the OpenAI client and says nothing about
 * the route, so that the route can change without breaking its callers. To
 * choose the enclave, pin what it runs, tighten the trust policy, send
 * through a proxy or observe verifications, use
 * [sh.tinfoil.openai.RouterOpenAIClient] or
 * [sh.tinfoil.openai.EnclaveOpenAIClient].
 *
 * How failures of this SDK reach the caller of [openAI], how often a request
 * can be sent again, which timeouts and cancellations apply, and what a
 * client made with `withOptions` can bypass, are as [EnclaveOpenAIClient]
 * describes them.
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 */
public class Client private constructor(
    private val route: RouterOpenAIClient,
    /**
     * The URL that the OpenAI client sends requests under, on the route
     * that was chosen. Build the URLs of requests for [httpClient] from it,
     * as in `baseUrl.resolve("models")`, so that they follow the route.
     */
    public val baseUrl: HttpUrl,
) : AutoCloseable {
    /**
     * The OpenAI SDK's client, with blocking calls. Its calls block while
     * the service is verified, too, so they are never for the main thread;
     * [openAIAsync] is.
     */
    public val openAI: OpenAIClient get() = route.openAI

    /**
     * The same client with calls that return a `CompletableFuture`, which a
     * coroutine awaits with `kotlinx.coroutines.future.await`, and streams
     * that [sh.tinfoil.openai.asFlow] turns into flows.
     */
    public val openAIAsync: OpenAIClientAsync get() = route.openAIAsync

    /**
     * The HTTP client that the OpenAI client sends through, for requests
     * that the OpenAI SDK has no call for. It is bound to the verified
     * service: it verifies the service again before a request when the
     * verification has expired or the key has changed, and refuses a
     * request to any origin but [baseUrl]'s, so that credentials in its
     * headers go nowhere else. The whole exchange is protected on the way to
     * the service.
     */
    public val httpClient: Call.Factory get() = route.httpClient

    /**
     * Closes the client: later requests fail, requests in flight are
     * cancelled, and every connection is closed. Closing again does nothing.
     * It is safe to call from any thread, the main thread included.
     */
    override fun close() {
        route.close()
    }

    /** Names nothing that is secret. */
    override fun toString(): String = "Client(baseUrl=$baseUrl)"

    public companion object {
        /**
         * Creates a client on Tinfoil's recommended route, verified before
         * this returns.
         *
         * The options are those of the OpenAI client, set in the block that
         * [options] is and described by [OpenAIOptions]:
         *
         * ```
         * val client = Client.create(apiKey) {
         *     openAI { maxRetries(1) }
         * }
         * ```
         *
         * Every argument and option is checked before any network I/O.
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
         *   request, to the verified service only. It must not be empty or
         *   blank. It is never read from the environment.
         * @param options Sets the options; see [OpenAIOptions]. Without it,
         *   every option has its default.
         * @throws ConfigurationException if [apiKey] is empty or blank, or
         *   the OpenAI options do not make a client. Its message never
         *   repeats the key.
         * @throws NetworkException if the service's attestation document
         *   cannot be fetched.
         * @throws AttestationException if the service is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            apiKey: String,
            options: OpenAIOptions.() -> Unit = {},
        ): Client = create(apiKey, null, CrossArtifact::routerHttpClient, options)

        /**
         * [create] with a trust policy, and with [connect] in place of what
         * makes the HTTP client, which tests replace.
         */
        @JvmSynthetic
        internal suspend fun create(
            apiKey: String,
            verifier: Verifier?,
            connect: suspend (settings: RouteSettings) -> RouterHttpClient,
            options: OpenAIOptions.() -> Unit,
        ): Client {
            val openAISettings = openAISettings(options)
            // The route's options, of which this client sets the one.
            val (routeSettings, _) = routerOpenAISettings { this.verifier = verifier }
            return CrossArtifact.creating {
                // Checking the options, which calls into the verifier
                // library, and everything after it run on a background
                // thread, so that any thread may call this.
                // Today the recommended route is one of Tinfoil's routers,
                // over connections that are pinned to its attested key.
                val route = RouterOpenAIClient.create(apiKey, routeSettings, openAISettings, connect)
                return@creating Client(route, PreparedOpenAIOptions.apiUrl(route.httpClient.baseUrl, null))
            }
        }
    }
}
