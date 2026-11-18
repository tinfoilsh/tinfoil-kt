package sh.tinfoil

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import com.openai.core.ClientOptions
import kotlinx.coroutines.CancellationException
import okhttp3.Call
import okhttp3.HttpUrl
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.OpenAIOptions
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
         * Every argument is checked before any network I/O.
         *
         * It is safe to call from the main thread: the OpenAI options are
         * prepared, the other options are checked, which loads the native
         * verifier library the first time, and everything is fetched and
         * verified on background threads.
         *
         * @param apiKey The API key, sent as a bearer token with every
         *   request, to the verified service only. It is required: null is
         *   for a credential that [configure] sets instead. It is never read
         *   from the environment.
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
         * @throws ConfigurationException if the OpenAI options name no
         *   credential.
         * @throws NetworkException if the service's attestation document
         *   cannot be fetched.
         * @throws AttestationException if the service is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            apiKey: String?,
            tinfoilEvents: Set<TinfoilEvent> = emptySet(),
            configure: (ClientOptions.Builder.() -> Unit)? = null,
        ): Client = create(apiKey, tinfoilEvents, configure, null, Internals())

        /** [create] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun create(
            apiKey: String?,
            tinfoilEvents: Set<TinfoilEvent>,
            configure: (ClientOptions.Builder.() -> Unit)?,
            verifier: Verifier?,
            internals: Internals,
        ): Client = Background.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            // Today the recommended route is one of Tinfoil's routers, over
            // connections that are pinned to its attested key.
            val route = RouterOpenAIClient.create(
                TransportMode.Tls, null, null, verifier, null, null, null, apiKey, tinfoilEvents, configure, internals,
            )
            return@creating Client(route, OpenAIOptions.apiUrl(route.httpClient.baseUrl, null))
        }
    }
}
