package sh.tinfoil.openai

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import com.openai.core.ClientOptions
import kotlinx.coroutines.CancellationException
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.NetworkException
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.TinfoilEvent
import sh.tinfoil.TransportMode
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import sh.tinfoil.Verifier
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.OpenAIOptions
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
 * inference that does not depend on the route, use [sh.tinfoil.Client].
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
         * Every argument is checked before any network I/O, the OpenAI
         * options included.
         *
         * It is safe to call from the main thread: the OpenAI options are
         * prepared, the other options are checked, which loads the native
         * verifier library the first time, and everything is fetched and
         * verified on background threads.
         *
         * The parameters from [transportMode] to [onVerificationResult] are
         * those of [RouterHttpClient.create], which describes them. Its
         * `userCacheSecret` is added to the chat, completions and responses
         * requests that the OpenAI client sends; a request that sets
         * `user_cache_secret` itself, as an additional body property, keeps
         * its own, so a server can give each of its users a prompt cache of
         * their own.
         *
         * @param baseUrl A proxy to send requests through, which requires
         *   [TransportMode.Ehbp]. The OpenAI client uses it as it is given:
         *   the OpenAI API's paths, such as `chat/completions`, are joined
         *   under it. Null selects the router's `https://<router>/v1/`.
         * @param apiKey The API key, sent as a bearer token with every
         *   request, to the router only, or to the proxy in front of it. It
         *   is required, unless [configure] sets a credential. It is never
         *   read from the environment.
         * @param tinfoilEvents The progress events to ask the router for,
         *   with the `X-Tinfoil-Events` header of every request; see
         *   [TinfoilEvent]. None by default, which sends no header. A
         *   request, or [configure], that sets that header itself keeps its
         *   own value.
         * @param configure Sets any other option of the OpenAI client, such
         *   as `maxRetries`, `timeout` or default headers, on the OpenAI
         *   SDK's own options builder. It runs once, here, before any
         *   network I/O, on a background thread. An HTTP client or a base
         *   URL that it sets is replaced by this client's. Logging is off
         *   unless it is turned on here; the builder's `fromEnv()`, if
         *   called here, reads the environment as the OpenAI SDK documents.
         * @throws ConfigurationException if an argument is invalid, or the
         *   OpenAI options name no credential.
         * @throws NetworkException if no router on the list was chosen and
         *   the attestation document of the fallback router cannot be
         *   fetched.
         * @throws AttestationException if no router on the list was chosen
         *   and the fallback router is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            transportMode: TransportMode = TransportMode.Tls,
            baseUrl: String? = null,
            attestationRelay: String? = null,
            verifier: Verifier? = null,
            userCacheSecret: String? = null,
            verificationCheck: VerificationCheck? = null,
            onVerificationResult: ((Result<Verification>) -> Unit)? = null,
            apiKey: String? = null,
            tinfoilEvents: Set<TinfoilEvent> = emptySet(),
            configure: (ClientOptions.Builder.() -> Unit)? = null,
        ): RouterOpenAIClient = create(
            transportMode, baseUrl, attestationRelay, verifier, userCacheSecret, verificationCheck,
            onVerificationResult, apiKey, tinfoilEvents, configure, Internals(),
        )

        /** [create] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun create(
            transportMode: TransportMode,
            baseUrl: String?,
            attestationRelay: String?,
            verifier: Verifier?,
            userCacheSecret: String?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            apiKey: String?,
            tinfoilEvents: Set<TinfoilEvent>,
            configure: (ClientOptions.Builder.() -> Unit)?,
            internals: Internals,
        ): RouterOpenAIClient = Background.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            val options = OpenAIOptions.prepare(apiKey, tinfoilEvents, configure)
            val httpClient = try {
                RouterHttpClient.create(
                    transportMode, baseUrl, attestationRelay, verifier, userCacheSecret, verificationCheck,
                    onVerificationResult, internals,
                )
            } catch (e: Throwable) {
                options.discard()
                throw e
            }
            val openAI = try {
                options.bind(httpClient, OpenAIOptions.apiUrl(httpClient.baseUrl, baseUrl))
            } catch (e: Throwable) {
                options.discard()
                httpClient.close()
                throw e
            }
            return@creating RouterOpenAIClient(httpClient, openAI)
        }
    }
}
