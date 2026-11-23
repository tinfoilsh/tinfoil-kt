@file:OptIn(InternalTinfoilApi::class)

package sh.tinfoil.openai

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import kotlinx.coroutines.CancellationException
import okhttp3.HttpUrl
import sh.tinfoil.AttestationException
import sh.tinfoil.AttestedHttpClient
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.InternalTinfoilApi
import sh.tinfoil.NetworkException
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.internal.CrossArtifact
import sh.tinfoil.openai.internal.ApiPath
import sh.tinfoil.openai.internal.OpenAISettings
import sh.tinfoil.openai.internal.PreparedOpenAIOptions
import sh.tinfoil.tinfoilException
import java.io.IOException

/**
 * An OpenAI client whose requests reach only the service that an attested
 * HTTP client verified.
 *
 * [openAI] is the OpenAI SDK's own client, to use as that SDK documents.
 * What differs is how it reaches the network: every request that it makes,
 * the API key included, goes through [httpClient], an [EnclaveHttpClient],
 * a [RouterHttpClient] or a [GatewayHttpClient], and through nothing else.
 * So each request waits for a verification that is valid at that moment,
 * goes out under the keys that the verification endorses, and is refused if
 * it is addressed to any other origin; see [EnclaveHttpClient.execute] for
 * the rules.
 *
 * Requests are sent under [baseUrl]: the [API path][OpenAIOptions.apiPath],
 * `/v1/` by default, under the HTTP client's base URL, which is the proxy
 * URL of a [sh.tinfoil.Transport.Ehbp] or the enclave's own
 * `https://<enclave>/`; or, over a gateway client, the gateway's URL.
 *
 * **Failures.** The OpenAI SDK throws unchecked exceptions, all of them
 * [com.openai.errors.OpenAIException]s. An error status from the API is one
 * of its subclasses, such as `UnauthorizedException`. A failure of this SDK
 * is the cause of the exception that the caller sees, and [tinfoilException]
 * finds it:
 * - an [AttestationException], when the enclave is not to be trusted, and a
 *   [ConfigurationException], when the client refuses the request or is
 *   closed, are wrapped in a plain `OpenAIException`. The OpenAI SDK does
 *   not send the request again after one;
 * - a [NetworkException], when the enclave has to be verified again and
 *   cannot be reached, and every other failure to exchange the request, are
 *   wrapped in an `OpenAIIoException`, as the OpenAI SDK reports a failure
 *   of the network. It sends the request again after one, as below.
 *
 * **Retries.** The OpenAI SDK sends a request again, a `POST` included,
 * after an `OpenAIIoException` and after a response with the status 408,
 * 409, 429 or 5xx: twice by default, which its `maxRetries` option changes.
 * Each of those attempts is a request to [httpClient] in its own right,
 * which may itself send it twice, when the enclave has changed its key and
 * is verified again. Over an enclave or a router client, a request with the
 * default options is therefore sent at most six times, three of which at
 * most reach an enclave that holds the key that the request was protected
 * with; this is besides what the HTTP client re-sends when a connection
 * fails, as [EnclaveHttpClient.execute] describes. Over a gateway client it
 * is sent at most 24 times, because the gateway can also route a request to
 * another replica up to 3 times. A request whose body the OpenAI SDK can
 * write only once, such as an upload that it streams, is sent once.
 *
 * **Timeouts.** Of the OpenAI SDK's timeout, only the time for a whole
 * request is applied (`Timeout.request`, ten minutes by default), to each
 * attempt, from the wait for a verification to the last byte of the response
 * body, a streamed one included. Its connect, read and write timeouts are
 * not: the HTTP client's own apply.
 *
 * **Cancellation.** Closing a streamed response cancels its request, and so
 * does cancelling the collection of [asFlow]. The OpenAI SDK does not cancel
 * a request whose `CompletableFuture` is cancelled, which is what cancelling
 * a coroutine in `await()` does: the result is dropped, and the exchange
 * runs to its end in the background, within its timeout.
 *
 * **What can bypass the enclave.** Nothing that `create` is given: the HTTP
 * client and the base URL are set after the caller's options, so a base URL
 * that the caller sets in `openAI { }`, or that the OpenAI SDK would read
 * from `OPENAI_BASE_URL`, has no effect; choose the path with
 * [OpenAIOptions.apiPath] instead. No credential, URL or option is taken from
 * the environment or from system properties. Two things are read there, and
 * neither decides where a request goes or what it carries of the caller's:
 * the OpenAI SDK's options builder reads the variable `OPENAI_LOG` when it is
 * made, and this SDK then sets logging off, whatever was read; and the
 * OpenAI SDK describes the platform in the `X-Stainless-*` headers of each
 * request, from the system properties `os.name`, `os.arch`, `os.version`
 * and `java.version`. A request's own options cannot change where it goes.
 * But `withOptions`, on [openAI] or on any of its services, returns a client
 * that the caller configures freely: if it is given another HTTP client, its
 * requests, and the API key in them, no longer go through [httpClient] and
 * have none of its protection. A base URL set there, off the HTTP client's
 * origin, only makes requests fail. WebSocket APIs, such as the realtime
 * API, are not available.
 *
 * A client holds threads until it is [closed][close]. It is safe to use from
 * several threads and coroutines at once.
 */
public class Client private constructor(
    /** The attested HTTP client that every request of [openAI] goes through. */
    public val httpClient: AttestedHttpClient,
    /**
     * The OpenAI SDK's client, with blocking calls. Its calls block while
     * the service is verified, too, so they are never for the main thread;
     * [openAIAsync] is.
     */
    public val openAI: OpenAIClient,
    /**
     * The URL that the OpenAI client sends requests under. Build the URLs of
     * requests for [httpClient] from it, as in `baseUrl.resolve("models")`.
     */
    public val baseUrl: HttpUrl,
    /** Whether [close] closes [httpClient], which this client made. */
    private val ownsHttpClient: Boolean,
) : AutoCloseable {
    /**
     * The same client with calls that return a `CompletableFuture`, which a
     * coroutine awaits with `kotlinx.coroutines.future.await`, and streams
     * that [asFlow] turns into flows. It shares everything with [openAI].
     */
    public val openAIAsync: OpenAIClientAsync get() = openAI.async()

    /**
     * Closes the OpenAI client: later requests fail, and its threads end. A
     * client that [create] made over an HTTP client of the caller's leaves
     * that one open, for the caller to close; the client of the drop-in
     * `create(apiKey)` closes the HTTP client that it made, too, which
     * cancels the requests in flight and closes every connection. Closing
     * again does nothing. It is safe to call from any thread, the main
     * thread included.
     */
    override fun close() {
        try {
            openAI.close()
        } finally {
            if (ownsHttpClient) {
                httpClient.close()
            }
        }
    }

    /** Names nothing that is secret. */
    override fun toString(): String = "Client(baseUrl=$baseUrl)"

    public companion object {
        /**
         * Creates an OpenAI client over [httpClient], which has already
         * verified the service that it sends to, so this performs no network
         * I/O.
         *
         * Its options are set in the block that [options] is and described
         * by [OpenAIOptions]:
         *
         * ```
         * val http = EnclaveHttpClient.create("enclave.example.com", Trust.RepoPin("org/repo"))
         * val client = Client.create(http, apiKey) {
         *     apiPath = "/openai/v1/"
         *     openAI { maxRetries(0) }
         * }
         * ```
         *
         * The OpenAI SDK's HTTP client and base URL are set after the
         * caller's options: a base URL that the block sets through
         * `openAI { }`, or that the OpenAI SDK takes from its environment,
         * has no effect. [OpenAIOptions.apiPath] chooses the path under the
         * HTTP client's base URL.
         *
         * The client does not own [httpClient]: closing it leaves
         * [httpClient] open, and one HTTP client may serve several OpenAI
         * clients, each with an API key of its own.
         *
         * It is safe to call from the main thread. [options] runs once, on
         * the calling thread, and what it set is copied as it returns; what
         * it throws is thrown from here as it is. The block that it gave to
         * `openAI { }` runs later, once, on a background thread, where the
         * OpenAI options are prepared.
         *
         * @param httpClient The attested HTTP client to send through. A null
         *   from Java throws the [NullPointerException] that names the
         *   parameter.
         * @param apiKey The API key, sent as a bearer token with every
         *   request, through [httpClient] only. It must not be empty or
         *   blank. It is never read from the environment.
         * @param options Sets the options; see [OpenAIOptions]. Without it,
         *   every option has its default.
         * @throws ConfigurationException if an argument or an option is
         *   invalid: [apiKey] is empty or blank, the OpenAI options do not
         *   make a client, or the API path is invalid or is set with a
         *   gateway client. Its message never repeats the key.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            httpClient: AttestedHttpClient,
            apiKey: String,
            options: OpenAIOptions.() -> Unit = {},
        ): Client = over(httpClient, apiKey, openAISettings(options), ownsHttpClient = false)

        /**
         * Creates a client on Tinfoil's recommended route: a
         * [RouterHttpClient] with the default options, verified before this
         * returns, and an OpenAI client over it, which closes it when it is
         * closed. To choose the route, or set the HTTP client's options,
         * create the HTTP client and pass it to the other `create`.
         *
         * ```
         * val client = Client.create(apiKey) {
         *     openAI { maxRetries(1) }
         * }
         * ```
         *
         * Every argument and option is checked before any network I/O. It
         * is safe to call from the main thread, as the other `create` is.
         *
         * @param apiKey The API key, sent as a bearer token with every
         *   request, to the verified service only. It must not be empty or
         *   blank. It is never read from the environment.
         * @param options Sets the options; see [OpenAIOptions]. Without it,
         *   every option has its default.
         * @throws ConfigurationException if [apiKey] is empty or blank, or
         *   an option is invalid. Its message never repeats the key.
         * @throws NetworkException if the service's attestation document
         *   cannot be fetched.
         * @throws AttestationException if the service is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            apiKey: String,
            options: OpenAIOptions.() -> Unit = {},
        ): Client = create(apiKey, { RouterHttpClient.create() }, options)

        /**
         * The drop-in [create], with [connect] in place of what makes the
         * HTTP client, which tests replace. Whatever it returns is an
         * attested client.
         */
        @JvmSynthetic
        internal suspend fun create(
            apiKey: String,
            connect: suspend () -> RouterHttpClient,
            options: OpenAIOptions.() -> Unit,
        ): Client {
            val settings = openAISettings(options)
            return CrossArtifact.creating {
                // The OpenAI options are prepared, and so checked, before
                // anything is contacted.
                val prepared = PreparedOpenAIOptions.prepare(apiKey, settings)
                val httpClient = try {
                    connect()
                } catch (e: Throwable) {
                    prepared.discard()
                    throw e
                }
                try {
                    bound(httpClient, prepared, settings, ownsHttpClient = true)
                } catch (e: Throwable) {
                    httpClient.close()
                    throw e
                }
            }
        }

        /** A client over [httpClient], made on a background thread. */
        private suspend fun over(
            httpClient: AttestedHttpClient,
            apiKey: String,
            settings: OpenAISettings,
            ownsHttpClient: Boolean,
        ): Client = CrossArtifact.creating {
            // Preparing the OpenAI options loads its JSON library, which is
            // not done on the caller's thread.
            val prepared = PreparedOpenAIOptions.prepare(apiKey, settings)
            bound(httpClient, prepared, settings, ownsHttpClient)
        }

        private fun bound(
            httpClient: AttestedHttpClient,
            prepared: PreparedOpenAIOptions,
            settings: OpenAISettings,
            ownsHttpClient: Boolean,
        ): Client {
            val openAI = try {
                val baseUrl = ApiPath.baseUrl(httpClient, settings.apiPath)
                prepared.bind(httpClient, baseUrl) to baseUrl
            } catch (e: Throwable) {
                prepared.discard()
                throw e
            }
            return Client(httpClient, openAI.first, openAI.second, ownsHttpClient)
        }
    }
}
