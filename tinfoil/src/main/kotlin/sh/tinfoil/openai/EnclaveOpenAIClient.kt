@file:OptIn(InternalTinfoilApi::class)

package sh.tinfoil.openai

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import kotlinx.coroutines.CancellationException
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.EnclaveOpenAIOptions
import sh.tinfoil.InternalTinfoilApi
import sh.tinfoil.NetworkException
import sh.tinfoil.Pin
import sh.tinfoil.TransportMode
import sh.tinfoil.enclaveOpenAISettings
import sh.tinfoil.internal.CrossArtifact
import sh.tinfoil.internal.OpenAISettings
import sh.tinfoil.internal.PreparedOpenAIOptions
import sh.tinfoil.internal.RouteSettings
import sh.tinfoil.tinfoilException
import java.io.IOException

/**
 * An OpenAI client whose requests reach only one attested enclave.
 *
 * [openAI] is the OpenAI SDK's own client, to use as that SDK documents.
 * What differs is how it reaches the network: every request that it makes,
 * the API key included, goes through [httpClient], an [EnclaveHttpClient],
 * and through nothing else. So each request waits for a verification of the
 * enclave that is valid at that moment, goes out under the keys that the
 * verification endorses, and is refused if it is addressed to any other
 * origin; see [EnclaveHttpClient.execute] for the rules, which depend on the
 * [TransportMode].
 *
 * Requests are sent under the base URL that the client was created with or,
 * when there is none, under the enclave's own `https://<enclave>/v1/`.
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
 * is verified again. On this route and on the router's, a request with the
 * default options is therefore sent at most six times, three of which at
 * most reach an enclave that holds the key that the request was protected
 * with; this is besides what the HTTP client re-sends when a connection
 * fails, as [EnclaveHttpClient.execute] describes. On the gateway's route
 * the number is higher; see [GatewayOpenAIClient]. A request whose body the OpenAI SDK can write only once, such
 * as an upload that it streams, is sent once.
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
 * **What can bypass the enclave.** Nothing that [create] is given: the HTTP
 * client and the base URL are set after the caller's options, and no
 * credential, URL or option is taken from the environment or from system
 * properties. Two things are read there, and neither decides where a
 * request goes or what it carries of the caller's: the OpenAI SDK's options
 * builder reads the variable `OPENAI_LOG` when it is made, and this SDK
 * then sets logging off, whatever was read; and the OpenAI SDK describes
 * the platform in the `X-Stainless-*` headers of each request, from the
 * system properties `os.name`, `os.arch`, `os.version` and `java.version`.
 * A request's own
 * options cannot change where it goes. But `withOptions`, on [openAI] or on
 * any of its services, returns a client that the caller configures freely:
 * if it is given another HTTP client, its requests, and the API key in
 * them, no longer go through [httpClient] and have none of its protection.
 * A base URL set there, off this client's origin, only makes requests fail.
 * WebSocket APIs, such as the realtime API, are not available.
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 */
public class EnclaveOpenAIClient private constructor(
    /** The attested HTTP client that every request of [openAI] goes through. */
    public val httpClient: EnclaveHttpClient,
    /**
     * The OpenAI SDK's client, with blocking calls. Its calls block while
     * the enclave is verified, too, so they are never for the main thread;
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

    /** Names the enclave, and nothing that is secret. */
    override fun toString(): String = "EnclaveOpenAIClient(enclave=${httpClient.enclave})"

    public companion object {
        /**
         * Creates an [EnclaveHttpClient] for [enclave], verified against
         * [pin] before this returns, and an OpenAI client over it.
         *
         * Everything else is an option, set in the one block that [options]
         * is and described by [EnclaveOpenAIOptions]:
         *
         * ```
         * val client = EnclaveOpenAIClient.create("enclave.example.com", pin, apiKey) {
         *     transportMode = TransportMode.EHBP
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
         * @param enclave The enclave's host, with an optional port, such as
         *   `inference.tinfoil.sh`. Not a URL.
         * @param pin What the enclave must be running; see
         *   [EnclaveHttpClient.create].
         * @param apiKey The API key, sent as a bearer token with every
         *   request, to the enclave only. It must not be empty or blank. It
         *   is never read from the environment.
         * @param options Sets the options; see [EnclaveOpenAIOptions].
         *   Without it, every option has its default.
         * @throws ConfigurationException if an argument or an option is
         *   invalid: [apiKey] is empty or blank, or the OpenAI options do
         *   not make a client. Its message never repeats the key.
         * @throws NetworkException if the attestation document cannot be
         *   fetched.
         * @throws AttestationException if the enclave is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            enclave: String,
            pin: Pin,
            apiKey: String,
            options: EnclaveOpenAIOptions.() -> Unit = {},
        ): EnclaveOpenAIClient = create(enclave, pin, apiKey, CrossArtifact::enclaveHttpClient, options)

        /**
         * [create] with [connect] in place of what makes the HTTP client,
         * which tests replace. Whatever it returns is an attested client.
         */
        @JvmSynthetic
        internal suspend fun create(
            enclave: String,
            pin: Pin,
            apiKey: String,
            connect: suspend (enclave: String, pin: Pin, settings: RouteSettings) -> EnclaveHttpClient,
            options: EnclaveOpenAIOptions.() -> Unit,
        ): EnclaveOpenAIClient {
            val (route, openAISettings) = enclaveOpenAISettings(options)
            return create(enclave, pin, apiKey, route, openAISettings, connect)
        }

        /** [create] with options that were read already. */
        @JvmSynthetic
        internal suspend fun create(
            enclave: String,
            pin: Pin,
            apiKey: String,
            route: RouteSettings,
            openAISettings: OpenAISettings,
            connect: suspend (enclave: String, pin: Pin, settings: RouteSettings) -> EnclaveHttpClient,
        ): EnclaveOpenAIClient = CrossArtifact.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            val prepared = PreparedOpenAIOptions.prepare(apiKey, openAISettings)
            val httpClient = try {
                connect(enclave, pin, route)
            } catch (e: Throwable) {
                prepared.discard()
                throw e
            }
            val openAI = try {
                prepared.bind(httpClient, PreparedOpenAIOptions.apiUrl(httpClient.baseUrl, route.baseUrl))
            } catch (e: Throwable) {
                prepared.discard()
                httpClient.close()
                throw e
            }
            return@creating EnclaveOpenAIClient(httpClient, openAI)
        }
    }
}
