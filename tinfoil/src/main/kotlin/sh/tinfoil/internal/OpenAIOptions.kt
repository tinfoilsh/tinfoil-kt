package sh.tinfoil.internal

import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientImpl
import com.openai.core.ClientOptions
import com.openai.core.LogLevel
import okhttp3.Call
import okhttp3.HttpUrl
import sh.tinfoil.ConfigurationException
import sh.tinfoil.TinfoilEvent

/**
 * The OpenAI SDK's options for a client of this SDK, checked and complete
 * except for where its requests go, which is known only once an enclave is
 * verified.
 *
 * [prepare] performs no I/O, so a caller's mistake in the OpenAI options is
 * reported before anything is contacted. [bind] then ties the options to the
 * attested client; [discard] releases them if there will be none.
 */
internal class OpenAIOptions private constructor(
    private val adapter: OpenAIHttpAdapter,
    private val options: ClientOptions,
) {
    /**
     * An OpenAI client that sends through [calls], and through nothing else,
     * to [baseUrl].
     */
    fun bind(calls: Call.Factory, baseUrl: HttpUrl): OpenAIClient {
        adapter.bind(calls)
        return OpenAIClientImpl(options.toBuilder().baseUrl(baseUrl.toString()).build())
    }

    fun discard() {
        options.close()
    }

    companion object {
        /** Stands in for the base URL until an enclave is verified. Nothing is sent to it. */
        private const val UNBOUND_URL = "https://unverified.invalid/v1/"

        /**
         * @throws ConfigurationException if the options do not make a
         *   client: there is no credential, or they select a destination of
         *   their own that cannot be overridden.
         */
        fun prepare(
            apiKey: String?,
            tinfoilEvents: Set<TinfoilEvent>,
            configure: (ClientOptions.Builder.() -> Unit)?,
        ): OpenAIOptions {
            val adapter = OpenAIHttpAdapter(TinfoilEvents.headerValue(tinfoilEvents))
            val builder = ClientOptions.builder()
            // Left alone, the OpenAI SDK takes its log level from the
            // environment and its telemetry switch from a system property.
            // Nothing is taken from either here: both get the SDK's own
            // defaults, and the caller's options can still change them.
            builder.logLevel(LogLevel.OFF)
            builder.disableTelemetry(false)
            apiKey.nullIfEmpty()?.let { builder.apiKey(it) }
            configure?.invoke(builder)
            // Set last, so that nothing in the caller's options replaces
            // them: the OpenAI client can reach the network only through
            // the adapter.
            val options = try {
                builder.httpClient(adapter)
                builder.baseUrl(UNBOUND_URL)
                builder.build()
            } catch (e: IllegalArgumentException) {
                throw invalid(e)
            } catch (e: IllegalStateException) {
                throw invalid(e)
            }
            return OpenAIOptions(adapter, options)
        }

        /**
         * Where an OpenAI client sends its requests: the [configured] base
         * URL as it was given or, when there is none, the OpenAI API under
         * the enclave's origin, [origin].
         */
        fun apiUrl(origin: HttpUrl, configured: String?): HttpUrl =
            if (configured.nullIfEmpty() == null) origin.newBuilder().encodedPath(API_PATH).build() else origin

        private const val API_PATH = "/v1/"

        private fun invalid(e: RuntimeException): ConfigurationException = ConfigurationException(
            "the OpenAI options do not make a client: ${e.message ?: e.javaClass.simpleName}",
            cause = e,
        )
    }
}
