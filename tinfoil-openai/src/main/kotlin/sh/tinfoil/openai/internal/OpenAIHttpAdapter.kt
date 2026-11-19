@file:OptIn(InternalTinfoilApi::class)

package sh.tinfoil.openai.internal

import com.openai.core.RequestOptions
import com.openai.core.http.Headers
import com.openai.core.http.HttpClient
import com.openai.core.http.HttpRequest
import com.openai.core.http.HttpRequestBody
import com.openai.core.http.HttpResponse
import com.openai.errors.OpenAIException
import com.openai.errors.OpenAIIoException
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.InternalTinfoilApi
import sh.tinfoil.internal.CrossArtifact
import sh.tinfoil.NetworkException
import sh.tinfoil.TinfoilException
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The OpenAI SDK's HTTP client, as a thin layer over one attested client.
 *
 * It is the only HTTP client that the OpenAI clients of this SDK are given,
 * so every request that the OpenAI SDK makes, its credentials included, goes
 * through [bind]'s call factory and is held to that client's rules: only to
 * its base URL's origin, and only under a valid verification. Nothing here
 * opens a connection of its own.
 *
 * It is made before the attested client exists, so that the OpenAI options
 * can be checked before any network I/O, and is bound to the client once
 * that is verified.
 */
internal class OpenAIHttpAdapter(
    /** The value of the `X-Tinfoil-Events` header for every request, if any. */
    private val events: String?,
) : HttpClient {
    @Volatile
    private var calls: Call.Factory? = null
    private val closed = AtomicBoolean()

    /** Sets the attested client that carries the requests. It is set once. */
    fun bind(calls: Call.Factory) {
        check(this.calls == null) { "the adapter is bound already" }
        this.calls = calls
    }

    override fun execute(request: HttpRequest, requestOptions: RequestOptions): HttpResponse {
        // The body is the SDK's to release once this attempt is over; one
        // that can be written again survives its close.
        return request.body.use {
            val call = newCall(request, requestOptions)
            try {
                AdaptedResponse(call, call.execute())
            } catch (e: IOException) {
                throw translate(e)
            }
        }
    }

    override fun executeAsync(request: HttpRequest, requestOptions: RequestOptions): CompletableFuture<HttpResponse> {
        val future = CompletableFuture<HttpResponse>()
        future.whenComplete { _, _ -> request.body?.close() }
        try {
            val call = newCall(request, requestOptions)
            future.whenComplete { _, _ ->
                if (future.isCancelled) {
                    call.cancel()
                }
            }
            // No thread waits for the response: the attested client calls
            // back when its headers arrive.
            call.enqueue(
                object : Callback {
                    override fun onResponse(call: Call, response: Response) {
                        val adapted = AdaptedResponse(call, response)
                        if (!future.complete(adapted)) {
                            adapted.close()
                        }
                    }

                    override fun onFailure(call: Call, e: IOException) {
                        future.completeExceptionally(translate(e))
                    }
                },
            )
        } catch (e: Throwable) {
            future.completeExceptionally(e)
        }
        return future
    }

    /**
     * Refuses later requests. The attested client belongs to the OpenAI
     * client's owner, which closes it; the OpenAI SDK may call this from a
     * cleaner, at a time of its choosing.
     */
    override fun close() {
        closed.set(true)
    }

    private fun newCall(request: HttpRequest, requestOptions: RequestOptions): Call {
        if (closed.get()) {
            throw refusal(invalid("the client is closed"))
        }
        val calls = calls ?: throw refusal(invalid("the client is not ready"))
        val outgoing = toRequest(request)
        val call = try {
            calls.newCall(outgoing)
        } catch (e: IOException) {
            throw translate(e)
        }
        // The whole exchange is bounded, from the wait for a verification to
        // the last byte of the response body. The attested client has no
        // per-request connect, read or write timeouts to set.
        val limit = requestOptions.timeout?.request()
        if (limit != null && !limit.isZero && !limit.isNegative) {
            call.timeout().timeout(limit.toNanos(), TimeUnit.NANOSECONDS)
        }
        return call
    }

    private fun toRequest(request: HttpRequest): Request {
        val base = request.baseUrl.toHttpUrlOrNull()
            ?: throw refusal(invalid("the OpenAI client's base URL is not an absolute HTTP URL"))
        val url = base.newBuilder().apply {
            request.pathSegments.forEach(::addPathSegment)
            request.queryParams.keys().forEach { key ->
                request.queryParams.values(key).forEach { addQueryParameter(key, it) }
            }
        }.build()

        val method = request.method.name
        val body = request.body?.let(::AdaptedBody)
            ?: EMPTY_BODY.takeIf { method == "POST" || method == "PUT" || method == "PATCH" }
        val builder = Request.Builder().url(url)
        try {
            builder.method(method, body)
        } catch (_: IllegalArgumentException) {
            throw refusal(invalid("a $method request cannot carry a body"))
        }
        request.headers.names().forEach { name ->
            request.headers.values(name).forEach { value ->
                try {
                    builder.addHeader(name, value)
                } catch (_: IllegalArgumentException) {
                    // The value may be a credential, so it is not repeated,
                    // and neither is a message that could quote it.
                    throw refusal(
                        invalid("the request header ${printable(name)} is not valid in an HTTP request"),
                    )
                }
            }
        }
        // A header that the caller set, for the client or for this request,
        // is the caller's choice of events.
        if (events != null && request.headers.values(TinfoilEvents.HEADER).isEmpty()) {
            builder.header(TinfoilEvents.HEADER, events)
        }
        return builder.build()
    }

    /**
     * The OpenAI SDK's request body as the HTTP client's. It says how long it
     * is whenever the SDK knows, and whether it can be written again, so that
     * a body is examined, re-sent and streamed as the attested client's rules
     * say.
     */
    private class AdaptedBody(private val body: HttpRequestBody) : RequestBody() {
        private val type: MediaType? = body.contentType()?.toMediaTypeOrNull()

        override fun contentType(): MediaType? = type

        override fun contentLength(): Long = body.contentLength()

        override fun isOneShot(): Boolean = !body.repeatable()

        override fun writeTo(sink: BufferedSink) {
            body.writeTo(sink.outputStream())
        }
    }

    /**
     * A response whose body streams as it is read. Closing it before the
     * body has been read to its end cancels the call, which also ends a read
     * that another thread is blocked in.
     */
    private class AdaptedResponse(private val call: Call, private val response: Response) : HttpResponse {
        private val headers: Headers = Headers.builder()
            .apply { response.headers.forEach { (name, value) -> put(name, value) } }
            .build()
        private val finished = AtomicBoolean()
        private val body: InputStream = object : FilterInputStream(response.body!!.byteStream()) {
            override fun read(): Int = super.read().also { if (it < 0) finished.set(true) }

            override fun read(b: ByteArray, off: Int, len: Int): Int =
                super.read(b, off, len).also { if (it < 0) finished.set(true) }

            override fun close() {
                // Closed by its reader, on the reader's own thread.
                finished.set(true)
                super.close()
            }
        }

        override fun statusCode(): Int = response.code

        override fun headers(): Headers = headers

        override fun body(): InputStream = body

        override fun close() {
            if (!finished.getAndSet(true)) {
                call.cancel()
            }
            try {
                response.close()
            } catch (_: Exception) {
                // Nothing can be done for a response that will not close.
            }
        }
    }

    private companion object {
        val EMPTY_BODY: RequestBody = object : RequestBody() {
            override fun contentType(): MediaType? = null

            override fun contentLength(): Long = 0

            override fun writeTo(sink: BufferedSink) {}
        }

        const val MAX_PRINTED_NAME = 64

        fun printable(name: String): String =
            name.take(MAX_PRINTED_NAME).map { if (it in '!'..'~') it else '?' }.joinToString("")

        /**
         * A failure of the attested client, as the OpenAI SDK reports
         * failures: unchecked, with the failure itself as the cause.
         *
         * The OpenAI SDK sends a request again after an [IOException] or an
         * [OpenAIIoException]. That is right for a failure of the network,
         * and wrong for an enclave that failed its verification or a request
         * that the client refuses: sending those again cannot help, and only
         * repeats the verification. So they are wrapped in the SDK's plain
         * exception, which it does not retry.
         */
        fun translate(e: IOException): OpenAIException = when (e) {
            is AttestationException, is ConfigurationException -> refusal(e)
            is NetworkException -> OpenAIIoException(e.message, e)
            else -> OpenAIIoException("Request failed", e)
        }

        fun refusal(e: TinfoilException): OpenAIException = OpenAIException(e.message, e)

        fun invalid(detail: String): ConfigurationException = CrossArtifact.configurationException(detail)
    }
}
