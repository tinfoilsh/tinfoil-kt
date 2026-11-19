package sh.tinfoil.openai

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.openai.client.OpenAIClientImpl
import com.openai.core.ClientOptions
import com.openai.core.RequestOptions
import com.openai.core.http.Headers
import com.openai.core.http.HttpClient
import com.openai.core.http.HttpRequest
import com.openai.core.http.HttpResponse
import com.openai.models.chat.completions.ChatCompletionCreateParams
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The OpenAI SDK itself on this platform, with no network: its JSON mapping
 * and the reflection behind it have to work on Android's runtime.
 */
@RunWith(AndroidJUnit4::class)
class OpenAISdkOnAndroidTest {
    private class Canned(private val contentType: String, private val body: String) : HttpClient {
        val requests = CopyOnWriteArrayList<Pair<HttpRequest, String>>()

        override fun execute(request: HttpRequest, requestOptions: RequestOptions): HttpResponse {
            val sent = ByteArrayOutputStream().also { request.body?.writeTo(it) }.toString("UTF-8")
            requests += request to sent
            return object : HttpResponse {
                override fun statusCode(): Int = 200
                override fun headers(): Headers = Headers.builder().put("Content-Type", contentType).build()
                override fun body(): InputStream = body.byteInputStream()
                override fun close() {}
            }
        }

        override fun executeAsync(request: HttpRequest, requestOptions: RequestOptions): CompletableFuture<HttpResponse> =
            CompletableFuture.completedFuture(execute(request, requestOptions))

        override fun close() {}
    }

    private fun params() = ChatCompletionCreateParams.builder().model("a-model").addUserMessage("hello").build()

    @Test
    fun aChatCompletionIsSerializedAndParsed() {
        val http = Canned(
            "application/json",
            """{"id":"c1","object":"chat.completion","created":1,"model":"a-model","choices":[{"index":0,
               "finish_reason":"stop","logprobs":null,"message":{"role":"assistant","content":"hi there","refusal":null}}]}""",
        )
        val client = OpenAIClientImpl(
            ClientOptions.builder().httpClient(http).baseUrl("https://enclave.invalid/v1/").apiKey("a-key").build(),
        )

        val completion = client.chat().completions().create(params())

        assertEquals("hi there", completion.choices().single().message().content().get())
        val (request, body) = http.requests.single()
        assertEquals("https://enclave.invalid/v1/chat/completions", request.url())
        assertEquals(listOf("Bearer a-key"), request.headers.values("Authorization"))
        assertTrue(body.contains("\"model\":\"a-model\""), body)
        client.close()
    }

    @Test
    fun aStreamedChatCompletionIsParsed() {
        fun chunk(text: String) =
            """data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"a-model","choices":[{"index":0,"delta":{"content":"$text"},"finish_reason":null}]}"""
        val http = Canned("text/event-stream", "${chunk("one")}\n\n${chunk("two")}\n\ndata: [DONE]\n\n")
        val client = OpenAIClientImpl(
            ClientOptions.builder().httpClient(http).baseUrl("https://enclave.invalid/v1/").apiKey("a-key").build(),
        )

        val texts = client.chat().completions().createStreaming(params()).use { stream ->
            val seen = ArrayList<String>()
            stream.stream().forEach { chunk -> chunk.choices().forEach { c -> c.delta().content().ifPresent(seen::add) } }
            seen
        }

        assertEquals(listOf("one", "two"), texts)
        client.close()
    }
}
