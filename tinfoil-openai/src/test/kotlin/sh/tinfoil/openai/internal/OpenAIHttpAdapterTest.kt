package sh.tinfoil.openai.internal

import com.openai.core.RequestOptions
import com.openai.core.Timeout
import com.openai.core.http.HttpMethod
import com.openai.core.http.HttpRequest
import com.openai.core.http.HttpRequestBody
import com.openai.errors.OpenAIException
import com.openai.errors.OpenAIIoException
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import sh.tinfoil.ConfigurationException
import sh.tinfoil.internal.CrossArtifact
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.tinfoilException
import java.io.OutputStream
import java.time.Duration
import java.util.concurrent.CancellationException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * How the adapter turns the OpenAI SDK's requests into the HTTP client's,
 * over a plain HTTP client: what an attested client adds is tested with the
 * OpenAI clients.
 */
class OpenAIHttpAdapterTest {
    private val server = MockWebServer().apply { start() }
    private val http = OkHttpClient()
    private val calls = CopyOnWriteArrayList<Call>()
    private val factory = Call.Factory { request -> http.newCall(request).also { calls += it } }
    private val base = server.url("/v1/").toString()

    @AfterTest
    fun shutDown() {
        http.dispatcher.executorService.shutdown()
        http.connectionPool.evictAll()
        server.shutdown()
    }

    private fun adapter(events: String? = null) = OpenAIHttpAdapter(events).apply { bind(factory) }

    private fun request(method: HttpMethod = HttpMethod.GET, configure: HttpRequest.Builder.() -> Unit = {}): HttpRequest =
        HttpRequest.builder().method(method).baseUrl(base).addPathSegment("models").apply(configure).build()

    private class Body(private val text: String, private val repeatable: Boolean, private val length: Long) : HttpRequestBody {
        val closes = AtomicInteger()

        override fun writeTo(outputStream: OutputStream) = outputStream.write(text.toByteArray())

        override fun contentType(): String = "text/plain; charset=utf-8"

        override fun contentLength(): Long = length

        override fun repeatable(): Boolean = repeatable

        override fun close() {
            closes.incrementAndGet()
        }
    }

    @Test
    fun aRequestIsMappedWithItsPathQueryAndEveryHeaderValue() {
        server.enqueue(MockResponse().setResponseCode(207).addHeader("X-Reply", "a").addHeader("X-Reply", "b").setBody("answer"))
        val adapter = adapter()

        val response = adapter.execute(
            request {
                addPathSegment("a b/c")
                putQueryParam("after", "x y")
                putHeaders("X-Many", listOf("one", "two"))
            },
        )

        assertEquals(207, response.statusCode())
        assertEquals(listOf("a", "b"), response.headers().values("x-reply"))
        assertEquals("answer", response.body().readBytes().toString(Charsets.UTF_8))
        response.close()
        val sent = server.takeRequest()
        assertEquals("/v1/models/a%20b%2Fc?after=x%20y", sent.path)
        assertEquals(listOf("one", "two"), sent.headers.values("X-Many"))
        assertNull(sent.getHeader("X-Tinfoil-Events"))
    }

    @Test
    fun aBodyDeclaresWhatTheSdkKnowsAboutIt() {
        repeat(3) { server.enqueue(MockResponse()) }
        val adapter = adapter()
        val known = Body("known", repeatable = true, length = 5)
        val streamed = Body("streamed", repeatable = false, length = -1)

        adapter.execute(request(HttpMethod.POST) { body(known) }).close()
        adapter.execute(request(HttpMethod.POST) { body(streamed) }).close()
        adapter.execute(request(HttpMethod.POST)).close()

        val first = server.takeRequest()
        assertEquals("5", first.getHeader("Content-Length"))
        assertEquals("text/plain; charset=utf-8", first.getHeader("Content-Type"))
        assertEquals("known", first.body.readUtf8())
        assertEquals(false, calls[0].request().body!!.isOneShot())
        val second = server.takeRequest()
        assertEquals("chunked", second.getHeader("Transfer-Encoding"))
        assertEquals("streamed", second.body.readUtf8())
        assertEquals(true, calls[1].request().body!!.isOneShot())
        assertEquals("0", server.takeRequest().getHeader("Content-Length"), "a POST without a body is sent with an empty one")
        assertEquals(1, known.closes.get(), "the body is released when the attempt is over")
        assertEquals(1, streamed.closes.get())
    }

    @Test
    fun theEventsHeaderIsAddedUnlessTheRequestHasOne() {
        repeat(2) { server.enqueue(MockResponse()) }
        val adapter = adapter(events = "web_search")

        adapter.execute(request()).close()
        adapter.execute(request { putHeader("x-tinfoil-events", "its_own") }).close()

        assertEquals(listOf("web_search"), server.takeRequest().headers.values("X-Tinfoil-Events"))
        assertEquals(listOf("its_own"), server.takeRequest().headers.values("X-Tinfoil-Events"))
    }

    @Test
    fun onlyTheTimeoutForTheWholeRequestIsSetOnTheCall() {
        repeat(3) { server.enqueue(MockResponse()) }
        val adapter = adapter()
        val timeout = Timeout.builder()
            .request(Duration.ofSeconds(7)).connect(Duration.ofSeconds(1)).read(Duration.ofSeconds(2)).write(Duration.ofSeconds(3))
            .build()

        adapter.execute(request(), RequestOptions.builder().timeout(timeout).build()).close()
        adapter.execute(request(), RequestOptions.builder().timeout(Duration.ZERO).build()).close()
        adapter.execute(request(), RequestOptions.none()).close()

        assertEquals(Duration.ofSeconds(7).toNanos(), calls[0].timeout().timeoutNanos())
        assertEquals(0, calls[1].timeout().timeoutNanos(), "zero means no timeout")
        assertEquals(0, calls[2].timeout().timeoutNanos())
    }

    @Test
    fun cancellingTheFutureOfAnAsyncRequestCancelsItsCall() {
        val release = CountDownLatch(1)
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                release.await(30, TimeUnit.SECONDS)
                return MockResponse()
            }
        }
        val body = Body("body", repeatable = true, length = 4)

        val future = adapter().executeAsync(request(HttpMethod.POST) { body(body) })
        server.takeRequest()
        assertEquals(false, future.isDone, "nothing waits for the response but the future")
        future.cancel(true)

        awaitUntil { calls.single().isCanceled() }
        assertFailsWith<CancellationException> { future.get() }
        assertEquals(1, body.closes.get())
        release.countDown()
    }

    @Test
    fun aResponseThatIsClosedUnreadCancelsItsCallAndOneThatWasReadDoesNot() {
        server.enqueue(MockResponse().setBody("read to the end"))
        val release = CountDownLatch(1)
        val adapter = adapter()

        val read = adapter.execute(request())
        read.body().readBytes()
        read.close()
        assertEquals(false, calls[0].isCanceled())

        server.enqueue(MockResponse().setBody("x".repeat(1 shl 20)).throttleBody(1024, 100, TimeUnit.MILLISECONDS))
        val unread = adapter.execute(request())
        assertEquals('x'.code, unread.body().read())
        unread.close()
        assertEquals(true, calls[1].isCanceled())
        release.countDown()
    }

    @Test
    fun aFailureOfTheNetworkIsOneThatTheSdkRetriesAndARefusalIsNot() {
        val adapter = adapter()
        val port = server.port
        server.shutdown()

        val network = assertFailsWith<OpenAIIoException> { adapter.execute(request()) }
        assertNull(network.tinfoilException)
        val async = runCatching { adapter.executeAsync(request()).get() }.exceptionOrNull()
        assertIs<OpenAIIoException>(async?.cause, "port $port")

        val refused = OpenAIHttpAdapter(null).apply {
            bind { throw CrossArtifact.configurationException("refusing to send a request") }
        }
        val refusal = assertFailsWith<OpenAIException> { refused.execute(request()) }
        assertEquals(OpenAIException::class.java, refusal.javaClass)
        assertTrue(assertIs<ConfigurationException>(refusal.cause).detail.startsWith("refusing"))
    }

    @Test
    fun anAdapterThatIsUnboundOrClosedSendsNothing() {
        val unbound = assertFailsWith<OpenAIException> { OpenAIHttpAdapter(null).execute(request()) }
        assertIs<ConfigurationException>(unbound.tinfoilException)

        val adapter = adapter()
        adapter.close()
        val closed = assertFailsWith<OpenAIException> { adapter.execute(request()) }
        assertEquals(OpenAIException::class.java, closed.javaClass)
        assertIs<ConfigurationException>(closed.tinfoilException)
        val async = runCatching { adapter.executeAsync(request()).get() }.exceptionOrNull()
        assertIs<ConfigurationException>(async?.tinfoilException)
        assertEquals(0, calls.size)
        assertEquals(0, server.requestCount)
    }
}
