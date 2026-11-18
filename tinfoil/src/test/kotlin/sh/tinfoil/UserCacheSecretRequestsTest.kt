package sh.tinfoil

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okio.BufferedSink
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.fingerprint
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class UserCacheSecretRequestsTest {
    private val enclave = TestEnclave()
    private val json = "application/json".toMediaType()
    private val secret = "hunter2-cache-scope"

    @AfterTest
    fun shutDown() {
        enclave.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    private fun chat(body: RequestBody, path: String = "/v1/chat/completions"): Request =
        Request.Builder().url(enclave.url(path)).post(body).build()

    private fun chat(text: String): Request = chat(text.toRequestBody(json))

    @Test
    fun theSecretArrivesInTheBodyAndNothingElseChanges() = test {
        val client = enclave.client(userCacheSecret = secret)
        val text = """{"model":"m", "seed":18446744073709551617,"messages":[{"role":"user","content":"hi"}] }"""
        enclave.server.enqueue(MockResponse().setBody("ok"))
        enclave.server.enqueue(MockResponse().setBody("ok"))

        client.execute(chat(text).newBuilder().header("Content-Length", "5").build()).close()
        client.newCall(chat(text)).execute().close()

        val expected = text.dropLast(1) + ""","user_cache_secret":"$secret"}"""
        repeat(2) {
            val received = enclave.server.takeRequest()
            assertEquals(expected, received.body.readUtf8())
            assertEquals(expected.length.toString(), received.getHeader("Content-Length"))
            assertEquals("application/json; charset=utf-8", received.getHeader("Content-Type"))
            assertEquals(null, received.getHeader("Transfer-Encoding"))
        }
    }

    @Test
    fun aClientWithoutASecretSendsBodiesAsTheyAre() = test {
        for (given in listOf(null, "")) {
            val client = enclave.client(userCacheSecret = given)
            enclave.server.enqueue(MockResponse())

            client.execute(chat("""{"model":"m"}""")).close()

            assertEquals("""{"model":"m"}""", enclave.server.takeRequest().body.readUtf8())
        }
    }

    @Test
    fun theRequestsOwnSecretAndOtherEndpointsAreLeftAlone() = test {
        val client = enclave.client(userCacheSecret = secret)
        val untouched = listOf(
            chat("""{"model":"m","user_cache_secret":"per-user"}"""),
            chat("""{"user_cache_secret":"","user_cache_secret":""}"""),
            chat("""{"model":"m"} trailing"""),
            chat("""{"input":"x"}""".toRequestBody(json), "/v1/embeddings"),
            chat("--boundary\r\n\r\n{}\r\n--boundary--".toRequestBody("multipart/form-data; boundary=boundary".toMediaType())),
        )
        for (request in untouched) {
            enclave.server.enqueue(MockResponse())
            client.execute(request).close()

            val sent = okio.Buffer().also { request.body!!.writeTo(it) }.readUtf8()
            val received = enclave.server.takeRequest().body.readUtf8()
            assertEquals(sent, received)
            assertFalse(received.contains(secret))
        }
    }

    @Test
    fun aRequestThatIsSentAgainAfterAKeyRotationCarriesTheSameBody() = test {
        val stale = enclave.authority.issue().fingerprint
        val endorsements = ArrayDeque(listOf(stale, enclave.certificate.fingerprint))
        enclave.endorsed = { endorsements.removeFirst() }
        val client = enclave.client(userCacheSecret = secret)
        enclave.server.enqueue(MockResponse().setBody("after rotation"))
        val writes = AtomicInteger()
        val body = object : RequestBody() {
            override fun contentType() = json

            override fun writeTo(sink: BufferedSink) {
                writes.incrementAndGet()
                sink.writeUtf8("""{"model":"m"}""")
            }
        }

        client.execute(chat(body)).close()

        assertEquals(2, enclave.fetches, "the enclave was verified again")
        assertEquals(1, enclave.server.requestCount)
        assertEquals("""{"model":"m","user_cache_secret":"$secret"}""", enclave.server.takeRequest().body.readUtf8())
        assertEquals(1, writes.get(), "the caller's body was read once, and both attempts used what was read")
    }

    @Test
    fun aBodyThatCanBeSentOnlyOnceIsGivenTheSecretButNeverSentTwice() = test {
        val stale = enclave.authority.issue().fingerprint
        val endorsements = ArrayDeque(listOf(enclave.certificate.fingerprint, stale, enclave.certificate.fingerprint))
        enclave.endorsed = { endorsements.removeFirst() }
        val client = enclave.client(userCacheSecret = secret)
        val writes = AtomicInteger()
        fun oneShot() = object : RequestBody() {
            override fun contentType() = json

            override fun contentLength() = 13L

            override fun isOneShot() = true

            override fun writeTo(sink: BufferedSink) {
                writes.incrementAndGet()
                sink.writeUtf8("""{"model":"m"}""")
            }
        }

        enclave.server.enqueue(MockResponse())
        client.execute(chat(oneShot())).close()
        assertEquals("""{"model":"m","user_cache_secret":"$secret"}""", enclave.server.takeRequest().body.readUtf8())
        assertEquals(1, writes.get())

        // Under a verification whose key the enclave does not hold, the
        // request is refused rather than sent a second time.
        client.reverify()
        val error = assertFailsWith<AttestationException> { client.execute(chat(oneShot())) }
        assertTrue(error.detail.contains("can be sent only once"), error.detail)
        assertEquals(2, writes.get())
        assertEquals(1, enclave.server.requestCount)
        assertFalse(error.toString().contains(secret))
    }

    @Test
    fun aRequestThatTheHttpClientSendsAgainCarriesTheSecretBothTimes() = test {
        val client = enclave.client(userCacheSecret = secret)
        enclave.server.enqueue(MockResponse().setResponseCode(503).setHeader("Retry-After", "0"))
        enclave.server.enqueue(MockResponse().setBody("ok"))

        client.execute(chat("""{"model":"m"}""")).use { assertEquals(200, it.code) }

        repeat(2) {
            assertEquals("""{"model":"m","user_cache_secret":"$secret"}""", enclave.server.takeRequest().body.readUtf8())
        }
    }

    @Test
    fun theSecretIsInNoErrorAndNoDescription() = test {
        val client = enclave.client(userCacheSecret = secret)
        val failures = mutableListOf<Throwable>()
        fun Throwable.all(): List<Throwable> = listOf(this) + suppressed.flatMap { it.all() } + listOfNotNull(cause).flatMap { it.all() }

        // A body that lies about its length, a refused origin, a server that
        // hangs up, and a closed client.
        val lying = object : RequestBody() {
            override fun contentType() = json

            override fun contentLength() = 3L

            override fun isOneShot() = true

            override fun writeTo(sink: BufferedSink) {
                sink.writeUtf8("""{"model":"m"}""")
            }
        }
        failures += assertFailsWith<IOException> { client.execute(chat(lying)) }
        failures += assertFailsWith<ConfigurationException> {
            client.execute(Request.Builder().url("https://other.example/v1/chat/completions").post("{}".toRequestBody()).build())
        }
        enclave.server.enqueue(MockResponse().setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AFTER_REQUEST))
        failures += assertFailsWith<IOException> { client.execute(chat("{}".toRequestBody(json)).newBuilder().post(oneShotOf("{}")).build()) }
        enclave.server.enqueue(MockResponse())
        val response = client.execute(chat("""{"model":"m"}"""))
        val described = listOf(client.toString(), response.toString(), response.request.toString(), response.request.body.toString())
        response.close()
        client.close()
        failures += assertFailsWith<ConfigurationException> { client.execute(chat("{}")) }

        for (text in failures.flatMap { it.all() }.map { it.toString() } + described) {
            assertFalse(text.contains(secret), text)
        }
        failures += assertFailsWith<ConfigurationException> { enclave.client(userCacheSecret = "$secret\ud800") }
        assertFalse(failures.last().toString().contains(secret))
        assertEquals(0, enclave.server.requestCount - 2, "only the two requests that were meant to arrive did")
    }

    private fun oneShotOf(text: String) = object : RequestBody() {
        override fun contentType() = json

        override fun contentLength() = text.length.toLong()

        override fun isOneShot() = true

        override fun writeTo(sink: BufferedSink) {
            sink.writeUtf8(text)
        }
    }
}
