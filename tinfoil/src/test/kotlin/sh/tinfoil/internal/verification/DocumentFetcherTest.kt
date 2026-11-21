package sh.tinfoil.internal.verification

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okio.Buffer
import sh.tinfoil.ConfigurationException
import sh.tinfoil.NetworkException
import sh.tinfoil.internal.SdkIdentity
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.testing.TestAuthority
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.httpsServer
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class DocumentFetcherTest {
    private val authority = TestAuthority()
    private val server = httpsServer(authority.issue())
    private val plain = MockWebServer().apply { start() }
    private val fetcher = DocumentFetcher(HttpSettings(authority.trust))

    @AfterTest
    fun shutDown() {
        fetcher.close()
        server.shutdown()
        plain.shutdown()
    }

    private fun MockWebServer.https(path: String = "/.well-known/tinfoil-attestation?nonce=00"): HttpUrl =
        "https://localhost:$port$path".toHttpUrl()

    private fun redirect(to: String, status: Int = 302) = MockResponse().setResponseCode(status).setHeader("Location", to)

    @Test
    fun aDocumentIsFetchedWithTheSdksIdentification() = runBlocking<Unit> {
        server.enqueue(MockResponse().setBody("document").setHeader("Set-Cookie", "a=b"))
        server.enqueue(MockResponse().setBody("again"))

        assertEquals("document", fetcher.fetch(server.https()).decodeToString())
        assertEquals("again", fetcher.fetch(server.https()).decodeToString())

        val first = server.takeRequest()
        assertEquals("GET", first.method)
        assertEquals("/.well-known/tinfoil-attestation?nonce=00", first.path)
        assertEquals(SdkIdentity.NAME, first.getHeader("Tinfoil-SDK"))
        assertEquals(SdkIdentity.VERSION, first.getHeader("Tinfoil-SDK-Version"))
        val second = server.takeRequest()
        assertNull(second.getHeader("Cookie"), "no cookies are kept")
        assertEquals(0, second.sequenceNumber, "each fetch has a connection of its own")
    }

    @Test
    fun onlyHttpsIsFetched() = runBlocking<Unit> {
        assertFailsWith<ConfigurationException> { fetcher.fetch("http://localhost:${plain.port}/".toHttpUrl()) }
        assertEquals(0, plain.requestCount)
    }

    @Test
    fun aStatusOutside2xxIsANetworkErrorThatCarriesIt() = runBlocking<Unit> {
        for (status in listOf(204, 299)) {
            server.enqueue(MockResponse().setResponseCode(status))
            assertEquals(0, fetcher.fetch(server.https()).size)
        }
        for (status in listOf(300, 304, 400, 404, 429, 500, 503)) {
            server.enqueue(MockResponse().setResponseCode(status).setBody("secret detail"))
            val error = assertFailsWith<NetworkException>("$status") { fetcher.fetch(server.https()) }
            assertEquals(status, error.status)
            assertTrue(error.detail.contains("HTTP $status"), error.detail)
            assertTrue(!error.detail.contains("nonce"), "the query is left out: ${error.detail}")
        }
    }

    @Test
    fun httpsRedirectsAreFollowedUpToALimit() = runBlocking<Unit> {
        server.enqueue(redirect("/a", 301))
        server.enqueue(redirect(server.https("/b").toString(), 307))
        server.enqueue(MockResponse().setBody("found"))
        assertEquals("found", fetcher.fetch(server.https()).decodeToString())
        assertEquals(listOf("/.well-known/tinfoil-attestation?nonce=00", "/a", "/b"), List(3) { server.takeRequest().path })

        repeat(DocumentFetcher.MAX_REDIRECTS) { server.enqueue(redirect("/hop$it")) }
        server.enqueue(MockResponse().setBody("at the limit"))
        assertEquals("at the limit", fetcher.fetch(server.https()).decodeToString())

        val before = server.requestCount
        repeat(DocumentFetcher.MAX_REDIRECTS + 1) { server.enqueue(redirect("/hop$it")) }
        val error = assertFailsWith<NetworkException> { fetcher.fetch(server.https()) }
        assertTrue(error.detail.contains("stopped after 10 redirects"), error.detail)
        assertNull(error.status)
        assertEquals(DocumentFetcher.MAX_REDIRECTS + 1, server.requestCount - before)
    }

    @Test
    fun aRedirectThatLeavesHttpsIsRefused() = runBlocking<Unit> {
        for (target in listOf("http://localhost:${plain.port}/doc", "ftp://localhost/doc", "file:///etc/passwd")) {
            server.enqueue(redirect(target))
            val error = assertFailsWith<NetworkException>(target) { fetcher.fetch(server.https()) }
            assertTrue(error.detail.contains("not HTTPS"), error.detail)
        }
        // Also when it comes second.
        server.enqueue(redirect("/next"))
        server.enqueue(redirect("http://localhost:${plain.port}/doc"))
        assertFailsWith<NetworkException> { fetcher.fetch(server.https()) }
        assertEquals(0, plain.requestCount, "nothing was sent in cleartext")
    }

    @Test
    fun theBodyIsCappedWhileItStreamsWhateverLengthIsDeclared() = runBlocking<Unit> {
        val capped = DocumentFetcher(HttpSettings(authority.trust), maxBodyBytes = 1000)
        try {
            server.enqueue(MockResponse().setBody("x".repeat(1000)))
            assertEquals(1000, capped.fetch(server.https()).size, "a body of exactly the cap")

            server.enqueue(MockResponse().setBody("x".repeat(1001)))
            assertTrue(assertFailsWith<NetworkException> { capped.fetch(server.https()) }.detail.contains("exceeds 1000 bytes"))

            // No declared length at all.
            server.enqueue(MockResponse().setChunkedBody("x".repeat(100_000), 512))
            assertFailsWith<NetworkException> { capped.fetch(server.https()) }

            // A declared length that understates the body does not let more through.
            server.enqueue(
                MockResponse().setBody(Buffer().writeUtf8("x".repeat(5000))).setHeader("Content-Length", "10"),
            )
            val understated = runCatching { capped.fetch(server.https()) }
            assertTrue(understated.getOrNull()?.size?.let { it <= 1000 } ?: true)
        } finally {
            capped.close()
        }
    }

    @Test
    fun theDefaultLimitsAreThoseOfTheContract() {
        assertEquals(32L * 1024 * 1024, DocumentFetcher.MAX_BODY_BYTES)
        assertEquals(30.seconds, DocumentFetcher.TIMEOUT)
        assertEquals(10, DocumentFetcher.MAX_REDIRECTS)
    }

    @Test
    fun oneTimeoutCoversTheWholeFetch() = runBlocking<Unit> {
        val hurried = DocumentFetcher(HttpSettings(authority.trust), timeout = 600.milliseconds)
        try {
            server.enqueue(MockResponse().setBody("late").setHeadersDelay(3, TimeUnit.SECONDS))
            val slowHeaders = assertFailsWith<NetworkException> { hurried.fetch(server.https()) }
            assertTrue(slowHeaders.detail.contains("timed out"), slowHeaders.detail)

            server.enqueue(MockResponse().setBody("x".repeat(100_000)).throttleBody(100, 1, TimeUnit.SECONDS))
            assertTrue(assertFailsWith<NetworkException> { hurried.fetch(server.https()) }.detail.contains("timed out"))

            // Redirects do not start the clock again.
            repeat(5) { server.enqueue(redirect("/hop$it").setHeadersDelay(250, TimeUnit.MILLISECONDS)) }
            server.enqueue(MockResponse().setBody("too late"))
            val started = System.nanoTime()
            assertFailsWith<NetworkException> { hurried.fetch(server.https()) }
            assertTrue(System.nanoTime() - started < 1_200_000_000L, "the fetch outlived its timeout")
        } finally {
            hurried.close()
        }
    }

    @Test
    fun aFailureToConnectIsANetworkErrorThatKeepsItsCause() = runBlocking<Unit> {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        val dropped = assertFailsWith<NetworkException> { fetcher.fetch(server.https()) }
        assertIs<IOException>(dropped.cause)
        assertNull(dropped.status)

        val untrusted = httpsServer(TestAuthority().issue())
        try {
            val error = assertFailsWith<NetworkException> { fetcher.fetch(untrusted.https()) }
            assertNotNull(error.cause)
            assertEquals(0, untrusted.requestCount, "an untrusted server is sent nothing")
        } finally {
            untrusted.shutdown()
        }

        val closedPort = plain.port.also { plain.shutdown() }
        val refused = assertFailsWith<NetworkException> { fetcher.fetch("https://localhost:$closedPort/".toHttpUrl()) }
        assertIs<IOException>(refused.cause)
    }

    @Test
    fun cancellingTheCallerCancelsTheFetchAndIsNotWrapped() = runBlocking<Unit> {
        server.enqueue(MockResponse().setBody("late").setHeadersDelay(3, TimeUnit.SECONDS))

        val outcome = async(Dispatchers.IO) { runCatching { fetcher.fetch(server.https()) } }
        val fetching = launch(Dispatchers.IO) { fetcher.fetch(server.https()) }
        awaitUntil { server.requestCount >= 1 }
        fetching.cancelAndJoin()
        assertTrue(fetching.isCancelled)
        outcome.cancel()
        assertIs<CancellationException>(runCatching { outcome.await() }.exceptionOrNull())
    }

    @Test
    fun theBytesAreReturnedAsTheyAre() = runBlocking<Unit> {
        val bytes = ByteArray(300_000) { (it % 251).toByte() }
        server.enqueue(MockResponse().setBody(Buffer().write(bytes)))

        assertContentEquals(bytes, fetcher.fetch(server.https()))
    }
}
