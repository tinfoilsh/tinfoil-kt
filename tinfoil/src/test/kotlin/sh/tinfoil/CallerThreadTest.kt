@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import okio.BufferedSink
import sh.tinfoil.internal.Background
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.TestGateway
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * What the HTTP clients do on the thread that calls them, which may be one that
 * must not block or touch the network, as Android's main thread: nothing
 * that calls into the verifier, reads a request body or closes a response.
 */
class CallerThreadTest {
    private val executor = Executors.newSingleThreadExecutor { Thread(it, "the-caller") }
    private val caller = executor.asCoroutineDispatcher()
    private val callerThread: Thread = executor.submit<Thread> { Thread.currentThread() }.get()
    private val closeables = CopyOnWriteArrayList<AutoCloseable>()

    /** What was done, and on which thread. */
    private val done = CopyOnWriteArrayList<Pair<String, Thread>>()

    private fun note(what: String) {
        done += what to Thread.currentThread()
    }

    private fun assertNothingOnTheCallersThread(vararg expected: String) {
        val names = done.map { it.first }.toSet()
        for (what in expected) {
            assertTrue(what in names, "$what was not done at all: $names")
        }
        assertEquals(emptyList(), done.filter { it.second === callerThread }.map { it.first }.distinct(), "done on the caller's thread")
    }

    @AfterTest
    fun shutDown() {
        closeables.reversed().forEach { it.close() }
        executor.shutdownNow()
    }

    /** Runs [block] in a coroutine that stays on the caller's thread. */
    private fun <T> fromCaller(block: suspend () -> T): T = runBlocking {
        withTimeout(60.seconds) {
            withContext(caller) {
                assertSame(callerThread, Thread.currentThread())
                block()
            }
        }
    }

    /** A body that notes when it is asked how long it is, and when it is written. */
    private inner class NotingBody(private val text: String) : RequestBody() {
        override fun contentType(): MediaType = "application/json".toMediaType()

        override fun contentLength(): Long {
            note("contentLength")
            return text.length.toLong()
        }

        override fun writeTo(sink: BufferedSink) {
            note("writeTo")
            sink.writeUtf8(text)
        }
    }

    @Test
    fun anEnclaveClientCallsTheVerifierAndReadsBodiesOffTheCallersThread() {
        val enclave = TestEnclave().also { closeables += it }
        enclave.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = MockResponse()
        }
        fromCaller {
            val client = EnclaveHttpClient.create(
                enclave.host,
                Trust.RepoPin("tinfoilsh/example"),
                enclave.internals(note = ::note),
            ) {
                attestationRelay = enclave.relayHost
                userCacheSecret = "a-cache-secret"
            }
            client.ensureVerified()
            client.reverify()
            for (path in listOf("/v1/chat/completions", "/v1/embeddings")) {
                client.execute(Request.Builder().url(enclave.url(path)).post(NotingBody("""{"model":"m"}""")).build())
            }
            client.close()
        }

        assertNothingOnTheCallersThread("newNonce", "attestationUrl", "checkPinVerifiability", "verify", "contentLength", "writeTo")
    }

    @Test
    fun aGatewayClientCallsTheVerifierAndReadsBodiesOffTheCallersThread() {
        val gateway = TestGateway().also { closeables += it }
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        fromCaller {
            val client = gateway.client(modelPins = mapOf("m" to ModelPin("tinfoilsh/m")), note = ::note)
            client.models()
            client.ensureVerified("m")
            val chat = Request.Builder().url(client.baseUrl.resolve("chat/completions")!!)
                .post(NotingBody("""{"model":"m","messages":[]}""")).build()
            client.execute(chat)
            client.close()
            GatewayHttpClient.fetchCatalog(gateway.host, gateway.internals())
        }

        assertNothingOnTheCallersThread("newNonce", "attestationUrl", "checkPinVerifiability", "verify", "contentLength", "writeTo")
    }

    @Test
    fun whatIsMadeForACallerThatWasCancelledIsReleased() = runBlocking<Unit> {
        val released = CopyOnWriteArrayList<String>()
        val made = AutoCloseable { released += "closed" }
        val parent = Job()

        val creating = launch(parent + caller, start = CoroutineStart.UNDISPATCHED) {
            Background.creating {
                // The caller gives up while the last of the work is done.
                parent.cancel()
                made
            }
            error("a cancelled caller was handed the result")
        }
        creating.join()

        assertTrue(creating.isCancelled)
        assertEquals(listOf("closed"), released, "what was made was not closed, and nothing else would close it")

        // A caller that waits receives what was made, off its own thread.
        var thread: Thread? = null
        val kept = withContext(caller) {
            Background.creating {
                thread = Thread.currentThread()
                made
            }
        }
        assertSame(made, kept)
        assertTrue(thread !== callerThread)
        assertEquals(1, released.size)
        assertFailsWith<IllegalStateException> { Background.creating<AutoCloseable> { error("it could not be made") } }
    }
}
