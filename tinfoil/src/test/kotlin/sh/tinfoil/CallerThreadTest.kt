@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil

import com.openai.core.http.AsyncStreamResponse
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
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
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.openai.EnclaveOpenAIClient
import sh.tinfoil.openai.asFlow
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.TestGateway
import sh.tinfoil.testing.awaitUntil
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * What the clients do on the thread that calls them, which may be one that
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

    /** A verifier that notes every call into it. */
    private inner class Noting(private val inner: AttestationVerifier) : AttestationVerifier {
        override val callerAuthorizesConfig: Boolean
            get() {
                note("callerAuthorizesConfig")
                return inner.callerAuthorizesConfig
            }

        override fun newNonce(): ByteArray {
            note("newNonce")
            return inner.newNonce()
        }

        override fun attestationUrl(host: String, relay: String?, nonce: ByteArray): String {
            note("attestationUrl")
            return inner.attestationUrl(host, relay, nonce)
        }

        override fun checkPinVerifiability(pin: Pin) {
            note("checkPinVerifiability")
            inner.checkPinVerifiability(pin)
        }

        override fun verify(document: ByteArray, nonce: ByteArray, pin: Pin): Verification {
            note("verify")
            return inner.verify(document, nonce, pin)
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
        val verifier = Verifier.appraisingWith(Noting(enclave.verifier))

        fromCaller {
            val client = EnclaveHttpClient.create(
                enclave.host, Pin(repo = "tinfoilsh/example"), TransportMode.Tls, null, enclave.relayHost, verifier,
                "a-cache-secret", null, null, enclave.internals(),
            )
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
        val verifier = Verifier.appraisingWith(Noting(gateway.verifier))

        fromCaller {
            val client = gateway.client(modelPins = mapOf("m" to ModelPin("tinfoilsh/m")), verifier = verifier)
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
    fun theOpenAIOptionsArePreparedOffTheCallersThread() {
        val enclave = TestEnclave().also { closeables += it }

        fromCaller {
            EnclaveOpenAIClient.create(
                enclave.host, Pin(repo = "tinfoilsh/example"), TransportMode.Tls, null, enclave.relayHost,
                Verifier.appraisingWith(Noting(enclave.verifier)), null, null, null, "a-key", emptySet(),
                { note("configure") }, enclave.internals(),
            ).close()
        }

        assertNothingOnTheCallersThread("configure", "checkPinVerifiability", "verify")
    }

    @Test
    fun aStreamIsSubscribedToAndClosedOffTheCollectorsThread() {
        val handlers = CompletableFuture<AsyncStreamResponse.Handler<String>>()
        val closed = AtomicBoolean()
        val stream = object : AsyncStreamResponse<String> {
            override fun subscribe(handler: AsyncStreamResponse.Handler<String>): AsyncStreamResponse<String> = apply {
                note("subscribe")
                handlers.complete(handler)
            }

            override fun subscribe(handler: AsyncStreamResponse.Handler<String>, executor: Executor): AsyncStreamResponse<String> =
                subscribe(handler)

            override fun onCompleteFuture(): CompletableFuture<Void?> = CompletableFuture()

            override fun close() {
                note("close")
                closed.set(true)
            }
        }
        val feeder = Thread {
            val handler = handlers.get()
            try {
                handler.onNext("one")
                handler.onNext("two")
            } catch (_: CancellationException) {
                // The collector took the first event and stopped.
            }
        }.apply { isDaemon = true }
        feeder.start()

        // The response is still open when the collector stops, as when a
        // screen that shows a stream goes away.
        assertEquals("one", fromCaller { stream.asFlow().first() })

        awaitUntil { closed.get() }
        assertNothingOnTheCallersThread("subscribe", "close")
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
