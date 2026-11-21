package sh.tinfoil.openai

import com.openai.core.http.AsyncStreamResponse
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import sh.tinfoil.Trust
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.awaitUntil
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * What the OpenAI clients do on the thread that calls them, which may be one
 * that must not block or touch the network, as Android's main thread:
 * nothing that prepares the OpenAI options, calls into the verifier or
 * closes a response.
 */
class OpenAICallerThreadTest {
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

    @Test
    fun theOpenAIOptionsArePreparedOffTheCallersThread() {
        val enclave = TestEnclave().also { closeables += it }

        fromCaller {
            val http = enclave.connections(::note).enclave(enclave.host, Trust.RepoPin("tinfoilsh/example")) {
                attestationRelay = enclave.relayHost
            }
            Client.create(http, "a-key") { openAI { note("configure") } }.close()
            http.close()
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
}
