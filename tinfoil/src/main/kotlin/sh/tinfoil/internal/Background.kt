package sh.tinfoil.internal

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Where this SDK does what must not happen on its caller's thread.
 *
 * A caller may be on a thread that must not block and must not touch the
 * network: on Android's main thread, even closing a TLS socket is refused,
 * with an exception. So whatever can reach a socket, read a file, load the
 * native verifier library or call into it runs here, whichever thread
 * asked for it.
 */
internal object Background {
    /**
     * Runs the suspending work. Its threads come from the shared pool for
     * blocking work, through a view of its own, so that it is not held to
     * that pool's limit: callers may fill that pool with threads that block
     * while they wait for this work, which must then still find a thread.
     */
    val dispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(PARALLELISM)

    private val threads = AtomicInteger()

    // Threads of its own, so that closing a client never waits behind
    // callers that block the shared pools. They end when they are idle.
    private val executor = ThreadPoolExecutor(
        0,
        Int.MAX_VALUE,
        IDLE_THREAD_SECONDS,
        TimeUnit.SECONDS,
        SynchronousQueue(),
    ) { task -> Thread(task, "tinfoil-background-${threads.incrementAndGet()}").apply { isDaemon = true } }

    private const val PARALLELISM = 64
    private const val IDLE_THREAD_SECONDS = 10L

    /**
     * Runs [work] on a background thread, soon, and returns at once. It is
     * for work that a function that cannot suspend must not do itself, such
     * as closing connections when a client closes. Nothing waits for the
     * work, so what it throws has no one to go to and is dropped.
     */
    fun run(work: () -> Unit) {
        executor.execute {
            try {
                work()
            } catch (_: Exception) {
                // The work is tidying up; there is no one to tell.
            }
        }
    }

    /**
     * Runs [block] on a background thread and returns what it made. A
     * caller that is cancelled while [block] finishes does not receive the
     * result, so the result is handed to [release] then, and is not lost
     * with whatever it holds.
     */
    suspend fun <T> making(release: (T) -> Unit, block: suspend () -> T): T {
        var made: Made<T>? = null
        try {
            return withContext(dispatcher) { block().also { made = Made(it) } }
        } catch (e: CancellationException) {
            made?.let { release(it.value) }
            throw e
        }
    }

    /** [making], for something that is closed when no one receives it. */
    suspend fun <T : AutoCloseable> creating(block: suspend () -> T): T = making(AutoCloseable::close, block)

    private class Made<T>(val value: T)
}
