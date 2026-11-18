package sh.tinfoil.internal.transport

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Request
import okhttp3.Response
import okio.Timeout
import sh.tinfoil.internal.EnclaveConnection
import java.io.IOException
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.coroutineContext
import kotlin.time.Duration.Companion.nanoseconds

/**
 * A request to an attested enclave, as a [Call] for code that is written
 * against the HTTP client's own interfaces.
 *
 * It behaves as such a call does: it runs once, on the calling thread or in
 * the background; it can be cancelled from any thread at any point; and its
 * [timeout], when set, spans everything from the verification that the
 * request may wait for to the last byte of the response body. Every failure
 * is an [IOException].
 */
internal class AttestedCall(
    private val connection: EnclaveConnection,
    private val request: Request,
) : Call {
    private val executed = AtomicBoolean()
    private val timeout = Timeout()
    private val lock = Any()

    // Guarded by lock.
    private var canceled = false
    private var job: Job? = null
    private var sent: Call? = null

    override fun request(): Request = request

    override fun timeout(): Timeout = timeout

    override fun isExecuted(): Boolean = executed.get()

    override fun isCanceled(): Boolean = synchronized(lock) { canceled }

    override fun clone(): Call = AttestedCall(connection, request)

    override fun cancel() {
        val (waiting, call) = synchronized(lock) {
            canceled = true
            Pair(job, sent)
        }
        waiting?.cancel()
        call?.cancel()
    }

    override fun execute(): Response {
        start()
        try {
            return runBlocking { run() }
        } catch (e: InterruptedException) {
            cancel()
            Thread.currentThread().interrupt()
            throw InterruptedIOException("interrupted").apply { initCause(e) }
        }
    }

    override fun enqueue(responseCallback: Callback) {
        start()
        // The connection's scope is never cancelled, so the callback is
        // always called: a closed connection fails the call instead.
        connection.scope.launch {
            val response = try {
                run()
            } catch (e: IOException) {
                responseCallback.onFailure(this@AttestedCall, e)
                return@launch
            } catch (e: Throwable) {
                responseCallback.onFailure(this@AttestedCall, IOException("canceled due to $e", e))
                throw e
            }
            try {
                responseCallback.onResponse(this@AttestedCall, response)
            } catch (_: IOException) {
                // The callback's own failure to read the response is its to
                // handle; the call itself succeeded.
                response.closeQuietly()
            } catch (e: Throwable) {
                cancel()
                throw e
            }
        }
    }

    private fun start() {
        check(executed.compareAndSet(false, true)) { "Already Executed" }
    }

    /** Runs the call in the current coroutine, turning every failure into an [IOException]. */
    private suspend fun run(): Response {
        val budget = Budget(timeout)
        try {
            synchronized(lock) {
                if (canceled) {
                    throw IOException(CANCELED)
                }
                job = coroutineContext.job
            }
            if (!budget.isLimited) {
                return connection.send(request) { attach(it, budget) }
            }
            // A response can arrive just as the time runs out; it is kept
            // here so that it is closed rather than lost with its connection.
            var response: Response? = null
            val inTime = withTimeoutOrNull(budget.remainingNanos().nanoseconds) {
                response = connection.send(request) { attach(it, budget) }
                true
            }
            val arrived = response
            if (inTime == null || arrived == null) {
                arrived?.closeQuietly()
                throw InterruptedIOException("timeout")
            }
            return arrived
        } catch (e: CancellationException) {
            throw IOException(CANCELED, e)
        } finally {
            synchronized(lock) { job = null }
        }
    }

    /** Ties a call that goes out for this one to its cancellation and to what is left of its timeout. */
    private fun attach(call: Call, budget: Budget) {
        if (budget.isLimited) {
            // The call that carries the request enforces the rest of the
            // budget itself, through the reading of the response body.
            call.timeout().timeout(maxOf(budget.remainingNanos(), 1L), TimeUnit.NANOSECONDS)
        }
        val alreadyCanceled = synchronized(lock) {
            sent = call
            canceled
        }
        if (alreadyCanceled) {
            call.cancel()
        }
    }

    /** What is left of a call's time, from its timeout and its deadline, read when the call starts. */
    private class Budget(timeout: Timeout) {
        private val endNanos: Long?

        init {
            val now = System.nanoTime()
            val byTimeout = timeout.timeoutNanos().takeIf { it > 0 }?.let { now + it }
            val byDeadline = if (timeout.hasDeadline()) timeout.deadlineNanoTime() else null
            endNanos = listOfNotNull(byTimeout, byDeadline).minByOrNull { it - now }
        }

        val isLimited: Boolean get() = endNanos != null

        fun remainingNanos(): Long = (endNanos ?: Long.MAX_VALUE) - System.nanoTime()
    }

    private companion object {
        const val CANCELED = "Canceled"
    }
}
