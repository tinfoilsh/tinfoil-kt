package sh.tinfoil.internal

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.TransportMode
import sh.tinfoil.Verification
import sh.tinfoil.internal.transport.BoundTransport
import sh.tinfoil.internal.transport.Origin
import sh.tinfoil.internal.transport.TransportProtocol
import sh.tinfoil.internal.transport.await
import sh.tinfoil.internal.verification.Attestor
import java.io.IOException
import java.time.Instant
import kotlin.coroutines.coroutineContext

/**
 * One enclave's verification state and the requests that depend on it.
 *
 * It verifies the enclave on demand, keeps the result together with the
 * transport that is bound to its keys, and sends each request over the
 * transport of a verification that is valid when the request starts. The two
 * are published together, so a request is never sent under keys other than
 * those of the verification that it checked.
 *
 * Creating one performs no I/O.
 */
internal class EnclaveConnection(
    val enclave: String,
    val pin: Pin,
    val baseUrl: HttpUrl,
    private val relay: String?,
    private val attestor: Attestor,
    private val protocol: TransportProtocol,
    private val onVerificationResult: ((Result<Verification>) -> Unit)?,
    private val clock: () -> Instant = Instant::now,
    /** Called once, when the connection closes, to release what its owner made for it. */
    private val onClose: () -> Unit = {},
) {
    val transportMode: TransportMode get() = protocol.mode

    /** Runs verifications, which no single caller owns, and calls that are not awaited. */
    val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + CoroutineName("tinfoil-enclave"))

    private val origin = Origin.of(baseUrl)
    private val lock = Any()

    // Guarded by lock.
    private var state: State? = null
    private var refresh: Refresh? = null
    private var closed = false

    /** A verification and the transport that was made for its keys. */
    private class State(val verification: Verification, val transport: BoundTransport) {
        /** Set once the enclave has refused these keys. Guarded by the connection's lock. */
        var rejected = false
    }

    /** A verification in progress, shared by every caller that needs one while it runs. */
    private class Refresh {
        /** Null once the enclave is verified; otherwise why it was not. */
        val failure = CompletableDeferred<TinfoilException?>()
        var job: Job? = null
    }

    /** The last successful verification, unchecked: it may have expired or been rejected. */
    val current: Verification?
        get() = synchronized(lock) { state?.verification }

    val isClosed: Boolean
        get() = synchronized(lock) { closed }

    /** A verification that is valid now, verifying first only when there is none. */
    @Throws(TinfoilException::class)
    suspend fun ensureVerified(): Verification = verified(force = false).verification

    /** Verifies again, even when the current verification is still valid. */
    @Throws(TinfoilException::class)
    suspend fun reverify(): Verification = verified(force = true).verification

    /**
     * Sends [request] over a transport that is bound to a verification that
     * is valid now, and returns the response with its body still to be read.
     * [onCall] is handed each call that goes out for it, at most two.
     *
     * A request that the client cannot protect is refused before any I/O.
     * If the enclave turns out not to hold the verified keys, which shows
     * before any of the request is handed to it, the enclave is verified
     * again and the request is sent once more, when its body can be sent
     * twice; otherwise, or if the new keys are refused too, the request
     * fails with an [AttestationException].
     */
    @Throws(IOException::class)
    suspend fun send(request: Request, onCall: (Call) -> Unit = {}): Response {
        checkOpen()
        checkRequest(request)
        var rejection: AttestationException? = null
        while (true) {
            val state = verified(force = false)
            // A caller that cancelled while the enclave was verified again
            // must not have its request, credentials included, sent.
            coroutineContext.ensureActive()
            val call = state.transport.newCall(request)
            onCall(call)
            try {
                return call.await()
            } catch (e: IOException) {
                val reason = state.transport.keyRejection(e) ?: throw e
                // The verification that the request was sent under is the
                // one that failed, whichever is current by now.
                synchronized(lock) { state.rejected = true }
                if (rejection != null) {
                    throw AttestationException("$reason, after the enclave was verified again", cause = e)
                        .alsoSuppressing(rejection)
                }
                if (!isReplayable(request)) {
                    throw AttestationException(
                        "$reason; the request was not sent again, because its body can be sent only once",
                        cause = e,
                    )
                }
                rejection = AttestationException(reason, cause = e)
            }
        }
    }

    /**
     * Refuses later requests and verifications, cancels a verification in
     * progress and the requests in flight, and closes every connection.
     */
    fun close() {
        val (transport, refreshing) = synchronized(lock) {
            if (closed) {
                return
            }
            closed = true
            Pair(state?.transport, refresh.also { refresh = null })
        }
        refreshing?.failure?.complete(closedError())
        refreshing?.job?.cancel()
        // Requests in flight end here, under whichever verification they
        // were sent; then the connections that are left idle are closed.
        protocol.close()
        transport?.retire()
        onClose()
    }

    private fun checkOpen() {
        if (isClosed) {
            throw closedError()
        }
    }

    /** The rules that keep a request, and the credentials in its headers, on the enclave. */
    private fun checkRequest(request: Request) {
        val url = request.url
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) {
            throw ConfigurationException("request URLs must not carry credentials")
        }
        val target = Origin.of(url)
        if (target != origin) {
            throw ConfigurationException(
                "refusing to send a request to $target: the client is bound to $origin for the enclave $enclave",
            )
        }
        if (request.header("Host") != null) {
            throw ConfigurationException("requests must not set the Host header, which names the verified enclave")
        }
        protocol.checkRequest(request)
    }

    private fun isReplayable(request: Request): Boolean {
        val body = request.body ?: return true
        return !body.isOneShot() && !body.isDuplex()
    }

    private fun State.isValid(): Boolean = !rejected && clock().isBefore(verification.freshnessExpiresAt)

    /**
     * A state that is valid now. Callers that need a verification while one
     * runs share it, its failure included. Cancelling a caller ends only its
     * own wait.
     */
    private suspend fun verified(force: Boolean): State {
        var forced = force
        while (true) {
            coroutineContext.ensureActive()
            val running = synchronized(lock) {
                if (closed) {
                    throw closedError()
                }
                val valid = state?.takeIf { !forced && it.isValid() }
                if (valid != null) {
                    return valid
                }
                refresh ?: startRefresh()
            }
            running.failure.await()?.let { throw it }
            // The new state can be rejected or replaced before this caller
            // wakes, so it is checked again rather than taken on trust.
            forced = false
        }
    }

    /** Called with the lock held. */
    private fun startRefresh(): Refresh {
        val starting = Refresh()
        refresh = starting
        // A refresh serves every waiting caller, so it runs under no single
        // caller's job, and its outcome reaches the waiters as a value.
        starting.job = scope.launch {
            var failure: TinfoilException? = AttestationException("the verification did not complete")
            try {
                failure = runRefresh()
            } finally {
                synchronized(lock) {
                    if (refresh === starting) {
                        refresh = null
                    }
                }
                starting.failure.complete(failure)
            }
        }
        return starting
    }

    /** Verifies the enclave and publishes the result. Returns why it failed, or null. */
    private suspend fun runRefresh(): TinfoilException? {
        val verification = try {
            attestor.attest(enclave, relay, pin)
        } catch (e: CancellationException) {
            throw e
        } catch (e: TinfoilException) {
            return reported(e)
        } catch (e: Exception) {
            // Whatever went wrong, the enclave is not verified.
            return reported(AttestationException("verification failed: ${e.message ?: e.javaClass.simpleName}", cause = e))
        }
        val transport = try {
            protocol.bind(verification)
        } catch (e: TinfoilException) {
            return reported(e)
        }
        var replaced: BoundTransport? = null
        val failure = synchronized(lock) {
            val next = State(verification, transport)
            when {
                closed -> closedError()
                // Making the transport or waiting for the lock can outlast
                // the deadline.
                !next.isValid() ->
                    AttestationException("the verification of $enclave is past its freshness deadline")
                else -> {
                    replaced = state?.transport
                    state = next
                    null
                }
            }
        }
        if (failure != null) {
            transport.retire()
            // A verification that the client's close ended is not a failed
            // one, so it is not reported as one.
            return if (failure is AttestationException) reported(failure) else failure
        }
        // Idle connections of the replaced transport are tied to its keys.
        replaced?.retire()
        observe(Result.success(verification))
        return null
    }

    private fun reported(failure: TinfoilException): TinfoilException {
        if (!isClosed) {
            observe(Result.failure(failure))
        }
        return failure
    }

    /** The observer only watches: what it throws changes nothing. */
    private fun observe(result: Result<Verification>) {
        try {
            onVerificationResult?.invoke(result)
        } catch (_: Exception) {
            // Deliberately ignored.
        }
    }

    private fun closedError() = ConfigurationException("the client is closed")
}

private fun <T : Throwable> T.alsoSuppressing(earlier: Throwable?): T = apply {
    if (earlier != null && earlier !== this) {
        addSuppressed(earlier)
    }
}
