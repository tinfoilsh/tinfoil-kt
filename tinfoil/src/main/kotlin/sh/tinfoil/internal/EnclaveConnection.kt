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
import sh.tinfoil.NetworkException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.TransportMode
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import sh.tinfoil.Verifier
import sh.tinfoil.RecoverableResponse
import sh.tinfoil.internal.transport.AttestedSender
import sh.tinfoil.internal.transport.BoundTransport
import sh.tinfoil.internal.transport.EhbpSealing
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.internal.transport.Origin
import sh.tinfoil.internal.transport.PinnedTls
import sh.tinfoil.internal.transport.RecoverableCall
import sh.tinfoil.internal.transport.SettledBody
import sh.tinfoil.internal.transport.TransportProtocol
import sh.tinfoil.internal.transport.Urls
import sh.tinfoil.internal.transport.UserCacheSecret
import sh.tinfoil.internal.transport.await
import sh.tinfoil.internal.verification.AttestationFetcher
import sh.tinfoil.internal.verification.Attestor
import java.io.IOException
import java.time.Instant
import kotlin.coroutines.coroutineContext
import kotlin.time.Duration
import kotlin.time.TimeSource

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
    /** The prompt-cache secret that requests are given, if any. */
    private val cacheSecret: UserCacheSecret? = null,
    private val clock: () -> Instant = Instant::now,
    /** Called once, when the connection closes, to release what its owner made for it. */
    private val onClose: () -> Unit = {},
) : AttestedSender {
    val transportMode: TransportMode get() = protocol.mode

    /**
     * Runs calls that are not awaited. Its threads come from the shared pool
     * for blocking work, through a view of its own, so that it is not held
     * to that pool's limit.
     */
    override val scope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(CALL_PARALLELISM) + CoroutineName("tinfoil-calls"))

    /**
     * Runs verifications, which no single caller owns. Callers may wait for
     * one while they block a thread of the shared pool for blocking work,
     * and enough of them would leave a verification on that pool without a
     * thread to finish on. A view of the pool gets threads beyond the pool's
     * own limit, so a verification can always run, whatever its waiters
     * block.
     */
    private val refreshScope: CoroutineScope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO.limitedParallelism(REFRESH_PARALLELISM) + CoroutineName("tinfoil-verification"),
    )

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

    /**
     * A verification that is valid now, from a single attempt if the enclave
     * has to be verified: a failure is not tried again, and is not reported
     * to the observer. It is for an enclave that is one of several
     * candidates, which the caller closes if it fails.
     */
    @Throws(TinfoilException::class)
    suspend fun verifyOnce(): Verification = verified(force = false, once = true).verification

    /** Verifies again, even when the current verification is still valid. */
    @Throws(TinfoilException::class)
    suspend fun reverify(): Verification = verified(force = true).verification

    /**
     * Finds out, without sending any of a request, whether the enclave's
     * host presents the key that connections are pinned to, under a
     * verification that is valid now. It is for an enclave that is one of
     * several candidates: an attestation document is not tied to the host
     * that served it, so a host can verify and still not be the enclave.
     * A transport that pins nothing has nothing to find out.
     *
     * @throws AttestationException if the host does not present the key.
     * @throws NetworkException if no connection to it can be opened.
     */
    @Throws(TinfoilException::class)
    suspend fun probe() {
        val state = verified(force = false)
        try {
            state.transport.probe(baseUrl)
        } catch (e: TinfoilException) {
            throw e
        } catch (e: IOException) {
            val reason = state.transport.keyRejection(e)
                ?: throw NetworkException("connecting to $enclave: ${e.message ?: e.javaClass.simpleName}", cause = e)
            synchronized(lock) { state.rejected = true }
            throw AttestationException(reason, cause = e)
        }
    }

    /**
     * Sends [request] over a transport that is bound to a verification that
     * is valid now, and returns the response with its body still to be read.
     * [onCall] is handed each call that goes out for it, at most two.
     *
     * A request that the client cannot protect is refused before any I/O.
     * One that takes the client's prompt-cache secret is given it once, so
     * that a request that is sent again carries the same body.
     * If the enclave turns out not to hold the verified keys, which shows
     * before it can read any of what those keys protect, the enclave is
     * verified again and the request is sent once more, when its body can be
     * sent twice; otherwise, or if the new keys are refused too, the request
     * fails with an [AttestationException].
     */
    @Throws(IOException::class)
    override suspend fun send(request: Request, onCall: (Call) -> Unit): Response {
        checkOpen()
        // What the body says about itself is taken once, so that the body
        // that is judged here is the body that is sent.
        val settled = SettledBody.settle(request)
        checkRequest(settled)
        val outgoing = cacheSecret?.provision(settled) ?: settled
        var rejection: AttestationException? = null
        while (true) {
            val state = verified(force = false)
            // A caller that cancelled while the enclave was verified again
            // must not have its request, credentials included, sent.
            coroutineContext.ensureActive()
            val call = state.transport.newCall(outgoing)
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
                if (!isReplayable(outgoing)) {
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
     * Sends [request] as [send] does, and returns the response with the
     * session recovery token of the request that it answers. Only a
     * transport that seals bodies has such tokens; any other is refused
     * before any I/O.
     */
    @Throws(IOException::class)
    suspend fun sendRecoverable(request: Request): RecoverableResponse {
        checkOpen()
        if (protocol.mode != TransportMode.Ehbp) {
            throw ConfigurationException(
                "session recovery tokens need TransportMode.Ehbp: TransportMode.${protocol.mode} seals no bodies",
            )
        }
        // A request that is sent again is sealed again, and the token is
        // that of the request that was answered: the last.
        var answered: Call? = null
        val response = send(request) { answered = it }
        return RecoverableResponse(response, (answered as? RecoverableCall)?.recoveryToken)
    }

    /**
     * Refuses later requests and verifications, cancels a verification in
     * progress and the requests in flight, and closes every connection.
     *
     * The refusals hold when this returns. Whatever reaches a socket, which
     * is the cancelling and the closing, is done on a background thread
     * right afterwards, so that any thread may call this: one that must not
     * touch the network, as Android's main thread, included.
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
        protocol.refuse()
        Background.run {
            refreshing?.job?.cancel()
            // Requests in flight end here, under whichever verification
            // they were sent; then the connections that are left idle are
            // closed.
            protocol.close()
            transport?.retire()
            onClose()
        }
    }

    private fun checkOpen() {
        if (isClosed) {
            throw closedError()
        }
    }

    /** The rules that keep a request, and the credentials in its headers, on the enclave. */
    private fun checkRequest(request: Request) {
        origin.requireDestinationOf(request, "the enclave $enclave")
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
    private suspend fun verified(force: Boolean, once: Boolean = false): State {
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
                refresh ?: startRefresh(once)
            }
            running.failure.await()?.let { throw it }
            // The new state can be rejected or replaced before this caller
            // wakes, so it is checked again rather than taken on trust.
            forced = false
        }
    }

    /** Called with the lock held. */
    private fun startRefresh(once: Boolean): Refresh {
        val starting = Refresh()
        refresh = starting
        // A refresh serves every waiting caller, so it runs under no single
        // caller's job, and its outcome reaches the waiters as a value.
        starting.job = refreshScope.launch {
            var outcome = Outcome(AttestationException("the verification did not complete"), report = null)
            try {
                outcome = runRefresh(once)
            } finally {
                synchronized(lock) {
                    if (refresh === starting) {
                        refresh = null
                    }
                }
                starting.failure.complete(outcome.failure)
            }
            // The observer is told only once this verification is over for
            // everyone: if it calls back into the client, it finds the
            // published state or starts a verification of its own, and never
            // waits for the one that is calling it.
            outcome.report?.let(::observe)
        }
        return starting
    }

    /** How a verification ended, and what its observer is to be told, if anything. */
    private class Outcome(val failure: TinfoilException?, val report: Result<Verification>?)

    private fun failed(failure: TinfoilException, once: Boolean = false): Outcome =
        // A verification that the client's close ended is not a failed one,
        // so it is not reported as one; neither is a candidate's.
        Outcome(failure, if (isClosed || once) null else Result.failure(failure))

    /** Verifies the enclave and publishes the result. */
    private suspend fun runRefresh(once: Boolean): Outcome {
        val verification = try {
            if (once) attestor.attestOnce(enclave, relay, pin) else attestor.attest(enclave, relay, pin)
        } catch (e: CancellationException) {
            throw e
        } catch (e: TinfoilException) {
            return failed(e, once)
        } catch (e: Exception) {
            // Whatever went wrong, the enclave is not verified.
            return failed(
                AttestationException("verification failed: ${e.message ?: e.javaClass.simpleName}", cause = e),
                once,
            )
        }
        val transport = try {
            protocol.bind(verification)
        } catch (e: TinfoilException) {
            return failed(e, once)
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
            return if (failure is AttestationException) failed(failure, once) else Outcome(failure, report = null)
        }
        // Idle connections of the replaced transport are tied to its keys.
        replaced?.retire()
        return Outcome(null, Result.success(verification))
    }

    /** The observer only watches: whatever it throws changes nothing. */
    private fun observe(result: Result<Verification>) {
        try {
            onVerificationResult?.invoke(result)
        } catch (_: Throwable) {
            // Deliberately ignored, an Error included: the verification is
            // over, and its observer's failure is not the client's.
        }
    }

    private fun closedError() = ConfigurationException("the client is closed")

    internal companion object {
        private const val REFRESH_PARALLELISM = 4
        private const val CALL_PARALLELISM = 64

        /**
         * A connection to [enclave] that is checked but not yet verified.
         * Every argument is checked here, and nothing here performs I/O.
         */
        @Throws(TinfoilException::class)
        fun create(
            enclave: String,
            pin: Pin,
            transportMode: TransportMode,
            baseUrl: String?,
            attestationRelay: String?,
            verifier: Verifier,
            cacheSecret: UserCacheSecret?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            internals: Internals,
            /**
             * Whether [enclave] was proposed by something that is not
             * trusted, such as a list of routers, and not named by the
             * caller. A direct connection to such a host is pinned to the
             * attested TLS key in every transport mode.
             */
            proposed: Boolean = false,
        ): EnclaveConnection {
            val enclaveUrl = Urls.enclaveUrl(enclave)
            val base = baseUrl.nullIfEmpty()?.let(Urls::baseUrl)
            val proxied = base != null && Origin.of(base) != Origin.of(enclaveUrl)
            when (transportMode) {
                TransportMode.Tls -> if (base != null) {
                    if (!base.isHttps) {
                        throw ConfigurationException("invalid base URL: TransportMode.Tls requires HTTPS")
                    }
                    if (proxied) {
                        throw ConfigurationException(
                            "a base URL off the enclave's origin ${Origin.of(enclaveUrl)} is a proxy, " +
                                "which a pinned TLS connection cannot pass through; a proxy requires TransportMode.Ehbp",
                        )
                    }
                }
                // Headers are not sealed, so they travel in the clear only
                // where they never leave the machine.
                TransportMode.Ehbp -> if (base != null && !base.isHttps && !Urls.isLoopback(base)) {
                    throw ConfigurationException(
                        "invalid base URL: HTTP is allowed only for localhost or a loopback IP address; " +
                            "use HTTPS to protect request headers",
                    )
                }
            }
            val relay = attestationRelay.nullIfEmpty()?.also(Urls::requireRelay)
            val fetcher = lazy { AttestationFetcher(internals.http) }
            val attestor = Attestor(
                verifier = verifier.backend,
                fetch = { url -> fetcher.value.fetch(url) },
                check = verificationCheck,
                clock = internals.clock,
                retryDelay = internals.retryDelay,
            )
            attestor.checkOptions(enclave, relay, pin)

            return EnclaveConnection(
                enclave = enclave,
                pin = pin,
                baseUrl = base ?: enclaveUrl,
                relay = relay,
                attestor = attestor,
                protocol = when (transportMode) {
                    TransportMode.Tls -> PinnedTls(internals.http)
                    TransportMode.Ehbp -> EhbpSealing(
                        cleartext = base != null && !base.isHttps,
                        // A proxy is told which enclave the client verified,
                        // as the caller named it.
                        enclaveUrl = if (proxied) "https://$enclave" else null,
                        // Bodies are sealed to the enclave whatever host
                        // the connection reaches; headers are not. A host
                        // that the caller named is trusted with them. One
                        // that was only proposed has to show the attested
                        // TLS key first, as it does with TransportMode.Tls.
                        pinned = proposed && !proxied,
                        local = Urls.isLoopback(base ?: enclaveUrl),
                        settings = internals.http,
                    )
                },
                onVerificationResult = onVerificationResult,
                cacheSecret = cacheSecret,
                clock = internals.clock,
                onClose = {
                    if (fetcher.isInitialized()) {
                        fetcher.value.close()
                    }
                },
            )
        }
    }
}

/** What tests replace; the defaults are what production runs with. */
internal class Internals(
    val http: HttpSettings = HttpSettings(),
    val clock: () -> Instant = Instant::now,
    val retryDelay: Duration = Attestor.RETRY_DELAY,
    val discovery: RouterDiscovery.Settings = RouterDiscovery.Settings(),
    /** What measures the time between fetches of a gateway's catalog. */
    val timeSource: TimeSource = TimeSource.Monotonic,
)

private fun <T : Throwable> T.alsoSuppressing(earlier: Throwable?): T = apply {
    if (earlier != null && earlier !== this) {
        addSuppressed(earlier)
    }
}
