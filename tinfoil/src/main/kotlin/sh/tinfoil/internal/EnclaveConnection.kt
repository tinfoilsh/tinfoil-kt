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
import sh.tinfoil.AttestationFetcher
import sh.tinfoil.ConfigurationException
import sh.tinfoil.NetworkException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.Transport
import sh.tinfoil.TransportMode
import sh.tinfoil.VerificationAttempt
import sh.tinfoil.VerificationCheck
import sh.tinfoil.VerificationReport
import sh.tinfoil.VerifiedFacts
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
import sh.tinfoil.internal.verification.DocumentFetcher
import sh.tinfoil.internal.verification.DocumentSources
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.internal.verification.GoAttestationVerifier
import sh.tinfoil.internal.verification.VerifierOptions
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
 * those of the verification that it checked. A verification stops being
 * valid at its freshness deadline, when the enclave refuses its keys, or when
 * a verification that was to replace it fails with an
 * [AttestationException].
 *
 * Creating one performs no I/O.
 */
internal class EnclaveConnection(
    val enclave: String,
    val pin: Pin,
    val baseUrl: HttpUrl,
    /** The proxy URL as the caller gave it, or null for a direct connection. */
    private val proxyUrl: String?,
    private val attestor: Attestor,
    private val protocol: TransportProtocol,
    /** Told of every attempt to verify the enclave; see [observe]. */
    private val onVerification: VerificationObserver?,
    /** The prompt-cache secret that requests are given, if any. */
    private val cacheSecret: UserCacheSecret? = null,
    private val clock: () -> Instant = Instant::now,
    /** Called once, when the connection closes, to release what its owner made for it. */
    private val onClose: () -> Unit = {},
) : AttestedSender {
    val transportMode: TransportMode get() = protocol.mode

    /** The transport that the connection was made with. */
    val transport: Transport
        get() = when (protocol.mode) {
            TransportMode.TLS -> Transport.Tls
            TransportMode.EHBP -> Transport.Ehbp(proxyUrl)
        }

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
    private var last: VerificationAttempt? = null

    /**
     * A verification and the transport that was made for its keys. [facts]
     * are [report]'s verified facts.
     */
    private class State(val report: VerificationReport, val facts: VerifiedFacts, val transport: BoundTransport) {
        /**
         * Set once the enclave has refused these keys, or once a
         * verification that was to replace this one has been rejected.
         * Guarded by the connection's lock.
         */
        var withdrawn = false
    }

    /** A verification in progress, shared by every caller that needs one while it runs. */
    private class Refresh {
        /** Null once the enclave is verified; otherwise why it was not. */
        val failure = CompletableDeferred<TinfoilException?>()
        var job: Job? = null
    }

    /**
     * The outcome of the most recent attempt to verify the enclave, once it
     * is decided, or null before the first: the report of one that passed,
     * unchecked, as it may have expired or been withdrawn since; or the
     * exception of one that failed. An attempt that the client's close
     * ended has no outcome, and leaves this as it was.
     */
    val lastVerification: VerificationAttempt?
        get() = synchronized(lock) { last }

    val isClosed: Boolean
        get() = synchronized(lock) { closed }

    /** The report of a verification that is valid now, verifying first only when there is none. */
    @Throws(TinfoilException::class)
    suspend fun ensureVerified(): VerificationReport = verified(force = false).report

    /**
     * The report of a verification that is valid now, from a single attempt
     * if the enclave has to be verified: a failure is not tried again. It is
     * for an enclave that is one of several candidates, which the caller
     * closes if it fails.
     */
    @Throws(TinfoilException::class)
    suspend fun verifyOnce(): VerificationReport = verified(force = false, once = true).report

    /** Verifies again, even when the current verification is still valid. */
    @Throws(TinfoilException::class)
    suspend fun reverify(): VerificationReport = verified(force = true).report

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
            synchronized(lock) { state.withdrawn = true }
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
                synchronized(lock) { state.withdrawn = true }
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
        if (protocol.mode != TransportMode.EHBP) {
            throw ConfigurationException(
                "session recovery tokens need Transport.Ehbp: Transport.Tls seals no bodies",
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

    private fun State.isValid(): Boolean = !withdrawn && clock().isBefore(facts.freshnessExpiresAt)

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
            // The outcome of each attempt, in order, once it is decided. Only
            // this coroutine touches it.
            val attempts = ArrayList<VerificationAttempt>()
            var failure: TinfoilException? = AttestationException("the verification did not complete")
            try {
                failure = runRefresh(once, attempts)
            } finally {
                synchronized(lock) {
                    if (refresh === starting) {
                        refresh = null
                    }
                }
                starting.failure.complete(failure)
                // The observer is told only once this verification is over
                // for everyone, and outside the lock: if it calls back into
                // the client, it finds the published state or starts a
                // verification of its own, and never waits for the one that
                // is calling it.
                attempts.forEach(::observe)
            }
        }
        return starting
    }

    /**
     * Verifies the enclave and publishes the result, adding the outcome of
     * each attempt to [attempts], and returns why the enclave is not
     * verified, or null if it is.
     *
     * A verification that fails with an [AttestationException] withdraws
     * the one that it was to replace, even one that is still before its
     * deadline: the enclave no longer passes, so nothing more is sent under
     * keys that it once proved. Any other failure, such as a
     * [NetworkException], leaves that one in use until its deadline.
     */
    private suspend fun runRefresh(once: Boolean, attempts: MutableList<VerificationAttempt>): TinfoilException? {
        // Refreshes run one at a time, so this is the state that the
        // refresh would replace.
        val replacing = synchronized(lock) { state }
        // An attempt that is tried again is the last verification until the
        // next one is decided.
        val failure = attestAndPublish(once) { retried -> recordFailure(retried)?.let(attempts::add) }
        if (failure == null) {
            // Published together with the state.
            synchronized(lock) { last }?.let(attempts::add)
            return null
        }
        if (failure is AttestationException && replacing != null) {
            withdraw(replacing)
        }
        recordFailure(failure)?.let(attempts::add)
        return failure
    }

    /**
     * Makes [failure] the last verification and returns it as the outcome
     * to report, or null if the client's close ended the attempt: that is
     * not a failed verification, so it is neither recorded nor reported.
     */
    private fun recordFailure(failure: TinfoilException): VerificationAttempt? =
        synchronized(lock) {
            if (closed) {
                null
            } else {
                VerificationAttempt.Failed(failure).also { last = it }
            }
        }

    /**
     * Stops [replacing] from carrying requests, unless a newer verification
     * has been published in its place, which is kept. Requests in flight
     * under it may complete; its idle connections, which are tied to its
     * keys, are closed, and so is each of its connections when its request
     * ends.
     */
    private fun withdraw(replacing: State) {
        synchronized(lock) {
            if (state !== replacing) {
                return
            }
            replacing.withdrawn = true
        }
        replacing.transport.retire()
    }

    /**
     * Verifies the enclave and, if it passes, publishes the new state and
     * makes its report the last verification, together. Returns why the
     * enclave is not verified, or null if it is. [retried] is given the
     * failure of each attempt that is tried again.
     */
    private suspend fun attestAndPublish(once: Boolean, retried: (TinfoilException) -> Unit): TinfoilException? {
        val report = try {
            if (once) attestor.attestOnce(enclave, pin) else attestor.attest(enclave, pin, retried)
        } catch (e: CancellationException) {
            throw e
        } catch (e: TinfoilException) {
            return e
        } catch (e: Exception) {
            // Whatever went wrong, the enclave is not verified.
            return AttestationException("verification failed: ${e.message ?: e.javaClass.simpleName}", cause = e)
        }
        val facts = report.verifiedFacts
            ?: return AttestationException("the verification of $enclave has no verified facts")
        val transport = try {
            protocol.bind(facts)
        } catch (e: TinfoilException) {
            return e
        }
        var replaced: BoundTransport? = null
        val failure = synchronized(lock) {
            val next = State(report, facts, transport)
            when {
                closed -> closedError()
                // Making the transport or waiting for the lock can outlast
                // the deadline.
                !next.isValid() ->
                    AttestationException("the verification of $enclave is past its freshness deadline")
                else -> {
                    replaced = state?.transport
                    state = next
                    last = VerificationAttempt.Passed(report)
                    null
                }
            }
        }
        if (failure != null) {
            transport.retire()
            return failure
        }
        // Idle connections of the replaced transport are tied to its keys.
        replaced?.retire()
        return null
    }

    /**
     * Tells the observer of one attempt's outcome. It only watches:
     * whatever it throws changes nothing, a [CancellationException]
     * included, which is its own and not the verification's.
     */
    private fun observe(attempt: VerificationAttempt) {
        try {
            onVerification?.invoke(enclave, attempt)
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
            transport: Transport,
            fetchAttestation: AttestationFetcher?,
            verifier: AttestationVerifier,
            cacheSecret: UserCacheSecret?,
            verificationCheck: VerificationCheck?,
            onVerification: VerificationObserver?,
            internals: Internals,
            /**
             * Whether [enclave] was proposed by something that is not
             * trusted, such as a list of routers, and not named by the
             * caller. A direct connection to such a host is pinned to the
             * attested TLS key in every transport mode.
             */
            proposed: Boolean = false,
            /**
             * Whether a proxy on [enclave]'s own origin is refused. It is
             * for an enclave that the caller named: a proxy there is no
             * proxy, and would reach the enclave under the name of one.
             */
            refuseProxyOnEnclaveOrigin: Boolean = false,
        ): EnclaveConnection {
            val enclaveUrl = Urls.enclaveUrl(enclave)
            val base = (transport as? Transport.Ehbp)?.proxyUrl?.let { Urls.routeUrl(it, "proxy URL") }
            if (refuseProxyOnEnclaveOrigin && base != null && Origin.of(base) == Origin.of(enclaveUrl)) {
                throw ConfigurationException(
                    "invalid proxy URL: it is the enclave's own origin ${Origin.of(enclaveUrl)}; " +
                        "leave proxyUrl null to connect directly",
                )
            }
            val proxied = base != null && Origin.of(base) != Origin.of(enclaveUrl)
            val fetcher = lazy { DocumentFetcher(internals.http) }
            val attestor = Attestor(
                verifier = verifier,
                fetch = DocumentSources.of(fetchAttestation, verifier) { fetcher.value },
                check = verificationCheck,
                clock = internals.clock,
                retryDelay = internals.retryDelay,
            )
            attestor.checkOptions(enclave, pin)

            return EnclaveConnection(
                enclave = enclave,
                pin = pin,
                baseUrl = base ?: enclaveUrl,
                proxyUrl = (transport as? Transport.Ehbp)?.proxyUrl,
                attestor = attestor,
                protocol = when (transport) {
                    Transport.Tls -> PinnedTls(internals.http)
                    is Transport.Ehbp -> EhbpSealing(
                        cleartext = base != null && !base.isHttps,
                        // A proxy is told which enclave the client verified,
                        // as the caller named it.
                        enclaveUrl = if (proxied) "https://$enclave" else null,
                        // Bodies are sealed to the enclave whatever host
                        // the connection reaches; headers are not. A host
                        // that the caller named is trusted with them. One
                        // that was only proposed has to show the attested
                        // TLS key first, as it does with Transport.Tls.
                        pinned = proposed && !proxied,
                        local = Urls.isLoopback(base ?: enclaveUrl),
                        settings = internals.http,
                    )
                },
                onVerification = onVerification,
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

/**
 * What a client tells of each attempt to verify an enclave: the enclave's
 * host, and the attempt's report or exception.
 */
internal typealias VerificationObserver = (host: String, attempt: VerificationAttempt) -> Unit

/** What tests replace; the defaults are what production runs with. */
internal class Internals(
    val http: HttpSettings = HttpSettings(),
    val clock: () -> Instant = Instant::now,
    val retryDelay: Duration = Attestor.RETRY_DELAY,
    val discovery: RouterDiscovery.Settings = RouterDiscovery.Settings(),
    /** What measures the time between fetches of a gateway's catalog. */
    val timeSource: TimeSource = TimeSource.Monotonic,
    /**
     * What builds a verifier from a config trust, null for Tinfoil's public
     * registry, and a policy. It loads the verifier library, so it is
     * called on a background thread only.
     */
    val newVerifier: (VerifierOptions.ConfigTrust?, VerifierOptions.Policy) -> AttestationVerifier =
        { config, policy -> GoAttestationVerifier.create(config, policy) },
    /** Where the router and gateway clients take the process's cache secret from. */
    val processSecret: UserCacheSecret.ProcessSecret = UserCacheSecret.PROCESS,
)

private fun <T : Throwable> T.alsoSuppressing(earlier: Throwable?): T = apply {
    if (earlier != null && earlier !== this) {
        addSuppressed(earlier)
    }
}
