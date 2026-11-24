package sh.tinfoil

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.fingerprint
import sh.tinfoil.testing.rejection
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * How a client reports each attempt to verify its enclave: through
 * `lastVerification()` and the `onVerification` option. Router discovery and
 * the gateway's replicas are tested with their clients.
 */
class VerificationAttemptTest {
    private val enclave = TestEnclave()

    /** Every attempt that the client reported, with the host that it verified. */
    private val attempts = CopyOnWriteArrayList<Pair<String, VerificationAttempt>>()

    @AfterTest
    fun shutDown() {
        enclave.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    private suspend fun client(verificationCheck: VerificationCheck? = null): EnclaveHttpClient =
        enclave.client(verificationCheck = verificationCheck, onVerification = { host, attempt -> attempts += host to attempt })

    /** Waits for [count] attempts to be reported, and for no more. */
    private fun awaitAttempts(count: Int): List<Pair<String, VerificationAttempt>> {
        awaitUntil { attempts.size >= count }
        Thread.sleep(50)
        assertEquals(count, attempts.size, "$attempts")
        return attempts.toList()
    }

    private fun ok() = MockResponse().setBody("ok")

    @Test
    fun anInitialVerificationIsReportedOnceWithTheEnclavesHostAndTheSameReport() = test {
        val client = client()

        val last = assertIs<VerificationAttempt.Passed>(client.lastVerification())
        assertNotNull(last.report.verifiedFacts)
        assertNull(last.report.partialFacts)
        assertNull(last.error)
        val (host, reported) = awaitAttempts(1).single()
        assertEquals(enclave.host, host)
        assertSame(last.report, reported.report)
        assertSame(last.report, client.ensureVerified())
    }

    @Test
    fun aRejectedDocumentIsAnAttestationErrorThatCarriesTheVerifiersReport() = test {
        enclave.verifier.verify = { _, _, _ -> throw rejection(VerificationLayer.POLICY, "measurement mismatch") }

        val error = assertFailsWith<AttestationException> { client() }

        val rejected = assertIs<VerificationException>(error.cause)
        assertEquals(VerificationLayer.POLICY, rejected.layer)
        assertEquals(VerificationLayer.POLICY, rejected.report.failedStep?.layer)
        assertNull(rejected.report.verifiedFacts)
        assertNotNull(rejected.report.partialFacts)
        // The rejection was tried once more, and each attempt is reported
        // with its own error.
        val reported = awaitAttempts(2)
        assertEquals(listOf(enclave.host, enclave.host), reported.map { it.first })
        assertSame(error.suppressed.single(), reported[0].second.error)
        assertSame(error, reported[1].second.error)
        assertTrue(reported.all { it.second.report == null })
    }

    @Test
    fun theLastVerificationOfARejectedDocumentIsTheErrorThatTheClientReported() = test {
        val client = client()
        enclave.verifier.verify = { _, _, _ -> throw rejection(VerificationLayer.QUOTE) }

        val error = assertFailsWith<AttestationException> { client.reverify() }

        val last = assertIs<VerificationAttempt.Failed>(client.lastVerification())
        assertSame(error, last.error)
        assertNull(last.report)
        assertIs<VerificationException>(last.error.cause)
        assertSame(error, awaitAttempts(3).last().second.error)
    }

    @Test
    fun aFailedFetchIsANetworkErrorWithoutAReport() = test {
        val client = client()
        enclave.relay.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = MockResponse().setResponseCode(503)
        }

        val error = assertFailsWith<NetworkException> { client.reverify() }

        assertEquals(503, error.status)
        var cause: Throwable? = error
        while (cause != null) {
            assertTrue(cause !is VerificationException, "a failed fetch has no report")
            cause = cause.cause
        }
        assertSame(error, client.lastVerification()?.error)
        assertSame(error, awaitAttempts(3).last().second.error)
    }

    @Test
    fun aFailedReverificationReplacesAnEarlierSuccess() = test {
        val client = client()
        val passed = assertNotNull(client.lastVerification()?.report)
        enclave.verifier.verify = { _, _, _ -> throw rejection() }

        assertFailsWith<AttestationException> { client.reverify() }

        assertIs<VerificationAttempt.Failed>(client.lastVerification())
        assertEquals(listOf(passed, null, null), awaitAttempts(3).map { it.second.report })
    }

    @Test
    fun aFailureThatItsRetryRecoversFromIsReportedAndTheRetryIsTheLast() = test {
        val passes = enclave.verifier.verify
        var first = true
        enclave.verifier.verify = { document, nonce, pin ->
            if (first) {
                first = false
                throw rejection(VerificationLayer.ENVELOPE, "nonce mismatch")
            }
            passes(document, nonce, pin)
        }

        val client = client()

        val reported = awaitAttempts(2)
        assertIs<VerificationAttempt.Failed>(reported[0].second)
        val retry = assertIs<VerificationAttempt.Passed>(reported[1].second)
        assertSame(retry.report, client.lastVerification()?.report)
    }

    @Test
    fun aKeyRotationIsReportedAsAnAttemptForTheSameHost() = test {
        val client = client()
        enclave.rotateKey()
        enclave.server.enqueue(ok())

        client.execute(enclave.get()).close()

        val reported = awaitAttempts(2)
        assertEquals(listOf(enclave.host, enclave.host), reported.map { it.first })
        assertEquals(enclave.certificate.fingerprint, reported[1].second.report?.verifiedFacts?.tlsPublicKeyFingerprint)
        assertSame(reported[1].second.report, client.lastVerification()?.report)
    }

    @Test
    fun concurrentRequestsShareOneAttempt() = test {
        val client = client()
        enclave.clock.advance(enclave.lifetimeSeconds)
        val release = CountDownLatch(1)
        val passes = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin ->
            release.await(30, TimeUnit.SECONDS)
            passes(document, nonce, pin)
        }
        enclave.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = ok()
        }

        val requests = List(8) { async(Dispatchers.IO) { client.execute(enclave.get()).close() } }
        Thread.sleep(200)
        release.countDown()
        requests.awaitAll()

        assertEquals(2, awaitAttempts(2).size, "one attempt at creation and one that every request shared")
    }

    @Test
    fun theCheckSeesOnlyVerifiedFactsAndNothingOfAFailedVerification() = test {
        val seen = CopyOnWriteArrayList<VerifiedFacts>()
        val client = client(verificationCheck = { seen += it })
        assertSame(client.lastVerification()?.report?.verifiedFacts, seen.single())

        enclave.verifier.verify = { _, _, _ -> throw rejection() }
        assertFailsWith<AttestationException> { client.reverify() }

        assertEquals(1, seen.size, "the check is not called for a verification that fails")
    }

    @Test
    fun theObserverMayReadTheLastVerificationWithoutADeadlock() = test {
        val holder = AtomicReference<EnclaveHttpClient>()
        val read = CopyOnWriteArrayList<Pair<VerificationAttempt, VerificationAttempt?>>()
        val client = enclave.client(onVerification = { _, attempt ->
            holder.get()?.let { read += attempt to it.lastVerification() }
        })
        holder.set(client)

        client.reverify()
        enclave.verifier.verify = { _, _, _ -> throw rejection() }
        assertFailsWith<AttestationException> { client.reverify() }

        awaitUntil { read.size == 3 }
        // The callback reads the attempt that it was told of, or a later one.
        assertSame(read[0].first.report, read[0].second?.report)
        assertIs<VerificationAttempt.Failed>(read[1].second)
        assertSame(read[2].first.error, read[2].second?.error)
    }

    @Test
    fun anObserverThatThrowsChangesNoOutcomeAndNoWaiterSeesWhatItThrew() = test {
        // Each call throws something else: an exception, an Error, and a
        // cancellation of its own.
        val thrown = listOf(IllegalStateException("observer"), NotImplementedError("observer"), CancellationException("observer"))
        val calls = AtomicInteger()
        val client = enclave.client(onVerification = { host, attempt ->
            attempts += host to attempt
            throw thrown[calls.getAndIncrement() % thrown.size]
        })
        enclave.clock.advance(enclave.lifetimeSeconds)
        val release = CountDownLatch(1)
        val passes = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin ->
            release.await(30, TimeUnit.SECONDS)
            passes(document, nonce, pin)
        }

        // Two callers wait for the same verification.
        val waiters = List(2) { async(Dispatchers.IO) { runCatching { client.ensureVerified() } } }
        Thread.sleep(200)
        release.countDown()
        val reports = waiters.awaitAll().map { it.getOrThrow() }

        assertSame(reports[0], reports[1], "both waiters got the one outcome")
        assertSame(reports[0], client.lastVerification()?.report)

        // A failed verification reaches both of its waiters as itself, and
        // each of its attempts is still reported after the observer threw.
        val failing = CountDownLatch(1)
        enclave.verifier.verify = { _, _, _ ->
            failing.await(30, TimeUnit.SECONDS)
            throw rejection(VerificationLayer.QUOTE)
        }
        val failed = List(2) { async(Dispatchers.IO) { runCatching { client.reverify() }.exceptionOrNull() } }
        Thread.sleep(200)
        failing.countDown()
        val errors = failed.awaitAll()

        val error = assertIs<AttestationException>(errors[0])
        assertSame(error, errors[1], "both waiters got the one outcome")
        assertIs<VerificationException>(error.cause)
        assertSame(error, client.lastVerification()?.error)
        // Creation, the shared verification, and the two attempts of the
        // failed one, which was tried once more.
        val reported = awaitAttempts(4)
        assertSame(reports[0], reported[1].second.report)
        assertSame(error.suppressed.single(), reported[2].second.error)
        assertSame(error, reported[3].second.error)
        assertEquals(4, calls.get())
    }

    @Test
    fun aReportCannotBeChangedByItsHolder() = test {
        val client = client()
        val report = client.ensureVerified()
        val before = report.toString()

        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (report.steps as MutableList<Step>).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (report.verifiedFacts!!.cryptoMaterial as MutableList<CryptoMaterial>).clear()
        }

        assertEquals(before, client.ensureVerified().toString())
        assertEquals(before, client.lastVerification()?.report.toString())
        assertEquals(4, client.ensureVerified().steps.size)
    }
}
