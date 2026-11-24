package sh.tinfoil

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.rejection
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.time.Duration.Companion.seconds

/**
 * `currentVerification()`: the verification that a client's requests are
 * sent under now, which `lastVerificationAttempt()` can differ from. Router
 * discovery and the gateway's replicas are tested with their clients.
 */
class CurrentVerificationTest {
    private val enclave = TestEnclave()

    @AfterTest
    fun shutDown() {
        enclave.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    private fun unreachable() {
        enclave.relay.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = MockResponse().setResponseCode(503)
        }
    }

    @Test
    fun aFreshVerificationIsCurrentWithoutAnyIo() = test {
        val client = enclave.client()
        val ensured = client.ensureVerified()
        val verifications = enclave.verifications

        val current = assertNotNull(client.currentVerification())
        assertEquals(ensured, current)
        assertSame(client.lastVerificationAttempt()?.report, current)
        assertNotNull(current.verifiedFacts)
        assertEquals(verifications, enclave.verifications, "reading it verifies nothing")
    }

    @Test
    fun theRetryThatRecoversIsCurrent() = test {
        val passes = enclave.verifier.verify
        var first = true
        enclave.verifier.verify = { document, nonce, pin ->
            if (first) {
                first = false
                throw rejection()
            }
            passes(document, nonce, pin)
        }

        val client = enclave.client()

        val retry = assertNotNull(client.lastVerificationAttempt()?.report)
        assertSame(retry, client.currentVerification())
    }

    @Test
    fun aNetworkFailureLeavesTheVerificationCurrentWhileItIsFresh() = test {
        val client = enclave.client()
        val ensured = client.ensureVerified()
        unreachable()

        val error = assertFailsWith<NetworkException> { client.reverify() }

        assertSame(ensured, client.currentVerification(), "requests are still sent under the verification")
        assertSame(error, client.lastVerificationAttempt()?.error, "the last attempt is the failure")
        enclave.server.enqueue(MockResponse().setBody("ok"))
        client.execute(enclave.get()).use { assertEquals(200, it.code, "requests still go through") }

        enclave.clock.advance(enclave.lifetimeSeconds)
        assertNull(client.currentVerification(), "until it expires")
    }

    @Test
    fun anAttestationFailureWithdrawsTheVerificationUntilTheNextOnePasses() = test {
        val client = enclave.client()
        val passes = enclave.verifier.verify
        enclave.verifier.verify = { _, _, _ -> throw rejection() }

        val error = assertFailsWith<AttestationException> { client.reverify() }

        assertNull(client.currentVerification(), "the failure withdrew the verification")
        assertSame(error, client.lastVerificationAttempt()?.error)

        enclave.verifier.verify = passes
        enclave.server.enqueue(MockResponse().setBody("ok"))
        client.execute(enclave.get()).close()
        val next = assertNotNull(client.currentVerification(), "the next request verified again")
        assertSame(client.lastVerificationAttempt()?.report, next)
    }

    @Test
    fun aRefusedKeyLeavesNothingCurrent() = test {
        val client = enclave.client()
        enclave.rotateKey()
        // The verification that the refusal starts cannot complete, so the
        // refused one is what is left.
        unreachable()

        assertFailsWith<NetworkException> { client.execute(enclave.get()) }

        assertNull(client.currentVerification(), "no request is sent under refused keys")
    }

    @Test
    fun anExpiredVerificationIsNotCurrentAndReadingItVerifiesNothing() = test {
        val client = enclave.client()
        val ensured = client.ensureVerified()
        val verifications = enclave.verifications

        enclave.clock.advance(enclave.lifetimeSeconds)

        assertNull(client.currentVerification(), "null at the freshness deadline")
        assertSame(ensured, client.lastVerificationAttempt()?.report, "the last attempt is still the expired success")
        assertEquals(verifications, enclave.verifications, "reading it verifies nothing")

        val next = client.ensureVerified()
        assertNotSame(ensured, next)
        assertSame(next, client.currentVerification())
    }

    @Test
    fun aCurrentReportCannotBeChangedByItsHolder() = test {
        val client = enclave.client()
        val current = assertNotNull(client.currentVerification())
        val before = current.toString()

        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (current.steps as MutableList<Step>).clear()
        }

        assertEquals(before, client.currentVerification().toString())
    }
}
