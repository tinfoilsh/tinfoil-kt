package sh.tinfoil

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.rejection
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/**
 * Every report that a client hands out names, in `metadata.host`, the host
 * that the client contacted; one from the verifier itself names none.
 * Router discovery and the gateway's replicas are tested with their
 * clients.
 */
class ReportHostTest {
    private val enclave = TestEnclave()
    private val attempts = CopyOnWriteArrayList<VerificationAttempt>()

    @AfterTest
    fun shutDown() {
        enclave.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    @Test
    fun everyReportOfAPassedVerificationNamesTheEnclave() = test {
        val client = enclave.client(onVerificationAttempt = { _, attempt -> attempts += attempt })

        assertEquals(enclave.host, jsonHost(client.ensureVerified()))
        assertEquals(enclave.host, jsonHost(client.currentVerification()))
        assertEquals(enclave.host, jsonHost(client.lastVerificationAttempt()?.report))
        assertEquals(enclave.host, jsonHost(client.reverify()))
        awaitUntil { attempts.size == 2 }
        attempts.forEach { assertEquals(enclave.host, jsonHost(it.report)) }
    }

    @Test
    fun theReportOfARejectionNamesTheEnclave() = test {
        val client = enclave.client(onVerificationAttempt = { _, attempt -> attempts += attempt })
        enclave.verifier.verify = { _, _, _ -> throw rejection(VerificationLayer.POLICY) }

        val error = assertFailsWith<AttestationException> { client.reverify() }

        assertEquals(enclave.host, jsonHost(rejectedReport(error)))
        assertEquals(enclave.host, jsonHost(rejectedReport(error.suppressed.single())), "the first attempt's too")
        assertEquals(enclave.host, jsonHost(rejectedReport(client.lastVerificationAttempt()?.error)))
        // Creation, and the two attempts of the rejected verification.
        awaitUntil { attempts.size == 3 }
        attempts.drop(1).forEach { assertEquals(enclave.host, jsonHost(rejectedReport(it.error))) }
        assertEquals(VerificationLayer.POLICY, rejectedReport(error).failedStep?.layer, "the rest of the report is kept")
    }

    @Test
    fun aReportFromTheVerifierItselfNamesNoHost() {
        assertNull(jsonHost(rejectedReport(rejection())))
    }
}
