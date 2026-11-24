package sh.tinfoil

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Request
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.runner.RunWith
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
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
 * Verifies Tinfoil's production router with the native verifier library and
 * the platform's own TLS, and sends it requests that need no API key.
 *
 * These tests reach the network, so they run only when the instrumentation
 * argument `tinfoilIntegration` is `true`:
 * `-Pandroid.testInstrumentationRunnerArguments.tinfoilIntegration=true`.
 */
@RunWith(AndroidJUnit4::class)
class EnclaveHttpClientLiveTest {
    private val enclave = "inference.tinfoil.sh"
    private val trust = Trust.RepoPin("tinfoilsh/confidential-model-router")

    @Before
    fun requireOptIn() {
        val enabled = InstrumentationRegistry.getArguments().getString("tinfoilIntegration")
        assumeTrue("live tests run only with the instrumentation argument tinfoilIntegration=true", enabled == "true")
    }

    /** The observer is told once a verification is over, which can be just after its caller is. */
    private fun <T> awaitOne(results: List<T>): T {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (results.isEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        return results.single()
    }

    private fun live(block: suspend () -> Unit) = runBlocking { withTimeout(120.seconds) { block() } }

    @Test
    fun theRouterVerifiesAndAnswersOverPinnedConnections() = live {
        val seen = CopyOnWriteArrayList<VerifiedFacts>()
        val results = CopyOnWriteArrayList<VerificationAttempt>()

        EnclaveHttpClient.create(enclave = enclave, trust = trust) {
            verificationCheck = VerificationCheck { seen += it }
            onVerification = { _, attempt -> results += attempt }
        }.use { client ->
            val report = assertNotNull(client.lastVerification()?.report, "a client is verified when it is returned")
            val verified = assertNotNull(report.verifiedFacts)
            assertSame(verified, seen.single())
            assertSame(report, awaitOne(results).report)
            assertSame(report, client.ensureVerified(), "a valid verification is reused")
            assertTrue(report.steps.all { it.status == StepStatus.PASSED || it.status == StepStatus.SKIPPED }, "$report")

            assertEquals("tinfoilsh/confidential-model-router", verified.configRepo)
            assertTrue(Regex("[0-9a-f]{64}").matches(verified.codeDigest), verified.codeDigest)
            assertTrue(Regex("[0-9a-f]{64}").matches(verified.tlsPublicKeyFingerprint.orEmpty()), "$verified")
            assertTrue(verified.cryptoMaterial.any { it.id == "tls" && it.data == verified.tlsPublicKeyFingerprint })
            assertNotNull(verified.enclaveMeasurement)
            assertTrue(verified.freshnessExpiresAt.isAfter(Instant.now()), "${verified.freshnessExpiresAt}")
            assertEquals("tinfoil-kt", report.metadata.verifier.name)

            assertEquals("https://$enclave/", client.baseUrl.toString())
            assertEquals(enclave, client.enclave)
            assertEquals(trust, client.trust)

            val models = Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build()
            val body = client.execute(models).use { response ->
                assertEquals(200, response.code)
                // The platform checked the chain, and the leaf's key is the attested one.
                assertNotNull(response.handshake)
                response.body!!.string()
            }
            assertTrue(body.contains("\"data\""), body.take(200))
            client.newCall(models).execute().use { assertEquals(200, it.code) }

            val again = client.reverify()
            assertEquals(2, seen.size)
            assertTrue(!again.metadata.verifiedAt.isBefore(report.metadata.verifiedAt))
            client.execute(models).use { assertEquals(200, it.code) }
        }
    }

    @Test
    fun anEnclaveThatRunsSomethingElseIsRefused() = live {
        val results = CopyOnWriteArrayList<VerificationAttempt>()

        val error = assertFailsWith<AttestationException> {
            EnclaveHttpClient.create(enclave = enclave, trust = Trust.RepoPin("tinfoilsh/not-the-router")) {
                onVerification = { _, attempt -> results += attempt }
            }
        }

        assertNotNull(error.layer, error.message)
        // The verifier's rejection, with its report, is the cause.
        val rejected = assertIs<VerificationException>(error.cause)
        assertEquals(error.layer, rejected.layer)
        assertEquals(error.layer, rejected.report.failedStep?.layer)
        assertNull(rejected.report.verifiedFacts)
        assertNotNull(rejected.report.partialFacts)
        val deadline = System.nanoTime() + 10_000_000_000L
        while (results.size < 2 && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertSame(error, results.last().error)
    }

    @Test
    fun aRequestToAnotherOriginIsRefusedByAVerifiedClient() = live {
        EnclaveHttpClient.create(enclave = enclave, trust = trust).use { client ->
            assertFailsWith<ConfigurationException> {
                client.execute(Request.Builder().url("https://example.com/").build())
            }
            assertFailsWith<ConfigurationException> {
                client.execute(Request.Builder().url("http://$enclave/v1/models").build())
            }
        }
    }
}
