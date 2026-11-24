package sh.tinfoil

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Creates clients with the native verifier library behind them. The enclave
 * is a name that cannot resolve, so an option that was not refused before
 * any I/O would show as a network failure instead.
 */
@RunWith(AndroidJUnit4::class)
class EnclaveHttpClientBindingTest {
    private val nowhere = "enclave.invalid"
    private val trust = Trust.RepoPin("tinfoilsh/example")

    /** The observer is told once a verification is over, which can be just after its caller is. */

    @Test
    fun theVerifiersOwnRulesRefuseOptionsBeforeAnyIo() = runBlocking<Unit> {
        val results = CopyOnWriteArrayList<VerificationAttempt>()
        val refused: List<Pair<String, suspend () -> Unit>> = listOf(
            "a malformed repository" to {
                EnclaveHttpClient.create(nowhere, Trust.RepoPin("not a repository")) { onVerificationAttempt = { _, attempt -> results += attempt } }
            },
            "a malformed project" to { EnclaveHttpClient.create(nowhere, Trust.ProjectPin("not a project")) },
            "keys that are not keys" to { EnclaveHttpClient.create(nowhere, Trust.SignedBy(listOf("not a key"))) },
            "a config that is not a config" to {
                EnclaveHttpClient.create(nowhere, Trust.EmbeddedConfig("not: a config".toByteArray()))
            },
            "freshness keys that are not keys" to {
                EnclaveHttpClient.create(nowhere, trust) {
                    policy = Policy(artifacts = ArtifactTrust.EndorsedArtifacts(listOf("not a key")))
                }
            },
            "a relay with a query" to {
                EnclaveHttpClient.create(nowhere, trust) { fetchAttestation = AttestationRelay("https://relay.invalid/path?x") }
            },
            "an enclave that is a URL" to { EnclaveHttpClient.create("https://$nowhere/", trust) },
            "a proxy over HTTP that is not on this machine" to {
                EnclaveHttpClient.create(nowhere, trust) { transport = Transport.Ehbp("http://proxy.invalid/") }
            },
            "a proxy on the enclave's origin" to {
                EnclaveHttpClient.create(nowhere, trust) { transport = Transport.Ehbp("https://$nowhere/relay") }
            },
        )
        for ((name, create) in refused) {
            assertFailsWith<ConfigurationException>(name) { create() }
        }
        assertTrue(results.isEmpty(), "no verification was attempted")
    }

    @Test
    fun anEnclaveThatCannotBeReachedIsANetworkError() = runBlocking<Unit> {
        val results = CopyOnWriteArrayList<VerificationAttempt>()

        val error = assertFailsWith<NetworkException> {
            EnclaveHttpClient.create(nowhere, trust) { onVerificationAttempt = { _, attempt -> results += attempt } }
        }

        assertTrue(error.cause != null, "the cause is kept")
        assertEquals(1, error.suppressed.size, "the first of the two attempts is kept as well")
        // Each attempt is reported.
        val deadline = System.nanoTime() + 10_000_000_000L
        while (results.size < 2 && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertEquals(listOf(error.suppressed.single(), error), results.map { it.error })
    }

    @Test
    fun aConfigThatTheCallerApprovesNeedsNoPin() = runBlocking<Unit> {
        // Accepted as a trust argument; it then fails on the network, not on the pin.
        assertFailsWith<NetworkException> { EnclaveHttpClient.create(nowhere, Trust.AuthorizedBy { }) }
    }
}
