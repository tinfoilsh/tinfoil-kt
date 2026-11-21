package sh.tinfoil

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
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
    private fun <T> awaitOne(results: List<T>): T {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (results.isEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        return results.single()
    }

    @Test
    fun theVerifiersOwnRulesRefuseOptionsBeforeAnyIo() = runBlocking<Unit> {
        val results = CopyOnWriteArrayList<Result<Verification>>()
        val refused: List<Pair<String, suspend () -> Unit>> = listOf(
            "a malformed repository" to {
                EnclaveHttpClient.create(nowhere, Trust.RepoPin("not a repository")) { onVerificationResult = { results += it } }
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
            "a relay that is a URL" to {
                EnclaveHttpClient.create(nowhere, trust) { attestationRelay = "https://relay.invalid/path" }
            },
            "an enclave that is a URL" to { EnclaveHttpClient.create("https://$nowhere/", trust) },
            "a proxy over HTTP that is not on this machine" to {
                EnclaveHttpClient.create(nowhere, trust) {
                    transportMode = TransportMode.EHBP
                    baseUrl = "http://proxy.invalid/"
                }
            },
            "a proxy" to { EnclaveHttpClient.create(nowhere, trust) { baseUrl = "https://proxy.invalid/" } },
        )
        for ((name, create) in refused) {
            assertFailsWith<ConfigurationException>(name) { create() }
        }
        assertTrue(results.isEmpty(), "no verification was attempted")
    }

    @Test
    fun anEnclaveThatCannotBeReachedIsANetworkError() = runBlocking<Unit> {
        val results = CopyOnWriteArrayList<Result<Verification>>()

        val error = assertFailsWith<NetworkException> {
            EnclaveHttpClient.create(nowhere, trust) { onVerificationResult = { results += it } }
        }

        assertTrue(error.cause != null, "the cause is kept")
        assertEquals(1, error.suppressed.size, "the first of the two attempts is kept as well")
        assertSame(error, awaitOne(results).exceptionOrNull())
    }

    @Test
    fun aConfigThatTheCallerApprovesNeedsNoPin() = runBlocking<Unit> {
        // Accepted as a trust argument; it then fails on the network, not on the pin.
        assertFailsWith<NetworkException> { EnclaveHttpClient.create(nowhere, Trust.AuthorizedBy { }) }
    }
}
