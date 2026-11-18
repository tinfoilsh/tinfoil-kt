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
    private val pin = Pin(repo = "tinfoilsh/example")

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
            "a pin that names nothing, under the default trust" to {
                EnclaveHttpClient.create(nowhere, Pin(), onVerificationResult = { results += it })
            },
            "a malformed pin" to { EnclaveHttpClient.create(nowhere, Pin(repo = "not a repository")) },
            "a relay that is a URL" to {
                EnclaveHttpClient.create(nowhere, pin, attestationRelay = "https://relay.invalid/path")
            },
            "an enclave that is a URL" to { EnclaveHttpClient.create("https://$nowhere/", pin) },
            "a pin for a verifier that authorizes configs itself" to {
                EnclaveHttpClient.create(nowhere, pin, verifier = Verifier(configAuthorizer = { }))
            },
            "a proxy over HTTP that is not on this machine" to {
                EnclaveHttpClient.create(nowhere, pin, transportMode = TransportMode.Ehbp, baseUrl = "http://proxy.invalid/")
            },
            "a proxy" to { EnclaveHttpClient.create(nowhere, pin, baseUrl = "https://proxy.invalid/") },
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
            EnclaveHttpClient.create(nowhere, pin, onVerificationResult = { results += it })
        }

        assertTrue(error.cause != null, "the cause is kept")
        assertEquals(1, error.suppressed.size, "the first of the two attempts is kept as well")
        assertSame(error, awaitOne(results).exceptionOrNull())
    }

    @Test
    fun aVerifierThatAuthorizesConfigsItselfNeedsNoPin() = runBlocking<Unit> {
        // Accepted as an option; it then fails on the network, not on the pin.
        assertFailsWith<NetworkException> {
            EnclaveHttpClient.create(nowhere, Pin(), verifier = Verifier(configAuthorizer = { }))
        }
    }
}
