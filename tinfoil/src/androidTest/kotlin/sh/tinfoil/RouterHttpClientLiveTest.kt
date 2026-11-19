package sh.tinfoil

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.runner.RunWith
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Discovers and verifies one of Tinfoil's production routers with the native
 * verifier library and the platform's own TLS, and sends it requests that
 * need no API key.
 *
 * These tests reach the network, so they run only when the instrumentation
 * argument `tinfoilIntegration` is `true`:
 * `-Pandroid.testInstrumentationRunnerArguments.tinfoilIntegration=true`.
 */
@RunWith(AndroidJUnit4::class)
class RouterHttpClientLiveTest {
    private val router = "tinfoilsh/confidential-model-router"

    @Before
    fun requireOptIn() {
        val enabled = InstrumentationRegistry.getArguments().getString("tinfoilIntegration")
        assumeTrue("live tests run only with the instrumentation argument tinfoilIntegration=true", enabled == "true")
    }

    private fun live(block: suspend () -> Unit) = runBlocking { withTimeout(180.seconds) { block() } }

    @Test
    fun aRouterIsDiscoveredVerifiedAndAnswersOverPinnedConnections() = live {
        val seen = CopyOnWriteArrayList<Verification>()
        val started = System.nanoTime()

        RouterHttpClient.create { verificationCheck = VerificationCheck { seen += it } }.use { client ->
            val verified = assertNotNull(client.current, "a client is verified when it is returned")
            Log.i(TAG, "discovered ${client.enclave} in ${(System.nanoTime() - started) / 1_000_000} ms, after ${seen.size} verification(s)")
            assertSame(verified, seen.last())
            assertSame(verified, client.ensureVerified(), "a valid verification is reused")

            assertTrue(client.enclave.endsWith(".tinfoil.sh"), client.enclave)
            assertEquals(Pin(repo = router, project = router), client.pin)
            assertEquals("https://${client.enclave}/", client.baseUrl.toString())
            assertEquals(TransportMode.TLS, client.transportMode)
            assertEquals(router, verified.configRepo)
            assertTrue(Regex("[0-9a-f]{64}").matches(verified.tlsPublicKeyFingerprint.orEmpty()), "$verified")
            assertTrue(verified.freshnessExpiresAt.isAfter(Instant.now()), "${verified.freshnessExpiresAt}")

            val models = Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build()
            val body = client.execute(models).use { response ->
                assertEquals(200, response.code)
                assertNotNull(response.handshake)
                response.body!!.string()
            }
            assertTrue(body.contains("\"data\""), body.take(200))
            client.newCall(models).execute().use { assertEquals(200, it.code) }

            // A request whose body is given the cache secret reaches the
            // router and is answered by it; without an API key, with a
            // refusal.
            val chat = Request.Builder()
                .url(client.baseUrl.resolve("v1/chat/completions")!!)
                .post("""{"model":"none","messages":[],"seed":18446744073709551617}""".toRequestBody("application/json".toMediaType()))
                .build()
            client.execute(chat).use { response ->
                Log.i(TAG, "a chat request without an API key was answered with ${response.code}")
                assertTrue(response.code in 400..499, "HTTP ${response.code}: ${response.body!!.string().take(200)}")
            }

            val enclave = client.enclave
            val again = client.reverify()
            assertEquals(enclave, client.enclave, "the same router is verified again")
            assertTrue(!again.metadata.verifiedAt.isBefore(verified.metadata.verifiedAt))
            client.execute(models).use { assertEquals(200, it.code) }

            assertFailsWith<ConfigurationException> {
                client.execute(Request.Builder().url("https://example.com/v1/models").build())
            }
        }
    }

    @Test
    fun aCheckThatRejectsEveryRouterFailsTheCreationAfterTheFallback() = live {
        val rejected = CopyOnWriteArrayList<String>()

        val error = assertFailsWith<AttestationException> {
            RouterHttpClient.create {
                verificationCheck = VerificationCheck {
                    rejected += it.tlsPublicKeyFingerprint.orEmpty()
                    throw IllegalStateException("no router is accepted")
                }
            }
        }

        Log.i(TAG, "a rejecting check saw ${rejected.size} verification(s), ${rejected.toSet().size} distinct key(s)")
        assertTrue(error.detail.contains("inference.tinfoil.sh"), error.detail)
        assertTrue(error.detail.contains("no router is accepted"), error.detail)
        assertTrue(rejected.isNotEmpty())
    }

    @Test
    fun aVerifierThatAuthorizesConfigsItselfIsRefused() = live {
        val verifier = Verifier(configAuthorizer = { })

        assertFailsWith<ConfigurationException> { RouterHttpClient.create { this.verifier = verifier } }
    }

    private companion object {
        const val TAG = "TinfoilLive"
    }
}
