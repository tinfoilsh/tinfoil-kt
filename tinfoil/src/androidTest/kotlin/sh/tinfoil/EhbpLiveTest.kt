package sh.tinfoil

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.runner.RunWith
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Verifies Tinfoil's production router with the native verifier library and
 * sends it requests whose bodies are sealed to its attested HPKE key, with
 * the sealing library and the platform's own TLS. No request needs an API
 * key: a sealed request that the router refuses is still answered by the
 * router, with a response that only it can have sealed.
 *
 * These tests reach the network, so they run only when the instrumentation
 * argument `tinfoilIntegration` is `true`:
 * `-Pandroid.testInstrumentationRunnerArguments.tinfoilIntegration=true`.
 */
@RunWith(AndroidJUnit4::class)
class EhbpLiveTest {
    private val enclave = "inference.tinfoil.sh"
    private val router = "tinfoilsh/confidential-model-router"

    @Before
    fun requireOptIn() {
        val enabled = InstrumentationRegistry.getArguments().getString("tinfoilIntegration")
        assumeTrue("live tests run only with the instrumentation argument tinfoilIntegration=true", enabled == "true")
    }

    private fun live(block: suspend () -> Unit) = runBlocking { withTimeout(180.seconds) { block() } }

    private fun chat(base: okhttp3.HttpUrl): Request = Request.Builder()
        .url(base.resolve("v1/chat/completions")!!)
        .post("""{"model":"none","messages":[{"role":"user","content":"hello"}]}""".toRequestBody("application/json".toMediaType()))
        .build()

    /**
     * Sends a sealed chat request without an API key and checks that the
     * answer is the router's own: sealed for this request, and opened.
     */
    private suspend fun assertSealedExchange(name: String, base: okhttp3.HttpUrl, send: suspend (Request) -> RecoverableResponse, factory: Call.Factory) {
        send(chat(base)).use { recoverable ->
            val response = recoverable.response
            val body = response.body!!.string()
            Log.i(
                TAG,
                "$name: a sealed chat request without an API key was answered with ${response.code}, " +
                    "nonce ${if (response.header(NONCE) == null) "absent" else "present"}, " +
                    "token ${if (recoverable.recoveryToken == null) "absent" else "present"}, body: ${body.take(200)}",
            )
            assertTrue(response.code in 400..499, "HTTP ${response.code}: ${body.take(200)}")
            assertNotNull(response.header(NONCE), "the router's answer was not sealed")
            assertNotNull(recoverable.recoveryToken, "a sealed answer has a token")
            assertNotNull(response.request.header("Ehbp-Encapsulated-Key"), "the request was not sealed")
            assertTrue(body.isNotEmpty(), "the sealed answer opened to nothing")
        }
        // The same exchange as an OkHttp call.
        factory.newCall(chat(base)).execute().use { response ->
            assertTrue(response.code in 400..499)
            assertNotNull(response.header(NONCE))
            assertTrue(response.body!!.string().isNotEmpty())
        }
    }

    @Test
    fun theRouterVerifiesAndAnswersSealedRequests() = live {
        EnclaveHttpClient.create(enclave = enclave, trust = Trust.RepoPin(router)) {
            transport = Transport.Ehbp()
        }.use { client ->
            val verified = assertNotNull(client.lastVerificationAttempt()?.report?.verifiedFacts)
            assertEquals(Transport.Ehbp(), client.transport)
            assertTrue(Regex("[0-9a-f]{64}").matches(verified.hpkePublicKey.orEmpty()), "$verified")
            assertTrue(verified.cryptoMaterial.any { it.id == "hpke" && it.data == verified.hpkePublicKey })
            assertEquals("https://$enclave/", client.baseUrl.toString())

            // A request without a body is not sealed, and is answered as such.
            val models = Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build()
            client.executeRecoverable(models).use { recoverable ->
                assertEquals(200, recoverable.response.code)
                assertNull(recoverable.response.header(NONCE))
                assertNull(recoverable.recoveryToken)
                assertTrue(recoverable.response.body!!.string().contains("\"data\""))
            }

            assertSealedExchange("enclave client", client.baseUrl, client::executeRecoverable, client)

            client.reverify()
            assertSealedExchange("enclave client, verified again", client.baseUrl, client::executeRecoverable, client)

            assertFailsWith<ConfigurationException> {
                client.execute(Request.Builder().url("https://example.com/v1/models").build())
            }
            assertFailsWith<ConfigurationException> {
                client.execute(models.newBuilder().header("Upgrade", "websocket").build())
            }
        }
    }

    @Test
    fun aDiscoveredRouterAnswersSealedRequests() = live {
        RouterHttpClient.create { transport = Transport.Ehbp() }.use { client ->
            val verified = assertNotNull(client.lastVerificationAttempt()?.report?.verifiedFacts)
            Log.i(TAG, "discovered ${client.enclave} for sealed requests")
            assertEquals(Transport.Ehbp(), client.transport)
            assertTrue(Regex("[0-9a-f]{64}").matches(verified.hpkePublicKey.orEmpty()), "$verified")
            assertEquals("https://${client.enclave}/", client.baseUrl.toString())

            assertSealedExchange("router client", client.baseUrl, client::executeRecoverable, client)
        }
    }

    @Test
    fun aTokenIsNotOfferedOverPinnedTls() = live {
        EnclaveHttpClient.create(enclave = enclave, trust = Trust.RepoPin(router)).use { client ->
            assertFailsWith<ConfigurationException> {
                client.executeRecoverable(Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build())
            }
        }
    }

    private companion object {
        const val TAG = "TinfoilLive"
        const val NONCE = "Ehbp-Response-Nonce"
    }
}
