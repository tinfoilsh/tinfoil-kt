@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.openai.errors.OpenAIServiceException
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.runner.RunWith
import sh.tinfoil.openai.GatewayOpenAIClient
import sh.tinfoil.openai.asFlow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Reads the catalog of Tinfoil's production gateway, verifies a replica of
 * one of its models through the gateway with the native verifier library,
 * and sends requests that are sealed to that replica.
 *
 * These tests reach the network, so they run only when the instrumentation
 * argument `tinfoilIntegration` is `true`. Those that complete a chat need an
 * API key, in the instrumentation argument `tinfoilApiKey`, and are skipped
 * without one. The others send no key, or one that is none, and record what
 * the gateway and the replica answer.
 */
@RunWith(AndroidJUnit4::class)
class GatewayLiveTest {
    private val gateway = "inference-gateway.tinfoil.sh"

    @Before
    fun requireOptIn() {
        val enabled = InstrumentationRegistry.getArguments().getString("tinfoilIntegration")
        assumeTrue("live tests run only with the instrumentation argument tinfoilIntegration=true", enabled == "true")
    }

    /** The API key that the test run was given. It is never logged. */
    private fun apiKey(): String {
        val key = InstrumentationRegistry.getArguments().getString("tinfoilApiKey").orEmpty()
        assumeTrue("this test needs an API key in the instrumentation argument tinfoilApiKey", key.isNotEmpty())
        return key
    }

    private fun live(block: suspend () -> Unit) = runBlocking { withTimeout(240.seconds) { block() } }

    private fun chat(client: GatewayHttpClient, model: String): Request = Request.Builder()
        .url(client.baseUrl.resolve("chat/completions")!!)
        .post("""{"model":"$model","messages":[{"role":"user","content":"hello"}],"max_tokens":8}""".toRequestBody("application/json".toMediaType()))
        .build()

    @Test
    fun theGatewaysCatalogListsModelsWithReplicas() = live {
        val catalog = GatewayHttpClient.fetchCatalog(gateway)
        Log.i(TAG, "catalog: ${catalog.entries.map { (model, entry) -> "$model=${entry.repo} x${entry.hosts.size}" }}")
        assertTrue(catalog.entries.isNotEmpty(), "the catalog lists no model that can be routed to")
        for ((model, entry) in catalog.entries) {
            assertTrue(Regex("tinfoilsh/[A-Za-z0-9_.-]+").matches(entry.repo), "$model: ${entry.repo}")
            assertTrue(entry.hosts.isNotEmpty(), model)
        }
        assertFailsWith<ConfigurationException> { GatewayHttpClient.fetchCatalog("https://$gateway/") }
    }

    @Test
    fun aReplicaIsVerifiedThroughTheGatewayAndAnswersASealedRequest() = live {
        val results = java.util.concurrent.CopyOnWriteArrayList<Result<Verification>>()
        GatewayHttpClient.create { onVerificationResult = { results += it } }.use { client ->
            assertEquals(GatewayHttpClient.DEFAULT_BASE_URL, client.baseUrl.toString())
            val models = client.models()
            Log.i(TAG, "models: $models")
            assertTrue(models.isNotEmpty())
            assertEquals(emptyList(), client.current, "creating a client verifies nothing")
            val model = models.first()
            val catalog = GatewayHttpClient.fetchCatalog(gateway)

            val verification = client.ensureVerified(model)

            Log.i(
                TAG,
                "verified a replica of $model: repo ${verification.configRepo}, code ${verification.codeDigest}, " +
                    "fresh until ${verification.freshnessExpiresAt}",
            )
            assertTrue(Regex("[0-9a-f]{64}").matches(verification.hpkePublicKey.orEmpty()), "$verification")
            val replica = client.current.single()
            assertEquals(verification, replica.verification)
            assertEquals(catalog[model]?.repo, replica.reference)
            assertTrue(replica.host in catalog[model]!!.hosts, replica.host)
            assertNull(replica.pinnedModel)
            assertEquals(verification, client.ensureVerified(model), "a valid verification is reused")

            // A sealed chat request without an API key.
            client.executeRecoverable(chat(client, model)).use { recoverable ->
                val response = recoverable.response
                val body = response.body!!.string()
                Log.i(
                    TAG,
                    "a sealed chat request for $model without an API key was answered with ${response.code}, " +
                        "nonce ${if (response.header(NONCE) == null) "absent" else "present"}, " +
                        "token ${if (recoverable.recoveryToken == null) "absent" else "present"}, " +
                        "sealed to ${response.request.header("X-Tinfoil-Seal")}, body: ${body.take(200)}",
                )
                assertNotNull(response.request.header("Ehbp-Encapsulated-Key"), "the request was not sealed")
                assertEquals(model, response.request.header("X-Tinfoil-Model"))
                assertNotNull(response.request.header("X-Tinfoil-Cache-Prefix"))
                assertTrue(response.code in 400..499, "HTTP ${response.code}: ${body.take(200)}")
            }
            assertTrue(model in client.current.flatMap { it.models })

            // A request that names no model, and a model that is not served.
            assertFailsWith<ConfigurationException> {
                client.execute(Request.Builder().url(client.baseUrl.resolve("models")!!).build())
            }
            assertFailsWith<ConfigurationException> { client.ensureVerified("no-such-model") }
        }
        assertTrue(results.isNotEmpty() && results.all { it.isSuccess }, "$results")
    }

    @Test
    fun aPinnedModelIsVerifiedAgainstItsPinAndNoOtherModelIsServed() = live {
        val catalog = GatewayHttpClient.fetchCatalog(gateway)
        val (model, entry) = catalog.entries.entries.first()
        val other = catalog.entries.keys.firstOrNull { it != model }
        GatewayHttpClient.create {
            modelPins = mapOf(model to ModelPin(entry.repo))
            pinnedModelsOnly = true
        }.use { client ->
            assertEquals(listOf(model), client.models())
            val verification = client.ensureVerified(model)
            assertEquals(entry.repo, verification.configRepo ?: entry.repo)
            assertEquals(model, client.current.single().pinnedModel)
            if (other != null) {
                assertFailsWith<ConfigurationException> { client.ensureVerified(other) }
            }
        }
        // A pin to another repository than the one that serves the model.
        GatewayHttpClient.create { modelPins = mapOf(model to ModelPin("tinfoilsh/confidential-model-router")) }.use { client ->
            val error = assertFailsWith<AttestationException> { client.ensureVerified(model) }
            Log.i(TAG, "a pin to another repository: ${error.detail}")
            assertEquals(emptyList(), client.current)
        }
        // A pin to a release that the replicas do not run.
        GatewayHttpClient.create { modelPins = mapOf(model to ModelPin("${entry.repo}@v0.0.0-no-such-release")) }.use { client ->
            val error = assertFailsWith<TinfoilException> { client.ensureVerified(model) }
            Log.i(TAG, "a pin to a release that is not running: ${error.message}")
            assertTrue(error is AttestationException, "$error")
            assertEquals(emptyList(), client.current)
        }
    }

    @Test
    fun aPinThatIsNotAReferenceIsRefusedByTheVerifier() = live {
        for (repo in listOf("tinfoilsh/bad@@", "tinfoilsh/a b", "tinfoilsh/a@sha256:zz", "tinfoilsh/")) {
            val error = assertFailsWith<ConfigurationException>(repo) {
                GatewayHttpClient.create { modelPins = mapOf("m" to ModelPin(repo)) }
            }
            Log.i(TAG, "pin $repo: ${error.detail}")
        }
    }

    @Test
    fun theOpenAiSdkReachesAReplicaThroughTheGateway() = live {
        val model = GatewayHttpClient.fetchCatalog(gateway).entries.keys.first()
        GatewayOpenAIClient.create(NOT_A_KEY) { openAI { maxRetries(0) } }.use { client ->
            val params = ChatCompletionCreateParams.builder().model(model).addUserMessage("hello").maxCompletionTokens(8).build()
            val error = assertFailsWith<OpenAIServiceException> { client.openAI.chat().completions().create(params) }
            Log.i(TAG, "OpenAI SDK through the gateway under a key that is none: ${error.javaClass.simpleName} (${error.statusCode()})")
            assertTrue(error.statusCode() in 400..499)
            assertNull(error.tinfoilException, "the refusal is the API's, not this SDK's")
            assertEquals(1, client.httpClient.current.size)
        }
    }

    @Test
    fun aChatIsCompletedAndStreamedThroughTheGateway() = live {
        val key = apiKey()
        val model = GatewayHttpClient.fetchCatalog(gateway).entries.keys.first()
        GatewayOpenAIClient.create(key).use { client ->
            val params = ChatCompletionCreateParams.builder().model(model)
                .addUserMessage("Reply with the single word: ready").maxCompletionTokens(64).build()
            val answer = client.openAI.chat().completions().create(params)
            val text = answer.choices().first().message().content().orElse("")
            Log.i(TAG, "gateway: a chat completion of ${text.length} characters, model ${answer.model()}")
            assertNotNull(answer.id())

            val chunks = client.openAIAsync.chat().completions().createStreaming(params).asFlow().toList()
            Log.i(TAG, "gateway: a streamed completion in ${chunks.size} chunks")
            assertTrue(chunks.size > 1, "the completion arrived in ${chunks.size} chunk(s)")
            assertTrue(client.httpClient.current.isNotEmpty())
        }
    }

    private companion object {
        const val TAG = "TinfoilLive"
        const val NONCE = "Ehbp-Response-Nonce"

        /** Has the shape of a credential, and is none. */
        const val NOT_A_KEY = "not-an-api-key"
    }
}
