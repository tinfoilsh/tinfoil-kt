package sh.tinfoil.openai

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.openai.client.OpenAIClient
import com.openai.client.OpenAIClientAsync
import com.openai.errors.UnauthorizedException
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.future.await
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.runner.RunWith
import sh.tinfoil.Client
import sh.tinfoil.Pin
import sh.tinfoil.TransportMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Drives the OpenAI SDK through clients that verify Tinfoil's production
 * router with the native verifier library and the platform's own TLS.
 *
 * These tests reach the network, so they run only when the instrumentation
 * argument `tinfoilIntegration` is `true`. Those that complete a chat need an
 * API key, in the instrumentation argument `tinfoilApiKey`, and are skipped
 * without one:
 * `-Pandroid.testInstrumentationRunnerArguments.tinfoilApiKey="$TINFOIL_API_KEY"`.
 * The others send a key that is none, and check the router's refusal.
 */
@RunWith(AndroidJUnit4::class)
class OpenAIClientsLiveTest {
    private val enclave = "inference.tinfoil.sh"
    private val router = "tinfoilsh/confidential-model-router"

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

    private fun params(prompt: String = "Reply with the single word: ready") =
        ChatCompletionCreateParams.builder().model(MODEL).addUserMessage(prompt).maxCompletionTokens(64).build()

    /** A chat request under a key that is none is answered by the router, with an error of the API's own. */
    private suspend fun assertRefused(name: String, openAI: OpenAIClient, async: OpenAIClientAsync) {
        val error = assertFailsWith<UnauthorizedException> { openAI.chat().completions().create(params()) }
        Log.i(TAG, "$name: a chat under a key that is none was refused with ${error.javaClass.simpleName} (${error.statusCode()})")
        assertEquals(401, error.statusCode())
        assertNull(error.tinfoilException, "the refusal is the API's, not this SDK's")

        val streamed = assertFailsWith<UnauthorizedException> {
            async.chat().completions().createStreaming(params()).asFlow().toList()
        }
        assertEquals(error.statusCode(), streamed.statusCode())
    }

    private suspend fun assertModelsListed(name: String, async: OpenAIClientAsync) {
        val models = async.models().list().await().data()
        Log.i(TAG, "$name: ${models.size} models listed")
        assertTrue(models.isNotEmpty())
    }

    private suspend fun assertChats(name: String, openAI: OpenAIClient, async: OpenAIClientAsync) {
        val answer = openAI.chat().completions().create(params())
        val text = answer.choices().first().message().content().orElse("")
        Log.i(TAG, "$name: a chat completion of ${text.length} characters, model ${answer.model()}")
        assertNotNull(answer.id())

        val chunks = async.chat().completions().createStreaming(params("Count from one to five.")).asFlow().toList()
        val streamed = chunks.flatMap { it.choices() }.mapNotNull { it.delta().content().orElse(null) }.joinToString("")
        Log.i(TAG, "$name: a streamed completion in ${chunks.size} chunks, ${streamed.length} characters")
        assertTrue(chunks.size > 1, "the completion arrived in ${chunks.size} chunk(s)")
    }

    @Test
    fun theDropInClientReachesTheRouterThroughTheOpenAiSdk() = live {
        Client.create(NOT_A_KEY) { openAI { maxRetries(0) } }.use { client ->
            assertTrue(client.baseUrl.toString().endsWith(".tinfoil.sh/v1/"), client.baseUrl.toString())
            assertModelsListed("drop-in", client.openAIAsync)
            assertRefused("drop-in", client.openAI, client.openAIAsync)
        }
    }

    @Test
    fun theRouterClientSealsWhatTheOpenAiSdkSends() = live {
        RouterOpenAIClient.create(NOT_A_KEY) {
            transportMode = TransportMode.EHBP
            openAI { maxRetries(0) }
        }.use { client ->
            assertEquals(TransportMode.EHBP, client.httpClient.transportMode)
            assertModelsListed("router, sealed", client.openAIAsync)
            assertRefused("router, sealed", client.openAI, client.openAIAsync)
        }
    }

    @Test
    fun theEnclaveClientReachesANamedEnclaveThroughTheOpenAiSdk() = live {
        EnclaveOpenAIClient.create(enclave, Pin(repo = router), NOT_A_KEY) { openAI { maxRetries(0) } }
            .use { client ->
                assertEquals("https://$enclave/", client.httpClient.baseUrl.toString())
                assertModelsListed("enclave", client.openAIAsync)
                assertRefused("enclave", client.openAI, client.openAIAsync)
            }
    }

    @Test
    fun aChatIsCompletedAndStreamedOverPinnedConnections() = live {
        val key = apiKey()
        Client.create(key).use { client -> assertChats("drop-in", client.openAI, client.openAIAsync) }
    }

    @Test
    fun aChatIsCompletedAndStreamedWithSealedBodies() = live {
        val key = apiKey()
        RouterOpenAIClient.create(key) { transportMode = TransportMode.EHBP }.use { client ->
            assertChats("router, sealed", client.openAI, client.openAIAsync)
        }
    }

    private companion object {
        const val TAG = "TinfoilLive"
        const val MODEL = "gpt-oss-120b"

        /** Has the shape of a credential, and is none. */
        const val NOT_A_KEY = "not-an-api-key"
    }
}
