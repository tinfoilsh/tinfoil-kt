@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.openai

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.openai.errors.OpenAIServiceException
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.runner.RunWith
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.tinfoilException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Drives the OpenAI SDK through Tinfoil's production gateway: each request
 * is sealed to a replica of its model that the native verifier library
 * verified.
 *
 * These tests reach the network, so they run only when the instrumentation
 * argument `tinfoilIntegration` is `true`. The one that completes a chat
 * needs an API key, in the instrumentation argument `tinfoilApiKey`, and is
 * skipped without one. The other sends a key that is none, and records what
 * the replica answers.
 */
@RunWith(AndroidJUnit4::class)
class GatewayOpenAIClientLiveTest {
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

        /** Has the shape of a credential, and is none. */
        const val NOT_A_KEY = "not-an-api-key"
    }
}
