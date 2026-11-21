package sh.tinfoil.openai

import com.openai.errors.OpenAIException
import com.openai.errors.OpenAIServiceException
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.future.await
import sh.tinfoil.AttestationException
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.ModelPin
import sh.tinfoil.Trust
import sh.tinfoil.Transport
import sh.tinfoil.tinfoilException
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The README's examples of this module, kept here so that they compile against the API as
 * it is. They are not run: each would verify a production enclave. Change
 * the README and this file together.
 */
@Suppress("unused")
class DocumentationExamplesTest {
    private suspend fun chatCompletion(apiKey: String) {
        val client = Client.create(apiKey)

        val params = ChatCompletionCreateParams.builder()
            .model("gpt-oss-120b")
            .addUserMessage("Hello!")
            .build()
        val completion = client.openAIAsync.chat().completions().create(params).await()
        println(completion.choices().first().message().content().orElse(""))

        client.close()
    }

    private suspend fun streaming(client: Client, params: ChatCompletionCreateParams) {
        client.openAIAsync.chat().completions().createStreaming(params).asFlow().collect { chunk ->
            chunk.choices().forEach { choice -> choice.delta().content().ifPresent(::print) }
        }
    }

    private suspend fun options(apiKey: String): Client {
        val client = Client.create(apiKey) {
            openAI {
                maxRetries(1)
                timeout(Duration.ofMinutes(2))
            }
        }
        return client
    }

    private suspend fun router(apiKey: String, cacheSecret: String): RouterOpenAIClient {
        val client = RouterOpenAIClient.create(apiKey) {
            transport = Transport.Ehbp(proxyUrl = "https://proxy.example.com/")
            userCacheSecret = cacheSecret
            tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH)
        }
        return client
    }

    private suspend fun enclave(apiKey: String) {
        val client = EnclaveOpenAIClient.create(
            enclave = "inference.tinfoil.sh",
            trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
            apiKey = apiKey,
        )
        println(client.httpClient.current?.codeDigest)
    }

    @OptIn(ExperimentalTinfoilApi::class)
    private suspend fun gateway(apiKey: String): GatewayOpenAIClient {
        val client = GatewayOpenAIClient.create(apiKey) {
            modelPins = mapOf("deepseek-v4-1-flash" to ModelPin("tinfoilsh/confidential-deepseek-v4-1-flash"))
            pinnedModelsOnly = true
        }
        println(client.httpClient.models())
        return client
    }

    private fun errors(client: Client, params: ChatCompletionCreateParams) {
        try {
            client.openAI.chat().completions().create(params)
        } catch (e: OpenAIException) {
            val failure = e.tinfoilException
            when {
                failure is AttestationException -> println("The enclave is not to be trusted: ${failure.detail}")
                failure != null -> println("The request could not be sent: ${failure.detail}")
                e is OpenAIServiceException -> println("The API answered with ${e.statusCode()}")
                else -> println("The request failed: ${e.message}")
            }
        }
    }

    @Test
    fun theExamplesNameTheEventThatTheyAskFor() {
        assertEquals("web_search", TinfoilEvent.WEB_SEARCH.value)
    }
}
