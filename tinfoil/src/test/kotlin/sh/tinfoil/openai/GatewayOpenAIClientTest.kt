@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.openai

import com.openai.core.ClientOptions
import com.openai.core.JsonValue
import com.openai.errors.OpenAIException
import com.openai.models.chat.completions.ChatCompletionChunk
import com.openai.models.audio.transcriptions.TranscriptionCreateParams
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.future.await
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.MockResponse
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.ModelPin
import sh.tinfoil.NetworkException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilEvent
import sh.tinfoil.Verifier
import sh.tinfoil.testing.TestGateway
import sh.tinfoil.testing.containsText
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The OpenAI client over the gateway: what the OpenAI SDK sends goes sealed to a verified replica, and nowhere else. */
class GatewayOpenAIClientTest {
    private val gateway = TestGateway()

    @AfterTest
    fun shutDown() {
        gateway.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    private suspend fun client(
        modelPins: Map<String, ModelPin> = emptyMap(),
        pinnedModelsOnly: Boolean = false,
        baseUrl: String? = gateway.baseUrl,
        userCacheSecret: String? = "test-secret",
        apiKey: String = KEY,
        tinfoilEvents: Set<TinfoilEvent> = emptySet(),
        configure: (ClientOptions.Builder.() -> Unit)? = null,
    ): GatewayOpenAIClient = GatewayOpenAIClient.create(apiKey, gateway.internals()) {
        this.modelPins = modelPins
        this.pinnedModelsOnly = pinnedModelsOnly
        this.baseUrl = baseUrl
        verifier = Verifier.appraisingWith(gateway.verifier)
        this.userCacheSecret = userCacheSecret
        this.tinfoilEvents = tinfoilEvents
        configure?.let { openAI(it) }
    }.also(gateway::track)

    private fun params(prompt: String = "hello", model: String = "a-model"): ChatCompletionCreateParams =
        ChatCompletionCreateParams.builder().model(model).addUserMessage(prompt).build()

    private fun chunk(text: String): String =
        """data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"a-model","choices":[{"index":0,""" +
            """"delta":{"content":"$text"},"finish_reason":null}]}""" + "\n\n"

    private fun texts(chunks: List<ChatCompletionChunk>): List<String> =
        chunks.flatMap { it.choices() }.mapNotNull { it.delta().content().orElse(null) }

    @Test
    fun aChatCompletionIsSealedToAVerifiedReplicaOfItsModel() = test {
        gateway.serve("a-model" to ("tinfoilsh/a-model" to listOf("a.example")))
        gateway.answer = { it.reply(completionJson("sealed answer")) }
        val client = client(tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH))
        val prompt = "a-prompt-that-must-not-be-seen-on-the-wire"

        val answer = client.openAI.chat().completions().create(params(prompt))

        assertEquals("sealed answer", answer.choices().single().message().content().get())
        assertEquals(listOf("a.example" to Pin(repo = "tinfoilsh/a-model", project = "tinfoilsh/a-model")), gateway.verified)
        val received = gateway.received.single()
        assertTrue(received.sealed)
        // The gateway's base URL is used as it is.
        assertEquals("/v1/chat/completions", received.request.path)
        assertEquals("a-model", received.request.getHeader("X-Tinfoil-Model"))
        assertEquals("a.example", received.request.getHeader("X-Tinfoil-Seal"))
        assertEquals("Bearer $KEY", received.request.getHeader("Authorization"))
        assertEquals("web_search", received.request.getHeader("X-Tinfoil-Events"))
        assertFalse(received.wire.containsText(prompt), "the prompt was sent in the clear")
        val text = received.text!!
        assertTrue(text.contains(prompt) && Regex(""","cache_salt":"[A-Za-z0-9_-]{43}"}$""").containsMatchIn(text), text)
        assertFalse(text.contains("user_cache_secret"))
        assertEquals(64, received.request.getHeader("X-Tinfoil-Cache-Prefix")!!.length)
        assertEquals("GatewayOpenAIClient(baseUrl=${gateway.baseUrl})", client.toString())
    }

    @Test
    fun anAsyncCompletionAndAStreamedOneAreOpenedAsTheyArrive() = test {
        gateway.serve("a-model" to ("tinfoilsh/a-model" to listOf("a.example", "b.example")))
        val client = client()
        gateway.answer = { it.reply(completionJson("async")) }
        assertEquals("async", client.openAIAsync.chat().completions().create(params()).await().choices().single().message().content().get())

        val events = chunk("one") + chunk("two") + chunk("three") + "data: [DONE]\n\n"
        gateway.answer = { it.reply(events, pieces = 7).setHeader("Content-Type", "text/event-stream") }
        val chunks = client.openAIAsync.chat().completions().createStreaming(params()).asFlow().toList()
        assertEquals(listOf("one", "two", "three"), texts(chunks))
        client.openAI.chat().completions().createStreaming(params()).use { stream ->
            assertEquals(listOf("one", "two", "three"), texts(stream.stream().toList()))
        }
        assertEquals(3, gateway.received.count { it.sealed })
        // One conversation, one replica.
        assertEquals(1, gateway.received.map { it.request.getHeader("X-Tinfoil-Seal") }.toSet().size)
    }

    @Test
    fun anUploadIsRoutedByItsModelFieldAndSealed() = test {
        gateway.serve("whisper" to ("tinfoilsh/whisper" to listOf("a.example")))
        gateway.answer = { it.reply("""{"text":"transcribed"}""") }
        val client = client()
        val audio = "audio-bytes-that-must-not-be-seen-on-the-wire"
        val params = TranscriptionCreateParams.builder().model("whisper").file(audio.toByteArray()).build()

        val answer = client.openAI.audio().transcriptions().create(params)

        assertEquals("transcribed", answer.asTranscription().text())
        val received = gateway.received.single()
        assertEquals("whisper", received.request.getHeader("X-Tinfoil-Model"))
        assertTrue(received.sealed)
        assertFalse(received.wire.containsText(audio))
        assertTrue(received.text!!.contains(audio))
    }

    @Test
    fun aRequestsOwnCacheSecretScopesItAndIsNotSent() = test {
        gateway.serve("a-model" to ("tinfoilsh/a-model" to listOf("a.example")))
        gateway.answer = { it.reply(completionJson("ok")) }
        val client = client(userCacheSecret = "the-clients-secret-0123456789")
        val own = "the-end-users-own-secret-0123456789"
        val scoped = params().toBuilder().putAdditionalBodyProperty("user_cache_secret", JsonValue.from(own)).build()

        client.openAI.chat().completions().create(scoped)
        client.openAI.chat().completions().create(params())

        val salts = gateway.received.map { Regex("\"cache_salt\":\"([A-Za-z0-9_-]{43})\"").find(it.text!!)!!.groupValues[1] }
        assertEquals(2, salts.toSet().size)
        for (received in gateway.received) {
            val everything = received.wire + received.plaintext!! + received.request.headers.toString().toByteArray()
            assertFalse(everything.containsText(own))
            assertFalse(everything.containsText("the-clients-secret-0123456789"))
            assertFalse(everything.containsText("user_cache_secret"))
        }
    }

    @Test
    fun failuresOfTheGatewayClientReachTheCallerWithTheirCategoryAndAreNotSentAgain() = test {
        gateway.serve("a-model" to ("tinfoilsh/a-model" to listOf("a.example")), "pinned" to ("tinfoilsh/other" to listOf("a.example")))
        val client = client(modelPins = mapOf("pinned" to ModelPin("tinfoilsh/pinned")))

        val unknown = assertFailsWith<OpenAIException> { client.openAI.chat().completions().create(params(model = "unknown")) }
        assertIs<ConfigurationException>(unknown.tinfoilException)
        val moved = assertFailsWith<OpenAIException> { client.openAI.chat().completions().create(params(model = "pinned")) }
        assertIs<AttestationException>(moved.tinfoilException)
        // A request that names no model, as a listing of models does not.
        val unnamed = assertFailsWith<OpenAIException> { client.openAI.models().list() }
        assertIs<ConfigurationException>(unnamed.tinfoilException)
        assertEquals(0, gateway.received.size)
        assertEquals(emptyList(), gateway.attestationFetches)

        gateway.endorse = { _, _ -> gateway.refuse() }
        val untrusted = assertFailsWith<OpenAIException> { client.openAI.chat().completions().create(params()) }
        assertIs<AttestationException>(untrusted.tinfoilException)
        assertEquals(2, gateway.attestationFetches.size, "the OpenAI SDK did not send the request again")
    }

    @Test
    fun optionsAreCheckedBeforeAnyIoAndACatalogThatCannotBeFetchedFailsTheCreation() = test {
        assertFailsWith<ConfigurationException> { client(apiKey = "") }
        assertFailsWith<ConfigurationException> { client(pinnedModelsOnly = true) }
        assertFailsWith<ConfigurationException> { client(baseUrl = "http://${gateway.host}/v1/") }
        assertFailsWith<ConfigurationException> { client(baseUrl = "") }
        assertFailsWith<ConfigurationException> { client(userCacheSecret = "") }
        assertEquals(0, gateway.server.requestCount)
        gateway.catalog = { MockResponse().setResponseCode(500) }
        assertFailsWith<NetworkException> { client() }
    }

    @Test
    fun aClosedClientRefusesRequests() = test {
        gateway.serve("a-model" to ("tinfoilsh/a-model" to listOf("a.example")))
        val client = client()
        client.close()
        client.close()
        val error = assertFailsWith<OpenAIException> { client.openAI.chat().completions().create(params()) }
        assertIs<ConfigurationException>(error.tinfoilException)
        assertFailsWith<ConfigurationException> { client.httpClient.models() }
    }

    private companion object {
        const val KEY = "an-api-key-0123456789abcdef"

        fun completionJson(text: String): String =
            """{"id":"c1","object":"chat.completion","created":1,"model":"a-model","choices":[{"index":0,""" +
                """"finish_reason":"stop","logprobs":null,"message":{"role":"assistant","content":"$text","refusal":null}}]}"""
    }
}
