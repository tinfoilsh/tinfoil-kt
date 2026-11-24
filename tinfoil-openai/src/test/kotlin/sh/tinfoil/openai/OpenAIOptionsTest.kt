@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.openai

import com.openai.core.ClientOptions
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.EnclaveOptions
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayOptions
import sh.tinfoil.RouterOptions
import sh.tinfoil.TinfoilOptionsDsl
import sh.tinfoil.Transport
import sh.tinfoil.Trust
import sh.tinfoil.openai.internal.ApiPath
import sh.tinfoil.openai.internal.TinfoilEvents
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.TestGateway
import sh.tinfoil.testing.httpsServer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The options of [Client]: its block runs once, on the calling thread, and
 * the client is made from copies of what it set; the API path is checked and
 * joined under the HTTP client's base URL.
 */
class OpenAIOptionsTest {
    private val enclave = TestEnclave()
    private val gateway = TestGateway()
    private val closeables = CopyOnWriteArrayList<AutoCloseable>()

    /** Where a router list would be fetched from, if one were. */
    private val listServer: MockWebServer = httpsServer(enclave.authority.issue()).also { server ->
        closeables += AutoCloseable { server.shutdown() }
    }

    @AfterTest
    fun shutDown() {
        closeables.reversed().forEach { it.close() }
        gateway.close()
        enclave.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    private suspend fun enclaveHttp(transport: Transport = Transport.Tls): EnclaveHttpClient =
        enclave.connections().enclave(enclave.host, Trust.RepoPin("tinfoilsh/example")) {
            this.transport = transport
            fetchAttestation = enclave.relayFetcher
        }.also { closeables += it }

    private fun completion(): MockResponse = MockResponse().setHeader("Content-Type", "application/json").setBody(COMPLETION)

    private fun params(): ChatCompletionCreateParams =
        ChatCompletionCreateParams.builder().model("a-model").addUserMessage("hello").build()

    @Test
    fun theBlockRunsExactlyOnceOnTheCallingThreadAndTheClientDoesNoIo() = test {
        val http = enclaveHttp()
        val io = enclave.fetches + enclave.server.requestCount
        val caller = Thread.currentThread()
        val runs = AtomicInteger()
        val threads = CopyOnWriteArrayList<Thread>()

        closeables += Client.create(http, KEY) {
            runs.incrementAndGet()
            threads += Thread.currentThread()
        }

        assertEquals(1, runs.get())
        assertEquals(listOf(caller), threads.toList())
        assertEquals(io, enclave.fetches + enclave.server.requestCount, "the OpenAI client is made without any I/O")
    }

    @Test
    fun whatTheBlockThrowsIsThrownAsItIsAndNothingIsContacted() = test {
        val thrown = IllegalStateException("from the caller's block")
        val http = enclaveHttp()

        assertSame(thrown, assertFailsWith<IllegalStateException> { Client.create(http, KEY) { throw thrown } })
        assertSame(
            thrown,
            assertFailsWith<IllegalStateException> {
                Client.create(KEY, { enclave.routerConnections(listServer.url("/routers")).router() }) { throw thrown }
            },
        )

        assertEquals(0, listServer.requestCount, "the drop-in client discovered nothing")
    }

    @Test
    fun aClientIsMadeFromWhatTheBlockSetAndNotFromWhatIsSetLater() = test {
        var leaked: OpenAIOptions? = null
        val events = mutableSetOf<TinfoilEvent>()
        val client = Client.create(enclaveHttp(), KEY) {
            tinfoilEvents = events
            openAI { maxRetries(0) }
            leaked = this
        }
        closeables += client

        val options = assertNotNull(leaked)
        events += TinfoilEvent.WEB_SEARCH
        options.apiPath = "/elsewhere/"
        options.tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH)
        options.openAI { putHeader("X-Set-Too-Late", "1") }

        enclave.server.enqueue(completion())
        client.openAI.chat().completions().create(params())
        val request = enclave.server.takeRequest()
        assertEquals("/v1/chat/completions", request.path)
        assertNull(request.getHeader(TinfoilEvents.HEADER))
        assertNull(request.getHeader("X-Set-Too-Late"))
    }

    @Test
    fun theCollectionsThatTheBlockSetAreCopiedWhenItReturns() {
        val events = mutableSetOf(TinfoilEvent.WEB_SEARCH)
        val order = ArrayList<String>()

        val settings = openAISettings {
            tinfoilEvents = events
            openAI { order += "first" }
            openAI { order += "second" }
        }
        events.clear()

        assertEquals(setOf(TinfoilEvent.WEB_SEARCH), settings.tinfoilEvents)
        assertEquals(emptyList(), order, "a block for the OpenAI options is kept, and does not run with the block around it")
        val builder = ClientOptions.builder()
        settings.configure.forEach { it(builder) }
        assertEquals(listOf("first", "second"), order)
    }

    @Test
    fun aBlockThatSetsNothingLeavesEveryOptionAtItsDefault() {
        val settings = openAISettings { }
        assertNull(settings.apiPath)
        assertEquals(emptySet(), settings.tinfoilEvents)
        assertEquals(emptyList(), settings.configure)
    }

    // Scopes. Inside `openAI { }`, an option of the block around it does not
    // compile unless its receiver is named: `apiPath = ...` there is an
    // error, which no test can show by running.

    @Test
    fun everyOptionsTypeIsMarkedSoThatANestedBlockSetsOnlyItsOwnOptions() {
        val types = listOf(EnclaveOptions::class.java, RouterOptions::class.java, GatewayOptions::class.java, OpenAIOptions::class.java)
        for (type in types) {
            assertTrue(type.isAnnotationPresent(TinfoilOptionsDsl::class.java), type.name)
        }
    }

    @Test
    fun anOuterOptionIsSetFromANestedBlockOnlyByNamingItsReceiver() {
        val ran = AtomicInteger()
        var outer: OpenAIOptions? = null
        val settings = openAISettings {
            outer = this
            openAI {
                // The receiver here is the OpenAI SDK's builder alone.
                maxRetries(0)
                outer!!.apiPath = "/set/by/name/"
                ran.incrementAndGet()
            }
        }

        assertNull(settings.apiPath, "the nested block has not run when the options are copied")
        settings.configure.forEach { it(ClientOptions.builder()) }
        assertEquals(1, ran.get())
        assertNull(settings.apiPath, "and what it sets on the outer options later reaches no client")
    }

    // The API path.

    @Test
    fun theApiPathIsJoinedUnderTheEnclavesOriginOrTheProxy() = test {
        val direct = enclaveHttp()
        assertEquals("https://${enclave.host}/v1/", ApiPath.baseUrl(direct, null).toString())
        assertEquals("https://${enclave.host}/openai/v1/", ApiPath.baseUrl(direct, "/openai/v1").toString())
        assertEquals("https://${enclave.host}/openai/v1/", ApiPath.baseUrl(direct, "/openai/v1/").toString())
        assertEquals("https://${enclave.host}/", ApiPath.baseUrl(direct, "/").toString())

        enclave.endorsedHpke = { sh.tinfoil.testing.SealingKey().publicKey }
        for (proxy in listOf("https://proxy.example/relay", "https://proxy.example/relay/")) {
            val proxied = enclaveHttp(Transport.Ehbp(proxy))
            assertEquals("https://proxy.example/relay/v1/", ApiPath.baseUrl(proxied, null).toString(), proxy)
            assertEquals("https://proxy.example/relay/openai/v1/", ApiPath.baseUrl(proxied, "/openai/v1").toString(), proxy)
        }
        // A proxy whose path ends in an empty segment keeps it: only the
        // one slash that the join adds is removed.
        val doubled = enclaveHttp(Transport.Ehbp("https://proxy.example/relay//"))
        assertEquals("https://proxy.example/relay//v1/", ApiPath.baseUrl(doubled, null).toString())
    }

    @Test
    fun theOpenAiClientSendsUnderItsApiPath() = test {
        val client = Client.create(enclaveHttp(), KEY) { apiPath = "/openai/v1" }
        closeables += client
        enclave.server.enqueue(completion())

        client.openAI.chat().completions().create(params())

        assertEquals("https://${enclave.host}/openai/v1/", client.baseUrl.toString())
        assertEquals("/openai/v1/chat/completions", enclave.server.takeRequest().path)
    }

    @Test
    fun anApiPathThatIsNotAnAbsolutePathOfPathCharactersIsRefused() = test {
        val http = enclaveHttp()
        val refused = listOf(
            "", "v1/", "//v1/", "https://elsewhere.example/v1/", "/v1?x=1", "/v1/?", "/v1#x", "/v1/#",
            "/v1/%2F/", "/v1/%2f", "/v1/%5C/", "/v1/%5c", "/v1/../admin/", "/v1/./", "/..", "/v1/%2e%2e/", "/%2E/",
            "/.%2e/", "/v1\\admin/", "/v 1/", "/v1\t/", "/v1\n/", "/v1/\u0000", "/vé/", "/[v1]/", "/v1^/", "/v1|/",
            "/v1/%", "/v1/%g0/", "/v1/%0", "/{v1}/", "/v1\"/", "/<v1>/", "/`v1`/",
        )
        for (path in refused) {
            val error = assertFailsWith<ConfigurationException>(path) { Client.create(http, KEY) { apiPath = path } }
            assertTrue(error.detail.startsWith("invalid apiPath"), "$path: ${error.detail}")
        }
        val accepted = listOf("/", "/v1", "/v1/", "/%ff/", "/a-b._~!$&'()*+,;=:@/", "/v1/.well/", "/...")
        for (path in accepted) {
            assertEquals(path, ApiPath.check(path))
        }
    }

    @Test
    fun anEmptyApiPathIsRefusedWithEveryClientAndSendsNothing() = test {
        gateway.serve("a-model" to ("tinfoilsh/a-model" to listOf("a.example")))
        for (http in listOf(enclaveHttp(), gateway.client())) {
            val sent = enclave.server.requestCount + gateway.server.requestCount
            val error = assertFailsWith<ConfigurationException>("$http") { Client.create(http, KEY) { apiPath = "" } }
            assertTrue(error.detail.startsWith("invalid apiPath"), error.detail)
            assertEquals(sent, enclave.server.requestCount + gateway.server.requestCount, "$http")
        }
    }

    @Test
    fun aGatewayClientsApiPathJoinsUnderItsUrl() = test {
        gateway.serve("a-model" to ("tinfoilsh/a-model" to listOf("a.example")))
        val http = gateway.client()
        val client = Client.create(http, KEY)
        closeables += client
        val other = Client.create(http, KEY) { apiPath = "/openai/v1" }
        closeables += other

        assertEquals("${gateway.baseUrl}v1/", client.baseUrl.toString())
        assertEquals("${gateway.baseUrl}openai/v1/", other.baseUrl.toString())
    }

    @Test
    fun tinfoilsGatewayKeepsItsApiUnderV1() {
        val http = gateway.unverified(baseUrl = null)
        assertEquals("https://inference-gateway.tinfoil.sh/v1/", ApiPath.baseUrl(http, null).toString())
    }

    @Test
    fun aBaseUrlInTheOpenAiOptionsOrItsEnvironmentHasNoEffect() = test {
        val client = Client.create(enclaveHttp(), KEY) {
            openAI {
                baseUrl("https://elsewhere.invalid/v1/")
                fromEnv()
            }
        }
        closeables += client
        enclave.server.enqueue(completion())

        client.openAI.chat().completions().create(params())

        assertEquals("https://${enclave.host}/v1/", client.baseUrl.toString())
        assertEquals("/v1/chat/completions", enclave.server.takeRequest().path)
    }

    private companion object {
        const val KEY = "an-api-key-0123456789abcdef"

        const val COMPLETION =
            """{"id":"c1","object":"chat.completion","created":1,"model":"a-model","choices":[{"index":0,""" +
                """"finish_reason":"stop","logprobs":null,"message":{"role":"assistant","content":"hi","refusal":null}}]}"""
    }
}
