@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.openai

import com.openai.core.ClientOptions
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import sh.tinfoil.Client
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EnclaveOpenAIOptions
import sh.tinfoil.EnclaveOptions
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayOpenAIOptions
import sh.tinfoil.GatewayOptions
import sh.tinfoil.ModelPin
import sh.tinfoil.OpenAIOptions
import sh.tinfoil.Pin
import sh.tinfoil.RouterOpenAIOptions
import sh.tinfoil.RouterOptions
import sh.tinfoil.TinfoilEvent
import sh.tinfoil.TinfoilOptionsDsl
import sh.tinfoil.TransportMode
import sh.tinfoil.VerificationCheck
import sh.tinfoil.enclaveOpenAISettings
import sh.tinfoil.gatewayOpenAISettings
import sh.tinfoil.internal.TinfoilEvents
import sh.tinfoil.openAISettings
import sh.tinfoil.routerOpenAISettings
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.TestGateway
import sh.tinfoil.testing.awaitUntil
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
 * The options blocks of the OpenAI clients' `create` functions: each runs
 * once, on the calling thread, before anything is contacted, and the client
 * is made from copies of what it set.
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

    private val pin = Pin(repo = "tinfoilsh/example")

    /** Makes a router client for which the test enclave is the router that is chosen when a relay is used. */
    private fun routerConnection() = enclave.routerConnections(listServer.url("/routers"))::router

    private fun EnclaveOptions.forTheTestEnclave() {
        attestationRelay = enclave.relayHost
        verifier = enclave.appraisingVerifier()
    }

    private fun RouterOptions.forTheTestEnclave() {
        attestationRelay = enclave.relayHost
        verifier = enclave.appraisingVerifier()
    }

    private fun GatewayOptions.forTheTestGateway() {
        baseUrl = gateway.baseUrl
        verifier = gateway.appraisingVerifier()
    }

    private fun assertNoIo() {
        assertEquals(0, enclave.fetches, "attestation fetches")
        assertEquals(0, enclave.verifications, "verifications")
        assertEquals(0, enclave.pinChecks, "checks of a pin")
        assertEquals(0, enclave.server.requestCount + listServer.requestCount, "requests")
        assertEquals(0, gateway.server.requestCount, "requests to the gateway")
        assertEquals(0, gateway.verifications, "verifications of replicas")
    }

    /**
     * Every `create`, with a block that does [inBlock] and then sets what
     * the test servers need. The API key is one that is refused once the
     * block has run, for the client that cannot be pointed at a test server.
     */
    private fun creations(inBlock: () -> Unit): List<Pair<String, suspend () -> AutoCloseable>> = listOf(
        "EnclaveOpenAIClient" to {
            EnclaveOpenAIClient.create(enclave.host, pin, KEY, enclave.connections()::enclave) {
                inBlock()
                forTheTestEnclave()
            }
        },
        "RouterOpenAIClient" to {
            RouterOpenAIClient.create(KEY, routerConnection()) {
                inBlock()
                forTheTestEnclave()
            }
        },
        "GatewayOpenAIClient" to {
            GatewayOpenAIClient.create(KEY, gateway.connections()::gateway) {
                inBlock()
                forTheTestGateway()
            }
        },
        "Client" to {
            Client.create("", enclave.appraisingVerifier(), routerConnection()) { inBlock() }
        },
    )

    @Test
    fun theBlockRunsExactlyOnceOnTheCallingThreadBeforeAnythingIsContacted() = test {
        gateway.serve("a-model" to ("tinfoilsh/a-model" to listOf("a.example")))
        val caller = Thread.currentThread()
        for (name in creations { }.map { it.first }) {
            val runs = AtomicInteger()
            val threads = CopyOnWriteArrayList<Thread>()
            var ioBefore = -1
            val create = creations {
                runs.incrementAndGet()
                threads += Thread.currentThread()
                ioBefore = enclave.fetches + enclave.pinChecks + gateway.server.requestCount
            }.single { it.first == name }.second
            val ioAtStart = enclave.fetches + enclave.pinChecks + gateway.server.requestCount

            try {
                closeables += create()
            } catch (e: ConfigurationException) {
                assertEquals("Client", name, "only the client with an empty API key is refused: ${e.detail}")
            }

            assertEquals(1, runs.get(), "runs of the block of $name")
            assertEquals(listOf(caller), threads.toList(), "the thread that ran the block of $name")
            assertEquals(ioAtStart, ioBefore, "nothing is checked or fetched before the block of $name has run")
        }
    }

    @Test
    fun whatTheBlockThrowsIsThrownAsItIsAndNothingIsContacted() = test {
        val thrown = IllegalStateException("from the caller's block")

        for ((name, create) in creations { throw thrown }) {
            val error = assertFailsWith<IllegalStateException>(name) { create().close() }
            assertSame(thrown, error, name)
        }

        assertNoIo()
    }

    @Test
    fun aClientIsMadeFromWhatTheBlockSetAndNotFromWhatIsSetLater() = test {
        var leaked: EnclaveOpenAIOptions? = null
        val events = mutableSetOf<TinfoilEvent>()
        val results = AtomicInteger()
        val client = EnclaveOpenAIClient.create(enclave.host, pin, KEY, enclave.connections()::enclave) {
            forTheTestEnclave()
            tinfoilEvents = events
            onVerificationResult = { results.incrementAndGet() }
            openAI { maxRetries(0) }
            leaked = this
        }
        closeables += client

        val options = assertNotNull(leaked)
        events += TinfoilEvent.WEB_SEARCH
        options.transportMode = TransportMode.EHBP
        options.baseUrl = "https://elsewhere.invalid/v1/"
        options.attestationRelay = "relay.invalid"
        options.verifier = null
        options.userCacheSecret = "a-secret-that-was-set-too-late"
        options.verificationCheck = VerificationCheck { throw IllegalStateException("set too late") }
        options.onVerificationResult = null
        options.tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH)
        options.openAI { putHeader("X-Set-Too-Late", "1") }

        assertEquals(TransportMode.TLS, client.httpClient.transportMode)
        assertEquals("https://${enclave.host}/", client.httpClient.baseUrl.toString())
        client.httpClient.reverify()
        assertEquals(2, enclave.fetches, "the client verifies again through the relay that the block set")
        awaitUntil { results.get() == 2 }
        enclave.server.enqueue(MockResponse().setHeader("Content-Type", "application/json").setBody(COMPLETION))
        client.openAI.chat().completions().create(
            ChatCompletionCreateParams.builder().model("a-model").addUserMessage("hello").build(),
        )
        val request = enclave.server.takeRequest()
        assertEquals("/v1/chat/completions", request.path)
        assertNull(request.getHeader(TinfoilEvents.HEADER))
        assertNull(request.getHeader("X-Set-Too-Late"))
        assertTrue("user_cache_secret" !in request.body.readUtf8())
    }

    @Test
    fun theCollectionsThatTheBlockSetAreCopiedWhenItReturns() {
        val pins = mutableMapOf("a-model" to ModelPin("tinfoilsh/a-model"))
        val events = mutableSetOf(TinfoilEvent.WEB_SEARCH)
        val order = ArrayList<String>()

        val (gatewayRoute, gatewayOpenAI) = gatewayOpenAISettings {
            modelPins = pins
            tinfoilEvents = events
        }
        val openAI = openAISettings {
            tinfoilEvents = events
            openAI { order += "first" }
            openAI { order += "second" }
        }
        val (_, enclaveOpenAI) = enclaveOpenAISettings { tinfoilEvents = events }
        val (_, routerOpenAI) = routerOpenAISettings { tinfoilEvents = events }
        pins.clear()
        events.clear()

        assertEquals(setOf("a-model"), gatewayRoute.modelPins.keys)
        for (settings in listOf(gatewayOpenAI, openAI, enclaveOpenAI, routerOpenAI)) {
            assertEquals(setOf(TinfoilEvent.WEB_SEARCH), settings.tinfoilEvents)
        }
        assertEquals(emptyList(), order, "a block for the OpenAI options is kept, and does not run with the block around it")
        val builder = ClientOptions.builder()
        openAI.configure.forEach { it(builder) }
        assertEquals(listOf("first", "second"), order)
    }

    @Test
    fun aBlockThatSetsNothingLeavesEveryOptionAtItsDefault() {
        for (settings in listOf(enclaveOpenAISettings { }.first, routerOpenAISettings { }.first)) {
            assertEquals(TransportMode.TLS, settings.transportMode)
            assertNull(settings.baseUrl)
            assertNull(settings.attestationRelay)
            assertNull(settings.verifier)
            assertNull(settings.userCacheSecret)
            assertNull(settings.verificationCheck)
            assertNull(settings.onVerificationResult)
        }
        for (settings in listOf(gatewayOpenAISettings { }.first)) {
            assertEquals(emptyMap(), settings.modelPins)
            assertEquals(false, settings.pinnedModelsOnly)
            assertNull(settings.baseUrl)
            assertNull(settings.verifier)
            assertNull(settings.userCacheSecret)
            assertNull(settings.verificationCheck)
            assertNull(settings.onVerificationResult)
            assertNull(settings.catalog)
        }
        val openAI = listOf(openAISettings { }, enclaveOpenAISettings { }.second, routerOpenAISettings { }.second, gatewayOpenAISettings { }.second)
        for (settings in openAI) {
            assertEquals(emptySet(), settings.tinfoilEvents)
            assertEquals(emptyList(), settings.configure)
        }
    }

    // Scopes. Inside `openAI { }`, an option of the block around it does not
    // compile unless its receiver is named: `transportMode = ...` there is
    // an error, which no test can show by running.

    @Test
    fun everyOptionsTypeIsMarkedSoThatANestedBlockSetsOnlyItsOwnOptions() {
        val types = listOf(
            EnclaveOptions::class.java, RouterOptions::class.java, GatewayOptions::class.java, OpenAIOptions::class.java,
            EnclaveOpenAIOptions::class.java, RouterOpenAIOptions::class.java, GatewayOpenAIOptions::class.java,
        )
        for (type in types) {
            val marked = generateSequence<Class<*>>(type) { it.superclass }.flatMap { sequenceOf(it) + it.interfaces }
            assertTrue(marked.any { it.isAnnotationPresent(TinfoilOptionsDsl::class.java) }, type.name)
        }
    }

    @Test
    fun anOuterOptionIsSetFromANestedBlockOnlyByNamingItsReceiver() {
        val ran = AtomicInteger()
        var route: EnclaveOpenAIOptions? = null
        val (settings, openAI) = enclaveOpenAISettings {
            route = this
            openAI {
                // The receiver here is the OpenAI SDK's builder alone.
                maxRetries(0)
                route!!.userCacheSecret = "set-by-name"
                ran.incrementAndGet()
            }
        }

        assertNull(settings.userCacheSecret, "the nested block has not run when the options are copied")
        openAI.configure.forEach { it(ClientOptions.builder()) }
        assertEquals(1, ran.get())
        assertEquals("set-by-name", route!!.userCacheSecret)
        assertNull(settings.userCacheSecret, "and what it sets on the outer options later reaches no client")
    }

    private companion object {
        const val KEY = "an-api-key-0123456789abcdef"

        const val COMPLETION =
            """{"id":"c1","object":"chat.completion","created":1,"model":"a-model","choices":[{"index":0,""" +
                """"finish_reason":"stop","logprobs":null,"message":{"role":"assistant","content":"hi","refusal":null}}]}"""
    }
}
