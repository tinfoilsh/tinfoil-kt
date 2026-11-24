@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.MockWebServer
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.RouterDiscovery
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.standInVerifiers
import sh.tinfoil.testing.TestGateway
import sh.tinfoil.testing.httpsServer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The options blocks of the HTTP clients' `create` functions: each runs
 * once, on the calling thread, before anything is contacted, and the client
 * is made from copies of what it set.
 */
class OptionsTest {
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

    private val trust = Trust.RepoPin("tinfoilsh/example")

    /** Internals under which the test enclave is the router that is chosen when a relay is used. */
    private fun routerInternals() = Internals(
        http = HttpSettings(trust = enclave.authority.trust),
        clock = enclave.clock,
        retryDelay = 1.milliseconds,
        discovery = RouterDiscovery.Settings(listUrl = listServer.url("/routers"), fallback = enclave.host),
        newVerifier = standInVerifiers(enclave.verifier, enclave.verifierRequests),
    )

    private fun EnclaveOptions.forTheTestEnclave() {
        fetchAttestation = enclave.relayFetcher
    }

    private fun RouterOptions.forTheTestEnclave() {
        fetchAttestation = enclave.relayFetcher
    }

    private fun GatewayOptions.forTheTestGateway() {
        modelPins = TestGateway.PINS
        url = gateway.baseUrl
    }

    private fun assertNoIo() {
        assertEquals(0, enclave.fetches, "attestation fetches")
        assertEquals(0, enclave.verifier.verifications.get(), "verifications")
        assertEquals(0, enclave.verifier.pinChecks.get(), "checks of a pin")
        assertEquals(0, enclave.server.requestCount + listServer.requestCount, "requests")
        assertEquals(0, gateway.server.requestCount, "requests to the gateway")
        assertEquals(0, gateway.verifier.verifications.get(), "verifications of replicas")
    }

    /**
     * Every `create`, with a block that does [inBlock] and then sets what
     * the test servers need.
     */
    private fun creations(inBlock: () -> Unit): List<Pair<String, suspend () -> AutoCloseable>> = listOf(
        "EnclaveHttpClient" to {
            EnclaveHttpClient.create(enclave.host, trust, enclave.internals()) {
                inBlock()
                forTheTestEnclave()
            }
        },
        "RouterHttpClient" to {
            RouterHttpClient.create(routerInternals()) {
                inBlock()
                forTheTestEnclave()
            }
        },
        "GatewayHttpClient" to {
            GatewayHttpClient.create(gateway.internals()) {
                inBlock()
                forTheTestGateway()
            }
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
                ioBefore = enclave.fetches + enclave.verifier.pinChecks.get() + gateway.server.requestCount
            }.single { it.first == name }.second
            val ioAtStart = enclave.fetches + enclave.verifier.pinChecks.get() + gateway.server.requestCount

            closeables += create()

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
    fun theCollectionsThatTheBlockSetAreCopiedWhenItReturns() {
        val pins = mutableMapOf("a-model" to ModelPin("tinfoilsh/a-model"))

        val gatewaySettings = gatewaySettings { modelPins = pins }
        pins.clear()

        assertEquals(setOf("a-model"), gatewaySettings.modelPins.keys)
    }

    @Test
    fun aBlockThatSetsNothingLeavesEveryOptionAtItsDefault() {
        for (settings in listOf(enclaveSettings { }, routerSettings { })) {
            assertEquals(Transport.Tls, settings.transport)
            assertNull(settings.fetchAttestation)
            assertNull(settings.fetchRouterList)
            assertEquals(Policy(), settings.policy)
            assertNull(settings.userCacheSecret)
            assertNull(settings.verificationCheck)
            assertNull(settings.onVerificationAttempt)
        }
        for (settings in listOf(gatewaySettings { })) {
            assertEquals(emptyMap(), settings.modelPins)
            assertNull(settings.url)
            assertEquals(Policy(), settings.policy)
            assertNull(settings.userCacheSecret)
            assertNull(settings.verificationCheck)
            assertNull(settings.onVerificationAttempt)
            assertNull(settings.catalog)
        }
    }

    // Scopes. A block that is nested in another sets only its own options;
    // the tests of the OpenAI clients, which nest one, show it.

    @Test
    fun everyOptionsTypeIsMarkedSoThatANestedBlockSetsOnlyItsOwnOptions() {
        val types = listOf(
            EnclaveOptions::class.java, RouterOptions::class.java, GatewayOptions::class.java,
        )
        for (type in types) {
            val marked = generateSequence<Class<*>>(type) { it.superclass }.flatMap { sequenceOf(it) + it.interfaces }
            assertTrue(marked.any { it.isAnnotationPresent(TinfoilOptionsDsl::class.java) }, type.name)
        }
    }
}
