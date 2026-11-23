package sh.tinfoil

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import sh.tinfoil.testing.TestEnclave
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The attestation and router-list relays, and the enclave client's use of a fetcher. */
class FetchersTest {
    private val enclave = TestEnclave()
    private val nonce = ByteArray(32) { it.toByte() }
    private val hex = nonce.joinToString("") { "%02x".format(it) }

    @AfterTest
    fun shutDown() {
        enclave.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    @Test
    fun aRelaysPathsJoinUnderItsUrlWithOrWithoutATrailingSlash() {
        for (url in listOf("https://app.example/tinfoil", "https://app.example/tinfoil/")) {
            assertEquals(
                "https://app.example/tinfoil/.well-known/tinfoil-attestation?nonce=$hex&enclave=enclave.example",
                AttestationRelay(url).documentUrl("enclave.example", nonce).toString(),
                url,
            )
            assertEquals("https://app.example/tinfoil/routers", RouterListRelay(url).listUrl.toString(), url)
        }
        assertEquals(
            "https://app.example/.well-known/tinfoil-attestation?nonce=$hex&enclave=enclave.example",
            AttestationRelay("https://app.example").documentUrl("enclave.example", nonce).toString(),
        )
        assertEquals("https://app.example/routers", RouterListRelay("https://app.example").listUrl.toString())
        assertEquals(
            "https://app.example:8443/a/b/.well-known/tinfoil-attestation?nonce=$hex&enclave=enclave.example%3A8443",
            AttestationRelay("https://app.example:8443/a/b").documentUrl("enclave.example:8443", nonce).toString(),
            "the enclave's host and port are one encoded query value",
        )
        assertEquals("http://localhost:8080/tinfoil/routers", RouterListRelay("http://localhost:8080/tinfoil").listUrl.toString())
        assertEquals(AttestationRelay("https://app.example/x/"), AttestationRelay("https://app.example/x"))
    }

    @Test
    fun aRelayUrlThatBreaksTheRulesForRouteUrlsIsRefusedWhenTheRelayIsMade() {
        val refused = listOf(
            "", "/tinfoil", "app.example/tinfoil", "ftp://app.example/", "http://app.example/tinfoil",
            "http://app.localhost/", "http://0.0.0.0:8080/", "https://user:hunter2@app.example/", "https://@app.example/",
            "https://app.example/?hunter2", "https://app.example/?", "https://app.example/#hunter2", "https://app.example/#",
        )
        for (url in refused) {
            for (make in listOf<(String) -> Any>(::AttestationRelay, ::RouterListRelay)) {
                val error = assertFailsWith<ConfigurationException>(url) { make(url) }
                assertFalse(error.toString().contains("hunter2"), "$url: $error")
            }
        }
        for (url in listOf("http://localhost:8080/tinfoil", "http://127.0.0.1:8080/", "http://[::1]:8080/", "https://app.example")) {
            AttestationRelay(url)
            RouterListRelay(url)
        }
    }

    @Test
    fun aRelayOnThisMachineIsReachedOverHttp() = test {
        val relay = MockWebServer().apply { start() }
        try {
            relay.enqueue(MockResponse().setBody("the document"))
            relay.enqueue(MockResponse().setBody("""["a.example", 1, "b.example"]"""))
            val url = "http://localhost:${relay.port}/tinfoil"

            assertContentEquals("the document".toByteArray(), AttestationRelay(url).fetchAttestation("enclave.example", nonce))
            assertEquals(listOf("a.example", "b.example"), RouterListRelay(url).fetchRouterList())

            val attestation = relay.takeRequest()
            assertEquals("/tinfoil/.well-known/tinfoil-attestation?nonce=$hex&enclave=enclave.example", attestation.path)
            assertEquals("tinfoil-kt", attestation.getHeader("Tinfoil-SDK"))
            assertEquals("/tinfoil/routers", relay.takeRequest().path)
        } finally {
            relay.shutdown()
        }
    }

    @Test
    fun aRelaysErrorStatusIsANetworkFailure() = test {
        val relay = MockWebServer().apply { start() }
        try {
            relay.enqueue(MockResponse().setResponseCode(502))
            val error = assertFailsWith<NetworkException> {
                AttestationRelay("http://localhost:${relay.port}/").fetchAttestation("enclave.example", nonce)
            }
            assertEquals(502, error.status)
        } finally {
            relay.shutdown()
        }
    }

    @Test
    fun anEnclaveClientObtainsEveryDocumentFromItsFetcher() = test {
        val asked = CopyOnWriteArrayList<String>()
        val client = enclave.client(fetchAttestation = { host, nonce ->
            asked += host
            assertEquals(32, nonce.size)
            "a document".toByteArray()
        })

        client.reverify()
        enclave.clock.advance(enclave.lifetimeSeconds)
        client.ensureVerified()

        assertEquals(listOf(enclave.host, enclave.host, enclave.host), asked.toList())
        assertEquals(0, enclave.fetches, "nothing was fetched through any other way")
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aFetchersFailureIsTriedOnceMoreAndAConfigurationErrorIsNot() = test {
        val calls = CopyOnWriteArrayList<String>()
        assertFailsWith<NetworkException> {
            enclave.client(fetchAttestation = { _, _ -> calls += "network"; throw java.io.IOException("down") })
        }
        assertFailsWith<ConfigurationException> {
            enclave.client(fetchAttestation = { _, _ -> calls += "configuration"; throw ConfigurationException("no") })
        }
        assertEquals(listOf("network", "network", "configuration"), calls.toList())
        assertTrue(enclave.server.requestCount == 0)
    }
}
