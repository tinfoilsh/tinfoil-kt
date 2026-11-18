package sh.tinfoil.internal.transport

import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockWebServer
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.TransportMode
import sh.tinfoil.testing.SealingDispatcher
import sh.tinfoil.testing.SealingKey
import sh.tinfoil.testing.TestAuthority
import sh.tinfoil.testing.containsText
import sh.tinfoil.testing.fingerprint
import sh.tinfoil.testing.httpsServer
import sh.tinfoil.testing.verification
import java.io.IOException
import java.time.Instant
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EhbpSealingTest {
    private val authority = TestAuthority()
    private val key = SealingKey()
    private val sealing = SealingDispatcher({ key })
    private val servers = mutableListOf<MockWebServer>()
    private val protocols = mutableListOf<EhbpSealing>()

    @AfterTest
    fun shutDown() {
        protocols.forEach { it.close() }
        servers.forEach { it.shutdown() }
    }

    private fun cleartextServer(): MockWebServer = MockWebServer().also {
        it.dispatcher = sealing
        it.start()
        servers += it
    }

    private fun tlsServer(): MockWebServer = httpsServer(authority.issue()).also {
        it.dispatcher = sealing
        servers += it
    }

    private fun protocol(cleartext: Boolean, enclaveUrl: String? = null): EhbpSealing =
        EhbpSealing(cleartext, enclaveUrl, HttpSettings(authority.trust)).also { protocols += it }

    private fun bind(cleartext: Boolean, hpke: String? = key.publicKey, enclaveUrl: String? = null): EhbpTransport =
        protocol(cleartext, enclaveUrl).bind(verification(authority.fingerprint, Instant.MAX, hpkePublicKey = hpke))

    private fun post(url: String) = Request.Builder().url(url).post("""{"q":"$MARKER"}""".toRequestBody()).build()

    @Test
    fun theKeyIsTheAttestedOneAndNothingElseWillDo() {
        assertEquals(TransportMode.Ehbp, protocol(cleartext = false).mode)
        assertEquals(key.publicKey, EhbpSealing.identityOf(key.publicKey).marshalPublicKeyHex())
        val refused = listOf(
            null, "", "ab", "ab".repeat(31), "ab".repeat(33), "AB".repeat(32), "g".repeat(64), "ab".repeat(32) + "\n",
        )
        for (hpke in refused) {
            assertFailsWith<AttestationException>("$hpke") { EhbpSealing.identityOf(hpke) }
            assertFailsWith<AttestationException>("$hpke") { bind(cleartext = false, hpke = hpke) }
        }
    }

    @Test
    fun aTransportThatIsNotForCleartextNeverUsesIt() {
        val server = cleartextServer()
        val transport = bind(cleartext = false)

        assertFailsWith<IOException> { transport.newCall(post("http://localhost:${server.port}/")).execute() }
        assertFailsWith<IOException> {
            transport.newCall(Request.Builder().url("http://localhost:${server.port}/").build()).execute()
        }

        assertEquals(0, server.requestCount)
    }

    @Test
    fun aTransportForCleartextNeverUsesTls() {
        val server = tlsServer()
        val transport = bind(cleartext = true)

        assertFailsWith<IOException> { transport.newCall(post("https://localhost:${server.port}/")).execute() }

        assertEquals(0, server.requestCount)
    }

    @Test
    fun aRequestIsSealedToTheBoundKeyAndCarriesTheEnclaveUrlOnlyForAProxy() {
        val server = tlsServer()
        val url = "https://localhost:${server.port}/v1/echo"

        bind(cleartext = false).newCall(post(url)).execute().use { assertEquals("ok", it.body!!.string()) }
        bind(cleartext = false, enclaveUrl = "https://enclave.example").newCall(post(url)).execute().close()

        val (direct, proxied) = sealing.received
        assertTrue(direct.sealed && proxied.sealed)
        assertFalse(direct.wire.containsText(MARKER) || proxied.wire.containsText(MARKER))
        assertNull(direct.request.getHeader(EhbpSealing.ENCLAVE_URL_HEADER))
        assertEquals("https://enclave.example", proxied.request.getHeader(EhbpSealing.ENCLAVE_URL_HEADER))
    }

    @Test
    fun onlyAKeyConfigurationProblemIsAKeyRejection() {
        val server = tlsServer()
        val stranger = SealingKey()
        val transport = bind(cleartext = false, hpke = stranger.publicKey)

        val rejection = assertFailsWith<IOException> { transport.newCall(post("https://localhost:${server.port}/")).execute() }

        assertEquals("the enclave does not hold the attested HPKE key", transport.keyRejection(rejection))
        assertNull(transport.keyRejection(IOException("connection reset")))
        assertNull(transport.keyRejection(IOException("KEY_CONFIG_MISMATCH: said a message, not the protocol")))
    }

    @Test
    fun aClosedProtocolRefusesCallsAndARetiredTransportKeepsNoConnections() {
        val server = tlsServer()
        val protocol = protocol(cleartext = false)
        val transport = protocol.bind(verification(authority.fingerprint, Instant.MAX, hpkePublicKey = key.publicKey))
        val url = "https://localhost:${server.port}/"

        transport.newCall(post(url)).execute().close()
        assertEquals(1, transport.connectionCount)
        transport.retire()
        assertEquals(0, transport.connectionCount)
        transport.newCall(post(url)).execute().close()
        assertEquals(0, transport.connectionCount, "a retired transport closes a connection once its request is over")

        protocol.close()
        assertFailsWith<ConfigurationException> { transport.newCall(post(url)) }
    }

    private companion object {
        const val MARKER = "plaintext-marker-41c0aa"
    }
}
