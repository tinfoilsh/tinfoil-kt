package sh.tinfoil.internal.transport

import kotlinx.coroutines.runBlocking
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.TransportMode
import sh.tinfoil.testing.TestAuthority
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.fingerprint
import sh.tinfoil.testing.httpsServer
import sh.tinfoil.testing.serverHandshake
import sh.tinfoil.testing.verification
import java.io.IOException
import java.net.Proxy
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PinnedTlsTest {
    private val authority = TestAuthority()
    private val certificate = authority.issue()
    private val servers = mutableListOf<MockWebServer>()
    private val protocols = mutableListOf<PinnedTls>()

    @AfterTest
    fun shutDown() {
        protocols.forEach { it.close() }
        servers.forEach { it.shutdown() }
    }

    private fun server(): MockWebServer = httpsServer(certificate).also { servers += it }

    private fun bind(fingerprint: String?, proxy: Proxy? = null): PinnedTlsTransport {
        val protocol = PinnedTls(HttpSettings(authority.trust, proxy)).also { protocols += it }
        return protocol.bind(verification(fingerprint, Instant.MAX))
    }

    private fun MockWebServer.get(path: String = "/"): Request =
        Request.Builder().url("https://localhost:$port$path").build()

    @Test
    fun aFingerprintIsTheSha256OfTheLeafsSubjectPublicKeyInfo() {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(certificate.keyPair.public.encoded)
        val expected = digest.joinToString("") { "%02x".format(it) }

        assertEquals(expected, certificate.fingerprint)
        assertTrue(LeafKeyPin.of(expected).matches(certificate.certificate))
        assertTrue(LeafKeyPin.of(expected).matches(authority.reissue(certificate).certificate), "the key, not the certificate")
        assertFalse(LeafKeyPin.of(expected).matches(authority.issue().certificate))
        assertFalse(LeafKeyPin.of(expected).matches(null))
    }

    @Test
    fun aVerificationWithoutAUsableFingerprintBindsNothing() {
        val malformed = listOf(
            null, "", "00", certificate.fingerprint.uppercase(), certificate.fingerprint.dropLast(1),
            certificate.fingerprint + "00", "g".repeat(64), "sha256/" + certificate.fingerprint.drop(7),
        )
        for (fingerprint in malformed) {
            assertFailsWith<AttestationException>("$fingerprint") { bind(fingerprint) }
        }
    }

    @Test
    fun onlyHttpsRequestsAreAccepted() {
        val protocol = PinnedTls().also { protocols += it }

        assertEquals(TransportMode.Tls, protocol.mode)
        protocol.checkRequest(Request.Builder().url("https://enclave.example/").build())
        assertFailsWith<ConfigurationException> {
            protocol.checkRequest(Request.Builder().url("http://enclave.example/").build())
        }
    }

    @Test
    fun aCleartextRequestCannotBeSentEvenIfItIsAskedFor() = runBlocking<Unit> {
        val plain = MockWebServer().also { servers += it }
        plain.start()
        val transport = bind(certificate.fingerprint)

        assertFailsWith<IOException> {
            transport.newCall(Request.Builder().url("http://localhost:${plain.port}/").build()).await()
        }
        assertEquals(0, plain.requestCount)
    }

    @Test
    fun onlyCertificateFailuresAreKeyRejections() = runBlocking<Unit> {
        val server = server()
        val wrong = bind(authority.issue().fingerprint)
        val right = bind(certificate.fingerprint)

        val mismatch = assertFailsWith<IOException> { wrong.newCall(server.get()).await() }
        assertNotNull(wrong.keyRejection(mismatch))
        assertTrue(wrong.keyRejection(mismatch)!!.contains("does not carry the attested TLS key"))
        assertEquals(0, server.requestCount)

        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START))
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START))
        val dropped = assertFailsWith<IOException> { right.newCall(server.get()).await() }
        assertNull(right.keyRejection(dropped), "$dropped")
        assertNull(right.keyRejection(IOException("Canceled")))
        assertNull(right.keyRejection(javax.net.ssl.SSLHandshakeException("no protocol in common")))
        assertNull(right.keyRejection(java.net.ConnectException("refused")))
    }

    @Test
    fun aRetiredTransportKeepsNoConnectionsAndLetsCallsFinish() = runBlocking<Unit> {
        val server = server()
        val transport = bind(certificate.fingerprint)
        server.enqueue(MockResponse().setBody("one"))
        server.enqueue(MockResponse().setBody("x".repeat(4096)).throttleBody(1024, 200, TimeUnit.MILLISECONDS))
        server.enqueue(MockResponse().setBody("three"))

        transport.newCall(server.get()).await().use { it.body!!.string() }
        assertEquals(1, transport.connectionCount)

        val inFlight = transport.newCall(server.get()).await()
        transport.retire()
        assertEquals(4096, inFlight.use { it.body!!.string() }.length, "a call in flight finishes")
        awaitUntil { transport.connectionCount == 0 }

        assertEquals("three", transport.newCall(server.get()).await().use { it.body!!.string() })
        awaitUntil { transport.connectionCount == 0 }
    }

    @Test
    fun closingEndsTheCallsOfEveryTransportRetiredOnesIncluded() = runBlocking<Unit> {
        val server = server()
        val protocol = PinnedTls(HttpSettings(authority.trust)).also { protocols += it }
        val old = protocol.bind(verification(certificate.fingerprint, Instant.MAX))
        val current = protocol.bind(verification(certificate.fingerprint, Instant.MAX))
        repeat(2) {
            server.enqueue(MockResponse().setBody("x".repeat(1 shl 20)).throttleBody(1024, 1, TimeUnit.SECONDS))
        }

        val onOld = old.newCall(server.get()).await()
        old.retire()
        val onCurrent = current.newCall(server.get()).await()
        protocol.close()
        current.retire()

        assertFailsWith<IOException> { onOld.body!!.string() }
        assertFailsWith<IOException> { onCurrent.body!!.string() }
        assertFailsWith<ConfigurationException> { old.newCall(server.get()) }
        assertFailsWith<ConfigurationException> { current.newCall(server.get()) }
        awaitUntil { old.connectionCount == 0 && current.connectionCount == 0 }
    }

    @Test
    fun aRequestThroughAProxyTunnelIsPinnedToTheEnclavesKey() = runBlocking<Unit> {
        val proxy = MockWebServer().also { servers += it }
        proxy.useHttps(certificate.serverHandshake().sslSocketFactory(), true)
        proxy.start()
        val tunnel = MockResponse().setSocketPolicy(SocketPolicy.UPGRADE_TO_SSL_AT_END).clearHeaders()
        val request = Request.Builder().url("https://localhost:443/v1")
            .header("Authorization", "Bearer hunter2").build()

        proxy.enqueue(tunnel)
        proxy.enqueue(MockResponse().setBody("through the tunnel"))
        val right = bind(certificate.fingerprint, proxy.toProxyAddress())
        assertEquals("through the tunnel", right.newCall(request).await().use { it.body!!.string() })
        val connect = proxy.takeRequest()
        assertEquals("CONNECT", connect.method)
        assertNull(connect.getHeader("Authorization"), "the proxy sees no credentials")
        assertEquals("Bearer hunter2", proxy.takeRequest().getHeader("Authorization"))

        proxy.enqueue(tunnel)
        val wrong = bind(authority.issue().fingerprint, proxy.toProxyAddress())
        val failure = assertFailsWith<IOException> { wrong.newCall(request).await() }
        assertNotNull(wrong.keyRejection(failure))
        assertEquals("CONNECT", proxy.takeRequest().method)
        assertEquals(3, proxy.requestCount, "nothing followed the second tunnel's handshake")
    }
}
