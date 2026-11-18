package sh.tinfoil

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okio.Buffer
import okio.BufferedSink
import okio.buffer
import okio.source
import sh.tinfoil.testing.ENCAPSULATED_KEY_HEADER
import sh.tinfoil.testing.ENCLAVE_URL_HEADER
import sh.tinfoil.testing.RESPONSE_NONCE_HEADER
import sh.tinfoil.testing.RawTlsServer
import sh.tinfoil.testing.SealingDispatcher
import sh.tinfoil.testing.SealingKey
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.containsText
import sh.tinfoil.testing.fingerprint
import java.io.IOException
import java.io.InterruptedIOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket
import kotlin.experimental.xor
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The clients with [TransportMode.Ehbp]: what is sealed, what is refused and what fails closed. */
class EhbpClientTest {
    private val enclave = TestEnclave()

    /** The HPKE key that the enclave holds, and that its attestation endorses unless a test says otherwise. */
    @Volatile
    private var key = SealingKey()

    /** What the enclave's own server does with requests. */
    private val atEnclave = SealingDispatcher({ key })

    /** What a proxy in front of the enclave does with requests: it forwards them, and the enclave answers. */
    private val atProxy = SealingDispatcher({ key })

    /** A proxy on this machine, over cleartext HTTP. */
    private val proxy = MockWebServer().apply {
        dispatcher = atProxy
        start()
    }
    private val proxyUrl = "http://localhost:${proxy.port}/"

    init {
        enclave.endorsedHpke = { key.publicKey }
        enclave.server.dispatcher = atEnclave
    }

    @AfterTest
    fun shutDown() {
        enclave.close()
        proxy.shutdown()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    private suspend fun direct(userCacheSecret: String? = null): EnclaveHttpClient =
        enclave.client(transportMode = TransportMode.Ehbp, userCacheSecret = userCacheSecret)

    private suspend fun proxied(userCacheSecret: String? = null): EnclaveHttpClient =
        enclave.client(transportMode = TransportMode.Ehbp, baseUrl = proxyUrl, userCacheSecret = userCacheSecret)

    private fun EnclaveHttpClient.post(body: String, path: String = "v1/echo"): Request =
        Request.Builder().url(baseUrl.resolve(path)!!).post(body.toRequestBody(JSON)).build()

    private fun EnclaveHttpClient.get(path: String = "v1/models"): Request =
        Request.Builder().url(baseUrl.resolve(path)!!).build()

    private fun Response.text(): String = use { it.body!!.string() }

    private fun assertNoIo() {
        assertEquals(0, enclave.fetches, "attestation fetches")
        assertEquals(0, enclave.verifier.verifications.get(), "verifications")
        assertEquals(0, enclave.server.requestCount + proxy.requestCount, "requests")
    }

    /** A client that is checked but has verified nothing, so that any I/O shows. */
    private fun unverified(baseUrl: String? = proxyUrl, transportMode: TransportMode = TransportMode.Ehbp): EnclaveHttpClient =
        EnclaveHttpClient.unverified(
            enclave.host, Pin(repo = "tinfoilsh/example"), transportMode, baseUrl, enclave.relayHost,
            Verifier.appraisingWith(enclave.verifier), null, null, null, enclave.internals(),
        )

    // Options.

    @Test
    fun aProxyMustUseHttpsUnlessItIsOnThisMachine() = test {
        val refused = listOf(
            "http://proxy.example/",
            "http://proxy.example:8080/v1/",
            "http://192.168.1.10/",
            "http://10.0.0.1:8080/",
            "http://0.0.0.0/",
            "http://localhost.example/",
            "http://localhost./",
            "http://127.0.0.1.example/",
            "http://128.0.0.1/",
            "http://[::2]/",
            "http://[fe80::1]/",
            "http://${enclave.host.substringBefore(':')}.example/",
        )
        for (url in refused) {
            val error = assertFailsWith<ConfigurationException>(url) { unverified(url) }
            assertTrue(error.message!!.contains("loopback"), "$url: ${error.message}")
        }
        val accepted = listOf(
            "http://localhost/",
            "http://localhost:8080/v1/",
            "HTTP://LOCALHOST:8080/",
            "http://127.0.0.1/",
            "http://127.0.0.1:9000/",
            "http://127.8.9.10:1/",
            "http://[::1]/",
            "http://[::1]:8080/",
            "https://proxy.example/",
            "https://proxy.example:8443/v1/",
            "https://${enclave.host}/v1/",
        )
        for (url in accepted) {
            unverified(url).use { client ->
                assertEquals(TransportMode.Ehbp, client.transportMode)
                assertEquals(url.toHttpUrl(), client.baseUrl, url)
            }
        }
        assertNoIo()
    }

    @Test
    fun aProxyIsRefusedWithoutEhbpEvenOnThisMachine() = test {
        for (url in listOf(proxyUrl, "https://proxy.example/", "http://${enclave.host}/")) {
            assertFailsWith<ConfigurationException>(url) { unverified(url, TransportMode.Tls) }
        }
        assertNoIo()
    }

    @Test
    fun requestsThatTheProtocolCannotProtectOrOwnsAreRefusedBeforeAnyIo() = test {
        val client = unverified()
        val url = client.baseUrl.resolve("v1/realtime")!!
        fun request(configure: Request.Builder.() -> Unit) = Request.Builder().url(url).apply(configure).build()
        val duplex = object : RequestBody() {
            override fun contentType(): MediaType? = null
            override fun isDuplex() = true
            override fun writeTo(sink: BufferedSink) = Unit
        }
        val refused = mapOf(
            "a WebSocket upgrade" to request { header("Connection", "Upgrade").header("Upgrade", "websocket") },
            "an Upgrade header alone" to request { header("Upgrade", "h2c") },
            "an empty Upgrade header" to request { header("upgrade", "") },
            "a Connection header that asks for an upgrade" to request { header("Connection", "keep-alive, UPGRADE") },
            "a CONNECT" to request { method("CONNECT", null) },
            "a connect in lowercase" to request { method("connect", null) },
            "the encapsulated key header" to request { header("Ehbp-Encapsulated-Key", "00".repeat(32)) },
            "the response nonce header" to request { header("ehbp-response-nonce", "00".repeat(32)) },
            "another header of the protocol's" to request { header("EHBP-Anything", "x") },
            "the enclave URL header" to request { header("x-tinfoil-enclave-url", "https://evil.example") },
            "the Host header" to request { header("Host", "evil.example") },
            "a duplex body" to request { post(duplex) },
            "the enclave's own origin, past the proxy" to Request.Builder().url("https://${enclave.host}/v1/models").build(),
            "another origin" to Request.Builder().url("https://evil.example/v1/models").build(),
            "the proxy over HTTPS" to Request.Builder().url("https://localhost:${proxy.port}/").build(),
            "the proxy on another port" to Request.Builder().url("http://localhost:1/").build(),
            "credentials in the URL" to Request.Builder().url("http://user:hunter2@localhost:${proxy.port}/").build(),
        )
        for ((name, request) in refused) {
            val error = assertFailsWith<ConfigurationException>(name) { client.execute(request) }
            assertFalse(error.message!!.contains("hunter2"), name)
            assertFailsWith<ConfigurationException>(name) { client.executeRecoverable(request) }
            assertIs<ConfigurationException>(assertFailsWith<IOException>(name) { client.newCall(request).execute() }, name)
        }
        client.close()
        assertNoIo()
    }

    @Test
    fun aTokenIsNotOfferedWithoutSealing() = test {
        val client = unverified(baseUrl = null, transportMode = TransportMode.Tls)

        val error = assertFailsWith<ConfigurationException> { client.executeRecoverable(enclave.get()) }

        assertTrue(error.message!!.contains("TransportMode.Ehbp"), error.message)
        client.close()
        assertNoIo()
    }

    // Keys.

    @Test
    fun anEnclaveWhoseAttestationEndorsesNoHpkeKeyIsRefused() = test {
        enclave.endorsedHpke = { null }

        val error = assertFailsWith<AttestationException> { direct() }

        assertTrue(error.message!!.contains("no HPKE key"), error.message)
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun anAttestedHpkeKeyThatIsMalformedIsRefused() = test {
        val malformed = listOf(
            "ab".repeat(31),
            "ab".repeat(33),
            "AB".repeat(32),
            "zz".repeat(32),
            "0x" + "ab".repeat(31),
            " " + "ab".repeat(32),
        )
        for (hpke in malformed) {
            enclave.endorsedHpke = { hpke }
            val error = assertFailsWith<AttestationException>(hpke) { direct() }
            assertTrue(error.message!!.contains("HPKE key"), error.message)
        }
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aKeyThatStopsBeingEndorsedStopsRequests() = test {
        val client = direct()
        enclave.endorsedHpke = { null }
        enclave.clock.advance(enclave.lifetimeSeconds)

        assertFailsWith<AttestationException> { client.execute(client.post("""{"q":"$MARKER"}""")) }

        assertEquals(0, enclave.server.requestCount, "nothing is sealed to a key that is no longer endorsed")
    }

    @Test
    fun anExpiredVerificationIsReplacedBeforeAnythingIsSealed() = test {
        val client = proxied()
        val expired = key
        key = SealingKey()
        enclave.clock.advance(enclave.lifetimeSeconds)

        client.execute(client.post("""{"q":"$MARKER"}""")).close()

        assertEquals(2, enclave.fetches)
        val received = atProxy.received.single()
        assertEquals("""{"q":"$MARKER"}""", received.text, "the body was sealed to the key of the new verification")
        assertNotEquals(expired.publicKey, client.current?.hpkePublicKey)
    }

    // What is sealed.

    @Test
    fun aRequestThroughAProxyIsSealedBothWaysAndNamesTheEnclave() = test {
        val client = proxied()
        atProxy.answer = { it.reply("""{"answer":"$ANSWER"}""") }

        val response = client.execute(client.post("""{"question":"$MARKER"}"""))

        assertEquals(200, response.code)
        assertEquals("""{"answer":"$ANSWER"}""", response.text())
        val received = atProxy.received.single()
        assertTrue(received.sealed)
        assertEquals("""{"question":"$MARKER"}""", received.text, "the enclave opens what the client sealed")
        assertFalse(received.wire.containsText(MARKER), "the proxy saw the request's plaintext")
        assertFalse(received.wire.containsText("question"), "the proxy saw the request's plaintext")
        assertEquals("https://${enclave.host}", received.request.getHeader(ENCLAVE_URL_HEADER))
        assertEquals("/v1/echo", received.request.path)
        assertEquals("POST", received.request.method)
        assertEquals("application/json; charset=utf-8", received.request.getHeader("Content-Type"))
        assertNull(received.request.getHeader("Content-Length"), "the sealed body's length is not the plaintext's")
        assertEquals(0, enclave.server.requestCount, "requests go to the proxy only")
        assertEquals(1, enclave.fetches)
    }

    @Test
    fun aRequestToTheEnclaveItselfIsSealedOverAnOrdinaryTlsConnection() = test {
        // The connection is not pinned in this mode: the body is sealed to
        // the attested HPKE key, whatever TLS key the attestation endorses.
        val other = enclave.authority.issue()
        enclave.endorsed = { other.fingerprint }
        val client = direct()
        assertEquals("https://${enclave.host}/".toHttpUrl(), client.baseUrl)
        assertEquals(key.publicKey, client.current?.hpkePublicKey)

        val response = client.execute(client.post("""{"question":"$MARKER"}"""))

        assertEquals("ok", response.text())
        val received = atEnclave.received.single()
        assertTrue(received.sealed)
        assertEquals("""{"question":"$MARKER"}""", received.text)
        assertFalse(received.wire.containsText(MARKER))
        assertNull(received.request.getHeader(ENCLAVE_URL_HEADER), "no proxy is told where to forward")
        assertNotNull(received.request.handshake, "the enclave is reached over TLS")
    }

    @Test
    fun theEnclavesCertificateIsStillValidatedWithoutAPin() = test {
        val client = direct()
        val untrusted = sh.tinfoil.testing.TestAuthority().issue()
        RawTlsServer(untrusted) { countWhatArrives(it) }.use { server ->
            val stranger = enclave.client(enclave = "localhost:${server.port}", transportMode = TransportMode.Ehbp)

            assertFailsWith<IOException> { stranger.execute(stranger.post("""{"q":"$MARKER"}""")) }

            assertEquals(0, server.bytesReceived.get(), "nothing is sent over a connection that the platform refuses")
        }
        client.close()
    }

    @Test
    fun aRequestWithoutABodyIsNotSealedAndNeitherIsItsResponse() = test {
        val client = proxied()
        atProxy.answer = { it.reply("""{"models":[]}""") }
        val empty = Request.Builder().url(client.baseUrl.resolve("v1/empty")!!).post(ByteArray(0).toRequestBody()).build()

        val got = client.executeRecoverable(client.get())
        val posted = client.executeRecoverable(empty)

        assertEquals("""{"models":[]}""", got.response.text())
        assertEquals("""{"models":[]}""", posted.response.text())
        assertNull(got.recoveryToken, "a response that is not sealed has no token")
        assertNull(posted.recoveryToken)
        for (received in atProxy.received) {
            assertFalse(received.sealed)
            assertNull(received.request.getHeader(ENCAPSULATED_KEY_HEADER))
            assertEquals("https://${enclave.host}", received.request.getHeader(ENCLAVE_URL_HEADER))
        }
        assertEquals(listOf("GET", "POST"), atProxy.received.map { it.request.method })
    }

    @Test
    fun aBodyThatDeclaresNoBytesSendsNone() = test {
        val client = proxied()
        val lying = object : RequestBody() {
            override fun contentType(): MediaType? = null
            override fun contentLength() = 0L
            override fun writeTo(sink: BufferedSink) {
                sink.writeUtf8(MARKER)
            }
        }

        val outcome = runCatching {
            client.execute(Request.Builder().url(client.baseUrl.resolve("v1/echo")!!).post(lying).build()).close()
        }

        assertIs<IOException>(outcome.exceptionOrNull())
        for (received in atProxy.received) {
            assertFalse(received.wire.containsText(MARKER), "an unsealed body reached the wire")
        }
    }

    @Test
    fun theUserCacheSecretIsAddedBeforeTheBodyIsSealed() = test {
        val client = proxied(userCacheSecret = CACHE_SECRET)

        client.execute(client.post("""{"model":"m","prompt":"$MARKER"}""", path = "v1/chat/completions")).close()

        val received = atProxy.received.single()
        assertEquals("""{"model":"m","prompt":"$MARKER","user_cache_secret":"$CACHE_SECRET"}""", received.text)
        assertFalse(received.wire.containsText(CACHE_SECRET), "the proxy saw the cache secret")
        assertFalse(received.wire.containsText("user_cache_secret"), "the proxy saw the body's plaintext")
        assertFalse(received.wire.containsText(MARKER))
    }

    @Test
    fun aLargeBodyIsSealedAsItStreams() = test {
        val client = proxied()
        val piece = "$MARKER-".repeat(1024).toByteArray()
        val pieces = 512
        val streamed = object : RequestBody() {
            override fun contentType(): MediaType? = null
            override fun writeTo(sink: BufferedSink) {
                repeat(pieces) { sink.write(piece) }
            }
        }
        atProxy.answer = { it.reply(it.plaintext!!.size.toString()) }

        val response = client.execute(Request.Builder().url(client.baseUrl.resolve("v1/upload")!!).post(streamed).build())

        assertEquals((piece.size.toLong() * pieces).toString(), response.text())
        val received = atProxy.received.single()
        assertFalse(received.wire.containsText(MARKER))
        // Sealed in frames of a few KiB each, and not as one buffered piece.
        assertTrue(received.wire.size > piece.size * pieces + 16 * 256, "the body was sealed in ${received.wire.size} bytes")
    }

    // Responses that are not what was asked for.

    @Test
    fun aSuccessThatIsNotSealedFailsClosed() = test {
        val client = proxied()
        atProxy.answer = { MockResponse().setBody("""{"answer":"$FORGED"}""") }

        val error = assertFailsWith<IOException> { client.execute(client.post("""{"q":"$MARKER"}""")) }

        assertTrue(error.message!!.contains("MISSING_RESPONSE_NONCE"), error.message)
        assertFalse(error.toString().contains(FORGED))
        assertEquals(1, atProxy.received.size)
        assertEquals(1, enclave.fetches, "an answer that is not sealed is not a reason to verify again")
    }

    @Test
    fun aNonceThatIsNotOneFailsClosed() = test {
        val client = proxied()
        val nonces = listOf("", "abcd", "zz".repeat(32), "ab".repeat(33))
        for (nonce in nonces) {
            atProxy.answer = { MockResponse().setHeader(RESPONSE_NONCE_HEADER, nonce).setBody(FORGED) }
            assertFailsWith<IOException>(nonce) { client.execute(client.post("""{"q":"$MARKER"}""")) }
        }
        atProxy.answer = { it.reply(ANSWER).addHeader(RESPONSE_NONCE_HEADER, "ab".repeat(32)) }
        assertFailsWith<IOException>("two nonces") { client.execute(client.post("""{"q":"$MARKER"}""")) }
    }

    @Test
    fun aSuccessWhoseSealedBodyProvesNothingFailsClosed() = test {
        val client = proxied()
        val forgedNonce = "5c".repeat(32)
        val empty = listOf<(sh.tinfoil.testing.Received) -> MockResponse>(
            // Any 32 bytes pass for a nonce, so the header alone proves nothing.
            { MockResponse().setHeader(RESPONSE_NONCE_HEADER, forgedNonce) },
            { MockResponse().setHeader(RESPONSE_NONCE_HEADER, forgedNonce).setBody(Buffer().writeInt(0).writeInt(0)) },
            { MockResponse().setResponseCode(201).setHeader(RESPONSE_NONCE_HEADER, forgedNonce).setChunkedBody("", 8) },
            // A sealed piece that carries no bytes shows nothing to the reader either.
            { it.respond().let { sealing -> MockResponse().setHeader(RESPONSE_NONCE_HEADER, sealing.nonce).setBody(Buffer().write(sealing.frame(""))) } },
        )
        for (answer in empty) {
            atProxy.answer = answer
            val recoverable = client.executeRecoverable(client.post("""{"q":"$MARKER"}"""))
            val error = assertFailsWith<IOException> { recoverable.response.text() }
            assertTrue(error.message!!.contains("FRAMING_TRUNCATED"), error.message)
        }
        for (code in listOf(204, 205)) {
            atProxy.answer = { MockResponse().setResponseCode(code).setHeader(RESPONSE_NONCE_HEADER, forgedNonce) }
            val error = assertFailsWith<IOException>("$code") { client.execute(client.post("""{"q":"$MARKER"}""")) }
            assertTrue(error.message!!.contains("FRAMING_TRUNCATED"), error.message)
        }
        // An error says nothing that needs proof, and one without a body is returned.
        atProxy.answer = { MockResponse().setResponseCode(500).setHeader(RESPONSE_NONCE_HEADER, forgedNonce) }
        client.execute(client.post("""{"q":"$MARKER"}""")).use { response ->
            assertEquals(500, response.code)
            assertEquals("", response.body!!.string())
        }
        assertEquals(1, enclave.fetches)
    }

    @Test
    fun aResponseSealedForAnotherRequestFailsTheRead() = test {
        val client = proxied()
        val first = CopyOnWriteArrayList<Pair<String, ByteArray>>()
        atProxy.answer = { received ->
            val sealing = received.respond()
            val frames = sealing.frame(ANSWER)
            first += sealing.nonce to frames
            // Every request is answered with the response to the first.
            MockResponse().setHeader(RESPONSE_NONCE_HEADER, first[0].first).setBody(Buffer().write(first[0].second))
        }
        assertEquals(ANSWER, client.execute(client.post("""{"q":1}""")).text())

        val swapped = client.execute(client.post("""{"q":2}"""))

        assertFailsWith<IOException> { swapped.text() }
    }

    @Test
    fun anErrorThatIsNotSealedIsReturnedWithoutAToken() = test {
        val client = proxied()
        atProxy.answer = { MockResponse().setResponseCode(502).setBody("bad gateway") }

        val recoverable = client.executeRecoverable(client.post("""{"q":"$MARKER"}"""))

        assertEquals(502, recoverable.response.code)
        assertEquals("bad gateway", recoverable.response.text())
        assertNull(recoverable.recoveryToken, "an answer that nothing authenticates has no token")
        assertFalse(atProxy.received.single().wire.containsText(MARKER))
    }

    @Test
    fun anErrorThatTheEnclaveSealedIsOpened() = test {
        val client = proxied()
        atProxy.answer = { it.reply("""{"error":"$ANSWER"}""", code = 404) }

        val recoverable = client.executeRecoverable(client.post("""{"q":"$MARKER"}"""))

        assertEquals(404, recoverable.response.code)
        assertEquals("""{"error":"$ANSWER"}""", recoverable.response.text())
        assertNotNull(recoverable.recoveryToken)
    }

    @Test
    fun anUnprocessableAnswerThatIsNotAKeyProblemIsNotAKeyRejection() = test {
        val client = proxied()
        val answers = listOf(
            MockResponse().setResponseCode(422).setBody("""{"type":"urn:ietf:params:ehbp:error:key-config"}"""),
            MockResponse().setResponseCode(422).setHeader("Content-Type", "application/problem+json")
                .setBody("""{"type":"about:blank","title":"validation failed"}"""),
            MockResponse().setResponseCode(400).setHeader("Content-Type", "application/problem+json")
                .setBody("""{"type":"urn:ietf:params:ehbp:error:key-config"}"""),
        )
        for (answer in answers) {
            atProxy.answer = { answer }
            client.execute(client.post("""{"q":1}""")).use { assertEquals(answer.status.split(' ')[1].toInt(), it.code) }
        }
        assertEquals(1, enclave.fetches, "none of them made the client verify again")
        assertEquals(answers.size, atProxy.received.size)
    }

    @Test
    fun aRedirectIsReturnedAndNotFollowedForARequestWithoutABody() = test {
        val client = proxied()
        atProxy.answer = { MockResponse().setResponseCode(302).setHeader("Location", "/elsewhere") }

        client.execute(client.get()).use { response ->
            assertEquals(302, response.code)
            assertEquals("/elsewhere", response.header("Location"))
        }
        assertEquals(1, proxy.requestCount)
    }

    @Test
    fun aRedirectInAnswerToASealedRequestFailsAndIsNotFollowed() = test {
        val client = proxied()
        for (code in listOf(301, 302, 303, 307, 308)) {
            atProxy.answer = { MockResponse().setResponseCode(code).setHeader("Location", "https://evil.example/") }
            val error = assertFailsWith<IOException>("$code") { client.execute(client.post("""{"q":"$MARKER"}""")) }
            assertTrue(error.message!!.contains("UNEXPECTED_REDIRECT"), error.message)
        }
        // A redirect that the enclave sealed is refused as well: its target is not sealed.
        atProxy.answer = { it.reply("moved", code = 307).setHeader("Location", "/elsewhere") }
        assertFailsWith<IOException> { client.execute(client.post("""{"q":"$MARKER"}""")) }
        assertEquals(6, proxy.requestCount, "no redirect was followed")
    }

    @Test
    fun anAuthenticationChallengeIsReturnedAndNoCookiesAreKept() = test {
        val client = proxied()
        atProxy.answer = {
            MockResponse().setResponseCode(401).setHeader("WWW-Authenticate", "Basic realm=x").setHeader("Set-Cookie", "id=1")
        }

        client.execute(client.get()).use { assertEquals(401, it.code) }
        client.execute(client.get()).close()

        assertEquals(2, proxy.requestCount)
        assertNull(atProxy.received[1].request.getHeader("Cookie"))
        assertNull(atProxy.received[1].request.getHeader("Authorization"))
    }

    // Bodies that stop authenticating.

    @Test
    fun aTamperedFrameFailsTheReadAndDeliversNothingAfterIt() = test {
        val client = proxied()
        atProxy.answer = { received ->
            val sealing = received.respond()
            val authentic = sealing.frame("$ANSWER|")
            val tampered = sealing.frame(FORGED).also { it[it.size - 1] = it[it.size - 1] xor 1 }
            val later = sealing.frame("later")
            MockResponse().setHeader(RESPONSE_NONCE_HEADER, sealing.nonce)
                .setBody(Buffer().write(authentic).write(tampered).write(later))
        }

        val response = client.execute(client.post("""{"q":"$MARKER"}"""))
        val source = response.body!!.source()
        val delivered = Buffer()
        val error = assertFailsWith<IOException> {
            while (source.read(delivered, 8192) != -1L) {
                // Read to the end, or to the failure.
            }
        }

        assertTrue(error.message!!.contains("AEAD_DECRYPT_FAILED"), error.message)
        assertEquals("$ANSWER|", delivered.readUtf8(), "only what authenticated was delivered")
        repeat(3) {
            assertFailsWith<IOException> { source.read(delivered, 8192) }
        }
        assertEquals(0, delivered.size, "nothing is delivered after a failure")
        response.close()
    }

    @Test
    fun aFrameOutOfOrderFailsTheRead() = test {
        val client = proxied()
        atProxy.answer = { received ->
            val sealing = received.respond()
            val first = sealing.frame("first")
            val second = sealing.frame("second")
            MockResponse().setHeader(RESPONSE_NONCE_HEADER, sealing.nonce).setBody(Buffer().write(second).write(first))
        }

        val response = client.execute(client.post("""{"q":1}"""))

        assertFailsWith<IOException> { response.text() }
    }

    @Test
    fun aBodyCutShortFailsTheRead() = test {
        val client = proxied()
        val cuts = listOf<(ByteArray) -> ByteArray>(
            { it.copyOf(it.size - 1) },
            { it.copyOf(it.size / 2) },
            { it.copyOf(2) },
        )
        for (cut in cuts) {
            atProxy.answer = { received ->
                val sealing = received.respond()
                MockResponse().setHeader(RESPONSE_NONCE_HEADER, sealing.nonce)
                    .setBody(Buffer().write(sealing.frame("$ANSWER|")).write(cut(sealing.frame(FORGED))))
            }
            val response = client.execute(client.post("""{"q":1}"""))
            val source = response.body!!.source()
            val delivered = Buffer()
            val error = assertFailsWith<IOException> {
                while (source.read(delivered, 8192) != -1L) {
                    // Read to the end, or to the failure.
                }
            }
            assertTrue(error.message!!.contains("FRAMING_TRUNCATED"), error.message)
            assertEquals("$ANSWER|", delivered.readUtf8())
            assertFailsWith<IOException> { source.read(delivered, 1) }
            response.close()
        }
    }

    @Test
    fun aConnectionThatDropsDuringTheBodyFailsTheRead() = test {
        val client = proxied()
        atProxy.answer = { it.reply("x".repeat(1 shl 20), pieces = 64).setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY) }

        val response = client.execute(client.post("""{"q":1}"""))

        assertFailsWith<IOException> { response.text() }
    }

    @Test
    fun aFrameThatClaimsToBeHugeIsRefusedBeforeItIsRead() = test {
        val client = proxied()
        atProxy.answer = { received ->
            val sealing = received.respond()
            MockResponse().setHeader(RESPONSE_NONCE_HEADER, sealing.nonce)
                .setBody(Buffer().writeInt(Int.MAX_VALUE).write(sealing.frame(ANSWER)))
        }

        val response = client.execute(client.post("""{"q":1}"""))

        val error = assertFailsWith<IOException> { response.text() }
        assertTrue(error.message!!.contains("CHUNK_TOO_LARGE"), error.message)
    }

    @Test
    fun plaintextIsReleasedFrameByFrame() = test {
        val client = proxied()
        atProxy.answer = { received ->
            val sealing = received.respond()
            val first = sealing.frame("$ANSWER|")
            val rest = Buffer().write(first)
            repeat(64) { rest.write(sealing.frame("x".repeat(1024))) }
            // The first frame arrives at once, and the rest over a minute.
            MockResponse().setHeader(RESPONSE_NONCE_HEADER, sealing.nonce).setBody(rest)
                .throttleBody(first.size.toLong(), 1, TimeUnit.SECONDS)
        }

        val response = client.execute(client.post("""{"q":1}"""))
        val started = System.nanoTime()
        val head = response.body!!.source().readUtf8("$ANSWER|".length.toLong())

        assertEquals("$ANSWER|", head)
        assertTrue(System.nanoTime() - started < 10_000_000_000, "the first frame waited for later ones")
        response.close()
    }

    @Test
    fun aSealedResponseThatIsNotReadIsNotBuffered() = test {
        val chunk = ByteArray(64 * 1024) { 'a'.code.toByte() }
        RawTlsServer(enclave.authority.issue()) { socket ->
            val (encapsulated, sealed) = readSealedRequest(socket)
            val sealing = key.open(encapsulated, sealed).respond()
            val output = socket.outputStream
            output.write(
                "HTTP/1.1 200 OK\r\n$RESPONSE_NONCE_HEADER: ${sealing.nonce}\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray(),
            )
            while (true) {
                val frame = sealing.frame(chunk)
                output.write("${frame.size.toString(16)}\r\n".toByteArray())
                output.write(frame)
                output.write("\r\n".toByteArray())
                bytesSent.addAndGet(frame.size.toLong())
            }
        }.use { server ->
            val client = enclave.client(enclave = "localhost:${server.port}", transportMode = TransportMode.Ehbp)

            val response = client.execute(client.post("""{"q":"$MARKER"}"""))
            assertEquals(200, response.code)

            // With nobody reading, the server can write only until the
            // buffers between it and the reader are full.
            var sent = -1L
            awaitUntil(30_000) {
                val now = server.bytesSent.get()
                Thread.sleep(500)
                (now == sent).also { sent = now }
            }
            assertTrue(sent < 64L * 1024 * 1024, "the server wrote $sent bytes to a client that read none")

            // Reading makes room for more, and what is read is the plaintext.
            val source = response.body!!.source()
            assertEquals("a".repeat(1024), source.readUtf8(1024))
            source.skip(sent + 1024 * 1024)
            awaitUntil { server.bytesSent.get() > sent }
            response.close()
        }
    }

    // A key that the enclave no longer holds.

    @Test
    fun aKeyThatTheEnclaveNoLongerHoldsIsVerifiedAgainAndTheRequestReplayedOnce() = test {
        val results = CopyOnWriteArrayList<Result<Verification>>()
        val client = enclave.client(
            transportMode = TransportMode.Ehbp, baseUrl = proxyUrl, userCacheSecret = CACHE_SECRET,
            onVerificationResult = { results += it },
        )
        val attested = key
        key = SealingKey()
        atProxy.answer = { it.reply(ANSWER) }

        val recoverable = client.executeRecoverable(
            client.post("""{"model":"m","prompt":"$MARKER"}""", path = "v1/chat/completions"),
        )

        assertEquals(ANSWER, recoverable.response.text())
        assertEquals(2, atProxy.received.size, "the request was sent once more, and only once")
        val (rejected, accepted) = atProxy.received
        assertNull(rejected.plaintext, "the enclave could not open the body that was sealed to the old key")
        assertEquals("""{"model":"m","prompt":"$MARKER","user_cache_secret":"$CACHE_SECRET"}""", accepted.text)
        for (received in atProxy.received) {
            assertTrue(received.sealed)
            assertFalse(received.wire.containsText(MARKER), "a body went out unsealed")
            assertFalse(received.wire.containsText(CACHE_SECRET))
            assertEquals("https://${enclave.host}", received.request.getHeader(ENCLAVE_URL_HEADER))
        }
        assertNotEquals(
            rejected.request.getHeader(ENCAPSULATED_KEY_HEADER),
            accepted.request.getHeader(ENCAPSULATED_KEY_HEADER),
            "each attempt is sealed anew",
        )
        assertEquals(2, enclave.fetches, "the enclave was verified again, once")
        assertEquals(key.publicKey, client.current?.hpkePublicKey)
        assertNotEquals(attested.publicKey, client.current?.hpkePublicKey)
        assertNotNull(recoverable.recoveryToken, "the token is that of the request that was answered")
        awaitUntil { results.size == 2 }

        // The new key is used from then on, without verifying again.
        client.execute(client.post("""{"q":2}""")).close()
        assertEquals(2, enclave.fetches)
        assertEquals(3, atProxy.received.size)
    }

    @Test
    fun aSecondRejectionIsAnAttestationError() = test {
        val stranger = SealingKey()
        enclave.endorsedHpke = { stranger.publicKey }
        val client = proxied()

        val error = assertFailsWith<AttestationException> { client.execute(client.post("""{"q":"$MARKER"}""")) }

        assertTrue(error.message!!.contains("after the enclave was verified again"), error.message)
        assertEquals(2, atProxy.received.size, "one replay, and no more")
        assertEquals(2, enclave.fetches)
        assertTrue(atProxy.received.none { it.wire.containsText(MARKER) })
    }

    @Test
    fun aBodyThatCanBeSentOnlyOnceIsNotReplayed() = test {
        val client = proxied()
        key = SealingKey()
        val writes = AtomicInteger()
        val once = object : RequestBody() {
            override fun contentType(): MediaType? = JSON
            override fun isOneShot() = true
            override fun writeTo(sink: BufferedSink) {
                writes.incrementAndGet()
                sink.writeUtf8("""{"q":"$MARKER"}""")
            }
        }

        val error = assertFailsWith<AttestationException> {
            client.execute(Request.Builder().url(client.baseUrl.resolve("v1/echo")!!).post(once).build())
        }

        assertTrue(error.message!!.contains("only once"), error.message)
        assertEquals(1, writes.get())
        assertEquals(1, atProxy.received.size)
        assertFalse(atProxy.received.single().wire.containsText(MARKER))
        // The rejection still withdrew the key: the next request verifies again.
        client.execute(client.post("""{"q":2}""")).close()
        assertEquals(2, enclave.fetches)
    }

    @Test
    fun aRequestIsNotReplayedWhenVerifyingAgainFails() = test {
        val client = proxied()
        key = SealingKey()
        enclave.verifier.verify = { _, _, _ -> throw AttestationException("the enclave no longer verifies") }

        assertFailsWith<AttestationException> { client.execute(client.post("""{"q":"$MARKER"}""")) }

        assertEquals(1, atProxy.received.size)
    }

    @Test
    fun aRequestCancelledWhileTheEnclaveIsVerifiedAgainIsNotReplayed() = test {
        val client = proxied()
        key = SealingKey()
        val verifying = CountDownLatch(1)
        val release = CountDownLatch(1)
        val inner = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin ->
            verifying.countDown()
            release.await(30, TimeUnit.SECONDS)
            inner(document, nonce, pin)
        }

        val call = client.newCall(client.post("""{"q":"$MARKER"}"""))
        val result = async(Dispatchers.IO) { runCatching { call.execute() }.exceptionOrNull() }
        assertTrue(verifying.await(30, TimeUnit.SECONDS))
        call.cancel()
        release.countDown()

        assertIs<IOException>(result.await())
        client.ensureVerified()
        assertEquals(1, atProxy.received.size, "a cancelled request is not sent again under the new key")
    }

    // The HTTP client's own retries.

    @Test
    fun theHttpClientNeverSendsASealedBodyAgain() = test {
        val client = proxied()
        val answers = listOf(
            MockResponse().setResponseCode(503).setHeader("Retry-After", "0"),
            MockResponse().setResponseCode(408),
            MockResponse().setResponseCode(421),
        )
        for (answer in answers) {
            atProxy.answer = { answer }
            client.execute(client.post("""{"q":"$MARKER"}""")).close()
        }
        assertEquals(answers.size, proxy.requestCount, "a sealed request was sent again")

        atProxy.answer = { MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) }
        assertFailsWith<IOException> { client.execute(client.post("""{"q":"$MARKER"}""")) }
        assertEquals(answers.size + 1, proxy.requestCount, "a sealed request was sent again after its connection failed")
    }

    // Connections.

    @Test
    fun sequentialRequestsReuseOneConnectionAndANewVerificationStartsAnother() = test {
        val client = proxied()

        repeat(3) { client.execute(client.post("""{"q":$it}""")).close() }
        assertEquals(listOf(0, 1, 2), atProxy.received.map { it.request.sequenceNumber })

        client.reverify()
        client.execute(client.post("""{"q":3}""")).close()
        assertEquals(0, atProxy.received.last().request.sequenceNumber, "a new verification has connections of its own")
    }

    @Test
    fun requestsInFlightAtOnceEachGetTheirOwnAnswerAndToken() = test {
        val client = proxied()
        val stored = java.util.concurrent.ConcurrentHashMap<String, Pair<String, ByteArray>>()
        atProxy.answer = { received ->
            val sealing = received.respond()
            val frames = sealing.frame("answer to ${received.text}")
            stored[received.text!!] = sealing.nonce to frames
            MockResponse().setHeader(RESPONSE_NONCE_HEADER, sealing.nonce).setBody(Buffer().write(frames))
                .setHeadersDelay(100, TimeUnit.MILLISECONDS)
        }

        val results = (0 until 16).map { index ->
            async(Dispatchers.IO) {
                val recoverable = client.executeRecoverable(client.post("question $index"))
                Triple(index, recoverable.recoveryToken, recoverable.response.text())
            }
        }.awaitAll()

        for ((index, token, text) in results) {
            assertEquals("answer to question $index", text)
            val (nonce, frames) = stored.getValue("question $index")
            assertEquals(text, assertNotNull(token).decryptResponse(storedResponse(nonce, frames)).text())
            val (otherNonce, otherFrames) = stored.getValue("question ${(index + 1) % 16}")
            assertFailsWith<IOException>("a token opened another request's response") {
                token.decryptResponse(storedResponse(otherNonce, otherFrames)).text()
            }
        }
    }

    // Session recovery.

    @Test
    fun theTokenOpensAStoredCopyOfTheResponseLaterAndIsNeverPrinted() = test {
        val client = proxied()
        var stored: Pair<String, ByteArray>? = null
        atProxy.answer = { received ->
            val sealing = received.respond()
            val frames = sealing.frame("$ANSWER, ") + sealing.frame("in two frames")
            stored = sealing.nonce to frames
            MockResponse().setHeader(RESPONSE_NONCE_HEADER, sealing.nonce).setBody(Buffer().write(frames))
        }

        val recoverable = client.executeRecoverable(client.post("""{"q":"$MARKER"}"""))
        val token = assertNotNull(recoverable.recoveryToken)
        val json = token.toJson()
        val secrets = Regex("\"([0-9a-f]{64})\"").findAll(json).map { it.groupValues[1] }.toList()
        assertEquals(2, secrets.size, "the token is two 32-byte values in lowercase hex")
        for (text in listOf(token.toString(), recoverable.toString(), "$token", listOf(token).toString())) {
            assertTrue(secrets.none { it in text }, text)
            assertFalse(json in text)
        }
        assertTrue("redacted" in token.toString())
        // The live response is read to its end, which ends the client's own use of the token.
        assertEquals("$ANSWER, in two frames", recoverable.response.text())
        client.close()

        // Elsewhere, later: the stored token and a stored copy of the sealed response.
        val (nonce, frames) = stored!!
        assertFalse(frames.containsText(ANSWER))
        val restored = SessionRecoveryToken.fromJson(json)
        assertEquals("$ANSWER, in two frames", restored.decryptResponse(storedResponse(nonce, frames)).text())
        assertEquals(json, restored.toJson())

        // A copy that was cut off yields what authenticates, and then fails.
        val cut = restored.decryptResponse(storedResponse(nonce, frames.copyOf(frames.size - 3)))
        val delivered = Buffer()
        assertFailsWith<IOException> {
            while (cut.body!!.source().read(delivered, 8192) != -1L) {
                // Read to the end, or to the failure.
            }
        }
        assertEquals("$ANSWER, ", delivered.readUtf8())
        // A copy without its nonce cannot be opened.
        val bare = Response.Builder().request(Request.Builder().url("https://storage.example/").build())
            .protocol(Protocol.HTTP_1_1).code(200).message("OK").body(frames.toResponseBody()).build()
        assertFailsWith<IOException> { restored.decryptResponse(bare) }
    }

    @Test
    fun textThatIsNotATokenIsRefusedWithoutRepeatingIt() {
        val inputs = listOf(
            "",
            "hunter2",
            """{"exportedSecret":"hunter2hunter2","requestEnc":"${"ab".repeat(32)}"}""",
            """{"exportedSecret":"${"ab".repeat(32)}"}""",
            """{"exportedSecret":"${"cd".repeat(32)}","requestEnc":"hunter2""",
            "[".repeat(100_000),
        )
        for (input in inputs) {
            val error = assertFailsWith<ConfigurationException> { SessionRecoveryToken.fromJson(input) }
            generateSequence<Throwable>(error) { it.cause }.forEach { cause ->
                assertFalse(cause.toString().contains("hunter2"), cause.toString())
                assertFalse(cause.toString().contains("cdcdcdcd"), cause.toString())
            }
        }
    }

    // Cancellation, timeouts and closing.

    @Test
    fun cancellingTheCoroutineAbortsTheSealedRequestInFlight() = test {
        silentServer().use { server ->
            val client = enclave.client(enclave = "localhost:${server.port}", transportMode = TransportMode.Ehbp)

            val sending = launch(Dispatchers.IO) { client.execute(client.post("""{"q":"$MARKER"}""")) }
            awaitUntil { server.bytesReceived.get() > 0 }
            assertEquals(0, server.finished.get())
            sending.cancelAndJoin()

            awaitUntil(5_000) { server.finished.get() == 1 }
        }
    }

    @Test
    fun aCallCanBeCancelledWhileItWaitsForTheResponseOrReadsIt() = test {
        silentServer().use { server ->
            val client = enclave.client(enclave = "localhost:${server.port}", transportMode = TransportMode.Ehbp)
            val waiting = client.newCall(client.post("""{"q":"$MARKER"}"""))
            val result = async(Dispatchers.IO) { runCatching { waiting.execute() }.exceptionOrNull() }
            awaitUntil { server.bytesReceived.get() > 0 }

            waiting.cancel()

            assertIs<IOException>(result.await())
            awaitUntil(5_000) { server.finished.get() == 1 }
        }

        val client = proxied()
        atProxy.answer = { it.reply("x".repeat(1 shl 20), pieces = 1024).throttleBody(1024, 1, TimeUnit.SECONDS) }
        val streaming = client.newCall(client.post("""{"q":1}"""))
        val response = streaming.execute()
        streaming.cancel()
        assertFailsWith<IOException> { response.body!!.string() }

        val unsent = client.newCall(client.post("""{"q":2}""")).apply { cancel() }
        assertEquals("Canceled", assertFailsWith<IOException> { unsent.execute() }.message)
        assertEquals(1, proxy.requestCount)
    }

    @Test
    fun aCallsTimeoutAbortsTheSealedRequestAndTheReadingOfItsBody() = test {
        silentServer().use { server ->
            val client = enclave.client(enclave = "localhost:${server.port}", transportMode = TransportMode.Ehbp)
            val slowHeaders = client.newCall(client.post("""{"q":"$MARKER"}""")).apply { timeout().timeout(300, TimeUnit.MILLISECONDS) }

            val started = System.nanoTime()
            val error = assertFailsWith<InterruptedIOException> { slowHeaders.execute() }

            assertEquals("timeout", error.message)
            assertTrue(System.nanoTime() - started < 5_000_000_000)
            awaitUntil(5_000) { server.finished.get() == 1 }
        }

        val client = proxied()
        atProxy.answer = { it.reply("x".repeat(1 shl 20), pieces = 1024).throttleBody(1024, 1, TimeUnit.SECONDS) }
        val slowBody = client.newCall(client.post("""{"q":1}""")).apply { timeout().timeout(500, TimeUnit.MILLISECONDS) }
        val response = slowBody.execute()
        val started = System.nanoTime()
        assertFailsWith<IOException> { response.body!!.string() }
        assertTrue(System.nanoTime() - started < 5_000_000_000, "the body's read outlived the call's timeout")
    }

    @Test
    fun anEnqueuedCallDeliversItsSealedResponse() = test {
        val client = proxied()
        atProxy.answer = { it.reply(ANSWER) }
        val done = CountDownLatch(1)
        var text: String? = null
        var failure: IOException? = null

        client.newCall(client.post("""{"q":"$MARKER"}""")).enqueue(
            object : okhttp3.Callback {
                override fun onFailure(call: okhttp3.Call, e: IOException) {
                    failure = e
                    done.countDown()
                }

                override fun onResponse(call: okhttp3.Call, response: Response) {
                    text = response.text()
                    done.countDown()
                }
            },
        )

        assertTrue(done.await(30, TimeUnit.SECONDS))
        assertNull(failure)
        assertEquals(ANSWER, text)
    }

    @Test
    fun closingAbortsSealedRequestsInFlightAndRefusesLaterOnes() = test {
        val client = proxied()
        atProxy.answer = { received ->
            if (received.request.path == "/v1/slow") {
                received.reply(ANSWER).setHeadersDelay(3, TimeUnit.SECONDS)
            } else {
                received.reply("x".repeat(1 shl 20), pieces = 1024).throttleBody(1024, 1, TimeUnit.SECONDS)
            }
        }

        val waiting = async(Dispatchers.IO) {
            runCatching { client.execute(client.post("""{"q":1}""", path = "v1/slow")) }.exceptionOrNull()
        }
        val streaming = client.execute(client.post("""{"q":2}""", path = "v1/stream"))
        awaitUntil { proxy.requestCount == 2 }
        val started = System.nanoTime()
        client.close()

        assertIs<IOException>(waiting.await())
        assertFailsWith<IOException> { streaming.body!!.string() }
        assertTrue(System.nanoTime() - started < 10_000_000_000, "closing did not abort what was in flight")
        assertFailsWith<ConfigurationException> { client.execute(client.post("""{"q":3}""")) }
        assertFailsWith<ConfigurationException> { client.executeRecoverable(client.post("""{"q":3}""")) }
        assertIs<ConfigurationException>(assertFailsWith<IOException> { client.newCall(client.get()).execute() })
        assertEquals(2, proxy.requestCount)
    }

    @Test
    fun aResponseKeepsStreamingWhenItsVerificationIsReplaced() = test {
        val client = proxied()
        atProxy.answer = { it.reply("x".repeat(8192), pieces = 8).throttleBody(1100, 100, TimeUnit.MILLISECONDS) }

        val finishing = client.execute(client.post("""{"q":1}"""))
        client.reverify()

        assertEquals(8192, finishing.text().length, "a newer verification does not interrupt a response")
    }

    /** A server that completes the TLS handshake, reads what it is sent and never answers. */
    private fun silentServer(): RawTlsServer = RawTlsServer(enclave.authority.issue()) { socket ->
        val buffer = ByteArray(4096)
        while (true) {
            val read = socket.inputStream.read(buffer)
            if (read < 0) {
                break
            }
            bytesReceived.addAndGet(read.toLong())
        }
    }

    /** Reads one HTTP/1.1 request with a chunked body: its encapsulated key and its sealed body. */
    private fun readSealedRequest(socket: SSLSocket): Pair<String, ByteArray> {
        val source = socket.inputStream.source().buffer()
        var encapsulated = ""
        while (true) {
            val line = source.readUtf8LineStrict()
            if (line.isEmpty()) {
                break
            }
            if (line.startsWith("$ENCAPSULATED_KEY_HEADER:", ignoreCase = true)) {
                encapsulated = line.substringAfter(':').trim()
            }
        }
        val body = Buffer()
        while (true) {
            val size = source.readUtf8LineStrict().trim().toLong(16)
            if (size == 0L) {
                break
            }
            source.readFully(body, size)
            source.readUtf8LineStrict()
        }
        return encapsulated to body.readByteArray()
    }

    /** A sealed response as it might be kept somewhere and fetched again. */
    private fun storedResponse(nonce: String, frames: ByteArray): Response =
        Response.Builder()
            .request(Request.Builder().url("https://storage.example/responses/1").build())
            .protocol(Protocol.HTTP_1_1)
            .code(200)
            .message("OK")
            .header(RESPONSE_NONCE_HEADER, nonce)
            .body(frames.toResponseBody())
            .build()

    private companion object {
        val JSON = "application/json; charset=utf-8".toMediaType()
        const val MARKER = "plaintext-marker-7f3a9c"
        const val ANSWER = "enclave-answer-b81d44"
        const val FORGED = "forged-answer-e02c57"
        const val CACHE_SECRET = "cache-secret-5d6e1f"
    }
}
