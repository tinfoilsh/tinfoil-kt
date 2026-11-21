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
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import okio.BufferedSink
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.internal.verification.VerifierOptions
import sh.tinfoil.testing.RawTlsServer
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.fingerprint
import sh.tinfoil.testing.verification
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

class EnclaveHttpClientTest {
    private var enclave = TestEnclave()

    @AfterTest
    fun shutDown() {
        enclave.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    private fun Response.text(): String = use { it.body!!.string() }

    private fun ok(body: String = "ok") = MockResponse().setBody(body)

    /** Replaces the enclave with one whose server presents another certificate. */
    private fun enclaveWith(issue: (sh.tinfoil.testing.TestAuthority) -> okhttp3.tls.HeldCertificate): TestEnclave {
        enclave.close()
        return TestEnclave(issue).also { enclave = it }
    }

    private fun assertNothingWasSent() {
        assertEquals(0, enclave.fetches, "attestation fetches")
        assertEquals(0, enclave.server.requestCount, "requests to the enclave")
        assertEquals(0, enclave.verifier.verifications.get(), "verifications")
    }

    // Creation.

    @Test
    fun aClientIsVerifiedWhenItIsReturned() = test {
        val client = enclave.client()

        assertEquals(1, enclave.fetches)
        assertEquals(enclave.certificate.fingerprint, client.current?.tlsPublicKeyFingerprint)
        assertEquals(enclave.host, client.enclave)
        assertEquals(Trust.RepoPin("tinfoilsh/example"), client.trust)
        assertEquals(Transport.Tls, client.transport)
        assertEquals("https://${enclave.host}/".toHttpUrl(), client.baseUrl)
        assertSame(client.current, client.ensureVerified(), "a valid verification is reused")
        assertEquals(1, enclave.fetches)
        assertEquals(0, enclave.server.requestCount, "verifying sends the enclave no request")
    }

    @Test
    fun aProxyOnTheEnclavesOwnOriginIsRefused() = test {
        for (url in listOf("https://${enclave.host}/relay", "https://LOCALHOST:${enclave.port}", "https://${enclave.host}/")) {
            val error = assertFailsWith<ConfigurationException>(url) { enclave.client(transport = Transport.Ehbp(url)) }
            assertTrue(error.detail.contains("leave proxyUrl null to connect directly"), error.detail)
        }
        val defaultPort = assertFailsWith<ConfigurationException> {
            enclave.client(enclave = "enclave.example", transport = Transport.Ehbp("https://enclave.example:443/relay"))
        }
        assertTrue(defaultPort.detail.contains("enclave's own origin"), defaultPort.detail)
        assertNothingWasSent()
    }

    @Test
    fun invalidOptionsAreRefusedBeforeAnyIo() = test {
        val origin = "https://${enclave.host}"
        val refused: List<Pair<String, suspend () -> Unit>> = listOf(
            "an empty enclave" to { enclave.client(enclave = "") },
            "an enclave that is a URL" to { enclave.client(enclave = origin) },
            "an enclave with a path" to { enclave.client(enclave = "${enclave.host}/v1") },
            "an enclave with user information" to { enclave.client(enclave = "user@${enclave.host}") },
            "an enclave with a space" to { enclave.client(enclave = "local host") },
            "an enclave with a query" to { enclave.client(enclave = "${enclave.host}?x") },
            "an enclave with an empty port" to { enclave.client(enclave = "localhost:") },
            "an enclave with a backslash" to { enclave.client(enclave = "localhost\\x") },
            "a repo pin without a repo" to { enclave.client(trust = Trust.RepoPin("")) },
            "a project pin without a project" to { enclave.client(trust = Trust.ProjectPin("")) },
            "an empty list of registries" to { enclave.client(trust = Trust.ProjectPin("org/project", emptyList())) },
            "an either pin without a project" to { enclave.client(trust = Trust.EitherPin("org/repo", "")) },
            "a negative freshness bound" to { enclave.client(policy = Policy(freshnessMaxAge = (-1).seconds)) },
            "an empty proxy URL" to { enclave.client(transport = Transport.Ehbp("")) },
            "a proxy over HTTP that is not on this machine" to {
                enclave.client(transport = Transport.Ehbp("http://proxy.example/"))
            },
            "a proxy with credentials" to {
                enclave.client(transport = Transport.Ehbp("https://user:hunter2@proxy.example/"))
            },
            "a proxy with an empty user" to { enclave.client(transport = Transport.Ehbp("https://@proxy.example/")) },
            "a proxy with a query" to {
                enclave.client(transport = Transport.Ehbp("https://proxy.example/?key=hunter2"))
            },
            "a proxy with an empty query" to { enclave.client(transport = Transport.Ehbp("https://proxy.example/v1?")) },
            "a proxy with a fragment" to { enclave.client(transport = Transport.Ehbp("https://proxy.example/v1#hunter2")) },
            "a proxy with an empty fragment" to { enclave.client(transport = Transport.Ehbp("https://proxy.example/#")) },
            "a proxy without a scheme" to { enclave.client(transport = Transport.Ehbp("proxy.example/v1")) },
            "a relative proxy" to { enclave.client(transport = Transport.Ehbp("/v1")) },
            "a proxy without slashes" to { enclave.client(transport = Transport.Ehbp("https:proxy.example/v1")) },
            "a proxy in another scheme" to { enclave.client(transport = Transport.Ehbp("ftp://proxy.example/")) },
            "a proxy with a backslash" to { enclave.client(transport = Transport.Ehbp("https://proxy.example\\@evil.example/")) },
            "a proxy on the enclave's origin" to { enclave.client(transport = Transport.Ehbp(origin)) },
            "a relay that is a URL" to { enclave.client(attestationRelay = "https://relay.example/x") },
            "a relay that is not ASCII" to { enclave.client(attestationRelay = "\u212Aelay.example") },
            "an enclave that is not ASCII" to { enclave.client(enclave = "\u212Aexample.com") },
            "an enclave that a resolver reads as an address" to { enclave.client(enclave = "127.1:${enclave.port}") },
        )
        for ((name, create) in refused) {
            val error = try {
                create()
                null
            } catch (e: ConfigurationException) {
                e
            } catch (e: Exception) {
                throw AssertionError("$name failed with $e, not a ConfigurationException", e)
            }
            assertNotNull(error, "$name was accepted")
            assertFalse(error.message!!.contains("hunter2"), "$name: the message echoes a secret: ${error.message}")
            assertNothingWasSent()
        }
    }

    @Test
    fun anEmptyStringOptionIsRefusedByNameAndNotReadAsNotSet() = test {
        val refused: Map<String, suspend () -> Unit> = mapOf(
            "proxy URL" to { enclave.client(transport = Transport.Ehbp("")) },
            "attestationRelay" to { enclave.client(attestationRelay = "") },
            "enclave" to { enclave.client(enclave = "") },
        )
        for ((option, create) in refused) {
            val error = assertFailsWith<ConfigurationException>(option) { create() }
            assertTrue(error.detail.startsWith(option), "$option: ${error.detail}")
            assertNothingWasSent()
        }
        // Null is how an option is left unset.
        val client = enclave.client(transport = Transport.Tls)
        assertEquals("https://${enclave.host}/".toHttpUrl(), client.baseUrl)
    }

    @Test
    fun aConfigThatTheCallerApprovesIsVerifiedWithoutAPin() = test {
        val pins = CopyOnWriteArrayList<Pin>()
        val inner = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin -> inner(document, nonce, pin.also { pins += it }) }
        val authorize = ConfigAuthorizer { }
        enclave.client(trust = Trust.AuthorizedBy(authorize)).use {
            assertEquals(Trust.AuthorizedBy(authorize), it.trust)
            assertEquals(listOf(Pin.NONE), pins.toList())
        }
        val request = enclave.verifierRequests.last()
        assertSame(authorize, assertIs<VerifierOptions.ConfigTrust.Authorizer>(request.config).authorizer)
    }

    @Test
    fun theTrustAndThePolicyBuildTheVerifier() = test {
        val policy = Policy(
            pinnedRegisters = Measurement("https://tinfoil.sh/predicate/tdx-guest/v2", listOf("ab")),
            freshnessMaxAge = 1.hours,
            artifacts = ArtifactTrust.EndorsedArtifacts(listOf("key")),
        )
        enclave.client(trust = Trust.ProjectPin("org/project", listOf("registry")), policy = policy).close()

        val request = enclave.verifierRequests.single()
        assertEquals(listOf("registry"), assertIs<VerifierOptions.ConfigTrust.Registries>(request.config).ids)
        assertEquals(policy.pinnedRegisters, request.policy.pinnedRegisters)
        assertEquals(3_600_000_000_000, request.policy.freshnessMaxAgeNs)
        assertEquals(listOf("key"), assertIs<VerifierOptions.Artifacts.Endorsed>(request.policy.artifacts).freshnessKeysPem)
    }

    @Test
    fun anEnclaveWhoseAttestationEndorsesNoTlsKeyIsRefused() = test {
        enclave.endorsed = { null }

        val error = assertFailsWith<AttestationException> { enclave.client() }

        assertTrue(error.detail.contains("\"tls\""), error.detail)
        assertEquals(2, enclave.fetches, "tried once more against fresh evidence")
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aFailedCreationLeavesNothingBehind() = test {
        enclave.verifier.verify = { _, _, _ -> throw AttestationException("policy: not this one") }
        val results = CopyOnWriteArrayList<Result<Verification>>()

        val error = assertFailsWith<AttestationException> { enclave.client(onVerificationResult = { results += it }) }

        assertEquals("policy: not this one", error.detail)
        awaitUntil { results.isNotEmpty() }
        Thread.sleep(50)
        assertEquals(1, results.size, "one result for one verification, however many attempts")
        assertSame(error, results.single().exceptionOrNull())
    }

    // The rules for requests.

    @Test
    fun requestsThatCouldLeakCredentialsAreRefusedBeforeAnyIo() = test {
        val client = enclave.client()
        // An expired verification, so that a request that got past the rules
        // would be seen to verify.
        enclave.clock.advance(enclave.lifetimeSeconds)
        val refused = mapOf(
            "another host" to Request.Builder().url("https://evil.example:${enclave.port}/v1/models"),
            "another port" to Request.Builder().url("https://localhost:${enclave.relay.port}/"),
            "the default port" to Request.Builder().url("https://localhost/"),
            "plain HTTP" to Request.Builder().url("http://${enclave.host}/v1/models"),
            "plain HTTP on the default port" to Request.Builder().url("http://localhost/"),
            "a host that only starts like the enclave" to Request.Builder().url("https://localhost.evil.example:${enclave.port}/"),
            "credentials in the URL" to Request.Builder().url("https://user:hunter2@${enclave.host}/"),
            "a user in the URL" to Request.Builder().url("https://user@${enclave.host}/"),
            "a Host header" to Request.Builder().url(enclave.url()).header("Host", "evil.example"),
            "a host header in another case" to Request.Builder().url(enclave.url()).header("hOST", enclave.host),
        )
        for ((name, builder) in refused) {
            val request = builder.header("Authorization", "Bearer hunter2").build()

            val error = assertFailsWith<ConfigurationException>(name) { client.execute(request) }
            assertFalse(error.message!!.contains("hunter2"), "$name: ${error.message}")
            val viaCall = assertFailsWith<ConfigurationException>(name) { client.newCall(request).execute() }
            assertFalse(viaCall.message!!.contains("hunter2"), "$name: ${viaCall.message}")
        }
        assertEquals(1, enclave.fetches, "a refused request does not verify")
        assertEquals(0, enclave.server.requestCount)
        assertEquals(1, enclave.relay.requestCount, "nothing went to the other origin")
    }

    @Test
    fun aRedirectIsReturnedAndNotFollowed() = test {
        val client = enclave.client()
        enclave.server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", enclave.url("/elsewhere")))
        enclave.server.enqueue(MockResponse().setResponseCode(307).setHeader("Location", "https://evil.example/"))

        client.execute(enclave.get("/a")).use { response ->
            assertEquals(302, response.code)
            assertEquals(enclave.url("/elsewhere").toString(), response.header("Location"))
        }
        client.newCall(enclave.get("/b")).execute().use { assertEquals(307, it.code) }

        assertEquals(2, enclave.server.requestCount)
        assertEquals("/a", enclave.server.takeRequest().path)
        assertEquals("/b", enclave.server.takeRequest().path)
    }

    @Test
    fun anAuthenticationChallengeIsReturnedAndNotAnswered() = test {
        val client = enclave.client()
        enclave.server.enqueue(MockResponse().setResponseCode(401).setHeader("WWW-Authenticate", "Basic realm=x"))
        enclave.server.enqueue(MockResponse().setResponseCode(407).setHeader("Proxy-Authenticate", "Basic realm=x"))

        client.execute(enclave.get()).use { assertEquals(401, it.code) }
        // A proxy's challenge from something that is not a proxy is a
        // protocol error; either way nothing is sent in answer.
        assertFailsWith<IOException> { client.execute(enclave.get()) }
        assertEquals(2, enclave.server.requestCount)
    }

    @Test
    fun noCookiesAreKept() = test {
        val client = enclave.client()
        enclave.server.enqueue(ok().setHeader("Set-Cookie", "session=1; Path=/"))
        enclave.server.enqueue(ok())

        client.execute(enclave.get()).close()
        client.execute(enclave.get()).close()

        enclave.server.takeRequest()
        assertNull(enclave.server.takeRequest().getHeader("Cookie"))
    }

    // The pin.

    @Test
    fun aRequestReachesAnEnclaveThatHoldsTheAttestedKey() = test {
        val client = enclave.client()
        enclave.server.enqueue(ok("hello"))

        val body = "{}".toRequestBody("application/json".toMediaType())
        val response = client.execute(
            Request.Builder().url(enclave.url("/v1/chat")).header("Authorization", "Bearer k").post(body).build(),
        )

        assertEquals("hello", response.text())
        val received = enclave.server.takeRequest()
        assertEquals("POST", received.method)
        assertEquals("Bearer k", received.getHeader("Authorization"))
        assertEquals("{}", received.body.readUtf8())
    }

    @Test
    fun aValidChainForTheRightHostWithAnotherKeyReceivesNoRequest() = test {
        val other = enclave.authority.issue()
        enclave.endorsed = { other.fingerprint }
        val client = enclave.client()

        val error = assertFailsWith<AttestationException> {
            client.execute(enclave.get().newBuilder().header("Authorization", "Bearer hunter2").build())
        }

        assertTrue(error.detail.contains("does not carry the attested TLS key"), error.detail)
        assertTrue(error.detail.contains("after the enclave was verified again"), error.detail)
        assertFalse(error.toString().contains("hunter2"))
        assertEquals(0, enclave.server.requestCount, "the enclave's server saw no request")
        assertEquals(2, enclave.fetches, "verified at creation and once more after the mismatch")
    }

    @Test
    fun aServerWithAnotherKeyReceivesNoBytes() = test {
        RawTlsServer(enclave.authority.issue()) { countWhatArrives(it) }.use { server ->
            val attested = enclave.authority.issue()
            enclave.endorsed = { attested.fingerprint }
            val client = enclave.client(enclave = "localhost:${server.port}")
            val body = "secret".repeat(1000).toRequestBody()
            val request = Request.Builder().url("https://localhost:${server.port}/v1").post(body).build()

            assertFailsWith<AttestationException> { client.execute(request) }
            assertFailsWith<AttestationException> { client.newCall(request).execute() }

            awaitUntil { server.finished.get() == 4 }
            assertEquals(4, server.handshakes.get(), "two requests, each tried under two verifications")
            assertEquals(0, server.bytesReceived.get(), "no request byte followed any handshake")
        }
    }

    @Test
    fun aPinDoesNotReplaceChainValidation() = test {
        // The enclave's key is the attested one, but nothing that the client
        // trusts vouches for its certificate.
        val untrusted = sh.tinfoil.testing.TestAuthority()
        enclaveWith { untrusted.issue() }
        val client = enclave.client()

        val error = assertFailsWith<AttestationException> { client.execute(enclave.get()) }

        assertTrue(error.detail.contains("certificate was refused"), error.detail)
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aPinDoesNotReplaceTheHostnameCheck() = test {
        enclaveWith { it.issue(host = "other.example") }
        val client = enclave.client()

        val error = assertFailsWith<AttestationException> { client.execute(enclave.get()) }

        assertTrue(error.detail.contains("certificate was refused"), error.detail)
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun onlyTheLeafCertificateMayCarryTheAttestedKey() = test {
        // The authority's key is in the validated chain, but it is not the
        // enclave's.
        enclave.endorsed = { enclave.authority.fingerprint }
        val client = enclave.client()

        assertFailsWith<AttestationException> { client.execute(enclave.get()) }

        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aNewCertificateForTheSameKeyIsAccepted() = test {
        val client = enclave.client()
        val attested = enclave.certificate.fingerprint
        enclave.server.shutdown()
        val renewed = enclave.authority.reissue(enclave.certificate)
        assertNotEquals(enclave.certificate.certificate, renewed.certificate)
        sh.tinfoil.testing.httpsServer(renewed, enclave.port).use { server ->
            server.enqueue(ok("renewed"))

            assertEquals("renewed", client.execute(enclave.get()).text())
            assertEquals(attested, client.current?.tlsPublicKeyFingerprint)
            assertEquals(1, enclave.fetches, "the key is what is attested, so nothing was verified again")
        }
    }

    // Connections.

    @Test
    fun sequentialRequestsReuseOneConnection() = test {
        val client = enclave.client()
        repeat(3) { enclave.server.enqueue(ok()) }

        client.execute(enclave.get()).text()
        client.newCall(enclave.get()).execute().text()
        client.execute(enclave.get()).text()

        assertEquals(listOf(0, 1, 2), List(3) { enclave.server.takeRequest().sequenceNumber })
    }

    @Test
    fun aNewVerificationRetiresTheConnectionsOfTheLast() = test {
        val client = enclave.client()
        repeat(3) { enclave.server.enqueue(ok()) }
        client.execute(enclave.get()).text()
        client.execute(enclave.get()).text()

        val before = client.current
        enclave.clock.advance(1)
        val after = client.reverify()
        client.execute(enclave.get()).text()

        assertNotEquals(before, after)
        assertSame(after, client.current)
        assertEquals(2, enclave.fetches)
        assertEquals(listOf(0, 1, 0), List(3) { enclave.server.takeRequest().sequenceNumber })
    }

    // Recovery.

    @Test
    fun aKeyThatWasRotatedSinceVerificationIsVerifiedAgainAndTheRequestReplayedOnce() = test {
        val stale = enclave.authority.issue().fingerprint
        val endorsements = ArrayDeque(listOf(stale, enclave.certificate.fingerprint))
        enclave.endorsed = { endorsements.removeFirst() }
        val results = CopyOnWriteArrayList<Result<Verification>>()
        val client = enclave.client(onVerificationResult = { results += it })
        enclave.server.enqueue(ok("after rotation"))

        val body = "payload".toRequestBody()
        val response = client.execute(Request.Builder().url(enclave.url("/v1")).post(body).build())

        assertEquals("after rotation", response.text())
        assertEquals(1, enclave.server.requestCount, "the request arrived once")
        assertEquals("payload", enclave.server.takeRequest().body.readUtf8())
        assertEquals(2, enclave.fetches)
        awaitUntil { results.size == 2 }
        assertEquals(listOf(stale, enclave.certificate.fingerprint), results.map { it.getOrThrow().tlsPublicKeyFingerprint })
        assertEquals(enclave.certificate.fingerprint, client.current?.tlsPublicKeyFingerprint)
    }

    @Test
    fun anEnclaveThatRestartsWithANewKeyIsVerifiedAgainOverFreshConnections() = test {
        val client = enclave.client()
        enclave.server.enqueue(ok("before"))
        assertEquals("before", client.execute(enclave.get()).text())
        val first = enclave.certificate.fingerprint

        enclave.rotateKey()
        enclave.server.enqueue(ok("after"))
        val response = client.newCall(enclave.get()).execute()

        assertEquals("after", response.text())
        assertNotEquals(first, enclave.certificate.fingerprint)
        assertEquals(enclave.certificate.fingerprint, client.current?.tlsPublicKeyFingerprint)
        assertEquals(2, enclave.fetches)
        assertEquals(1, enclave.server.requestCount)
        assertEquals(0, enclave.server.takeRequest().sequenceNumber)
    }

    @Test
    fun aBodyThatCanBeSentOnlyOnceIsNotReplayed() = test {
        val stale = enclave.authority.issue().fingerprint
        val endorsements = ArrayDeque(listOf(stale, enclave.certificate.fingerprint))
        enclave.endorsed = { endorsements.removeFirst() }
        val client = enclave.client()
        val writes = AtomicInteger()
        val oneShot = object : RequestBody() {
            override fun contentType() = null

            override fun isOneShot() = true

            override fun writeTo(sink: BufferedSink) {
                writes.incrementAndGet()
                sink.writeUtf8("once")
            }
        }

        val error = assertFailsWith<AttestationException> {
            client.execute(Request.Builder().url(enclave.url()).post(oneShot).build())
        }

        assertTrue(error.detail.contains("can be sent only once"), error.detail)
        assertEquals(0, writes.get(), "the body was never read")
        assertEquals(0, enclave.server.requestCount)
        assertEquals(1, enclave.fetches, "nothing is verified for a request that will not be sent again")

        // The rejected verification is not used again: the next request
        // verifies first.
        enclave.server.enqueue(ok())
        client.execute(enclave.get()).close()
        assertEquals(2, enclave.fetches)
    }

    @Test
    fun aRequestIsNotSentWhenVerifyingAgainFails() = test {
        val stale = enclave.authority.issue().fingerprint
        enclave.endorsed = { stale }
        val client = enclave.client()
        enclave.relay.dispatcher = status(503)

        val error = assertFailsWith<NetworkException> { client.execute(enclave.get()) }

        assertEquals(503, error.status)
        assertEquals(0, enclave.server.requestCount)
        assertEquals(3, enclave.fetches, "one at creation, then two attempts to verify again")
    }

    // Freshness.

    @Test
    fun aVerificationIsUsedUntilItsDeadlineAndNotAtIt() = test {
        val client = enclave.client()
        repeat(2) { enclave.server.enqueue(ok()) }

        enclave.clock.advance(enclave.lifetimeSeconds - 1)
        client.execute(enclave.get()).close()
        assertEquals(1, enclave.fetches, "one second before the deadline")

        enclave.clock.advance(1)
        client.execute(enclave.get()).close()
        assertEquals(2, enclave.fetches, "at the deadline")
        assertEquals(2, enclave.server.requestCount)
    }

    @Test
    fun anExpiredVerificationIsNeverUsedWhenVerifyingAgainFails() = test {
        val results = CopyOnWriteArrayList<Result<Verification>>()
        val client = enclave.client(onVerificationResult = { results += it })
        enclave.server.enqueue(ok())
        client.execute(enclave.get()).close()

        enclave.clock.advance(enclave.lifetimeSeconds)
        enclave.relay.dispatcher = status(500)

        val failed = assertFailsWith<NetworkException> { client.execute(enclave.get()) }
        assertEquals(500, failed.status)
        assertFailsWith<NetworkException> { client.newCall(enclave.get()).execute() }
        assertFailsWith<NetworkException> { client.ensureVerified() }
        assertEquals(1, enclave.server.requestCount, "nothing was sent under the expired verification")
        assertNotNull(client.current, "the last verification is still reported, unchecked")
        awaitUntil { results.size == 4 }
        assertEquals(listOf(true, false, false, false), results.map { it.isSuccess })
    }

    @Test
    fun aVerificationThatExpiresWhileItIsCheckedIsNotUsed() = test {
        val check = VerificationCheck { enclave.clock.advance(enclave.lifetimeSeconds) }

        val error = assertFailsWith<AttestationException> { enclave.client(verificationCheck = check) }

        assertTrue(error.detail.contains("freshness deadline"), error.detail)
        assertEquals(2, enclave.fetches, "tried once more against fresh evidence")
    }

    @Test
    fun aFailedReverificationKeepsAVerificationThatIsStillValid() = test {
        val client = enclave.client()
        val valid = client.current
        enclave.relay.dispatcher = status(502)

        assertFailsWith<NetworkException> { client.reverify() }

        enclave.server.enqueue(ok())
        client.execute(enclave.get()).close()
        assertSame(valid, client.current)
        assertSame(valid, client.ensureVerified())
    }

    // Shared verifications.

    @Test
    fun concurrentRequestsShareOneVerification() = test {
        val client = enclave.client()
        enclave.clock.advance(enclave.lifetimeSeconds)
        val release = CountDownLatch(1)
        val verifying = CountDownLatch(1)
        val inner = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin ->
            verifying.countDown()
            release.await(30, TimeUnit.SECONDS)
            inner(document, nonce, pin)
        }
        enclave.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = ok()
        }

        val requests = List(12) { index ->
            async(Dispatchers.IO) {
                if (index % 2 == 0) client.execute(enclave.get()).text() else client.newCall(enclave.get()).execute().text()
            }
        }
        val explicit = async(Dispatchers.IO) { client.ensureVerified() }
        verifying.await(30, TimeUnit.SECONDS)
        Thread.sleep(200)
        release.countDown()

        assertEquals(List(12) { "ok" }, requests.awaitAll())
        assertSame(client.current, explicit.await())
        assertEquals(2, enclave.fetches, "one at creation and one for everyone who waited")
        assertEquals(2, enclave.verifier.verifications.get())
        assertEquals(12, enclave.server.requestCount)
    }

    @Test
    fun cancellingOneWaiterLeavesTheSharedVerificationToTheOthers() = test {
        val client = enclave.client()
        val release = CountDownLatch(1)
        val verifying = CountDownLatch(1)
        val inner = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin ->
            verifying.countDown()
            release.await(30, TimeUnit.SECONDS)
            inner(document, nonce, pin)
        }
        enclave.clock.advance(enclave.lifetimeSeconds)

        val cancelled = launch(Dispatchers.IO) { client.ensureVerified() }
        val request = launch(Dispatchers.IO) { client.execute(enclave.get()) }
        val patient = async(Dispatchers.IO) { client.ensureVerified() }
        verifying.await(30, TimeUnit.SECONDS)
        Thread.sleep(100)
        cancelled.cancelAndJoin()
        request.cancelAndJoin()
        assertTrue(cancelled.isCancelled && request.isCancelled)
        release.countDown()

        val verified = patient.await()
        assertSame(client.current, verified)
        assertEquals(2, enclave.verifier.verifications.get(), "the shared verification ran once, to its end")
        assertEquals(0, enclave.server.requestCount, "the cancelled request was never sent")
    }

    @Test
    fun aFailedVerificationIsSharedAndTheNextCallStartsAnother() = test {
        val client = enclave.client()
        enclave.clock.advance(enclave.lifetimeSeconds)
        val release = CountDownLatch(1)
        enclave.verifier.verify = { _, _, _ ->
            release.await(30, TimeUnit.SECONDS)
            throw ConfigurationException("not usable")
        }

        val waiters = List(4) { async(Dispatchers.IO) { runCatching { client.ensureVerified() }.exceptionOrNull() } }
        Thread.sleep(200)
        release.countDown()
        val failures = waiters.awaitAll()

        assertIs<ConfigurationException>(failures.first())
        assertTrue(failures.all { it === failures.first() }, "every waiter got the one failure")
        assertEquals(2, enclave.verifier.verifications.get(), "a configuration error is not tried again")
        assertFailsWith<ConfigurationException> { client.ensureVerified() }
        assertEquals(3, enclave.verifier.verifications.get(), "a failure is not remembered")
    }

    // The caller's check and observer.

    @Test
    fun theCheckSeesEveryVerificationBeforeItsKeysAreUsed() = test {
        val seen = CopyOnWriteArrayList<Verification>()
        val requestsAtCheck = CopyOnWriteArrayList<Int>()
        val client = enclave.client(
            verificationCheck = {
                seen += it
                requestsAtCheck += enclave.server.requestCount
            },
        )
        enclave.server.enqueue(ok())
        client.execute(enclave.get()).close()
        enclave.clock.advance(enclave.lifetimeSeconds)
        enclave.server.enqueue(ok())
        client.execute(enclave.get()).close()
        val third = client.reverify()

        assertEquals(3, seen.size)
        assertSame(third, seen.last())
        assertEquals(listOf(0, 1, 2), requestsAtCheck.toList())
    }

    @Test
    fun aRejectionByTheCheckIsAnAttestationErrorThatIsNotRetried() = test {
        val reason = IllegalStateException("not the measurement that I expect")
        val results = CopyOnWriteArrayList<Result<Verification>>()

        val error = assertFailsWith<AttestationException> {
            enclave.client(verificationCheck = { throw reason }, onVerificationResult = { results += it })
        }

        assertSame(reason, error.cause)
        assertTrue(error.detail.contains("verification check rejected ${enclave.host}"), error.detail)
        assertEquals(1, enclave.fetches, "a rejection is a decision, not a fault to retry")
        awaitUntil { results.size == 1 }
        assertSame(error, results.single().exceptionOrNull())
    }

    @Test
    fun aRejectionOnceTheLastVerificationHasExpiredStopsRequests() = test {
        val accept = AtomicInteger(1)
        val client = enclave.client(
            verificationCheck = { if (accept.getAndDecrement() <= 0) throw IOException("changed") },
        )
        enclave.server.enqueue(ok())
        client.execute(enclave.get()).close()
        enclave.clock.advance(enclave.lifetimeSeconds)

        assertFailsWith<AttestationException> { client.execute(enclave.get()) }
        assertFailsWith<AttestationException> { client.newCall(enclave.get()).execute() }

        assertEquals(1, enclave.server.requestCount)
    }

    @Test
    fun aRejectedReverificationLeavesAValidVerificationInUseUntilItsDeadline() = test {
        val accept = AtomicInteger(1)
        val client = enclave.client(
            verificationCheck = { if (accept.getAndDecrement() <= 0) throw IOException("changed") },
        )
        val valid = client.current
        enclave.clock.advance(enclave.lifetimeSeconds - 1)

        assertFailsWith<AttestationException> { client.reverify() }
        enclave.verifier.verify = { _, _, _ -> throw AttestationException("policy: no longer") }
        assertFailsWith<AttestationException> { client.reverify() }

        enclave.server.enqueue(ok("still served"))
        assertEquals("still served", client.execute(enclave.get()).text())
        assertSame(valid, client.current)
        assertSame(valid, client.ensureVerified())

        enclave.clock.advance(1)
        assertFailsWith<AttestationException> { client.execute(enclave.get()) }
        assertEquals(1, enclave.server.requestCount, "nothing is sent once the deadline is reached")

        client.close()
        assertFailsWith<ConfigurationException> { client.execute(enclave.get()) }
    }

    @Test
    fun aCheckThatThrowsAnErrorRejectsTheEnclave() = test {
        val results = CopyOnWriteArrayList<Result<Verification>>()

        val error = assertFailsWith<AttestationException> {
            enclave.client(verificationCheck = { throw AssertionError("not what I expect") }, onVerificationResult = { results += it })
        }

        assertIs<AssertionError>(error.cause)
        assertEquals(1, enclave.fetches, "not tried again")
        awaitUntil { results.size == 1 }
        assertSame(error, results.single().exceptionOrNull())
    }

    @Test
    fun anObserverThatThrowsAnErrorChangesNothing() = test {
        val calls = AtomicInteger()
        val client = enclave.client(
            onVerificationResult = {
                calls.incrementAndGet()
                throw NotImplementedError("observer failure")
            },
        )
        enclave.server.enqueue(ok())

        client.reverify()
        client.execute(enclave.get()).close()

        awaitUntil { calls.get() == 2 }
        assertEquals(1, enclave.server.requestCount)
    }

    @Test
    fun anObserverMayCallBackIntoTheClientOnSuccess() = test {
        val holder = java.util.concurrent.atomic.AtomicReference<EnclaveHttpClient>()
        val reentered = CopyOnWriteArrayList<Verification>()
        val client = enclave.client(
            onVerificationResult = { result ->
                val client = holder.get()
                if (client != null && result.isSuccess) {
                    reentered += runBlocking { client.ensureVerified() }
                    enclave.server.enqueue(ok("from the observer"))
                    client.newCall(enclave.get()).execute().close()
                }
            },
        )
        holder.set(client)

        val verified = client.reverify()

        awaitUntil { enclave.server.requestCount == 1 }
        assertSame(verified, reentered.single(), "the observer finds the verification that it was told of")
        enclave.server.enqueue(ok())
        client.execute(enclave.get()).close()
        assertEquals(2, enclave.fetches)
    }

    @Test
    fun anObserverMayVerifyAgainOnFailure() = test {
        val holder = java.util.concurrent.atomic.AtomicReference<EnclaveHttpClient>()
        val retried = CopyOnWriteArrayList<Result<Verification>>()
        val serving = enclave.relay.dispatcher
        val client = enclave.client(
            onVerificationResult = { result ->
                val client = holder.get()
                if (client != null && result.isFailure) {
                    enclave.relay.dispatcher = serving
                    retried += runBlocking { runCatching { client.reverify() } }
                    retried += runBlocking { runCatching { client.ensureVerified() } }
                }
            },
        )
        holder.set(client)
        enclave.clock.advance(enclave.lifetimeSeconds)
        enclave.relay.dispatcher = status(503)

        assertFailsWith<NetworkException> { client.ensureVerified() }

        awaitUntil { retried.size == 2 }
        assertTrue(retried.all { it.isSuccess }, "$retried")
        enclave.server.enqueue(ok())
        client.execute(enclave.get()).close()
        assertSame(retried.last().getOrThrow(), client.current)
    }

    @Test
    fun blockedCallersDoNotStarveTheVerificationThatTheyWaitFor() = test {
        val client = enclave.client()
        enclave.clock.advance(enclave.lifetimeSeconds)
        enclave.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = ok()
        }

        // More blocking calls than the shared pool for blocking work has
        // threads, each of which needs the one verification.
        val calls = List(100) { client.newCall(enclave.get()) }
        val bodies = calls.map { async(Dispatchers.IO) { it.execute().text() } }

        try {
            assertEquals(List(100) { "ok" }, withTimeout(30.seconds) { bodies.awaitAll() })
        } finally {
            // Frees the threads of a run that did starve.
            calls.forEach { it.cancel() }
        }
        assertEquals(2, enclave.fetches)
    }

    @Test
    fun anObserverThatThrowsChangesNothing() = test {
        val calls = AtomicInteger()
        val client = enclave.client(
            onVerificationResult = {
                calls.incrementAndGet()
                throw IllegalStateException("observer failure")
            },
        )
        enclave.server.enqueue(ok())

        client.execute(enclave.get()).close()
        client.reverify()

        awaitUntil { calls.get() == 2 }
        assertEquals(2, calls.get())
        assertEquals(1, enclave.server.requestCount)
    }

    // Closing.

    @Test
    fun aClosedClientRefusesRequestsAndVerifications() = test {
        val client = enclave.client()
        client.close()
        client.close()

        for (attempt in listOf<suspend () -> Unit>(
            { client.execute(enclave.get()) },
            { client.newCall(enclave.get()).execute() },
            { client.ensureVerified() },
            { client.reverify() },
        )) {
            val error = assertFailsWith<ConfigurationException> { attempt() }
            assertEquals("the client is closed", error.detail)
        }
        assertEquals(0, enclave.server.requestCount)
        assertEquals(1, enclave.fetches)
        assertNotNull(client.current)
    }

    @Test
    fun closingCancelsAVerificationInProgress() = test {
        val results = CopyOnWriteArrayList<Result<Verification>>()
        val client = enclave.client(onVerificationResult = { results += it })
        val first = client.current
        val verifying = CountDownLatch(1)
        val release = CountDownLatch(1)
        val inner = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin ->
            verifying.countDown()
            release.await(30, TimeUnit.SECONDS)
            inner(document, nonce, pin)
        }
        enclave.clock.advance(enclave.lifetimeSeconds)

        val waiter = async(Dispatchers.IO) { runCatching { client.ensureVerified() }.exceptionOrNull() }
        val request = async(Dispatchers.IO) { runCatching { client.execute(enclave.get()) }.exceptionOrNull() }
        verifying.await(30, TimeUnit.SECONDS)
        client.close()

        assertIs<ConfigurationException>(waiter.await())
        assertIs<ConfigurationException>(request.await())
        release.countDown()
        Thread.sleep(100)
        assertEquals(0, enclave.server.requestCount)
        awaitUntil { results.size >= 1 }
        assertEquals(1, results.size, "a verification that the close ended is not reported")
        assertSame(first, client.current, "a verification that finishes after the close is not kept")
    }

    @Test
    fun closingCancelsRequestsInFlight() = test {
        val client = enclave.client()
        enclave.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = if (request.path == "/slow") {
                ok().setHeadersDelay(2, TimeUnit.SECONDS)
            } else {
                ok("x".repeat(1 shl 20)).throttleBody(1024, 1, TimeUnit.SECONDS)
            }
        }

        val waiting = async(Dispatchers.IO) { runCatching { client.execute(enclave.get("/slow")) }.exceptionOrNull() }
        val streaming = client.execute(enclave.get("/stream"))
        awaitUntil { enclave.server.requestCount == 2 }
        client.close()

        assertIs<IOException>(waiting.await())
        assertFailsWith<IOException> { streaming.body!!.string() }
    }

    @Test
    fun aResponseKeepsStreamingWhenItsVerificationIsReplacedAndEndsWhenTheClientCloses() = test {
        val client = enclave.client()
        enclave.server.enqueue(ok("x".repeat(8192)).throttleBody(1024, 100, TimeUnit.MILLISECONDS))
        enclave.server.enqueue(ok("x".repeat(1 shl 20)).throttleBody(1024, 1, TimeUnit.SECONDS))

        val finishing = client.execute(enclave.get())
        val ending = client.execute(enclave.get())
        client.reverify()
        assertEquals(8192, finishing.text().length, "a newer verification does not interrupt a response")
        client.close()

        assertFailsWith<IOException> { ending.body!!.string() }
    }

    // As an OkHttp call factory.

    @Test
    fun anEnqueuedCallDeliversItsResponse() = test {
        val client = enclave.client()
        enclave.server.enqueue(ok("queued"))
        val outcome = Outcome()

        val call = client.newCall(enclave.get())
        call.enqueue(outcome)

        assertEquals("queued", outcome.response().text())
        assertTrue(call.isExecuted())
        assertFalse(call.isCanceled())
        assertSame(call, outcome.call)
    }

    @Test
    fun anEnqueuedCallDeliversThisSdksErrorsAsIoExceptions() = test {
        val other = enclave.authority.issue()
        enclave.endorsed = { other.fingerprint }
        val client = enclave.client()

        val offOrigin = Outcome().also { client.newCall(Request.Builder().url("https://evil.example/").build()).enqueue(it) }
        val mismatch = Outcome().also { client.newCall(enclave.get()).enqueue(it) }

        assertIs<ConfigurationException>(offOrigin.failure())
        assertIs<AttestationException>(mismatch.failure())
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aCallRunsOnceAndItsCloneRunsAgain() = test {
        val client = enclave.client()
        repeat(2) { enclave.server.enqueue(ok()) }
        val call = client.newCall(enclave.get("/once"))
        assertFalse(call.isExecuted())
        assertSame(call.request(), call.clone().request())

        call.execute().close()

        assertFailsWith<IllegalStateException> { call.execute() }
        assertFailsWith<IllegalStateException> { call.enqueue(Outcome()) }
        call.clone().execute().close()
        assertEquals(2, enclave.server.requestCount)
    }

    @Test
    fun aCallCancelledBeforeItRunsSendsNothing() = test {
        val client = enclave.client()
        val call = client.newCall(enclave.get())
        call.cancel()

        assertTrue(call.isCanceled())
        val error = assertFailsWith<IOException> { call.execute() }
        assertEquals("Canceled", error.message)
        val queued = Outcome().also { client.newCall(enclave.get()).apply { cancel() }.enqueue(it) }
        assertEquals("Canceled", queued.failure().message)
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aCallCanBeCancelledWhileItWaitsForAVerification() = test {
        val client = enclave.client()
        val verifying = CountDownLatch(1)
        val release = CountDownLatch(1)
        val inner = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin ->
            verifying.countDown()
            release.await(30, TimeUnit.SECONDS)
            inner(document, nonce, pin)
        }
        enclave.clock.advance(enclave.lifetimeSeconds)

        val blocking = client.newCall(enclave.get())
        val result = async(Dispatchers.IO) { runCatching { blocking.execute() }.exceptionOrNull() }
        val queued = client.newCall(enclave.get())
        val outcome = Outcome().also { queued.enqueue(it) }
        verifying.await(30, TimeUnit.SECONDS)
        Thread.sleep(100)
        blocking.cancel()
        queued.cancel()

        assertEquals("Canceled", assertIs<IOException>(result.await()).message)
        assertEquals("Canceled", outcome.failure().message)
        release.countDown()
        client.ensureVerified()
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aCallCanBeCancelledWhileItWaitsForTheResponseOrReadsIt() = test {
        val client = enclave.client()
        enclave.server.enqueue(ok().setHeadersDelay(2, TimeUnit.SECONDS))
        enclave.server.enqueue(ok("x".repeat(1 shl 20)).throttleBody(1024, 1, TimeUnit.SECONDS))

        val waiting = client.newCall(enclave.get("/slow"))
        val result = async(Dispatchers.IO) { runCatching { waiting.execute() }.exceptionOrNull() }
        awaitUntil { enclave.server.requestCount == 1 }
        waiting.cancel()
        assertIs<IOException>(result.await())

        val streaming = client.newCall(enclave.get("/stream"))
        val response = streaming.execute()
        streaming.cancel()
        assertFailsWith<IOException> { response.body!!.string() }
    }

    @Test
    fun aCallsTimeoutSpansTheVerificationTheRequestAndTheBody() = test {
        val client = enclave.client()
        enclave.server.enqueue(ok().setHeadersDelay(2, TimeUnit.SECONDS))
        enclave.server.enqueue(ok("x".repeat(1 shl 20)).throttleBody(1024, 1, TimeUnit.SECONDS))

        val slowHeaders = client.newCall(enclave.get("/slow")).apply { timeout().timeout(300, TimeUnit.MILLISECONDS) }
        assertFailsWith<java.io.InterruptedIOException> { slowHeaders.execute() }

        val slowBody = client.newCall(enclave.get("/stream")).apply { timeout().timeout(500, TimeUnit.MILLISECONDS) }
        val response = slowBody.execute()
        assertFailsWith<IOException> { response.body!!.string() }

        val release = CountDownLatch(1)
        val inner = enclave.verifier.verify
        enclave.verifier.verify = { document, nonce, pin ->
            release.await(30, TimeUnit.SECONDS)
            inner(document, nonce, pin)
        }
        enclave.clock.advance(enclave.lifetimeSeconds)
        val slowVerification = client.newCall(enclave.get("/never")).apply { timeout().timeout(300, TimeUnit.MILLISECONDS) }
        val error = assertFailsWith<java.io.InterruptedIOException> { slowVerification.execute() }
        assertEquals("timeout", error.message)
        release.countDown()
        assertEquals(2, enclave.server.requestCount)
    }

    // Streaming.

    @Test
    fun aResponseThatIsNotReadIsNotBuffered() = test {
        val chunk = ByteArray(64 * 1024) { 'a'.code.toByte() }
        val certificate = enclave.authority.issue()
        enclave.endorsed = { certificate.fingerprint }
        RawTlsServer(certificate) { socket ->
            val input = socket.inputStream.bufferedReader()
            while (input.readLine().orEmpty().isNotEmpty()) {
                // Skip the request's headers.
            }
            val output = socket.outputStream
            output.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray())
            while (true) {
                output.write("${chunk.size.toString(16)}\r\n".toByteArray())
                output.write(chunk)
                output.write("\r\n".toByteArray())
                bytesSent.addAndGet(chunk.size.toLong())
            }
        }.use { server ->
            val client = enclave.client(enclave = "localhost:${server.port}")

            val response = client.execute(Request.Builder().url("https://localhost:${server.port}/stream").build())
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

            // Reading makes room for more.
            val source = response.body!!.source()
            source.skip(sent + 1024 * 1024)
            awaitUntil { server.bytesSent.get() > sent }
            response.close()
        }
    }

    private fun status(code: Int) = object : Dispatcher() {
        override fun dispatch(request: RecordedRequest) = MockResponse().setResponseCode(code)
    }

    /** Collects what an enqueued call delivers. */
    private class Outcome : okhttp3.Callback {
        private val done = CountDownLatch(1)
        private var response: Response? = null
        private var failure: IOException? = null

        @Volatile
        var call: okhttp3.Call? = null

        override fun onFailure(call: okhttp3.Call, e: IOException) {
            this.call = call
            failure = e
            done.countDown()
        }

        override fun onResponse(call: okhttp3.Call, response: Response) {
            this.call = call
            this.response = response
            done.countDown()
        }

        fun response(): Response {
            assertTrue(done.await(30, TimeUnit.SECONDS), "the callback was not called")
            return response ?: throw AssertionError("the call failed", failure)
        }

        fun failure(): IOException {
            assertTrue(done.await(30, TimeUnit.SECONDS), "the callback was not called")
            response?.close()
            return failure ?: throw AssertionError("the call succeeded")
        }
    }
}
