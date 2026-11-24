package sh.tinfoil

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import sh.tinfoil.internal.EnclaveConnection
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.RouterDiscovery
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.internal.verification.DocumentFetcher
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.testing.FakeVerifier
import sh.tinfoil.testing.ENCAPSULATED_KEY_HEADER
import sh.tinfoil.testing.ENCLAVE_URL_HEADER
import sh.tinfoil.testing.SealingDispatcher
import sh.tinfoil.testing.SealingKey
import sh.tinfoil.testing.containsText
import sh.tinfoil.testing.RawTlsServer
import sh.tinfoil.testing.TestAuthority
import sh.tinfoil.testing.VerifierRequest
import sh.tinfoil.testing.standInVerifiers
import sh.tinfoil.testing.TestClock
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.facts
import sh.tinfoil.testing.rejection
import sh.tinfoil.testing.fingerprint
import sh.tinfoil.testing.httpsServer
import sh.tinfoil.testing.verification
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource
import kotlin.time.TimeSource

class RouterHttpClientTest {
    private val authority = TestAuthority()
    private val clock = TestClock()
    private val closeables = CopyOnWriteArrayList<AutoCloseable>()

    /** Every pin that a document was verified against. */
    private val pins = CopyOnWriteArrayList<Pin>()

    /**
     * Endorses the TLS key that a document names, so that each router
     * decides what its own attestation says.
     */
    private val verifier = FakeVerifier { document, _, pin ->
        pins += pin
        val fingerprint = document.toString(Charsets.UTF_8)
        if (!Regex("[0-9a-f]{64}|malformed").matches(fingerprint)) {
            throw rejection(VerificationLayer.QUOTE, "the document does not verify")
        }
        verification(fingerprint, clock().plusSeconds(3600), hpkePublicKey = hpkeKeys[fingerprint]?.publicKey)
    }

    /** The HPKE key that each router holds, by the TLS key that its attestation names. */
    private val hpkeKeys = java.util.concurrent.ConcurrentHashMap<String, SealingKey>()

    /** A router: one HTTPS server that serves its attestation document and takes requests. */
    private inner class Router {
        val certificate = authority.issue()
        var server: MockWebServer = httpsServer(certificate)
            private set
        val host = "localhost:${server.port}"
        val fetches = AtomicInteger()
        val requests = CopyOnWriteArrayList<RecordedRequest>()

        /** The HPKE key that the router holds, and what it does with sealed requests. */
        val key = SealingKey()
        val sealing = SealingDispatcher({ key }) { it.reply("sealed by $host") }

        /** What the router answers a fetch of its attestation document with. */
        @Volatile
        var attestation: () -> MockResponse = { MockResponse().setBody(certificate.fingerprint) }

        private val dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                if (request.path!!.startsWith("/.well-known/tinfoil-attestation?nonce=")) {
                    fetches.incrementAndGet()
                    attestation()
                } else if (request.getHeader(ENCAPSULATED_KEY_HEADER) != null) {
                    requests += request
                    sealing.dispatch(request)
                } else {
                    requests += request
                    MockResponse().setBody("from $host")
                }
        }

        init {
            closeables += AutoCloseable { server.shutdown() }
            hpkeKeys[certificate.fingerprint] = key
            server.dispatcher = dispatcher
        }

        /**
         * Replaces the server with one at the same address that holds a
         * certificate with another key, which the test authority issued
         * too, and that still serves the first attestation document: what
         * a host does that passes on an attestation that is not its own.
         */
        fun presentAnotherKey() {
            server.shutdown()
            server = httpsServer(authority.issue(), server.port).also { it.dispatcher = dispatcher }
        }

        fun unreachable() = apply { attestation = { MockResponse().setResponseCode(503) } }

        fun unverifiable() = apply { attestation = { MockResponse().setBody("not a document that verifies") } }
    }

    /** A router that completes a TLS handshake and then never answers. */
    private fun silentRouter(): RawTlsServer = RawTlsServer(authority.issue()) { socket ->
        socket.soTimeout = 60_000
        while (socket.inputStream.read() >= 0) {
            // Whatever is asked, nothing is answered.
        }
    }.also { closeables += it }

    private val RawTlsServer.host: String get() = "localhost:$port"

    private val fallback = Router()
    private val listServer: MockWebServer = httpsServer(authority.issue()).also { server ->
        closeables += AutoCloseable { server.shutdown() }
    }

    private fun serveList(vararg hosts: String) {
        serveList(MockResponse().setBody(hosts.joinToString(",", "[", "]") { "\"$it\"" }))
    }

    private fun serveList(response: MockResponse) {
        listServer.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = response
        }
    }

    /** What each client asked of the verifier library's constructor. */
    private val verifierRequests = CopyOnWriteArrayList<VerifierRequest>()

    private fun internals(
        budget: Duration = 30.seconds,
        timeSource: TimeSource = TimeSource.Monotonic,
        fallbackHost: String = fallback.host,
        verifier: AttestationVerifier = this.verifier,
    ) = Internals(
        http = HttpSettings(trust = authority.trust),
        clock = clock,
        retryDelay = 1.milliseconds,
        discovery = RouterDiscovery.Settings(
            listUrl = listServer.url("/routers"),
            fallback = fallbackHost,
            budget = budget,
            timeSource = timeSource,
            // The list's order, so that a test knows which router is tried first.
            order = { it },
        ),
        newVerifier = standInVerifiers(verifier, verifierRequests),
    )

    private suspend fun client(
        transport: Transport = Transport.Tls,
        fetchAttestation: AttestationFetcher? = null,
        fetchRouterList: RouterListFetcher? = null,
        policy: Policy = Policy(),
        userCacheSecret: String? = null,
        verificationCheck: VerificationCheck? = null,
        onVerificationAttempt: ((host: String, attempt: VerificationAttempt) -> Unit)? = null,
        internals: Internals = internals(),
    ): RouterHttpClient = RouterHttpClient.create(internals) {
        this.transport = transport
        this.fetchAttestation = fetchAttestation
        this.fetchRouterList = fetchRouterList
        this.policy = policy
        this.userCacheSecret = userCacheSecret
        this.verificationCheck = verificationCheck
        this.onVerificationAttempt = onVerificationAttempt
    }.also { closeables += it }

    @AfterTest
    fun shutDown() {
        closeables.reversed().forEach { it.close() }
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    private val routerPin = Pin(repo = "tinfoilsh/confidential-model-router", project = "tinfoilsh/confidential-model-router")

    // Choosing a router.

    @Test
    fun theFirstRouterOnTheListThatVerifiesIsChosen() = test {
        val first = Router()
        val second = Router()
        serveList(first.host, second.host)
        val results = CopyOnWriteArrayList<Pair<String, VerificationAttempt>>()

        val client = client(onVerificationAttempt = { host, result -> results += host to result })

        assertEquals(first.host, client.enclave)
        assertEquals("https://${first.host}/", client.baseUrl.toString())
        assertEquals(Transport.Tls, client.transport)
        assertEquals(first.certificate.fingerprint, client.lastVerificationAttempt().facts?.tlsPublicKeyFingerprint)
        assertSame(client.lastVerificationAttempt()?.report, client.ensureVerified())
        assertEquals(1, first.fetches.get(), "the chosen router is not verified a second time")
        assertEquals(0, second.fetches.get())
        assertEquals(0, fallback.fetches.get())
        assertEquals(listOf(routerPin), pins.distinct(), "every router is verified against the router's pin")
        awaitUntil { results.isNotEmpty() }
        assertEquals(first.host, results.single().first)
        assertSame(client.lastVerificationAttempt()?.report, results.single().second.report)

        val list = listServer.takeRequest()
        assertEquals("/routers", list.path)
        assertEquals("GET", list.method)
        assertEquals("tinfoil-kt", list.getHeader(DocumentFetcher.SDK_NAME_HEADER))
        assertNotNull(list.getHeader(DocumentFetcher.SDK_VERSION_HEADER))
        assertEquals(1, listServer.requestCount)

        client.execute(Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build()).use {
            assertEquals("from ${first.host}", it.body!!.string())
        }
        client.newCall(Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build()).execute().close()
        assertEquals(2, first.requests.size)
        assertEquals(0, second.requests.size + fallback.requests.size)
    }

    @Test
    fun routersThatFailArePassedOverInOrderWithoutASecondAttempt() = test {
        val unreachable = Router().unreachable()
        val unverifiable = Router().unverifiable()
        val rejected = Router()
        val keyless = Router().apply { attestation = { MockResponse().setBody("malformed") } }
        val good = Router()
        val later = Router()
        serveList(unreachable.host, unverifiable.host, rejected.host, keyless.host, good.host, later.host)
        val checked = CopyOnWriteArrayList<String?>()
        val results = CopyOnWriteArrayList<Pair<String, VerificationAttempt>>()

        val client = client(
            verificationCheck = {
                checked += it.tlsPublicKeyFingerprint
                if (it.tlsPublicKeyFingerprint == rejected.certificate.fingerprint) {
                    throw IllegalStateException("not this router")
                }
            },
            onVerificationAttempt = { host, result -> results += host to result },
        )

        assertEquals(good.host, client.enclave)
        for (router in listOf(unreachable, unverifiable, rejected, keyless, good)) {
            assertEquals(1, router.fetches.get(), "one attempt for each router that was tried")
        }
        assertEquals(0, later.fetches.get())
        assertEquals(0, fallback.fetches.get())
        assertEquals<List<String?>>(listOf(rejected.certificate.fingerprint, "malformed", good.certificate.fingerprint), checked)
        // Every router that was tried is reported, with its own host; the
        // client describes the one that it chose.
        val tried = listOf(unreachable, unverifiable, rejected, keyless, good).map { it.host }
        awaitUntil { results.size >= tried.size }
        Thread.sleep(50)
        assertEquals(tried, results.map { it.first })
        assertEquals(listOf(false, false, false, false, true), results.map { it.second.report != null })
        assertIs<NetworkException>(results[0].second.error)
        val rejection = assertIs<AttestationException>(results[1].second.error)
        assertIs<VerificationException>(rejection.cause)
        assertSame(client.lastVerificationAttempt()?.report, results.last().second.report)
        assertSame(client.lastVerificationAttempt()?.report, client.currentVerification(), "the chosen router's")
        assertEquals(0, listOf(unreachable, unverifiable, rejected, keyless, later).sumOf { it.requests.size })
    }

    @Test
    fun eachCandidatesReportNamesItsOwnRouter() = test {
        val unverifiable = Router().unverifiable()
        val good = Router()
        serveList(unverifiable.host, good.host)
        val results = CopyOnWriteArrayList<Pair<String, VerificationAttempt>>()

        val client = client(onVerificationAttempt = { host, result -> results += host to result })

        awaitUntil { results.size == 2 }
        assertEquals(unverifiable.host, jsonHost(rejectedReport(results[0].second.error)))
        assertEquals(good.host, jsonHost(results[1].second.report))
        assertEquals(good.host, jsonHost(client.currentVerification()))
        assertEquals(good.host, jsonHost(client.lastVerificationAttempt()?.report))
        assertEquals(good.host, jsonHost(client.ensureVerified()))
        assertEquals(good.host, jsonHost(client.reverify()))
    }

    @Test
    fun entriesThatAreNotHostsAreSkipped() = test {
        val good = Router()
        val port = good.server.port
        serveList(
            MockResponse().setBody(
                """["https://localhost:$port/", "localhost:$port/v1", "user@localhost:$port", "user:pw@localhost:$port",
                    "", " ", "localhost :$port", "localhost:$port?x", "localhost:$port#x", "Kocalhost:$port",
                    "127.1:$port", "0x7f.1:$port", "localhost:port", "localhost:", "local\\host:$port", "//localhost:$port",
                    5, null, true, 1.5, -0e1,
                    "localhost:$port", "localhost:$port", "LOCALHOST:$port"]""",
            ),
        )

        val client = client()

        assertEquals(good.host, client.enclave)
        assertEquals(1, good.fetches.get())
        assertEquals(0, fallback.fetches.get())
    }

    @Test
    fun theListProposesHostsAsEnclavesAreNamedEachOnceAndNoMoreThanItsCap() {
        fun candidates(bytes: ByteArray) = RouterDiscovery.candidates(RouterDiscovery.parse(bytes)) { it }
        fun candidates(text: String) = candidates(text.toByteArray())

        assertEquals(
            listOf("a.example", "b.example:8443", "192.0.2.1", "[2001:db8::1]:443", "xn--bcher-kva.example", "c.example."),
            candidates(
                """["a.example", "b.example:8443", "192.0.2.1", "[2001:db8::1]:443", "xn--bcher-kva.example", "c.example.",
                    "A.Example", "bücher.example", "a.example/", "a.example\n", "a.example\u0000", "evil.example@a.example",
                    "a.example:99999", "http://a.example", "a..example:x", "%61.example", "a.example%2f"]""",
            ),
        )
        assertEquals(emptyList<String>(), candidates(""))
        assertEquals(emptyList<String>(), candidates("null"))
        assertEquals(emptyList<String>(), candidates("\"a.example\""))
        assertEquals(emptyList<String>(), candidates("""{"routers":["a.example"]}"""))
        assertEquals(emptyList<String>(), candidates("""["a.example""""))
        assertEquals(emptyList<String>(), candidates("""["a.example"] trailing"""))
        assertEquals(emptyList<String>(), candidates("""["a.example",]"""))
        assertEquals(emptyList<String>(), candidates("""["a.example" "b.example"]"""))
        assertEquals(emptyList<String>(), candidates("""["a.example", ["b.example"]]"""), "a nested list is not a list of hosts")
        assertEquals(emptyList<String>(), candidates("""["a.example", {"host":"b.example"}]"""))
        assertEquals(emptyList<String>(), candidates("""["a.example", b.example]"""))
        assertEquals(emptyList<String>(), candidates("""["a.example\"]"""))
        assertEquals(emptyList<String>(), candidates("""["a.example", "\x"]"""))
        assertEquals(listOf("a.example"), candidates(""" [ "a.ex\u0061mple" , 1 , null , "a.example" ] """))
        assertEquals(emptyList<String>(), candidates("[]"))
        assertEquals(emptyList<String>(), candidates("[".repeat(500_000)), "nesting that never closes")
        assertEquals(emptyList<String>(), candidates("[".repeat(200_000) + "]".repeat(200_000)))
        assertEquals(emptyList<String>(), candidates("[\"a.example\"]".toByteArray() + byteArrayOf(0xff.toByte())))
        assertEquals(emptyList<String>(), candidates(byteArrayOf('['.code.toByte(), '"'.code.toByte(), 0xc0.toByte(), 0x80.toByte(), '"'.code.toByte(), ']'.code.toByte())))

        val many = (1..10_000).joinToString(",", "[", "]") { "\"router$it.example\"" }
        assertEquals((1..RouterDiscovery.MAX_CANDIDATES).map { "router$it.example" }, candidates(many))
        assertEquals(64, RouterDiscovery.MAX_CANDIDATES)
        assertEquals("https://atc.tinfoil.sh/routers", RouterDiscovery.LIST_URL)
        assertEquals("inference.tinfoil.sh", RouterDiscovery.FALLBACK_ROUTER)
        assertEquals(30.seconds, RouterDiscovery.BUDGET)
        assertEquals(routerPin, RouterDiscovery.ROUTER_PIN)
    }

    // Falling back.

    @Test
    fun theFallbackIsUsedWhenNoRouterVerifiesAndGetsASecondAttempt() = test {
        val bad = Router().unverifiable()
        serveList(bad.host)
        val answers = ArrayDeque(listOf(MockResponse().setResponseCode(503), MockResponse().setBody(fallback.certificate.fingerprint)))
        fallback.attestation = { answers.removeFirst() }

        val client = client()

        assertEquals(fallback.host, client.enclave)
        assertEquals(1, bad.fetches.get())
        assertEquals(2, fallback.fetches.get())
        assertEquals(fallback.certificate.fingerprint, client.lastVerificationAttempt().facts?.tlsPublicKeyFingerprint)
        assertEquals(listOf(routerPin), pins.distinct())
    }

    @Test
    fun aListThatCannotBeUsedLeavesTheFallback() = test {
        val good = Router()
        val elsewhere = MockWebServer().also { server ->
            closeables += AutoCloseable { server.shutdown() }
            server.dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest) = MockResponse().setBody("[\"${good.host}\"]")
            }
            server.start()
        }
        val lists = mapOf(
            "a server error" to MockResponse().setResponseCode(500).setBody("[\"${good.host}\"]"),
            "a missing list" to MockResponse().setResponseCode(404),
            "text that is not JSON" to MockResponse().setBody("<html>"),
            "an object" to MockResponse().setBody("{\"routers\":[\"${good.host}\"]}"),
            "an empty list" to MockResponse().setBody("[]"),
            "an empty body" to MockResponse().setBody(""),
            "a list that is too large" to
                MockResponse().setBody("[\"${good.host}\"" + " ".repeat(RouterDiscovery.MAX_LIST_BYTES.toInt()) + "]"),
            "a redirect to plain HTTP" to
                MockResponse().setResponseCode(302).setHeader("Location", elsewhere.url("/routers").toString()),
            "a connection that drops" to MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START),
        )
        for ((name, response) in lists) {
            serveList(response)

            val client = client()

            assertEquals(fallback.host, client.enclave, name)
            client.close()
        }
        assertEquals(0, good.fetches.get())
        assertEquals(0, elsewhere.requestCount, "the list is never fetched in cleartext")
        assertEquals(lists.size, fallback.fetches.get())
    }

    @Test
    fun aFallbackThatFailsFailsTheCreationWithItsError() = test {
        val unverifiable = Router().unverifiable()
        serveList(unverifiable.host)
        val results = CopyOnWriteArrayList<Pair<String, VerificationAttempt>>()

        fallback.unreachable()
        val network = assertFailsWith<NetworkException> { client(onVerificationAttempt = { host, result -> results += host to result }) }
        assertEquals(503, network.status)
        assertEquals(2, fallback.fetches.get())
        // The router that was passed over, then each attempt at the fallback.
        awaitUntil { results.size >= 3 }
        assertEquals(listOf(unverifiable.host, fallback.host, fallback.host), results.map { it.first })
        assertSame(network.suppressed.single(), results[1].second.error)
        assertSame(network, results[2].second.error)

        fallback.unverifiable()
        val attestation = assertFailsWith<AttestationException> { client() }
        assertEquals(VerificationLayer.QUOTE, assertIs<VerificationException>(attestation.cause).layer)

        fallback.attestation = { MockResponse().setBody(fallback.certificate.fingerprint) }
        val rejection = assertFailsWith<AttestationException> { client(verificationCheck = { error("no router at all") }) }
        assertTrue(rejection.detail.contains("no router at all"), rejection.detail)
        assertEquals(0, fallback.requests.size)
    }

    @Test
    fun aRouterThatIsAlsoTheFallbackIsTriedAsBoth() = test {
        serveList(fallback.host)
        val answers = ArrayDeque(listOf(MockResponse().setResponseCode(503), MockResponse().setBody(fallback.certificate.fingerprint)))
        fallback.attestation = { answers.removeFirst() }

        val client = client()

        assertEquals(fallback.host, client.enclave)
        assertEquals(2, fallback.fetches.get())
    }

    // Bounds.

    @Test
    fun oneBudgetCoversEveryRouterAndThenTheFallbackIsUsed() = test {
        val silent = silentRouter()
        val never = Router()
        serveList(silent.host, never.host)
        val started = System.nanoTime()

        val client = client(internals = internals(budget = 400.milliseconds))

        val elapsedMillis = (System.nanoTime() - started) / 1_000_000
        assertEquals(fallback.host, client.enclave)
        assertTrue(elapsedMillis in 400..10_000, "took $elapsedMillis ms")
        assertEquals(1, silent.handshakes.get())
        assertEquals(0, never.fetches.get(), "no router is tried once the budget is spent")
        awaitUntil(5_000) { silent.finished.get() == 1 }
    }

    @Test
    fun aSlowListCountsAgainstTheBudget() = test {
        val never = Router()
        serveList(MockResponse().setBody("[\"${never.host}\"]").setHeadersDelay(2, java.util.concurrent.TimeUnit.SECONDS))
        val started = System.nanoTime()

        val client = client(internals = internals(budget = 300.milliseconds))

        assertEquals(fallback.host, client.enclave)
        assertTrue((System.nanoTime() - started) / 1_000_000 < 1_500)
        assertEquals(0, never.fetches.get())
    }

    @Test
    fun noRouterIsTriedOnceTheBudgetIsSpentEvenIfItsTimerHasNotFired() = test {
        val first = Router()
        val second = Router()
        serveList(first.host, second.host)
        val time = TestTimeSource()

        val client = client(
            verificationCheck = {
                if (it.tlsPublicKeyFingerprint == first.certificate.fingerprint) {
                    // The first router uses up all of the time, and fails.
                    time += 30.seconds
                    error("too slow")
                }
            },
            internals = internals(timeSource = time),
        )

        assertEquals(fallback.host, client.enclave)
        assertEquals(1, first.fetches.get())
        assertEquals(0, second.fetches.get())
    }

    @Test
    fun aRouterJustInsideTheBudgetIsStillTried() = test {
        val first = Router()
        val second = Router()
        serveList(first.host, second.host)
        val time = TestTimeSource()

        val client = client(
            verificationCheck = {
                if (it.tlsPublicKeyFingerprint == first.certificate.fingerprint) {
                    time += 30.seconds - 1.milliseconds
                    error("slow")
                }
            },
            internals = internals(timeSource = time),
        )

        assertEquals(second.host, client.enclave)
    }

    @Test
    fun cancellingWhileARouterIsTriedLeavesNothingRunning() = test {
        val silent = silentRouter()
        val never = Router()
        serveList(silent.host, never.host)
        val results = CopyOnWriteArrayList<VerificationAttempt>()

        val creating = async(Dispatchers.Default) { client(onVerificationAttempt = { _, result -> results += result }) }
        awaitUntil { silent.handshakes.get() == 1 }
        creating.cancelAndJoin()

        assertTrue(creating.isCancelled)
        awaitUntil(5_000) { silent.finished.get() == 1 }
        Thread.sleep(200)
        assertEquals(0, never.fetches.get())
        assertEquals(0, fallback.fetches.get(), "a cancelled creation does not go on to the fallback")
        assertEquals(1, listServer.requestCount)
        assertTrue(results.isEmpty(), "an attempt that the cancellation ended has no outcome to report")
    }

    @Test
    fun cancellingWhileTheListIsFetchedOrTheFallbackIsVerifiedStopsThere() = test {
        serveList(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        val fetchingList = async(Dispatchers.Default) { client() }
        awaitUntil { listServer.requestCount == 1 }
        fetchingList.cancelAndJoin()
        Thread.sleep(100)
        assertEquals(0, fallback.fetches.get())

        serveList()
        fallback.attestation = { MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE) }
        val verifyingFallback = async(Dispatchers.Default) { client() }
        awaitUntil { fallback.fetches.get() == 1 }
        verifyingFallback.cancelAndJoin()
        Thread.sleep(100)
        assertEquals(1, fallback.fetches.get(), "no second attempt after the caller gave up")
        assertEquals(0, fallback.requests.size)
    }

    @Test
    fun everyConnectionThatIsNotChosenIsClosed() = test {
        val bad = Router().unverifiable()
        val unreachable = Router().unreachable()
        val good = Router()
        val later = Router()
        val opened = CopyOnWriteArrayList<EnclaveConnection>()
        val settings = internals()
        val open = { host: String ->
            EnclaveConnection.create(
                host, RouterDiscovery.ROUTER_PIN, Transport.Tls, null, verifier, null,
                null, null, settings,
            ).also {
                opened += it
                closeables += AutoCloseable(it::close)
            }
        }
        val list = "[\"${bad.host}\",\"${unreachable.host}\",\"${good.host}\",\"${later.host}\"]".toByteArray()

        val chosen = RouterDiscovery(settings.discovery) { RouterDiscovery.parse(list) }.discover(open)

        assertEquals(listOf(bad.host, unreachable.host, good.host), opened.map { it.enclave })
        assertSame(opened[2], chosen)
        assertEquals(listOf(true, true, false), opened.map { it.isClosed })
        assertNotNull(chosen!!.lastVerificationAttempt?.report)

        // With no router that verifies, there is nothing to return.
        opened.clear()
        assertNull(RouterDiscovery(settings.discovery) { listOf(bad.host) }.discover(open))
        assertEquals(listOf(true), opened.map { it.isClosed })
        assertNull(RouterDiscovery(settings.discovery) { throw NetworkException("no list") }.discover(open))
        assertEquals(1, opened.size, "a list that cannot be fetched proposes nothing")
        // Whatever the list's source throws, it proposes nothing.
        assertNull(RouterDiscovery(settings.discovery) { throw IllegalStateException("broken") }.discover(open))
        assertNull(RouterDiscovery(settings.discovery) { throw kotlinx.coroutines.CancellationException("its own") }.discover(open))
        assertEquals(1, opened.size)
    }

    // After creation.

    @Test
    fun aRejectedReverificationStopsRequestsToTheRouterUntilItPassesAgain() = test {
        val router = Router()
        serveList(router.host)
        val client = client()
        val request = Request.Builder().url(client.baseUrl).build()
        client.execute(request).close()

        val serving = router.attestation
        router.unverifiable()
        assertFailsWith<AttestationException> { client.reverify() }
        assertFailsWith<AttestationException> { client.execute(request) }
        assertEquals(1, router.requests.size, "nothing was sent after the rejection")

        router.attestation = serving
        val fetched = router.fetches.get()
        client.execute(request).close()
        assertEquals(fetched + 1, router.fetches.get(), "the request verified the router first")
        assertEquals(2, router.requests.size)
        assertEquals(router.host, client.enclave, "the client keeps its router")
        assertEquals(1, listServer.requestCount, "the router is verified again without discovery")
    }

    @Test
    fun aClientKeepsItsRouterAndEachCreationChoosesAgain() = test {
        val first = Router()
        val second = Router()
        serveList(first.host, second.host)
        val client = client()
        assertEquals(first.host, client.enclave)

        // The list now prefers another router, and the first one fails.
        serveList(second.host, first.host)
        val again = client.reverify()
        assertEquals(first.certificate.fingerprint, again.verifiedFacts?.tlsPublicKeyFingerprint)
        assertEquals(2, first.fetches.get(), "the same router is verified again")
        assertEquals(1, listServer.requestCount, "verifying again does not consult the list")

        first.unverifiable()
        assertFailsWith<AttestationException> { client.reverify() }
        assertEquals(first.host, client.enclave, "a client never moves to another router")
        assertEquals(0, second.fetches.get())

        val other = client()
        assertEquals(second.host, other.enclave)
        assertEquals(2, listServer.requestCount)

        client.close()
        assertFailsWith<ConfigurationException> { client.ensureVerified() }
        assertFailsWith<ConfigurationException> { client.execute(Request.Builder().url(client.baseUrl).build()) }
        other.execute(Request.Builder().url(other.baseUrl).build()).close()
    }

    @Test
    fun aRequestOffTheRoutersOriginIsRefused() = test {
        val first = Router()
        val second = Router()
        serveList(first.host)
        val client = client()

        assertFailsWith<ConfigurationException> {
            client.execute(Request.Builder().url("https://${second.host}/v1/models").build())
        }
        assertFailsWith<ConfigurationException> {
            client.newCall(Request.Builder().url("https://${fallback.host}/v1/models").build()).execute()
        }
        assertEquals(0, second.requests.size + fallback.requests.size)
    }

    // Sealed bodies and proxies.

    @Test
    fun aRouterClientSealsBodiesToTheRouterThatItChose() = test {
        val first = Router().unverifiable()
        val second = Router()
        serveList(first.host, second.host)

        val client = client(transport = Transport.Ehbp(), userCacheSecret = "cache-secret-91ab3e")

        assertEquals(second.host, client.enclave)
        assertEquals(Transport.Ehbp(), client.transport)
        assertEquals("https://${second.host}/", client.baseUrl.toString())
        assertEquals(second.key.publicKey, client.lastVerificationAttempt().facts?.hpkePublicKey)
        val request = Request.Builder().url(client.baseUrl.resolve("v1/chat/completions")!!)
            .post("""{"prompt":"plaintext-marker-0c77d1"}""".toRequestBody()).build()
        val recoverable = client.executeRecoverable(request)
        assertEquals("sealed by ${second.host}", recoverable.response.use { it.body!!.string() })
        assertNotNull(recoverable.recoveryToken)
        val received = second.sealing.received.single()
        assertEquals("""{"prompt":"plaintext-marker-0c77d1","user_cache_secret":"cache-secret-91ab3e"}""", received.text)
        assertFalse(received.wire.containsText("plaintext-marker-0c77d1"))
        assertFalse(received.wire.containsText("cache-secret-91ab3e"))
        assertNull(received.request.getHeader(ENCLAVE_URL_HEADER))
        assertEquals(0, first.requests.size + fallback.requests.size)
    }

    @Test
    fun throughAProxyDiscoveryRunsAndTheChosenRouterIsNamedToTheProxy() = test {
        val listed = Router()
        serveList(listed.host)
        val atProxy = SealingDispatcher({ listed.key }) { it.reply("through the proxy") }
        val proxy = MockWebServer().apply {
            dispatcher = atProxy
            start()
        }
        closeables += AutoCloseable { proxy.shutdown() }

        val client = client(transport = Transport.Ehbp("http://localhost:${proxy.port}/v1/"))

        // The proxy forwards a request, headers and all, to the host that
        // the request names, which the list proposed: the list's source is
        // trusted with the headers there.
        assertEquals(listed.host, client.enclave)
        assertEquals(1, listServer.requestCount, "the list is fetched")
        assertEquals("http://localhost:${proxy.port}/v1/", client.baseUrl.toString())
        assertEquals(1, listed.fetches.get(), "the router is verified directly, and not through the proxy")
        assertEquals(0, fallback.fetches.get())
        assertEquals(0, proxy.requestCount, "creating the client sends the proxy nothing")
        val request = Request.Builder().url(client.baseUrl.resolve("chat/completions")!!)
            .post("""{"prompt":"plaintext-marker-0c77d1"}""".toRequestBody()).build()
        client.execute(request).use { assertEquals("through the proxy", it.body!!.string()) }
        client.execute(Request.Builder().url(client.baseUrl.resolve("models")!!).build()).close()

        val (sealed, bodyless) = atProxy.received
        assertTrue(sealed.sealed)
        assertFalse(sealed.wire.containsText("plaintext-marker-0c77d1"))
        assertEquals("/v1/chat/completions", sealed.request.path)
        assertFalse(bodyless.sealed)
        for (received in atProxy.received) {
            assertEquals("https://${listed.host}", received.request.getHeader(ENCLAVE_URL_HEADER))
        }
        assertEquals(0, fallback.requests.size + listed.requests.size, "requests go to the proxy only")
        assertFailsWith<ConfigurationException> {
            client.execute(Request.Builder().url("https://${fallback.host}/v1/models").build())
        }
    }

    @Test
    fun aRouterThatEndorsesNoHpkeKeyIsPassedOverWhenBodiesAreSealed() = test {
        val keyless = Router().also { hpkeKeys.remove(it.certificate.fingerprint) }
        val good = Router()
        serveList(keyless.host, good.host)

        val client = client(transport = Transport.Ehbp())

        assertEquals(good.host, client.enclave)
        assertEquals(1, keyless.fetches.get())
        assertEquals(0, keyless.requests.size)
    }

    // The attested TLS key.

    /** A host with a valid certificate of its own that passes on [genuine]'s attestation document. */
    private fun relaying(genuine: Router): Router = Router().apply { attestation = genuine.attestation }

    private fun RouterHttpClient.chatRequest(): Request =
        Request.Builder().url(baseUrl.resolve("v1/chat/completions")!!).post("""{"prompt":"hello"}""".toRequestBody(json)).build()

    @Test
    fun aListedHostThatDoesNotHoldTheAttestedTlsKeyIsPassedOverAndReceivesNothing() = test {
        for (mode in listOf(Transport.Tls, Transport.Ehbp())) {
            val genuine = Router()
            val impostor = relaying(genuine)
            val next = Router()
            serveList(impostor.host, next.host)

            val client = client(transport = mode)

            assertEquals(next.host, client.enclave, "$mode: the host that presented another key was not chosen")
            assertEquals(1, impostor.fetches.get(), "$mode")
            client.execute(client.chatRequest()).close()
            client.execute(Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build()).close()
            assertEquals(2, next.requests.size, "$mode")
            assertEquals(0, impostor.requests.size, "$mode: the impostor was sent a request")
            assertEquals(1, impostor.server.requestCount, "$mode: only its attestation document was fetched")
            assertEquals(0, genuine.requests.size + fallback.requests.size, "$mode")
        }
    }

    @Test
    fun aHostThatIsPassedOverForItsKeyLeavesTheFallback() = test {
        val impostor = relaying(Router())
        serveList(impostor.host)

        val client = client(transport = Transport.Ehbp())

        assertEquals(fallback.host, client.enclave)
        assertEquals(0, impostor.requests.size)
    }

    @Test
    fun aRouterThatStopsPresentingItsAttestedKeyReceivesNothingWhenBodiesAreSealed() = test {
        val router = Router()
        serveList(router.host)
        val client = client(transport = Transport.Ehbp())
        client.execute(client.chatRequest()).close()
        assertEquals(1, router.requests.size)

        router.presentAnotherKey()

        val sealed = assertFailsWith<AttestationException> { client.execute(client.chatRequest()) }
        assertTrue(sealed.message!!.contains("does not carry the attested TLS key"), sealed.message)
        // A request without a body is all headers, an API key among them.
        assertFailsWith<AttestationException> {
            client.execute(Request.Builder().url(client.baseUrl.resolve("v1/models")!!).header("Authorization", "Bearer k").build())
        }
        assertEquals(1, router.requests.size, "nothing was sent to the server with the other key")
        assertEquals(router.fetches.get() - 1, router.server.requestCount, "it was asked only for attestation documents")
    }

    @Test
    fun theFallbackRouterIsHeldToItsAttestedKeyWhenBodiesAreSealed() = test {
        serveList()
        fallback.attestation = Router().attestation

        val client = client(transport = Transport.Ehbp())

        assertEquals(fallback.host, client.enclave)
        assertFailsWith<AttestationException> { client.execute(client.chatRequest()) }
        assertEquals(0, fallback.requests.size)
    }

    // Options.

    @Test
    fun invalidOptionsAreRefusedBeforeAnyIo() = test {
        val router = Router()
        serveList(router.host)
        val refused: Map<String, suspend () -> Unit> = mapOf(
            "a proxy over HTTP that is not on this machine" to {
                client(transport = Transport.Ehbp("http://proxy.example/"))
            },
            "a proxy with credentials under EHBP" to {
                client(transport = Transport.Ehbp("https://user:hunter2@proxy.example/"))
            },
            "a proxy with a query" to { client(transport = Transport.Ehbp("https://proxy.example/?key=hunter2")) },
            "a proxy that is not a URL" to { client(transport = Transport.Ehbp("hunter2")) },
            "a relay with a query" to { client(fetchAttestation = AttestationRelay("https://relay.example/?hunter2")) },
            "a relay with user information" to { client(fetchAttestation = AttestationRelay("https://hunter2@relay.example/")) },
            "a list relay over HTTP off this machine" to { client(fetchRouterList = RouterListRelay("http://relay.example/hunter2")) },
            "a negative freshness bound" to { client(policy = Policy(freshnessMaxAge = (-1).seconds)) },
            "a cache secret that is not well-formed text" to { client(userCacheSecret = "hunter2\ud800") },
            "proxy URL must not be empty" to { client(transport = Transport.Ehbp("")) },
            "attestation relay URL must not be empty" to { client(fetchAttestation = AttestationRelay("")) },
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
            assertFalse(error.message!!.contains("hunter2"), "$name: ${error.message}")
            if (name.contains("must not be empty")) {
                assertTrue(error.detail.startsWith(name.substringBefore(" under")), "$name: ${error.detail}")
            }
            assertEquals(0, listServer.requestCount, "$name: the list was fetched")
            assertEquals(0, router.fetches.get() + fallback.fetches.get(), "$name: a router was contacted")
            assertEquals(0, verifier.verifications.get(), name)
        }
        // Null is how an option is left unset.
        assertEquals(router.host, client(transport = Transport.Ehbp(null), fetchAttestation = null, userCacheSecret = null).enclave)
    }

    @Test
    fun aPolicyThatNoPinCanSatisfyIsRefusedBeforeAnyIo() = test {
        serveList(Router().host)
        val strict = object : AttestationVerifier by verifier {
            override fun checkPinVerifiability(pin: Pin) = throw ConfigurationException("this policy takes no pin")
        }

        val error = assertFailsWith<ConfigurationException> { client(internals = internals(verifier = strict)) }

        assertEquals("this policy takes no pin", error.detail)
        assertEquals(0, listServer.requestCount)
    }

    // Attestation and router-list fetchers.

    /** A relay on this machine's loopback address, over HTTPS, that serves each router's document from its own server. */
    private inner class Relay {
        val server: MockWebServer = httpsServer(authority.issue()).also { server -> closeables += AutoCloseable { server.shutdown() } }
        val url = "https://localhost:${server.port}/tinfoil"
        val requests = CopyOnWriteArrayList<RecordedRequest>()

        /** The routers by host, whose documents the relay serves, and the list that it serves. */
        val routers = java.util.concurrent.ConcurrentHashMap<String, Router>()

        @Volatile
        var list: MockResponse = MockResponse().setResponseCode(404)

        init {
            server.dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse {
                    requests += request
                    val url = request.requestUrl!!
                    return when (url.encodedPath) {
                        "/tinfoil/routers" -> list
                        "/tinfoil/.well-known/tinfoil-attestation" ->
                            routers[url.queryParameter("enclave")]?.let { MockResponse().setBody(it.certificate.fingerprint) }
                                ?: MockResponse().setResponseCode(502)
                        else -> MockResponse().setResponseCode(404)
                    }
                }
            }
        }

        fun serve(vararg served: Router) = apply { served.forEach { routers[it.host] = it } }
    }

    @Test
    fun withARelayDiscoveryStillRunsAndEveryDocumentComesThroughIt() = test {
        val bad = Router().unverifiable()
        val listed = Router()
        serveList(bad.host, listed.host)
        val relay = Relay().serve(listed, fallback)

        val client = client(fetchAttestation = AttestationRelay(relay.url))

        assertEquals(listed.host, client.enclave, "the router list was consulted")
        assertEquals(1, listServer.requestCount)
        client.reverify()
        val fetched = relay.requests.map { it.requestUrl!!.queryParameter("enclave") }
        assertEquals(listOf(bad.host, listed.host, listed.host), fetched, "every candidate, and the verification again")
        assertEquals(0, bad.fetches.get() + listed.fetches.get() + fallback.fetches.get(), "nothing was fetched directly")
        for (request in relay.requests) {
            assertEquals("tinfoil-kt", request.getHeader("Tinfoil-SDK"))
            assertNotNull(request.getHeader("Tinfoil-SDK-Version"))
            assertNull(request.getHeader("Authorization"))
            assertTrue(Regex("[0-9a-f]{64}").matches(request.requestUrl!!.queryParameter("nonce")!!))
        }
    }

    @Test
    fun aCallersFetcherIsUsedForEveryCandidateTheFallbackAndEveryLaterVerification() = test {
        val listed = Router().unverifiable()
        serveList(listed.host)
        val asked = CopyOnWriteArrayList<String>()
        val byHost = mapOf(fallback.host to fallback, listed.host to listed)
        val fetcher = AttestationFetcher { host, nonce ->
            assertEquals(32, nonce.size)
            asked += host
            byHost.getValue(host).let { if (it === listed) "not a document".toByteArray() else it.certificate.fingerprint.toByteArray() }
        }

        val client = client(fetchAttestation = fetcher)
        client.reverify()

        assertEquals(fallback.host, client.enclave)
        assertEquals(listOf(listed.host, fallback.host, fallback.host), asked.toList())
        assertEquals(0, listed.fetches.get() + fallback.fetches.get(), "nothing was fetched directly")
    }

    @Test
    fun aCallersFetchersFailuresAreClassified() = test {
        serveList()
        val cause = IllegalStateException("the relay is down")
        val network = assertFailsWith<NetworkException> {
            client(fetchAttestation = { _, _ -> throw cause })
        }
        // The fetcher's error is the cause. Under a JVM with assertions on,
        // coroutines may rethrow a copy of it, with the original as its cause.
        val kept = assertIs<IllegalStateException>(network.cause)
        assertTrue(kept === cause || kept.cause === cause, "$kept")
        assertTrue(network.detail.contains("the relay is down"), network.detail)

        val own = ConfigurationException("not a host that this app expects")
        val configuration = assertFailsWith<ConfigurationException> { client(fetchAttestation = { _, _ -> throw own }) }
        assertSame(own, configuration, "an SDK error keeps its category, and is not wrapped")

        val cancelled = assertFailsWith<NetworkException> {
            client(fetchAttestation = { _, _ -> throw kotlinx.coroutines.CancellationException("its own") })
        }
        assertIs<kotlinx.coroutines.CancellationException>(cancelled.cause, "a fetcher's own cancellation is not the caller's")

        val refused = assertFailsWith<AttestationException> {
            client(fetchAttestation = { _, _ -> "a document that does not verify".toByteArray() })
        }
        assertEquals(VerificationLayer.QUOTE, assertIs<VerificationException>(refused.cause).layer)
    }

    @Test
    fun aFetcherThatTakesTooLongTimesOutAsANetworkFailure() = test {
        val error = assertFailsWith<NetworkException> {
            sh.tinfoil.internal.verification.DocumentSources.fromCaller(
                { _, _ -> kotlinx.coroutines.delay(60_000); ByteArray(0) },
                "enclave.example",
                ByteArray(32),
                timeout = 50.milliseconds,
            )
        }
        assertIs<kotlinx.coroutines.TimeoutCancellationException>(error.cause)
        assertTrue(error.detail.contains("timed out"), error.detail)
    }

    @Test
    fun theCallersCancellationPassesThroughAndDiscoveryDoesNotFallBack() = test {
        val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
        val creating = async {
            client(
                fetchRouterList = {
                    entered.complete(Unit)
                    kotlinx.coroutines.awaitCancellation()
                },
            )
        }
        entered.await()
        creating.cancel()
        assertFailsWith<kotlinx.coroutines.CancellationException> { creating.await() }
        assertEquals(0, fallback.fetches.get(), "the fallback was not tried")
    }

    @Test
    fun aCallersRouterListIsTriedInTheOrderThatDiscoveryGivesACopyOfIt() = test {
        val bad = Router().unverifiable()
        val good = Router()
        val listed = listOf(bad.host, good.host, "not a host/")
        val given = ArrayList(listed)
        val ordered = CopyOnWriteArrayList<List<String>>()
        val internals = internals().let {
            sh.tinfoil.internal.Internals(
                http = it.http,
                clock = it.clock,
                retryDelay = it.retryDelay,
                discovery = RouterDiscovery.Settings(
                    listUrl = listServer.url("/routers"),
                    fallback = fallback.host,
                    order = { candidates -> ordered += candidates; candidates.reversed() },
                ),
                newVerifier = it.newVerifier,
            )
        }

        val client = client(fetchRouterList = { given }, internals = internals)

        assertEquals(good.host, client.enclave, "the order that discovery gave is the one that is tried")
        assertEquals(listOf(listOf(bad.host, good.host)), ordered.toList(), "the valid hosts, as a copy")
        assertEquals(listed, given, "the caller's list is not changed")
        assertEquals(0, listServer.requestCount, "Tinfoil's list is not fetched")
        assertEquals(0, bad.fetches.get())
    }

    @Test
    fun theDefaultOrderIsAUniformShuffleOfACopy() {
        val hosts = (1..8).map { "router$it.example" }
        val orders = (1..400).map { RouterDiscovery.Settings().order(hosts) }
        for (order in orders) {
            assertEquals(hosts.toSet(), order.toSet())
        }
        assertEquals((1..8).map { "router$it.example" }, hosts)
        val firsts = orders.groupingBy { it.first() }.eachCount()
        assertEquals(hosts.toSet(), firsts.keys, "every router comes first sometimes")
        assertTrue(firsts.values.all { it in 20..90 }, "about one in eight each time: $firsts")
    }

    @Test
    fun aCallersRouterListThatFailsCountsAsEmptyAndTinfoilsIsNotFetched() = test {
        serveList(Router().host)

        val client = client(fetchRouterList = { throw java.io.IOException("no list") })

        assertEquals(fallback.host, client.enclave)
        assertEquals(0, listServer.requestCount)
    }

    @Test
    fun aRelayedRouterListIsReadAsTinfoilsIs() = test {
        val listed = Router()
        val relay = Relay()
        relay.list = MockResponse().setBody("[\"${listed.host}\"]")

        val client = client(fetchRouterList = RouterListRelay(relay.url))

        assertEquals(listed.host, client.enclave)
        assertEquals("/tinfoil/routers", relay.requests.single().path)
        assertEquals(0, listServer.requestCount)

        for (list in listOf(MockResponse().setBody("{\"routers\":[]}"), MockResponse().setResponseCode(500),
            MockResponse().setBody("[\"" + "a".repeat(2 shl 20) + "\"]"))) {
            relay.list = list
            assertEquals(fallback.host, client(fetchRouterList = RouterListRelay(relay.url)).enclave)
        }
    }

    @Test
    fun withAProxyAndBothRelaysDiscoveryRunsRequestsGoToTheProxyAndFetchesToTheRelays() = test {
        val listed = Router()
        val relay = Relay().serve(listed)
        relay.list = MockResponse().setBody("[\"${listed.host}\"]")
        val proxy = httpsServer(authority.issue()).also { server -> closeables += AutoCloseable { server.shutdown() } }
        proxy.dispatcher = listed.sealing

        val client = client(
            transport = Transport.Ehbp("https://localhost:${proxy.port}/"),
            fetchAttestation = AttestationRelay(relay.url),
            fetchRouterList = RouterListRelay(relay.url),
        )

        assertEquals(listed.host, client.enclave, "discovery ran")
        val request = Request.Builder().url(client.baseUrl.resolve("v1/chat/completions")!!)
            .post("""{"prompt":"hi"}""".toRequestBody()).build()
        assertEquals("sealed by ${listed.host}", client.execute(request).use { it.body!!.string() })
        assertEquals("https://${listed.host}", listed.sealing.received.single().request.getHeader(ENCLAVE_URL_HEADER))
        assertEquals(0, listServer.requestCount + listed.fetches.get() + listed.requests.size)
    }

    // The cache secret.

    private val json = "application/json".toMediaType()

    private fun secretOf(recorded: RecordedRequest): String? =
        Regex("\"user_cache_secret\":\"([^\"]*)\"").find(recorded.body.readUtf8())?.groupValues?.get(1)

    private suspend fun RouterHttpClient.chat(body: String) {
        execute(Request.Builder().url(baseUrl.resolve("v1/chat/completions")!!).post(body.toRequestBody(json)).build()).close()
    }

    @Test
    fun clientsWithoutASecretShareOneRandomSecretForTheProcess() = test {
        val router = Router()
        serveList(router.host)
        val first = client()
        val second = client(userCacheSecret = null)
        val failures = mutableListOf<Throwable>()

        first.chat("""{"model":"m","n":9007199254740993}""")
        second.chat("""{"model":"m"}""")
        first.newCall(
            Request.Builder().url(first.baseUrl.resolve("v1/responses")!!).post("""{"user_cache_secret":""}""".toRequestBody(json)).build(),
        ).execute().close()

        val bodies = router.requests.map { it.body.clone().readUtf8() }
        val secrets = router.requests.map { secretOf(it) }
        assertEquals(3, secrets.size)
        val secret = assertNotNull(secrets.first())
        assertTrue(Regex("[0-9a-f]{64}").matches(secret), "256 random bits in hex")
        assertEquals(listOf(secret, secret, secret), secrets, "one secret for every client in the process")
        assertEquals("""{"model":"m","n":9007199254740993,"user_cache_secret":"$secret"}""", bodies[0])
        assertEquals("""{"user_cache_secret":"$secret"}""", bodies[2])

        // Nothing that the client says about itself or its failures holds it.
        failures += assertFailsWith<ConfigurationException> {
            first.execute(Request.Builder().url("https://other.example/v1/responses").post("{}".toRequestBody(json)).build())
        }
        first.close()
        failures += assertFailsWith<ConfigurationException> { first.chat("{}") }
        router.unverifiable()
        failures += assertFailsWith<AttestationException> { second.reverify() }
        for (text in failures.map { it.toString() + it.stackTraceToString() } + first.toString() + second.toString()) {
            assertFalse(text.contains(secret), text)
        }
    }

    @Test
    fun aGivenSecretIsUsedAsItIsAndARequestsOwnSecretWins() = test {
        val router = Router()
        serveList(router.host)
        val client = client(userCacheSecret = "tenant \"A\"")

        client.chat("""{"model":"m"}""")
        client.chat("""{"model":"m","user_cache_secret":"end-user-7"}""")
        client.execute(Request.Builder().url(client.baseUrl.resolve("v1/embeddings")!!).post("""{"input":"x"}""".toRequestBody(json)).build()).close()

        val bodies = router.requests.map { it.body.readUtf8() }
        assertEquals(
            listOf(
                """{"model":"m","user_cache_secret":"tenant \"A\""}""",
                """{"model":"m","user_cache_secret":"end-user-7"}""",
                """{"input":"x"}""",
            ),
            bodies,
        )
    }

    @Test
    fun theFallbackRouterIsGivenTheSecretToo() = test {
        serveList()
        val client = client(userCacheSecret = "scope")

        client.chat("{}")

        assertEquals("""{"user_cache_secret":"scope"}""", fallback.requests.single().body.readUtf8())
    }
}
