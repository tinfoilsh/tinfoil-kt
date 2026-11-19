@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.testing

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import sh.tinfoil.AttestationException
import sh.tinfoil.Catalog
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.ModelPin
import sh.tinfoil.Pin
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import sh.tinfoil.Verifier
import sh.tinfoil.internal.GatewaySettings
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.transport.HttpSettings
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TestTimeSource

/**
 * A gateway for tests: one HTTPS server that serves a catalog, relays the
 * attestation documents of replicas, and forwards sealed requests to them.
 * The replicas are not servers: each is an HPKE key that the gateway opens
 * requests with, by the replica that a request says it is sealed to, as a
 * real replica would. A verifier endorses whatever the test says.
 */
public class TestGateway : AutoCloseable {
    public val authority: TestAuthority = TestAuthority()
    public val clock: TestClock = TestClock()
    public val timeSource: TestTimeSource = TestTimeSource()
    public val server: MockWebServer = httpsServer(authority.issue())
    public val host: String = "localhost:${server.port}"
    public val baseUrl: String = "https://$host/v1/"

    /** The catalog that the gateway serves. */
    @Volatile
    public var catalog: () -> MockResponse = { MockResponse().setBody("{}") }

    /** How many times the catalog was fetched. */
    public val catalogFetches: AtomicInteger = AtomicInteger()

    /** The replicas whose attestation documents were fetched, in order. */
    public val attestationFetches: CopyOnWriteArrayList<String> = CopyOnWriteArrayList<String>()

    /** What the relay answers for a replica's attestation document; the document names the replica. */
    @Volatile
    public var attestation: (replica: String) -> MockResponse = { MockResponse().setBody(it) }

    /** Every request that was not for the catalog or an attestation document, in order. */
    public val received: CopyOnWriteArrayList<Received> = CopyOnWriteArrayList<Received>()

    /** What a request that the gateway forwarded is answered. */
    @Volatile
    public var answer: (Received) -> MockResponse = { it.reply("ok") }

    /** What the gateway does with a request before it forwards it; a response here is the gateway's own. */
    @Volatile
    public var intercept: (RecordedRequest) -> MockResponse? = { null }

    /** The key that each replica holds. */
    private val keys = ConcurrentHashMap<String, SealingKey>()

    /** Every pin that a replica's document was verified against, with the replica. */
    public val verified: CopyOnWriteArrayList<Pair<String, Pin>> = CopyOnWriteArrayList<Pair<String, Pin>>()

    /** What a replica's verification says; throw to fail it. */
    @Volatile
    public var endorse: (replica: String, pin: Pin) -> Verification = { replica, _ -> endorsement(replica) }

    internal val verifier = FakeVerifier { document, _, pin ->
        val replica = document.toString(Charsets.UTF_8)
        verified += replica to pin
        endorse(replica, pin)
    }
    private val clients = CopyOnWriteArrayList<AutoCloseable>()
    private val gates = CopyOnWriteArrayList<CountDownLatch>()

    /**
     * A response that the gateway does not send until the test opens the
     * gate that this returns, or ends.
     */
    public fun hold(): CountDownLatch = CountDownLatch(1).also { gates += it }

    init {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val url = request.requestUrl!!
                return when {
                    url.encodedPath == "/catalog" -> {
                        catalogFetches.incrementAndGet()
                        catalog()
                    }
                    url.encodedPath == "/.well-known/tinfoil-attestation" -> {
                        val replica = url.queryParameter("enclave").orEmpty()
                        attestationFetches += replica
                        attestation(replica)
                    }
                    else -> intercept(request) ?: forward(request)
                }
            }
        }
    }

    /** The key of [replica], made when it is first asked for. */
    public fun key(replica: String): SealingKey = keys.computeIfAbsent(replica) { SealingKey() }

    /** Gives [replica] a new key, as a replica that restarted has. */
    public fun rotateKey(replica: String) {
        keys[replica] = SealingKey()
    }

    /** A verification that endorses [replica]'s key for an hour. */
    public fun endorsement(replica: String): Verification =
        verification("ab".repeat(32), clock().plusSeconds(3600), hpkePublicKey = key(replica).publicKey)

    /** Serves [models] as the catalog: each model's repository and replicas. */
    public fun serve(vararg models: Pair<String, Pair<String, List<String>>>) {
        val body = models.joinToString(",", "{", "}") { (model, entry) ->
            """"$model":{"repo":"${entry.first}","hosts":[${entry.second.joinToString(",") { "\"$it\"" }}],"context":1048576}"""
        }
        catalog = { MockResponse().setHeader("Content-Type", "application/json").setBody(body) }
    }

    private fun forward(request: RecordedRequest): MockResponse {
        val wire = request.body.clone().readByteArray()
        val encapsulated = request.getHeader(ENCAPSULATED_KEY_HEADER)
        if (encapsulated == null) {
            return Received(request, wire, wire, null).also { received += it }.let(answer)
        }
        val replica = request.getHeader("X-Tinfoil-Seal").orEmpty()
        val opened = try {
            keys[replica]!!.open(encapsulated, wire)
        } catch (_: Exception) {
            received += Received(request, wire, null, null)
            return SealingDispatcher.keyConfigProblem()
        }
        return Received(request, wire, opened.plaintext, opened).also { received += it }.let(answer)
    }

    /** A trust policy that appraises with [verifier]. */
    public fun appraisingVerifier(): Verifier = Verifier.appraisingWith(verifier)

    /** How many documents [verifier] was asked to verify. */
    public val verifications: Int get() = verifier.verifications.get()

    /** What makes clients as [internals] has them made. */
    public fun connections(): TestConnections = TestConnections(internals())

    internal fun internals(): Internals = Internals(
        http = HttpSettings(trust = authority.trust),
        clock = clock,
        retryDelay = 1.milliseconds,
        timeSource = timeSource,
    )

    public suspend fun client(
        modelPins: Map<String, ModelPin> = emptyMap(),
        pinnedModelsOnly: Boolean = false,
        baseUrl: String? = this.baseUrl,
        verifier: Verifier? = Verifier.appraisingWith(this.verifier),
        userCacheSecret: String? = "test-secret",
        verificationCheck: VerificationCheck? = null,
        onVerificationResult: ((Result<Verification>) -> Unit)? = null,
        catalog: (() -> Catalog)? = null,
    ): GatewayHttpClient = GatewayHttpClient.create(internals()) {
        this.modelPins = modelPins
        this.pinnedModelsOnly = pinnedModelsOnly
        this.baseUrl = baseUrl
        this.verifier = verifier
        this.userCacheSecret = userCacheSecret
        this.verificationCheck = verificationCheck
        this.onVerificationResult = onVerificationResult
        this.catalog = catalog
    }.also { clients += it }

    /** A client that is checked but has fetched nothing, so that any I/O shows. */
    public fun unverified(
        modelPins: Map<String, ModelPin> = emptyMap(),
        pinnedModelsOnly: Boolean = false,
        baseUrl: String? = this.baseUrl,
        verifier: Verifier? = Verifier.appraisingWith(this.verifier),
        userCacheSecret: String? = "test-secret",
        catalog: (() -> Catalog)? = null,
    ): GatewayHttpClient = GatewayHttpClient.unverified(
        GatewaySettings(modelPins, pinnedModelsOnly, baseUrl, verifier, userCacheSecret, null, null, catalog), internals(),
    ).also { clients += it }

    public fun track(client: AutoCloseable) {
        clients += client
    }

    /** A document that does not verify. */
    public fun refuse(): Nothing = throw AttestationException("the document does not verify")

    override fun close() {
        clients.forEach { it.close() }
        gates.forEach { it.countDown() }
        server.shutdown()
    }
}
