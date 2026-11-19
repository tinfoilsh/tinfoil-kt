package sh.tinfoil.testing

// What is public here is what the tests of another module use; they cannot
// see this module's internals, so what names one stays internal.

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.CryptoMaterial
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.Pin
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.SoftwareIdentity
import sh.tinfoil.TransportMode
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import sh.tinfoil.VerificationLayer
import sh.tinfoil.VerificationMetadata
import sh.tinfoil.Verifier
import sh.tinfoil.internal.GatewaySettings
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.RouteSettings
import sh.tinfoil.internal.RouterDiscovery
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.internal.transport.LeafKeyPin
import sh.tinfoil.internal.transport.TlsTrust
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.internal.verification.Attestor
import java.net.Proxy
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** A clock that tests move by hand. */
public class TestClock(start: Instant = Instant.parse("2026-01-01T00:00:00Z")) : () -> Instant {
    private val now = AtomicReference(start)

    override fun invoke(): Instant = now.get()

    public fun advance(seconds: Long) {
        now.updateAndGet { it.plusSeconds(seconds) }
    }
}

/** A certificate authority that test clients trust, and that nothing else does. */
public class TestAuthority {
    private val root: HeldCertificate = HeldCertificate.Builder().certificateAuthority(1).build()

    /** A leaf certificate for [host] with a key of its own. */
    public fun issue(host: String = "localhost"): HeldCertificate =
        HeldCertificate.Builder().addSubjectAlternativeName(host).signedBy(root).build()

    /** A leaf certificate for [host] that carries [key]'s key pair. */
    public fun reissue(key: HeldCertificate, host: String = "localhost"): HeldCertificate =
        HeldCertificate.Builder().keyPair(key.keyPair).addSubjectAlternativeName(host).signedBy(root).build()

    /** The fingerprint of the authority's own key, which signs the leaves. */
    public val fingerprint: String get() = root.fingerprint

    internal val trust: TlsTrust = HandshakeCertificates.Builder().addTrustedCertificate(root.certificate).build()
        .let { TlsTrust(it.sslSocketFactory(), it.trustManager) }
}

public val HeldCertificate.fingerprint: String get() = LeafKeyPin.fingerprint(certificate)

public fun HeldCertificate.serverHandshake(): HandshakeCertificates =
    HandshakeCertificates.Builder().heldCertificate(this).build()

/** A started HTTPS server that presents [certificate]. */
public fun httpsServer(certificate: HeldCertificate, port: Int = 0): MockWebServer =
    MockWebServer().apply {
        useHttps(certificate.serverHandshake().sslSocketFactory(), false)
        start(port)
    }

public const val TLS_KEY_FORMAT: String = Attestor.TLS_KEY_FORMAT
public const val HPKE_KEY_FORMAT: String = Attestor.HPKE_KEY_FORMAT

/**
 * A verification that endorses [fingerprint] as the TLS key, and [hpkePublicKey]
 * as the HPKE key if there is one, until [expiresAt].
 */
public fun verification(
    fingerprint: String?,
    expiresAt: Instant,
    hpkePublicKey: String? = null,
    cryptoMaterial: List<CryptoMaterial> = listOfNotNull(
        fingerprint?.let { CryptoMaterial("tls", TLS_KEY_FORMAT, it) },
        hpkePublicKey?.let { CryptoMaterial("hpke", HPKE_KEY_FORMAT, it) },
    ),
    codeDigest: String = "ab".repeat(32),
): Verification = Verification(
    configRepo = "tinfoilsh/example",
    codeDigest = codeDigest,
    codeTag = null,
    codeMeasurement = null,
    enclaveMeasurement = null,
    config = null,
    runtime = null,
    platform = null,
    tlsPublicKeyFingerprint = fingerprint,
    hpkePublicKey = hpkePublicKey,
    cryptoMaterial = cryptoMaterial,
    freshnessExpiresAt = expiresAt,
    metadata = VerificationMetadata(SoftwareIdentity("test", "0"), Instant.EPOCH),
)

/**
 * A verifier that appraises nothing: it returns what [verify] says for each
 * document, and records what it was asked.
 */
internal class FakeVerifier(
    @Volatile var verify: (document: ByteArray, nonce: ByteArray, pin: Pin) -> Verification = { _, _, _ ->
        throw AttestationException("no verification was set up")
    },
) : AttestationVerifier {
    override val callerAuthorizesConfig: Boolean = false

    val nonces = CopyOnWriteArrayList<String>()
    val verifications = AtomicInteger()
    val pinChecks = AtomicInteger()

    override fun newNonce(): ByteArray =
        ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }

    override fun attestationUrl(host: String, relay: String?, nonce: ByteArray): String {
        for (authority in listOfNotNull(host, relay)) {
            if (authority.isEmpty() || authority.any { it in "/@?# " }) {
                throw ConfigurationException("invalid host: want a host with an optional port")
            }
        }
        val hex = nonce.joinToString("") { "%02x".format(it) }
        return if (relay == null) {
            "https://$host/.well-known/tinfoil-attestation?nonce=$hex"
        } else {
            "https://$relay/.well-known/tinfoil-attestation?nonce=$hex&enclave=$host"
        }
    }

    override fun checkPinVerifiability(pin: Pin) {
        pinChecks.incrementAndGet()
        if (pin.repo == null && pin.project == null) {
            throw ConfigurationException("a pin is required under the default config trust")
        }
    }

    override fun verify(document: ByteArray, nonce: ByteArray, pin: Pin): Verification {
        verifications.incrementAndGet()
        nonces += nonce.joinToString("") { "%02x".format(it) }
        return verify.invoke(document, nonce, pin)
    }
}

/** The failure of a verification, for a test that cannot make one itself: the constructor is this module's. */
public fun attestationFailure(detail: String, layer: VerificationLayer? = null): AttestationException =
    AttestationException(detail, layer = layer)

/** A verifier that tells [note] the name of every call into [inner], and then makes it. */
internal class NotingVerifier(
    private val inner: AttestationVerifier,
    private val note: (String) -> Unit,
) : AttestationVerifier {
    override val callerAuthorizesConfig: Boolean
        get() {
            note("callerAuthorizesConfig")
            return inner.callerAuthorizesConfig
        }

    override fun newNonce(): ByteArray {
        note("newNonce")
        return inner.newNonce()
    }

    override fun attestationUrl(host: String, relay: String?, nonce: ByteArray): String {
        note("attestationUrl")
        return inner.attestationUrl(host, relay, nonce)
    }

    override fun checkPinVerifiability(pin: Pin) {
        note("checkPinVerifiability")
        inner.checkPinVerifiability(pin)
    }

    override fun verify(document: ByteArray, nonce: ByteArray, pin: Pin): Verification {
        note("verify")
        return inner.verify(document, nonce, pin)
    }
}

/**
 * Makes HTTP clients under a test's trust anchors, clock and router list in
 * place of the platform's, from options that were read already. It is how
 * the tests of another module put their own clients over a test server.
 */
public class TestConnections internal constructor(private val internals: Internals) {
    public suspend fun enclave(enclave: String, pin: Pin, settings: RouteSettings): EnclaveHttpClient =
        EnclaveHttpClient.create(enclave, pin, settings, internals)

    public suspend fun router(settings: RouteSettings): RouterHttpClient = RouterHttpClient.create(settings, internals)

    @ExperimentalTinfoilApi
    public suspend fun gateway(settings: GatewaySettings): GatewayHttpClient = GatewayHttpClient.create(settings, internals)
}

/**
 * An enclave for tests: an HTTPS server with a certificate of its own, a
 * relay that serves its attestation document, and a verifier that endorses
 * whatever the test says. Attestation is fetched through the relay, so the
 * enclave's own server sees only attested requests.
 */
public class TestEnclave(
    /** The certificate that the enclave's server presents first. */
    issue: (TestAuthority) -> HeldCertificate = { it.issue() },
) : AutoCloseable {
    public val authority: TestAuthority = TestAuthority()
    public val clock: TestClock = TestClock()
    public var certificate: HeldCertificate = issue(authority)
        private set
    public var server: MockWebServer = httpsServer(certificate)
        private set
    public val relay: MockWebServer = httpsServer(authority.issue())
    public val port: Int = server.port
    public val host: String = "localhost:$port"
    public val relayHost: String = "localhost:${relay.port}"

    /** How long a verification stays fresh on [clock]. */
    public val lifetimeSeconds: Long = 3600L

    /** The TLS key that the next verification endorses; the server's own unless a test says otherwise. */
    @Volatile
    public var endorsed: () -> String? = { certificate.fingerprint }

    /** The HPKE key that the next verification endorses; none unless a test says otherwise. */
    @Volatile
    public var endorsedHpke: () -> String? = { null }

    internal val verifier = FakeVerifier { _, _, _ ->
        verification(endorsed(), clock().plusSeconds(lifetimeSeconds), hpkePublicKey = endorsedHpke())
    }

    /** How many documents [verifier] was asked to verify. */
    public val verifications: Int get() = verifier.verifications.get()

    /** How many pins [verifier] was asked to check. */
    public val pinChecks: Int get() = verifier.pinChecks.get()

    /** Replaces what [verifier] says of every document. */
    public fun verifyWith(verify: (document: ByteArray, nonce: ByteArray, pin: Pin) -> Verification) {
        verifier.verify = verify
    }

    /** A trust policy that appraises with [verifier], and tells [note] the name of each call into it. */
    public fun appraisingVerifier(note: ((String) -> Unit)? = null): Verifier =
        Verifier.appraisingWith(if (note == null) verifier else NotingVerifier(verifier, note))
    private val clients = CopyOnWriteArrayList<EnclaveHttpClient>()

    init {
        relay.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = MockResponse().setBody("document")
        }
    }

    /** How many attestation documents were fetched. */
    public val fetches: Int get() = relay.requestCount

    /** Replaces the enclave's server with one on the same port that holds a new key. */
    public fun rotateKey() {
        server.shutdown()
        certificate = authority.issue()
        server = httpsServer(certificate, port)
    }

    public fun url(path: String = "/"): HttpUrl = "https://$host$path".toHttpUrl()

    public fun get(path: String = "/"): Request = Request.Builder().url(url(path)).build()

    internal fun internals(proxy: Proxy? = null, retryDelay: Duration = 1.milliseconds): Internals =
        Internals(
            http = HttpSettings(trust = authority.trust, proxy = proxy),
            clock = clock,
            retryDelay = retryDelay,
        )

    /** Internals under which this enclave is the router that is chosen when [listUrl] names none that verifies. */
    internal fun routerInternals(listUrl: HttpUrl): Internals = Internals(
        http = HttpSettings(trust = authority.trust),
        clock = clock,
        retryDelay = 1.milliseconds,
        discovery = RouterDiscovery.Settings(listUrl = listUrl, fallback = host),
    )

    /** What makes clients as [internals] has them made. */
    public fun connections(): TestConnections = TestConnections(internals())

    /** What makes clients as [routerInternals] has them made. */
    public fun routerConnections(listUrl: HttpUrl): TestConnections = TestConnections(routerInternals(listUrl))

    internal suspend fun client(
        enclave: String = host,
        pin: Pin = Pin(repo = "tinfoilsh/example"),
        transportMode: TransportMode = TransportMode.TLS,
        baseUrl: String? = null,
        attestationRelay: String? = relayHost,
        userCacheSecret: String? = null,
        verificationCheck: VerificationCheck? = null,
        onVerificationResult: ((Result<Verification>) -> Unit)? = null,
        internals: Internals = internals(),
    ): EnclaveHttpClient = EnclaveHttpClient.create(enclave, pin, internals) {
        this.transportMode = transportMode
        this.baseUrl = baseUrl
        this.attestationRelay = attestationRelay
        this.verifier = Verifier.appraisingWith(this@TestEnclave.verifier)
        this.userCacheSecret = userCacheSecret
        this.verificationCheck = verificationCheck
        this.onVerificationResult = onVerificationResult
    }.also { clients += it }

    override fun close() {
        clients.forEach { it.close() }
        server.shutdown()
        relay.shutdown()
    }
}
