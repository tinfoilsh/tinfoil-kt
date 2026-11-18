package sh.tinfoil.testing

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
import sh.tinfoil.Pin
import sh.tinfoil.SoftwareIdentity
import sh.tinfoil.TransportMode
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import sh.tinfoil.VerificationMetadata
import sh.tinfoil.Verifier
import sh.tinfoil.internal.Internals
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
internal class TestClock(start: Instant = Instant.parse("2026-01-01T00:00:00Z")) : () -> Instant {
    private val now = AtomicReference(start)

    override fun invoke(): Instant = now.get()

    fun advance(seconds: Long) {
        now.updateAndGet { it.plusSeconds(seconds) }
    }
}

/** A certificate authority that test clients trust, and that nothing else does. */
internal class TestAuthority {
    private val root: HeldCertificate = HeldCertificate.Builder().certificateAuthority(1).build()

    /** A leaf certificate for [host] with a key of its own. */
    fun issue(host: String = "localhost"): HeldCertificate =
        HeldCertificate.Builder().addSubjectAlternativeName(host).signedBy(root).build()

    /** A leaf certificate for [host] that carries [key]'s key pair. */
    fun reissue(key: HeldCertificate, host: String = "localhost"): HeldCertificate =
        HeldCertificate.Builder().keyPair(key.keyPair).addSubjectAlternativeName(host).signedBy(root).build()

    /** The fingerprint of the authority's own key, which signs the leaves. */
    val fingerprint: String get() = root.fingerprint

    val trust: TlsTrust = HandshakeCertificates.Builder().addTrustedCertificate(root.certificate).build()
        .let { TlsTrust(it.sslSocketFactory(), it.trustManager) }
}

internal val HeldCertificate.fingerprint: String get() = LeafKeyPin.fingerprint(certificate)

internal fun HeldCertificate.serverHandshake(): HandshakeCertificates =
    HandshakeCertificates.Builder().heldCertificate(this).build()

/** A started HTTPS server that presents [certificate]. */
internal fun httpsServer(certificate: HeldCertificate, port: Int = 0): MockWebServer =
    MockWebServer().apply {
        useHttps(certificate.serverHandshake().sslSocketFactory(), false)
        start(port)
    }

internal const val TLS_KEY_FORMAT = Attestor.TLS_KEY_FORMAT

/** A verification that endorses [fingerprint] as the TLS key until [expiresAt]. */
internal fun verification(
    fingerprint: String?,
    expiresAt: Instant,
    cryptoMaterial: List<CryptoMaterial> = listOfNotNull(fingerprint?.let { CryptoMaterial("tls", TLS_KEY_FORMAT, it) }),
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
    hpkePublicKey = null,
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

/**
 * An enclave for tests: an HTTPS server with a certificate of its own, a
 * relay that serves its attestation document, and a verifier that endorses
 * whatever the test says. Attestation is fetched through the relay, so the
 * enclave's own server sees only attested requests.
 */
internal class TestEnclave(
    /** The certificate that the enclave's server presents first. */
    issue: (TestAuthority) -> HeldCertificate = { it.issue() },
) : AutoCloseable {
    val authority = TestAuthority()
    val clock = TestClock()
    var certificate: HeldCertificate = issue(authority)
        private set
    var server: MockWebServer = httpsServer(certificate)
        private set
    val relay: MockWebServer = httpsServer(authority.issue())
    val port: Int = server.port
    val host: String = "localhost:$port"
    val relayHost: String = "localhost:${relay.port}"

    /** How long a verification stays fresh on [clock]. */
    val lifetimeSeconds = 3600L

    /** The TLS key that the next verification endorses; the server's own unless a test says otherwise. */
    @Volatile
    var endorsed: () -> String? = { certificate.fingerprint }

    val verifier = FakeVerifier { _, _, _ -> verification(endorsed(), clock().plusSeconds(lifetimeSeconds)) }
    private val clients = CopyOnWriteArrayList<EnclaveHttpClient>()

    init {
        relay.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = MockResponse().setBody("document")
        }
    }

    /** How many attestation documents were fetched. */
    val fetches: Int get() = relay.requestCount

    /** Replaces the enclave's server with one on the same port that holds a new key. */
    fun rotateKey() {
        server.shutdown()
        certificate = authority.issue()
        server = httpsServer(certificate, port)
    }

    fun url(path: String = "/"): HttpUrl = "https://$host$path".toHttpUrl()

    fun get(path: String = "/"): Request = Request.Builder().url(url(path)).build()

    fun internals(proxy: Proxy? = null, retryDelay: Duration = 1.milliseconds): Internals =
        Internals(
            http = HttpSettings(trust = authority.trust, proxy = proxy),
            clock = clock,
            retryDelay = retryDelay,
        )

    suspend fun client(
        enclave: String = host,
        pin: Pin = Pin(repo = "tinfoilsh/example"),
        transportMode: TransportMode = TransportMode.Tls,
        baseUrl: String? = null,
        attestationRelay: String? = relayHost,
        userCacheSecret: String? = null,
        verificationCheck: VerificationCheck? = null,
        onVerificationResult: ((Result<Verification>) -> Unit)? = null,
        internals: Internals = internals(),
    ): EnclaveHttpClient = EnclaveHttpClient.create(
        enclave, pin, transportMode, baseUrl, attestationRelay, Verifier.appraisingWith(verifier), userCacheSecret,
        verificationCheck, onVerificationResult, internals,
    ).also { clients += it }

    override fun close() {
        clients.forEach { it.close() }
        server.shutdown()
        relay.shutdown()
    }
}
