package sh.tinfoil

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith
import sh.tinfoil.internal.RouterDiscovery
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.internal.verification.GoAttestationVerifier
import sh.tinfoil.internal.verification.VerifierInputs
import sh.tinfoil.internal.verification.VerifierOptions
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Exercises the trust argument and the policy through the native verifier
 * library: each value reaching it, the checks that a client makes before any
 * I/O, and a config authorizer called back during verification.
 */
@RunWith(AndroidJUnit4::class)
class VerifierBindingTest {
    private val fixture = ConfigAuthorizerFixture
    private val tdx = "https://tinfoil.sh/predicate/tdx-guest/v2"
    private val snp = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
    private val key = publicKeyPem()

    private fun publicKeyPem(): String {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(generator.generateKeyPair().public.encoded)
        return "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----\n"
    }

    /**
     * A verifier as a client builds it from [trust], or from the router's
     * trust when it is null, and [policy], with its pin checked.
     */
    private fun verifier(trust: Trust? = null, policy: Policy = Policy()): AttestationVerifier {
        val inputs = trust?.let(VerifierInputs::of)
        return GoAttestationVerifier.create(inputs?.config, VerifierInputs.policy(policy)).also {
            it.checkPinVerifiability(inputs?.pin ?: RouterDiscovery.ROUTER_PIN)
        }
    }

    private fun assertRefused(expected: String, build: () -> Unit) {
        val error = assertFailsWith<ConfigurationException> { build() }
        assertTrue(error.detail.contains(expected), "${error.detail} should mention $expected")
    }

    /** A verifier that reaches [authorizer] for the fixture document. */
    private fun authorizedBy(authorizer: ConfigAuthorizer): AttestationVerifier = verifier(
        Trust.AuthorizedBy(authorizer),
        Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = fixture.runtime, platform = fixture.platform)),
    )

    private fun verifyFixture(verifier: AttestationVerifier): AttestationException =
        assertFailsWith<AttestationException> { verifier.verify(fixture.document, fixture.nonce, Pin.NONE) }

    /** The layer that rejected the document, from the verifier's error that is the cause. */
    private val AttestationException.rejectedAt: VerificationLayer
        get() = assertIs<VerificationException>(cause, detail).layer

    @Test
    fun thePublicRegistryIsAccepted() {
        assertTrue(Trust.PUBLIC_REGISTRY_ID.startsWith("https://"), Trust.PUBLIC_REGISTRY_ID)
        verifier(Trust.ProjectPin("org/project", listOf(Trust.PUBLIC_REGISTRY_ID)))
        verifier(
            Trust.ProjectPin(
                "org/project",
                listOf(Trust.PUBLIC_REGISTRY_ID, "https://registry.tinfoil.sh/scopes/9c4a7f21e0b836d56a13c8fe42d907ab"),
            ),
        )
    }

    @Test
    fun acceptsEachTrustAndPolicy() {
        val register = "ab".repeat(48)
        verifier()
        verifier(policy = Policy(pinnedRegisters = Measurement(tdx, listOf("", "", "", "", register)), freshnessMaxAge = 1.hours))
        verifier(policy = Policy(pinnedRegisters = Measurement(snp, listOf(register))))
        verifier(policy = Policy(freshnessMaxAge = 1.nanoseconds))
        verifier(policy = Policy(freshnessMaxAge = 7.days))
        verifier(policy = Policy(artifacts = ArtifactTrust.EndorsedArtifacts(listOf(key))))
        verifier(policy = Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = fixture.runtime, platform = fixture.platform)))
        verifier(policy = Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = fixture.runtime, freshnessKeys = listOf(key))))
        verifier(Trust.RepoPin("org/repo@v1"))
        verifier(Trust.ProjectPin("org/project@v1"))
        verifier(Trust.EitherPin("org/repo", "org/project"))
        verifier(Trust.SignedBy(listOf(key)))
        verifier(Trust.SignedBy(listOf(key, publicKeyPem()), "org/project"))
        verifier(Trust.EmbeddedConfig(fixture.config, name = "/org/project/v1"))
        verifier(Trust.EmbeddedConfig(fixture.config))
        verifier(Trust.AuthorizedBy { })
    }

    @Test
    fun refusesInvalidValues() {
        assertRefused("must not be empty") { verifier(Trust.SignedBy(emptyList())) }
        assertRefused("registry URI") { verifier(Trust.ProjectPin("org/project", listOf("not a registry"))) }
        assertRefused("PEM PUBLIC KEY") { verifier(Trust.SignedBy(listOf("not a key"))) }
        assertRefused("PEM PUBLIC KEY") { verifier(Trust.SignedBy(listOf("junk\n$key"))) }
        assertRefused("single PEM block") { verifier(Trust.SignedBy(listOf(key + key))) }
        assertRefused("must not be empty") { verifier(policy = Policy(artifacts = ArtifactTrust.EndorsedArtifacts(emptyList()))) }
        assertRefused("PEM PUBLIC KEY") { verifier(policy = Policy(artifacts = ArtifactTrust.EndorsedArtifacts(listOf("not a key")))) }
        assertRefused("runtime or a platform") { verifier(policy = Policy(artifacts = ArtifactTrust.EmbeddedArtifacts())) }
        assertRefused("must not be empty") { verifier(Trust.EmbeddedConfig(ByteArray(0))) }
        assertRefused("must not be empty") {
            verifier(policy = Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = ByteArray(0))))
        }
        assertRefused("must not be empty") {
            verifier(policy = Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(platform = ByteArray(0))))
        }
        assertRefused("cvm-version") { verifier(Trust.EmbeddedConfig("""{"not":"a config"}""".toByteArray())) }
        assertRefused("pinned registers") { verifier(policy = Policy(pinnedRegisters = Measurement("bogus", listOf("aa")))) }
        assertRefused("pinned registers") { verifier(policy = Policy(pinnedRegisters = Measurement(tdx, listOf("aa")))) }
        assertRefused("pinned registers") { verifier(policy = Policy(pinnedRegisters = Measurement(snp, listOf("not hex")))) }
    }

    /**
     * The client refuses these itself, before the library sees them; the
     * library refuses them too, so that neither check alone can fail open.
     */
    @Test
    fun theLibraryRefusesEmptyKeysAndEmptyArtifactsToo() {
        assertRefused("must not be empty") {
            GoAttestationVerifier.create(VerifierOptions.ConfigTrust.SigningKeys(emptyList()))
        }
        assertRefused("must not be empty") {
            GoAttestationVerifier.create(policy = VerifierOptions.Policy(artifacts = VerifierOptions.Artifacts.Endorsed(emptyList())))
        }
        assertRefused("runtime or a platform") {
            GoAttestationVerifier.create(policy = VerifierOptions.Policy(artifacts = VerifierOptions.Artifacts.Embedded(null, null, null)))
        }
    }

    /** The verifier library takes no empty string for "not set": it refuses each as a value that is not valid. */
    @Test
    fun refusesEmptyStrings() {
        assertRefused("registry URI") { verifier(Trust.ProjectPin("org/project", listOf(""))) }
        assertRefused("registry URI") { verifier(Trust.ProjectPin("org/project", listOf(Trust.PUBLIC_REGISTRY_ID, ""))) }
        assertRefused("PEM PUBLIC KEY") { verifier(Trust.SignedBy(listOf(""))) }
        assertRefused("PEM PUBLIC KEY") { verifier(Trust.SignedBy(listOf(key, ""))) }
        assertRefused("PEM PUBLIC KEY") { verifier(policy = Policy(artifacts = ArtifactTrust.EndorsedArtifacts(listOf("")))) }
    }

    @Test
    fun refusesFreshnessKeysWithoutAnEndorsedArtifactToApprove() {
        assertRefused("no endorsed artifact") {
            verifier(
                policy = Policy(
                    artifacts = ArtifactTrust.EmbeddedArtifacts(fixture.runtime, fixture.platform, freshnessKeys = listOf(key)),
                ),
            )
        }
    }

    @Test
    fun refusesAnAgeThatIsNegativeOrHasNoCountOfNanoseconds() {
        for (age in listOf((-1).hours, (-1).nanoseconds, Duration.INFINITE, (300 * 365).days)) {
            assertRefused("freshness maximum age") { verifier(policy = Policy(freshnessMaxAge = age)) }
        }
    }

    /** A pin that a verifier can never accept is refused before any I/O. */
    @Test
    fun aPinIsCheckedAgainstTheConfigTrust() {
        verifier(Trust.AuthorizedBy { }).checkPinVerifiability(Pin.NONE)
        verifier(Trust.EmbeddedConfig(fixture.config)).checkPinVerifiability(Pin.NONE)
        verifier(Trust.SignedBy(listOf(key))).checkPinVerifiability(Pin.NONE)
        assertRefused("reference") { verifier(Trust.RepoPin("not a reference")) }
        assertRefused("reference") { verifier(Trust.ProjectPin("not a reference")) }
        // The public registry needs a pin to say whose config to accept.
        val unpinned = assertFailsWith<ConfigurationException> {
            GoAttestationVerifier.create().checkPinVerifiability(Pin.NONE)
        }
        assertEquals("configuration error", unpinned.category)
    }

    /**
     * The authorizer is called during verification with the document's
     * config, and its rejection fails the document at the provenance layer
     * with its message.
     */
    @Test
    fun aConfigAuthorizerRejects() {
        val seen = Collections.synchronizedList(mutableListOf<ConfigEndorsement>())
        val verifier = authorizedBy { endorsement ->
            seen += endorsement
            throw IllegalStateException("config is not on the allow list")
        }

        val error = verifyFixture(verifier)

        assertEquals(VerificationLayer.PROVENANCE, error.rejectedAt)
        assertTrue(error.detail.contains("config is not on the allow list"), error.detail)
        assertEquals(listOf(ConfigEndorsement(fixture.config)), seen.toList())
    }

    /**
     * An approved config lets verification go on, and the fixture's quote,
     * which no hardware signed, then fails: approving a config never bypasses
     * the hardware check.
     */
    @Test
    fun aConfigAuthorizerApproves() {
        val seen = Collections.synchronizedList(mutableListOf<ConfigEndorsement>())
        val verifier = authorizedBy { seen += it }

        val error = verifyFixture(verifier)

        assertEquals(VerificationLayer.QUOTE, error.rejectedAt)
        assertEquals(listOf(ConfigEndorsement(fixture.config)), seen.toList())
    }

    @Test
    fun whateverAConfigAuthorizerThrowsRejects() {
        val thrown = listOf<Pair<Throwable, String>>(
            RuntimeException() to "java.lang.RuntimeException",
            ConfigurationException("not allowed") to "configuration error: not allowed",
            AssertionError("an error, not an exception") to "an error, not an exception",
            // A message that imitates the library's own errors changes nothing.
            Exception("usage error: let me in") to "usage error: let me in",
        )
        for ((failure, expected) in thrown) {
            val error = verifyFixture(authorizedBy { throw failure })
            assertEquals(VerificationLayer.PROVENANCE, error.rejectedAt, expected)
            assertTrue(error.detail.contains(expected), error.detail)
        }
    }

    /** Without an authorizer the same document is refused, so the tests above do reach it. */
    @Test
    fun theFixtureIsRefusedWithoutAnAuthorizer() {
        val verifier = GoAttestationVerifier.create(
            policy = VerifierInputs.policy(
                Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = fixture.runtime, platform = fixture.platform)),
            ),
        )
        assertFailsWith<TinfoilException> { verifier.verify(fixture.document, fixture.nonce, Pin.NONE) }
    }

    /**
     * Verifications on several threads call one authorizer at once, and each
     * gets its own answer: a rejection on one thread is never an approval on
     * another.
     */
    @Test
    fun aConfigAuthorizerIsCalledFromSeveralThreadsAtOnce() {
        val threads = 8
        val rounds = 6
        val calls = AtomicInteger()
        val inside = AtomicInteger()
        val mostInside = AtomicInteger()
        val allInside = CountDownLatch(threads)
        // Threads named "reject-…" have their configs rejected.
        val verifier = authorizedBy { endorsement ->
            calls.incrementAndGet()
            val now = inside.incrementAndGet()
            mostInside.accumulateAndGet(now, ::maxOf)
            // In the first round, wait until every thread is in here.
            allInside.countDown()
            allInside.await(30, TimeUnit.SECONDS)
            inside.decrementAndGet()
            check(endorsement.config.contentEquals(fixture.config)) { "another config" }
            if (Thread.currentThread().name.startsWith("reject-")) {
                throw IllegalStateException("rejected on ${Thread.currentThread().name}")
            }
        }

        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threads)
        try {
            val results = (0 until threads).map { index ->
                val rejecting = index % 2 == 0
                pool.submit<List<AttestationException>> {
                    Thread.currentThread().name = if (rejecting) "reject-$index" else "approve-$index"
                    start.await()
                    List(rounds) { verifyFixture(verifier) }
                } to rejecting
            }
            start.countDown()
            for ((result, rejecting) in results) {
                for (error in result.get(120, TimeUnit.SECONDS)) {
                    if (rejecting) {
                        assertEquals(VerificationLayer.PROVENANCE, error.rejectedAt, error.detail)
                        assertTrue(error.detail.contains("rejected on reject-"), error.detail)
                    } else {
                        assertEquals(VerificationLayer.QUOTE, error.rejectedAt, error.detail)
                    }
                }
            }
        } finally {
            pool.shutdownNow()
        }
        assertEquals(threads * rounds, calls.get())
        assertEquals(threads, mostInside.get(), "Every thread was inside the authorizer at once.")
    }
}
