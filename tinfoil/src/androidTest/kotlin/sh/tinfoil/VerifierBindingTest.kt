package sh.tinfoil

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith
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
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Exercises [Verifier] through the native verifier library: each option
 * reaching it, the checks that a client makes before any I/O, and a config
 * authorizer called back during verification.
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

    private fun assertRefused(expected: String, build: () -> Verifier) {
        val error = assertFailsWith<ConfigurationException> { build() }
        assertTrue(error.detail.contains(expected), "${error.detail} should mention $expected")
    }

    /** A verifier that reaches [authorizer] for the fixture document. */
    private fun authorizedBy(authorizer: ConfigAuthorizer): Verifier = Verifier(
        embeddedReferences = EmbeddedReferences(runtime = fixture.runtime, platform = fixture.platform),
        configAuthorizer = authorizer,
    )

    private fun verifyFixture(verifier: Verifier): AttestationException =
        assertFailsWith<AttestationException> { verifier.backend.verify(fixture.document, fixture.nonce, Pin()) }

    @Test
    fun thePublicRegistryIsAccepted() {
        assertTrue(Verifier.PUBLIC_REGISTRY_ID.startsWith("https://"), Verifier.PUBLIC_REGISTRY_ID)
        Verifier(configRegistryIds = listOf(Verifier.PUBLIC_REGISTRY_ID))
        Verifier(configRegistryIds = listOf(Verifier.PUBLIC_REGISTRY_ID, "https://registry.tinfoil.sh/scopes/9c4a7f21e0b836d56a13c8fe42d907ab"))
    }

    @Test
    fun acceptsEachOption() {
        val register = "ab".repeat(48)
        assertFalse(Verifier().backend.callerAuthorizesConfig)
        Verifier(pinnedRegisters = Measurement(tdx, listOf("", "", "", "", register)), freshnessMaxAge = 1.hours)
        Verifier(pinnedRegisters = Measurement(snp, listOf(register)))
        Verifier(freshnessMaxAge = 1.nanoseconds)
        Verifier(freshnessMaxAge = 7.days)
        Verifier(configSigningKeysPem = listOf(key))
        Verifier(configSigningKeysPem = listOf(key, publicKeyPem()))
        Verifier(freshnessSigningKeysPem = listOf(key))
        assertFalse(
            Verifier(embeddedReferences = EmbeddedReferences(runtime = fixture.runtime, platform = fixture.platform))
                .backend.callerAuthorizesConfig,
        )

        val bytes = Verifier(
            embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Bytes(fixture.config, name = "/org/project/v1")),
        )
        assertTrue(bytes.backend.callerAuthorizesConfig)

        val reference = Verifier(
            embeddedReferences = EmbeddedReferences(
                config = EmbeddedConfig.Reference(
                    digest = fixture.sha256Hex(fixture.config),
                    runtime = RuntimeReference("tinfoilsh/cvmimage", "v0.15.0", fixture.sha256Hex(fixture.runtime)),
                ),
            ),
        )
        assertTrue(reference.backend.callerAuthorizesConfig)

        val everything = Verifier(
            embeddedReferences = EmbeddedReferences(EmbeddedConfig.Bytes(fixture.config), fixture.runtime, fixture.platform),
        )
        assertTrue(everything.backend.callerAuthorizesConfig)

        assertTrue(Verifier(configAuthorizer = { }).backend.callerAuthorizesConfig)
    }

    @Test
    fun refusesInvalidOptions() {
        assertRefused("must not be empty") { Verifier(configRegistryIds = emptyList()) }
        assertRefused("registry URI") { Verifier(configRegistryIds = listOf("not a registry")) }
        assertRefused("must not be empty") { Verifier(configSigningKeysPem = emptyList()) }
        assertRefused("PEM PUBLIC KEY") { Verifier(configSigningKeysPem = listOf("not a key")) }
        assertRefused("PEM PUBLIC KEY") { Verifier(configSigningKeysPem = listOf("junk\n$key")) }
        assertRefused("single PEM block") { Verifier(configSigningKeysPem = listOf(key + key)) }
        assertRefused("must not be empty") { Verifier(freshnessSigningKeysPem = emptyList()) }
        assertRefused("PEM PUBLIC KEY") { Verifier(freshnessSigningKeysPem = listOf("not a key")) }
        assertRefused("at least one component") { Verifier(embeddedReferences = EmbeddedReferences()) }
        assertRefused("must not be empty") {
            Verifier(embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Bytes(ByteArray(0))))
        }
        assertRefused("must not be empty") { Verifier(embeddedReferences = EmbeddedReferences(runtime = ByteArray(0))) }
        assertRefused("must not be empty") { Verifier(embeddedReferences = EmbeddedReferences(platform = ByteArray(0))) }
        assertRefused("cvm-version") {
            Verifier(embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Bytes("not: a config".toByteArray())))
        }
        assertRefused("either bytes, or digest and runtime") {
            Verifier(
                embeddedReferences = EmbeddedReferences(
                    config = EmbeddedConfig.Reference("", RuntimeReference("tinfoilsh/cvmimage", "v0.15.0", "ab")),
                ),
            )
        }
        assertRefused("pinned registers") { Verifier(pinnedRegisters = Measurement("bogus", listOf("aa"))) }
        assertRefused("pinned registers") { Verifier(pinnedRegisters = Measurement(tdx, listOf("aa"))) }
        assertRefused("pinned registers") { Verifier(pinnedRegisters = Measurement(snp, listOf("not hex"))) }
    }

    /** The verifier library takes no empty string for "not set": it refuses each as a value that is not valid. */
    @Test
    fun refusesEmptyStrings() {
        val runtime = RuntimeReference("tinfoilsh/cvmimage", "v0.15.0", "ab".repeat(32))
        val digest = "cd".repeat(32)
        fun reference(runtime: RuntimeReference) =
            Verifier(embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Reference(digest, runtime)))
        reference(runtime)
        assertRefused("registry URI") { Verifier(configRegistryIds = listOf("")) }
        assertRefused("registry URI") { Verifier(configRegistryIds = listOf(Verifier.PUBLIC_REGISTRY_ID, "")) }
        assertRefused("PEM PUBLIC KEY") { Verifier(configSigningKeysPem = listOf("")) }
        assertRefused("PEM PUBLIC KEY") { Verifier(configSigningKeysPem = listOf(key, "")) }
        assertRefused("PEM PUBLIC KEY") { Verifier(freshnessSigningKeysPem = listOf("")) }
        assertRefused("runtime repository") { reference(RuntimeReference("", runtime.tag, runtime.digest)) }
        assertRefused("runtime tag") { reference(RuntimeReference(runtime.repo, "", runtime.digest)) }
        assertRefused("runtime digest") { reference(RuntimeReference(runtime.repo, runtime.tag, "")) }
    }

    @Test
    fun refusesConflictingTrustSources() {
        assertRefused("registry ID policy") {
            Verifier(configRegistryIds = listOf(Verifier.PUBLIC_REGISTRY_ID), configSigningKeysPem = listOf(key))
        }
        assertRefused("conflicting trust sources") {
            Verifier(
                configSigningKeysPem = listOf(key),
                embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Bytes(fixture.config)),
            )
        }
        assertRefused("no endorsed artifact") {
            Verifier(
                freshnessSigningKeysPem = listOf(key),
                embeddedReferences = EmbeddedReferences(EmbeddedConfig.Bytes(fixture.config), fixture.runtime, fixture.platform),
            )
        }
        assertRefused("config authorizer conflicts") {
            Verifier(configSigningKeysPem = listOf(key), configAuthorizer = { })
        }
        assertRefused("config authorizer conflicts") {
            Verifier(
                embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Bytes(fixture.config)),
                configAuthorizer = { },
            )
        }
        assertRefused("require endorsement verification") {
            Verifier(configRegistryIds = listOf(Verifier.PUBLIC_REGISTRY_ID), configAuthorizer = { })
        }
    }

    @Test
    fun refusesAnAgeThatIsNotPositiveOrHasNoCountOfNanoseconds() {
        for (age in listOf(Duration.ZERO, 0.4.nanoseconds, (-1).hours, Duration.INFINITE, (300 * 365).days)) {
            assertRefused("freshness maximum age") { Verifier(freshnessMaxAge = age) }
        }
    }

    /** A pin that a verifier can never accept is refused before any I/O. */
    @Test
    fun aPinIsCheckedAgainstThePolicy() {
        val authorized = Verifier(configAuthorizer = { })
        authorized.backend.checkPinVerifiability(Pin())
        val unauthenticated = assertFailsWith<ConfigurationException> {
            authorized.backend.checkPinVerifiability(Pin(project = "org/repo"))
        }
        assertTrue(unauthenticated.detail.contains("config authorizer cannot authenticate"), unauthenticated.detail)

        val embedded = Verifier(
            embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Bytes(fixture.config, name = "/org/project/v1")),
        )
        embedded.backend.checkPinVerifiability(Pin(project = "org/project@v1"))
        val mismatch = assertFailsWith<ConfigurationException> {
            embedded.backend.checkPinVerifiability(Pin(project = "org/other"))
        }
        assertTrue(mismatch.detail.contains("does not match"), mismatch.detail)
        val wrongNamespace = assertFailsWith<ConfigurationException> {
            embedded.backend.checkPinVerifiability(Pin(repo = "org/project"))
        }
        assertTrue(wrongNamespace.detail.contains("registry collateral only"), wrongNamespace.detail)
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

        assertEquals(VerificationLayer.PROVENANCE, error.layer)
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

        assertEquals(VerificationLayer.QUOTE, error.layer)
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
            assertEquals(VerificationLayer.PROVENANCE, error.layer, expected)
            assertTrue(error.detail.contains(expected), error.detail)
        }
    }

    /** Without an authorizer the same document is refused, so the tests above do reach it. */
    @Test
    fun theFixtureIsRefusedWithoutAnAuthorizer() {
        val verifier = Verifier(
            embeddedReferences = EmbeddedReferences(runtime = fixture.runtime, platform = fixture.platform),
        )
        assertFailsWith<TinfoilException> { verifier.backend.verify(fixture.document, fixture.nonce, Pin()) }
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
                        assertEquals(VerificationLayer.PROVENANCE, error.layer, error.detail)
                        assertTrue(error.detail.contains("rejected on reject-"), error.detail)
                    } else {
                        assertEquals(VerificationLayer.QUOTE, error.layer, error.detail)
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
