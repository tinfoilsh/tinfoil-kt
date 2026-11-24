package sh.tinfoil.internal.verification

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.CryptoMaterial
import sh.tinfoil.NetworkException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.VerifiedFacts
import sh.tinfoil.VerificationCheck
import sh.tinfoil.testing.FakeVerifier
import sh.tinfoil.testing.TLS_KEY_FORMAT
import sh.tinfoil.testing.TestClock
import sh.tinfoil.testing.verification
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class AttestorTest {
    private val clock = TestClock()
    private val fingerprint = "ab".repeat(32)
    private val pin = Pin(repo = "tinfoilsh/example")
    /** The host and the nonce, in hex, of each fetch. */
    private val fetched = mutableListOf<Pair<String, String>>()
    private val verifier = FakeVerifier { _, _, _ -> good() }

    /** What each fetch does, in order; the last one repeats. */
    private val fetches = ArrayDeque<() -> ByteArray>(listOf({ "document".toByteArray() }))

    private fun good(): VerifiedFacts = verification(fingerprint, clock().plusSeconds(60))

    private fun attestor(check: VerificationCheck? = null) = Attestor(
        verifier = verifier,
        fetch = { host, nonce ->
            fetched += host to nonce.joinToString("") { "%02x".format(it) }
            (if (fetches.size > 1) fetches.removeFirst() else fetches.first())()
        },
        check = check,
        clock = clock,
    )

    @Test
    fun aDocumentIsFetchedFromTheVerifiersUrlAndVerifiedWithItsNonce() = runTest {
        val seen = mutableListOf<Triple<String, String, Pin>>()
        verifier.verify = { document, nonce, pin ->
            seen += Triple(document.decodeToString(), nonce.joinToString("") { "%02x".format(it) }, pin)
            good()
        }

        val direct = attestor().attest("enclave.example", pin)
        attestor().attest("enclave.example:8443", pin)

        assertEquals(fingerprint, direct.verifiedFacts?.tlsPublicKeyFingerprint)
        assertEquals(listOf("enclave.example", "enclave.example:8443"), fetched.map { it.first })
        assertEquals(listOf("document", "document"), seen.map { it.first })
        assertEquals(fetched.map { it.second }, seen.map { it.second })
        assertEquals(pin, seen[0].third)
        assertEquals(0, currentTime, "a verification that succeeds does not wait")
    }

    @Test
    fun aFailedFetchIsTriedOnceMoreWithAFreshNonce() = runTest {
        val unreachable = NetworkException("unreachable")
        fetches.addFirst { throw unreachable }

        attestor().attest("enclave.example", pin)

        assertEquals(2, fetched.size)
        assertNotEquals(fetched[0].second, fetched[1].second)
        assertEquals(1000, currentTime, "the second attempt waits a second")
    }

    @Test
    fun aRejectedDocumentIsTriedOnceMoreAndThenFailsWithBothErrors() = runTest {
        val rejections = ArrayDeque(listOf(AttestationException("quote: first"), AttestationException("quote: second")))
        verifier.verify = { _, _, _ -> throw rejections.removeFirst() }

        val error = assertFailsWith<AttestationException> { attestor().attest("enclave.example", pin) }

        assertEquals("quote: second", error.detail)
        assertEquals(listOf("quote: first"), error.suppressed.map { (it as TinfoilException).detail })
        assertEquals(2, fetched.size)
        assertEquals(2, verifier.nonces.toSet().size, "each attempt has a nonce of its own")
    }

    @Test
    fun theFailureOfAnAttemptThatIsTriedAgainIsReportedBeforeTheWait() = runTest {
        val first = AttestationException("quote: first")
        val rejections = ArrayDeque(listOf<() -> VerifiedFacts>({ throw first }, { good() }))
        verifier.verify = { _, _, _ -> rejections.removeFirst()() }
        val retried = mutableListOf<Pair<TinfoilException, Long>>()

        val report = attestor().attest("enclave.example", pin) { retried += it to currentTime }

        assertEquals(listOf<Pair<TinfoilException, Long>>(first to 0L), retried)
        assertEquals(fingerprint, report.verifiedFacts?.tlsPublicKeyFingerprint)
        assertEquals(1000, currentTime)
    }

    @Test
    fun aFailureThatIsNotTriedAgainIsNotReportedAsRetried() = runTest {
        val retried = mutableListOf<TinfoilException>()
        verifier.verify = { _, _, _ -> throw ConfigurationException("the pin names no such project") }
        assertFailsWith<ConfigurationException> { attestor().attest("enclave.example", pin) { retried += it } }
        verifier.verify = { _, _, _ -> good() }
        assertFailsWith<AttestationException> {
            attestor { throw IllegalStateException("no") }.attest("enclave.example", pin) { retried += it }
        }
        assertEquals(emptyList(), retried)
    }

    @Test
    fun aPersistentNetworkFailureFailsAfterTwoAttempts() = runTest {
        fetches.clear()
        fetches.add { throw NetworkException("HTTP 503", status = 503) }

        val error = assertFailsWith<NetworkException> { attestor().attest("enclave.example", pin) }

        assertEquals(503, error.status)
        assertEquals(2, fetched.size)
        assertEquals(0, verifier.verifications.get())
    }

    @Test
    fun aConfigurationErrorIsNotTriedAgain() = runTest {
        verifier.verify = { _, _, _ -> throw ConfigurationException("the pin names no such project") }

        assertFailsWith<ConfigurationException> { attestor().attest("enclave.example", pin) }

        assertEquals(1, fetched.size)
        assertEquals(0, currentTime)
    }

    @Test
    fun theCheckSeesAVerifiedResultAndItsRejectionIsNotTriedAgain() = runTest {
        val seen = mutableListOf<VerifiedFacts>()
        val accepted = attestor { seen += it }.attest("enclave.example", pin)
        assertSame(accepted.verifiedFacts, seen.single())

        val reason = IllegalArgumentException("unexpected measurement")
        val error = assertFailsWith<AttestationException> {
            attestor { throw reason }.attest("enclave.example", pin)
        }

        assertSame(reason, error.cause)
        assertEquals("verification check rejected enclave.example: unexpected measurement", error.detail)
        assertEquals(2, fetched.size, "one fetch for each of the two verifications")
        assertEquals(0, currentTime)
    }

    @Test
    fun theCheckIsNotCalledForADocumentThatDoesNotVerify() = runTest {
        verifier.verify = { _, _, _ -> throw AttestationException("policy: no") }
        var calls = 0

        assertFailsWith<AttestationException> { attestor { calls++ }.attest("enclave.example", pin) }

        assertEquals(0, calls)
    }

    @Test
    fun aRejectionOnTheSecondAttemptIsFinalToo() = runTest {
        fetches.addFirst { throw NetworkException("unreachable") }
        var calls = 0

        val error = assertFailsWith<AttestationException> {
            attestor {
                calls++
                throw IllegalStateException("no")
            }.attest("enclave.example", pin)
        }

        assertEquals(1, calls)
        assertEquals(2, fetched.size)
        assertEquals(1, error.suppressed.size)
    }

    @Test
    fun aResultIsExpiredAtItsDeadlineAndNotBefore() = runTest {
        verifier.verify = { _, _, _ -> verification(fingerprint, clock().plusSeconds(1)) }
        attestor().attest("enclave.example", pin)

        verifier.verify = { _, _, _ -> verification(fingerprint, clock()) }
        val atDeadline = assertFailsWith<AttestationException> { attestor().attest("enclave.example", pin) }
        assertTrue(atDeadline.detail.contains("freshness deadline"), atDeadline.detail)

        verifier.verify = { _, _, _ -> verification(fingerprint, java.time.Instant.EPOCH) }
        assertFailsWith<AttestationException> { attestor().attest("enclave.example", pin) }
    }

    @Test
    fun aCheckThatOutlastsTheDeadlineLeadsToFreshEvidence() = runTest {
        var slow = true
        val attestor = attestor {
            if (slow) {
                slow = false
                clock.advance(120)
            }
        }

        val verified = attestor.attest("enclave.example", pin)

        assertEquals(2, fetched.size)
        assertEquals(clock().plusSeconds(60), verified.verifiedFacts?.freshnessExpiresAt)
    }

    @Test
    fun theTransportKeysMustBeThereInAFormatThatIsUnderstood() = runTest {
        val hpkeFormat = "https://tinfoil.sh/key/x25519-hpke/v1"
        val cases = mapOf(
            "no TLS key" to verification(null, clock().plusSeconds(60)),
            "a TLS key in another format" to verification(
                fingerprint, clock().plusSeconds(60),
                cryptoMaterial = listOf(CryptoMaterial("tls", "https://tinfoil.sh/key/spki-fp-sha512/v9", fingerprint)),
            ),
            "an HPKE key in another format" to verification(
                fingerprint, clock().plusSeconds(60),
                cryptoMaterial = listOf(
                    CryptoMaterial("tls", TLS_KEY_FORMAT, fingerprint),
                    CryptoMaterial("hpke", "https://tinfoil.sh/key/other/v1", "00"),
                ),
            ),
        )
        for ((name, result) in cases) {
            verifier.verify = { _, _, _ -> result }
            assertFailsWith<AttestationException>(name) { attestor().attest("enclave.example", pin) }
        }

        verifier.verify = { _, _, _ ->
            verification(
                fingerprint, clock().plusSeconds(60),
                cryptoMaterial = listOf(
                    CryptoMaterial("tls", TLS_KEY_FORMAT, fingerprint),
                    CryptoMaterial("hpke", hpkeFormat, "00"),
                    CryptoMaterial("other", "https://example.com/unknown", "00"),
                ),
            )
        }
        attestor().attest("enclave.example", pin)
    }

    @Test
    fun cancellationIsNotAFailedVerification() = runTest {
        fetches.clear()
        fetches.add { throw CancellationException("cancelled") }

        assertFailsWith<CancellationException> { attestor().attest("enclave.example", pin) }

        assertEquals(1, fetched.size, "a cancelled verification is not tried again")
    }

    @Test
    fun theOptionsAreCheckedWithoutFetching() = runTest {
        attestor().checkOptions("enclave.example", pin)
        assertFailsWith<ConfigurationException> { attestor().checkOptions("enclave.example", Pin.NONE) }
        assertFailsWith<ConfigurationException> { attestor().checkOptions("enclave.example/x", pin) }

        assertTrue(fetched.isEmpty())
        assertEquals(0, verifier.verifications.get())
        assertContentEquals(emptyList(), verifier.nonces)
    }

    @Test
    fun aVerifierThatReturnsAnUnusableUrlIsNotFollowed() = runTest {
        val odd = object : AttestationVerifier by verifier {
            override fun attestationUrl(host: String, nonce: ByteArray) = "http://$host/doc"
        }
        val source = DocumentSources.of(null, odd) { error("nothing is fetched") }
        val attestor = Attestor(odd, fetch = source, clock = clock)

        assertFailsWith<AttestationException> { attestor.attest("enclave.example", pin) }

        assertTrue(fetched.isEmpty())
    }
}
