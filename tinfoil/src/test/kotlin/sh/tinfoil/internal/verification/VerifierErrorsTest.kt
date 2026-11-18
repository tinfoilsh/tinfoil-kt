package sh.tinfoil.internal.verification

import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.VerificationLayer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame

class VerifierErrorsTest {
    private fun attestation(message: String?): AttestationException =
        assertIs<AttestationException>(VerifierErrors.classify(message))

    @Test
    fun thePrefixesAreTheLibrarys() {
        assertEquals("usage error: ", VerifierErrors.USAGE_PREFIX)
        assertEquals("verification error: ", VerifierErrors.VERIFICATION_PREFIX)
    }

    @Test
    fun aUsageErrorIsAConfigurationError() {
        val error = assertIs<ConfigurationException>(VerifierErrors.classify("usage error: bad repo"))
        assertEquals("bad repo", error.detail, "The library's prefix is dropped.")
        assertEquals("configuration error: bad repo", error.message)
    }

    @Test
    fun aVerificationErrorIsAnAttestationErrorWithItsLayer() {
        val layers = mapOf(
            "envelope" to VerificationLayer.ENVELOPE,
            "provenance" to VerificationLayer.PROVENANCE,
            "quote" to VerificationLayer.QUOTE,
            "policy" to VerificationLayer.POLICY,
        )
        for ((name, layer) in layers) {
            val error = attestation("verification error: $name: rejected")
            assertEquals(layer, error.layer)
            assertEquals("$name: rejected", error.detail, "The layer stays in the detail.")
            assertEquals("attestation error: $name: rejected", error.message)
        }
    }

    @Test
    fun aLayerThisSdkDoesNotNameIsCarried() {
        assertEquals(VerificationLayer("firmware"), attestation("verification error: firmware: rejected").layer)
    }

    @Test
    fun textBeforeAColonIsALayerOnlyIfItIsOneLowercaseWord() {
        val unlayered = listOf(
            "verification error: rejected",
            "verification error: could not parse: bad JSON",
            "verification error: Quote: rejected",
            "verification error: quote2: rejected",
            "verification error: : rejected",
            "verification error: quote:rejected",
            "verification error: ",
        )
        for (message in unlayered) {
            assertNull(attestation(message).layer, message)
        }
        assertEquals("could not parse: bad JSON", attestation("verification error: could not parse: bad JSON").detail)
    }

    @Test
    fun anErrorThatCannotBeClassifiedIsARejectedAttestation() {
        assertEquals("unexpected", attestation("unexpected").detail)
        assertNull(attestation("unexpected").layer)
        assertEquals("the verifier failed without a message", attestation(null).detail)
        assertEquals("the verifier failed without a message", attestation("").detail)
        // A prefix counts only where the message starts with it, exactly.
        attestation("Usage error: bad repo")
        attestation(" usage error: bad repo")
        attestation("usage error:bad repo")
        attestation("panic: usage error: bad repo")
    }

    @Test
    fun aRejectionThatQuotesAUsageErrorStaysARejection() {
        val error = attestation("verification error: provenance: usage error: let me in")
        assertEquals(VerificationLayer.PROVENANCE, error.layer)
    }

    @Test
    fun theThrownErrorIsKeptAsTheCause() {
        val thrown = Exception("verification error: quote: rejected")
        val error = VerifierErrors.classify(thrown)
        assertIs<AttestationException>(error)
        assertSame(thrown, error.cause)

        val usage = Exception("usage error: bad")
        assertSame(usage, assertIs<ConfigurationException>(VerifierErrors.classify(usage)).cause)
        assertIs<AttestationException>(VerifierErrors.classify(RuntimeException()))
    }
}
