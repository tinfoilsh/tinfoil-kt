package sh.tinfoil.internal.verification

import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
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
    fun aVerificationErrorIsAnAttestationErrorThatKeepsItsLayerInTheDetail() {
        for (name in listOf("envelope", "provenance", "quote", "policy", "firmware")) {
            val error = attestation("verification error: $name: rejected")
            assertEquals("$name: rejected", error.detail, "The layer stays in the detail.")
            assertEquals("attestation error: $name: rejected", error.message)
        }
        assertEquals("could not parse: bad JSON", attestation("verification error: could not parse: bad JSON").detail)
        assertEquals("", attestation("verification error: ").detail)
    }

    @Test
    fun anErrorThatCannotBeClassifiedIsARejectedAttestation() {
        assertEquals("unexpected", attestation("unexpected").detail)
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
        assertEquals("provenance: usage error: let me in", error.detail)
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
