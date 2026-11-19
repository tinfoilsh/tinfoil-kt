package sh.tinfoil

import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame

class TinfoilExceptionTest {
    @Test
    fun messagesLeadWithTheCategory() {
        val configuration = ConfigurationException("no API key was given")
        assertEquals("configuration error", configuration.category)
        assertEquals("no API key was given", configuration.detail)
        assertEquals("configuration error: no API key was given", configuration.message)

        val network = NetworkException("attestation fetch failed", status = 503)
        assertEquals("network error", network.category)
        assertEquals("network error: attestation fetch failed", network.message)
        assertEquals(503, network.status)

        val attestation = AttestationException("quote: rejected", VerificationLayer.QUOTE)
        assertEquals("attestation error", attestation.category)
        assertEquals("attestation error: quote: rejected", attestation.message)
        assertEquals(VerificationLayer.QUOTE, attestation.layer)
    }

    @Test
    fun optionalDetailsDefaultToNull() {
        assertNull(NetworkException("offline").status)
        assertNull(AttestationException("rejected by the verification check").layer)
        assertNull(ConfigurationException("bad option").cause)
    }

    @Test
    fun theCauseIsKept() {
        val cause = IllegalStateException("underlying")
        assertSame(cause, ConfigurationException("bad option", cause).cause)
        assertSame(cause, NetworkException("offline", cause = cause).cause)
        assertSame(cause, AttestationException("rejected", cause = cause).cause)
    }

    @Test
    fun everyCategoryIsAnIOException() {
        val errors: List<TinfoilException> = listOf(
            ConfigurationException("a"),
            NetworkException("b"),
            AttestationException("c"),
        )
        for (error in errors) {
            // Checked through the supertype, as an HTTP stack would see it.
            val seen: Throwable = error
            assertEquals(true, seen is IOException, error.category)
        }
    }

    @Test
    fun onlyANetworkFailureIsRetryable() {
        assertEquals(true, NetworkException("offline").isRetryable)
        assertEquals(true, NetworkException("unavailable", status = 503).isRetryable)
        assertEquals(false, ConfigurationException("bad option").isRetryable)
        assertEquals(false, AttestationException("rejected").isRetryable)
        assertEquals(false, AttestationException("quote: rejected", VerificationLayer.QUOTE).isRetryable)
    }

    @Test
    fun retryabilityIsReadThroughTheSupertype() {
        // A retry loop catches an IOException and has to ask it.
        val seen: IOException = AttestationException("rejected", cause = NetworkException("offline"))
        assertEquals(false, (seen as? TinfoilException)?.isRetryable)
    }

    @Test
    fun layersAreAnOpenSet() {
        assertEquals("envelope", VerificationLayer.ENVELOPE.value)
        assertEquals("provenance", VerificationLayer.PROVENANCE.value)
        assertEquals("quote", VerificationLayer.QUOTE.value)
        assertEquals("policy", VerificationLayer.POLICY.value)
        assertEquals(VerificationLayer.QUOTE, VerificationLayer("quote"))
        assertEquals("firmware", VerificationLayer("firmware").toString())
    }
}
