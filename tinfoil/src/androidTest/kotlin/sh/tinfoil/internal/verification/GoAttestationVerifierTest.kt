package sh.tinfoil.internal.verification

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Pin
import sh.tinfoil.VerificationLayer
import sh.tinfoil.Trust
import sh.tinfoil.go.mobile.Mobile
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Exercises the native verifier library through its boundary: the types that
 * cross it, and how each kind of error that it reports arrives.
 */
@RunWith(AndroidJUnit4::class)
class GoAttestationVerifierTest {
    private val routerPin = Pin(repo = "tinfoilsh/confidential-model-router")

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /**
     * The library's constants are compiled into this SDK, so that reading
     * them does not load the library. Read here from the library that is
     * loaded, they are the same.
     */
    @Test
    fun theConstantsCompiledInAreTheLibrarys() {
        fun loaded(name: String): Any? = Mobile::class.java.getField(name).get(null)

        assertEquals(loaded("UsageErrorPrefix"), VerifierErrors.USAGE_PREFIX)
        assertEquals(loaded("VerificationErrorPrefix"), VerifierErrors.VERIFICATION_PREFIX)
        assertEquals(loaded("PublicRegistryID"), Trust.PUBLIC_REGISTRY_ID)
        assertEquals(loaded("VerificationSchemaVersion"), VerificationPayload.SUPPORTED_SCHEMA_VERSION.toLong())
    }

    @Test
    fun noncesAreFreshAndFullLength() {
        val verifier = GoAttestationVerifier.create()
        val first = verifier.newNonce()
        val second = verifier.newNonce()

        assertEquals(GoAttestationVerifier.NONCE_SIZE, first.size)
        assertFalse(first.contentEquals(second))
        assertFalse(first.all { it == 0.toByte() })
    }

    @Test
    fun attestationUrls() {
        val verifier = GoAttestationVerifier.create()
        val nonce = verifier.newNonce()

        assertEquals(
            "https://enclave.example/.well-known/tinfoil-attestation?nonce=${hex(nonce)}",
            verifier.attestationUrl("enclave.example", nonce),
        )
    }

    @Test
    fun anAttestationUrlNeedsAHostAndAFullNonce() {
        val verifier = GoAttestationVerifier.create()
        val nonce = verifier.newNonce()

        val refused = listOf<() -> Any>(
            { verifier.attestationUrl("https://enclave.example", nonce) },
            { verifier.attestationUrl("", nonce) },
            { verifier.attestationUrl("enclave.example/path", nonce) },
            { verifier.attestationUrl("user@enclave.example", nonce) },
            { verifier.attestationUrl("enclave.example", nonce.copyOf(31)) },
            { verifier.attestationUrl("enclave.example", ByteArray(0)) },
        )
        for (call in refused) {
            val error = assertFailsWith<ConfigurationException> { call() }
            assertFalse(error.detail.startsWith(Mobile.UsageErrorPrefix), "The library's prefix is dropped.")
        }
    }

    @Test
    fun aDocumentThatIsNotOneIsRejectedAtTheEnvelope() {
        val verifier = GoAttestationVerifier.create()
        val nonce = verifier.newNonce()
        val garbage = ByteArray(256) { (it * 31 + 7).toByte() }

        for (document in listOf(ByteArray(0), "{}".toByteArray(), "not a document".toByteArray(), garbage)) {
            val error = assertFailsWith<AttestationException> { verifier.verify(document, nonce, routerPin) }
            assertEquals(VerificationLayer.ENVELOPE, error.layer)
            assertTrue(error.detail.startsWith("envelope: "), error.detail)
            assertFalse(error.detail.startsWith(Mobile.VerificationErrorPrefix), "The library's prefix is dropped.")
            assertTrue(error.message.orEmpty().startsWith("attestation error: envelope: "), error.message)
            assertTrue(error.cause != null, "The library's error is kept as the cause.")
        }
    }

    @Test
    fun aNonceOfTheWrongSizeIsAConfigurationError() {
        val verifier = GoAttestationVerifier.create()
        val nonce = verifier.newNonce()

        assertFailsWith<ConfigurationException> { verifier.verify("{}".toByteArray(), nonce.copyOf(31), routerPin) }
        assertFailsWith<ConfigurationException> { verifier.verify("{}".toByteArray(), ByteArray(0), routerPin) }
    }

    @Test
    fun verifyDoesNotModifyItsArguments() {
        val verifier = GoAttestationVerifier.create()
        val nonce = verifier.newNonce()
        val document = "{}".toByteArray()
        val nonceBefore = nonce.copyOf()

        assertFailsWith<AttestationException> { verifier.verify(document, nonce, routerPin) }

        assertContentEquals(nonceBefore, nonce)
        assertContentEquals("{}".toByteArray(), document)
    }

    @Test
    fun aPinIsCheckedBeforeAnyDocument() {
        val defaults = GoAttestationVerifier.create()

        defaults.checkPinVerifiability(routerPin)
        defaults.checkPinVerifiability(Pin(repo = "tinfoilsh/confidential-model-router@v1.2.3"))
        defaults.checkPinVerifiability(Pin(project = "org/project@v1"))
        defaults.checkPinVerifiability(Pin(repo = "tinfoilsh/confidential-model-router", project = "org/project"))
        assertFailsWith<ConfigurationException> { defaults.checkPinVerifiability(Pin(repo = "not a reference")) }
        assertFailsWith<ConfigurationException> { defaults.checkPinVerifiability(Pin(project = "not a reference")) }
        // The default config trust needs a pin to say whose config to accept.
        assertFailsWith<ConfigurationException> { defaults.checkPinVerifiability(Pin.NONE) }
    }
}
