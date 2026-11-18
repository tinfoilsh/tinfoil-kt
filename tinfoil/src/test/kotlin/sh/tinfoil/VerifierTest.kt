package sh.tinfoil

import sh.tinfoil.internal.verification.AttestationVerifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

class VerifierTest {
    @Test
    fun thePublicRegistryIdIsReadableWithoutTheNativeLibrary() {
        assertEquals("https://registry.tinfoil.sh/scopes/public", Verifier.PUBLIC_REGISTRY_ID)
    }

    /** Code that takes a verifier can be tested where the native library cannot load. */
    @Test
    fun aVerifierCanWrapAStandIn() {
        val standIn = object : AttestationVerifier {
            override val callerAuthorizesConfig: Boolean = false

            override fun newNonce(): ByteArray = ByteArray(32)

            override fun attestationUrl(host: String, relay: String?, nonce: ByteArray): String = "https://$host/"

            override fun checkPinVerifiability(pin: Pin) = Unit

            override fun verify(document: ByteArray, nonce: ByteArray, pin: Pin): Verification =
                throw AttestationException("a stand-in verifies nothing")
        }
        assertSame(standIn, Verifier(standIn).backend)
    }
}
