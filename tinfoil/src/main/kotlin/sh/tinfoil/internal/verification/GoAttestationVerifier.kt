package sh.tinfoil.internal.verification

import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigAuthorizer
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.Verification
import sh.tinfoil.go.mobile.Mobile
import sh.tinfoil.go.mobile.Verifier as GoVerifier

/**
 * The attestation verifier of the native library that is bundled with this
 * SDK. The library makes every trust decision; this only translates types
 * and errors across its boundary.
 */
internal class GoAttestationVerifier private constructor(
    // An immutable policy, which the library allows several threads to use
    // at once.
    private val verifier: GoVerifier,
    // The library reaches the bridge only through a reference that it
    // tracks itself; holding it here ties its lifetime to the verifier's.
    @Suppress("unused") private val configAuthorizer: ConfigAuthorizerBridge?,
) : AttestationVerifier {
    override val callerAuthorizesConfig: Boolean
        get() = verifier.callerAuthorizesConfig()

    override fun newNonce(): ByteArray = Companion.newNonce()

    override fun attestationUrl(host: String, relay: String?, nonce: ByteArray): String {
        val url = calling { Mobile.attestationURL(host, relay.orEmpty(), nonce) }
        // The library returns only HTTPS URLs; anything else is not one to
        // fetch evidence from.
        if (url == null || !url.startsWith("https://")) {
            throw AttestationException("the verifier returned no usable attestation URL")
        }
        return url
    }

    override fun checkPinVerifiability(pin: Pin) {
        calling { verifier.checkPinVerifiability(pin.repo.orEmpty(), pin.project.orEmpty()) }
    }

    override fun verify(document: ByteArray, nonce: ByteArray, pin: Pin): Verification {
        val payload = calling { verifier.verify(document, nonce, pin.repo.orEmpty(), pin.project.orEmpty()) }
        if (payload.isNullOrEmpty()) {
            throw AttestationException("the verifier returned no result")
        }
        return VerificationPayload.decode(payload)
    }

    internal companion object {
        /** The number of bytes in a nonce. */
        const val NONCE_SIZE: Int = 32

        /**
         * A verifier for the policy in [optionsJson], the library's options;
         * an empty string selects the defaults. With [configAuthorizer], it
         * decides which configs are authorized in place of their
         * endorsements.
         */
        @Throws(ConfigurationException::class, AttestationException::class)
        fun create(optionsJson: String = "", configAuthorizer: ConfigAuthorizer? = null): GoAttestationVerifier {
            val bridge = configAuthorizer?.let(::ConfigAuthorizerBridge)
            val verifier = calling {
                if (bridge != null) {
                    Mobile.newVerifierWithConfigAuthorizer(optionsJson, bridge)
                } else {
                    Mobile.newVerifier(optionsJson)
                }
            } ?: throw ConfigurationException("the verifier library returned no verifier")
            return GoAttestationVerifier(verifier, bridge)
        }

        /** A fresh random nonce for one attestation fetch. */
        @Throws(AttestationException::class)
        fun newNonce(): ByteArray {
            val nonce: ByteArray? = Mobile.newNonce()
            if (nonce == null || nonce.size != NONCE_SIZE) {
                throw AttestationException("the verifier returned no usable nonce")
            }
            return nonce
        }

        /**
         * Runs a call into the library, whose errors arrive as plain
         * exceptions that carry only a message, and classifies what it
         * throws.
         */
        @Throws(TinfoilException::class)
        private inline fun <T> calling(call: () -> T): T =
            try {
                call()
            } catch (e: TinfoilException) {
                throw e
            } catch (e: Exception) {
                throw VerifierErrors.classify(e)
            }
    }
}
