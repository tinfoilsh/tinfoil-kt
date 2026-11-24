package sh.tinfoil.internal.verification

import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.VerificationReport
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
    override fun newNonce(): ByteArray = Companion.newNonce()

    override fun attestationUrl(host: String, nonce: ByteArray): String {
        val url = calling { Mobile.attestationURL(host, "", nonce) }
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

    override fun verify(document: ByteArray, nonce: ByteArray, pin: Pin): VerificationReport {
        return report { verifier.verify(document, nonce, pin.repo.orEmpty(), pin.project.orEmpty()) }
    }

    internal companion object {
        /** The number of bytes in a nonce. */
        const val NONCE_SIZE: Int = 32

        /**
         * A verifier that trusts configs as [config] says, or as Tinfoil's
         * public registry does when it is null, under [policy].
         */
        @Throws(ConfigurationException::class, AttestationException::class)
        fun create(
            config: VerifierOptions.ConfigTrust? = null,
            policy: VerifierOptions.Policy = VerifierOptions.Policy(),
        ): GoAttestationVerifier {
            val bridge = (config as? VerifierOptions.ConfigTrust.Authorizer)?.let { ConfigAuthorizerBridge(it.authorizer) }
            val verifier = calling {
                if (bridge != null) {
                    Mobile.newVerifierWithConfigAuthorizer(VerifierOptions.encodePolicy(policy), bridge)
                } else {
                    Mobile.newVerifier(VerifierOptions.encode(config, policy))
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
         * The report that the library returns from [verify], a call into it
         * that returns a result payload: an error that it throws classified,
         * or its payload decoded, which throws for a rejected document.
         */
        @JvmSynthetic
        @Throws(TinfoilException::class)
        fun report(verify: () -> String?): VerificationReport {
            val payload = calling(verify)
            if (payload.isNullOrEmpty()) {
                throw AttestationException("the verifier returned no result")
            }
            return VerificationPayload.decode(payload)
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
