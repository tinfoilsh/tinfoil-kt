package sh.tinfoil.internal.verification

import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.TinfoilException
import sh.tinfoil.VerificationLayer
import sh.tinfoil.go.mobile.Mobile

/**
 * Classifies errors from the verifier library. An error crosses the library's
 * boundary as a message alone, led by its type's prefix.
 */
internal object VerifierErrors {
    // Compile-time constants of the verifier library, so reading them does
    // not load the library.

    /** Leads an error in the caller's arguments or options. */
    const val USAGE_PREFIX: String = Mobile.UsageErrorPrefix

    /**
     * Leads the rejection of a document. The layer that rejected it comes
     * next, then `: ` and the detail.
     */
    const val VERIFICATION_PREFIX: String = Mobile.VerificationErrorPrefix

    /**
     * The exception for an [error] that the verifier library threw, which is
     * kept as the cause.
     */
    fun classify(error: Throwable): TinfoilException = classify(error.message, error)

    /**
     * The exception for a verifier error with [message]. The type's prefix is
     * dropped, because the exception's type carries it. A rejection's layer
     * stays in the detail, as in `quote: <detail>`, and is also lifted out.
     *
     * A message with neither prefix is treated as a rejected attestation: an
     * error that cannot be classified must never read as anything milder.
     */
    fun classify(message: String?, cause: Throwable? = null): TinfoilException {
        if (message.isNullOrEmpty()) {
            return AttestationException("the verifier failed without a message", cause = cause)
        }
        if (message.startsWith(USAGE_PREFIX)) {
            return ConfigurationException(message.removePrefix(USAGE_PREFIX), cause)
        }
        if (message.startsWith(VERIFICATION_PREFIX)) {
            val rejection = message.removePrefix(VERIFICATION_PREFIX)
            return AttestationException(rejection, leadingLayer(rejection), cause)
        }
        return AttestationException(message, cause = cause)
    }

    /**
     * The layer that a rejection leads with, as in `quote: <detail>`. A
     * layer's name is a single lowercase word, so a rejection whose text
     * before `: ` is anything else names no layer.
     */
    private fun leadingLayer(rejection: String): VerificationLayer? {
        val separator = rejection.indexOf(": ")
        if (separator <= 0) {
            return null
        }
        val name = rejection.substring(0, separator)
        return if (name.all { it in 'a'..'z' }) VerificationLayer(name) else null
    }
}
