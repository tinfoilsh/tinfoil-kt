package sh.tinfoil.internal.verification

import sh.tinfoil.go.mobile.Mobile

/**
 * The attestation verifier, a native library bundled with this SDK. It
 * performs no I/O: callers fetch attestation documents themselves and pass
 * the bytes in.
 */
internal object GoVerifierLibrary {
    /** The number of bytes in a nonce. */
    const val NONCE_SIZE: Int = 32

    /** Returns a fresh random nonce for one attestation fetch. */
    fun newNonce(): ByteArray {
        val nonce = Mobile.newNonce()
        check(nonce != null && nonce.size == NONCE_SIZE) { "the verifier returned no usable nonce" }
        return nonce
    }
}
