package sh.tinfoil

import java.io.IOException

/**
 * An error from this SDK, in one of three categories: [ConfigurationException],
 * [NetworkException] or [AttestationException]. Errors from the inference API
 * itself keep their own types.
 *
 * [message] leads with the category, as in
 * `attestation error: quote: <detail>`; [detail] is the same text without it.
 * The error that caused this one, if any, is kept as [cause].
 *
 * These are [IOException]s on purpose. HTTP stacks built on OkHttp hand only
 * an `IOException` to a call's failure callback and treat anything else that
 * is thrown inside a call as a crash, so an attestation failure has to be an
 * `IOException` to reach the caller of such a library intact. The supertype
 * therefore does not say whether a retry can help; [isRetryable] does.
 */
public sealed class TinfoilException(
    /**
     * The category's name, as it leads [message]: `configuration error`,
     * `network error` or `attestation error`.
     */
    public val category: String,
    /** What went wrong, without the category. */
    public val detail: String,
    cause: Throwable?,
) : IOException("$category: $detail", cause) {
    /**
     * Whether trying again can help: true for a [NetworkException], and
     * false for a [ConfigurationException] and an [AttestationException].
     *
     * These exceptions are [IOException]s, which generic retry loops retry.
     * Check this first. An attestation failure in particular must not be
     * retried blindly: the client already verifies again by itself where
     * that is right, so what reaches the caller is an enclave that is not
     * to be trusted.
     */
    public abstract val isRetryable: Boolean
}

/**
 * The caller's arguments or the client's configuration are invalid, or the
 * client refuses a request as such. Retrying will not help.
 */
public class ConfigurationException internal constructor(
    detail: String,
    cause: Throwable? = null,
) : TinfoilException(CONFIGURATION_ERROR, detail, cause) {
    override val isRetryable: Boolean get() = false
}

/**
 * The client could not reach what it needed: a network failure, a timeout or
 * an HTTP error status while it fetched attestation material.
 */
public class NetworkException internal constructor(
    detail: String,
    /** The HTTP status, when a server answered with an error status. */
    public val status: Int? = null,
    cause: Throwable? = null,
) : TinfoilException(NETWORK_ERROR, detail, cause) {
    override val isRetryable: Boolean get() = true
}

/**
 * The enclave's evidence, the trust policy or the channel binding was
 * rejected. The enclave must not be used.
 *
 * When the verifier rejected the attestation document with a report, the
 * [cause] is a [VerificationException], which names the layer that rejected
 * it and carries the report. Any other attestation failure says what failed
 * in its [detail] alone: expired verified facts, a rejection by the
 * verification check, a key that the enclave does not hold, or a rejection
 * that the verifier reported without a report, whose detail leads with the
 * layer, as in `quote: <detail>`.
 */
public class AttestationException internal constructor(
    detail: String,
    cause: Throwable? = null,
) : TinfoilException(ATTESTATION_ERROR, detail, cause) {
    override val isRetryable: Boolean get() = false
}

private const val CONFIGURATION_ERROR = "configuration error"
private const val NETWORK_ERROR = "network error"
private const val ATTESTATION_ERROR = "attestation error"

/**
 * A layer of the verifier: the subject of a [Step] of a [VerificationReport],
 * and the layer that a [VerificationException] names as the one that
 * rejected the document. More layers may be added, so handle the ones that
 * you know and tolerate any other.
 */
@JvmInline
public value class VerificationLayer(
    /** The layer's name, a single lowercase word. */
    public val value: String,
) {
    override fun toString(): String = value

    public companion object {
        /** A document that cannot be parsed or is not bound to the request. */
        public val ENVELOPE: VerificationLayer = VerificationLayer("envelope")

        /** Reference values that fail to authenticate. */
        public val PROVENANCE: VerificationLayer = VerificationLayer("provenance")

        /** Hardware evidence that is not authentic. */
        public val QUOTE: VerificationLayer = VerificationLayer("quote")

        /** Authentic evidence that does not satisfy the policy. */
        public val POLICY: VerificationLayer = VerificationLayer("policy")
    }
}
