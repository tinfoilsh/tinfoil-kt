package sh.tinfoil

import sh.tinfoil.internal.immutableCopy
import java.util.Objects

/**
 * A record of one verification of an attestation document: the steps that
 * the verifier ran, and the facts that it established. It describes a
 * verification that passed and one that failed in the same way, so that a
 * caller can show or log either.
 *
 * - **Passed:** the client returns the report. [verifiedFacts] is set, and
 *   no step failed.
 * - **Failed:** the client throws an [AttestationException] whose cause is
 *   a [VerificationException], which carries the report. One step failed,
 *   [partialFacts] is set, and [verifiedFacts] is null.
 *
 * A report authorizes nothing. Decide what to do from the outcome, the
 * report or the exception, never from the steps or the partial facts; only
 * the keys in [verifiedFacts] are bound to a channel.
 *
 * Instances are immutable and compare by value.
 */
public class VerificationReport internal constructor(
    steps: List<Step>,
    /** What the verification proved. Set if and only if no step failed. */
    public val verifiedFacts: VerifiedFacts?,
    /** What the verification established before a step failed. Set if and only if a step failed. */
    public val partialFacts: PartialFacts?,
    /** How the verification was performed. */
    public val metadata: VerificationMetadata,
) {
    /**
     * One step for each layer of the verifier, in the order of the layers:
     * today [VerificationLayer.ENVELOPE], [VerificationLayer.PROVENANCE],
     * [VerificationLayer.QUOTE] and [VerificationLayer.POLICY]. Every step
     * is always present. More layers may be added, so tolerate a layer that
     * you do not know.
     */
    public val steps: List<Step> = steps.immutableCopy()

    /** The step that failed, or null for a verification that passed. */
    public val failedStep: Step? get() = steps.firstOrNull { it.status == StepStatus.FAILED }

    override fun equals(other: Any?): Boolean =
        this === other || (
            other is VerificationReport &&
                steps == other.steps &&
                verifiedFacts == other.verifiedFacts &&
                partialFacts == other.partialFacts &&
                metadata == other.metadata
            )

    override fun hashCode(): Int = Objects.hash(steps, verifiedFacts, partialFacts, metadata)

    override fun toString(): String =
        "VerificationReport(steps=$steps, verifiedFacts=$verifiedFacts, partialFacts=$partialFacts, " +
            "metadata=$metadata)"
}

/** The outcome of one layer of a verification. */
public class Step internal constructor(
    /** The layer that the step covers. */
    public val layer: VerificationLayer,
    /** Whether the layer passed, failed, was skipped or did not run. */
    public val status: StepStatus,
    /**
     * For a failed step, the message of the verifier's error; for a skipped
     * step, the reason that it was skipped; otherwise null. It is for
     * people to read, and may change in any release.
     */
    public val message: String?,
) {
    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is Step && layer == other.layer && status == other.status && message == other.message)

    override fun hashCode(): Int = Objects.hash(layer, status, message)

    override fun toString(): String = "Step(layer=$layer, status=$status, message=$message)"
}

/**
 * The outcome of a [Step]. Only the verifier sets it: show a step as passed
 * only when its status is [PASSED].
 */
@JvmInline
public value class StepStatus(
    /** The status's name. */
    public val value: String,
) {
    override fun toString(): String = value

    public companion object {
        /** Every check of the layer ran and passed. */
        public val PASSED: StepStatus = StepStatus("passed")

        /** The layer rejected the document. At most one step fails. */
        public val FAILED: StepStatus = StepStatus("failed")

        /**
         * The layer does not apply to the document or to the verifier's
         * configuration, as provenance when the caller embeds every
         * reference value. It is not a failure.
         */
        public val SKIPPED: StepStatus = StepStatus("skipped")

        /**
         * The layer's checks did not all run, because another step failed
         * first. A step that precedes the failed one can be in this state
         * too, since checks do not always run in the order of the layers.
         */
        public val NOT_RUN: StepStatus = StepStatus("not_run")
    }
}

/**
 * What a verification established before one of its steps failed, in two
 * groups: what the enclave was expected to run, and what its document and
 * hardware claim. A mismatch of measurements shows side by side, as
 * [ExpectedFacts.measurement] or [ExpectedFacts.codeMeasurement] against
 * [MeasuredFacts.cpu].
 *
 * A fact is set only once the step that establishes it has passed.
 */
public class PartialFacts internal constructor(
    /** Set once the provenance step passed or was skipped; null otherwise. */
    public val expected: ExpectedFacts?,
    /** Set once the envelope step passed; null otherwise. */
    public val measured: MeasuredFacts?,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is PartialFacts && expected == other.expected && measured == other.measured)

    override fun hashCode(): Int = Objects.hash(expected, measured)

    override fun toString(): String = "PartialFacts(expected=$expected, measured=$measured)"
}

/**
 * The reference values that the provenance step authenticated: what the
 * enclave should be running.
 */
public class ExpectedFacts internal constructor(
    /** The repository that was selected, without a tag or digest, or null. */
    public val configRepo: String?,
    /** The code release, or the runtime of a config-based verification. */
    public val artifact: ArtifactVerification,
    /** The config that a config-based verification accepted; null for a code release. */
    public val config: ConfigVerification?,
    /** The platform endorsements that a config-based verification accepted; null for a code release. */
    public val platform: ArtifactVerification?,
    /**
     * The registers that the release fixes, in the layout of the platform
     * that the document's hardware evidence names, with an empty register
     * for one that the release leaves to the platform; or null if the
     * release fixes none on that platform. The values are authenticated;
     * the platform that selects their layout is authenticated only once the
     * quote step passed.
     */
    public val codeMeasurement: Measurement?,
    /**
     * Every register that the hardware evidence had to attest: the code
     * measurement, the policy's pinned registers, and the registers that
     * the endorsed platform supplies, such as TDX MRTD and RTMR0. It is set
     * once the policy step resolved them, even if a later check of that
     * step failed, and null otherwise.
     */
    public val measurement: Measurement?,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (
            other is ExpectedFacts &&
                configRepo == other.configRepo &&
                artifact == other.artifact &&
                config == other.config &&
                platform == other.platform &&
                codeMeasurement == other.codeMeasurement &&
                measurement == other.measurement
            )

    override fun hashCode(): Int = Objects.hash(configRepo, artifact, config, platform, codeMeasurement, measurement)

    override fun toString(): String =
        "ExpectedFacts(configRepo=$configRepo, artifact=$artifact, config=$config, platform=$platform, " +
            "codeMeasurement=$codeMeasurement, measurement=$measurement)"
}

/**
 * What the attestation document and its hardware evidence claim.
 *
 * **The key fingerprints are unverified.** Only the policy step binds the
 * keys to the enclave, and in a report that has partial facts that step did
 * not pass: the fingerprints are the document's claim alone. Present them as
 * unverified, and never bind a channel to them. A report holds no key, only
 * these fingerprints.
 */
public class MeasuredFacts internal constructor(
    /** What the hardware evidence proves. Set once the quote step passed; null otherwise. */
    public val cpu: CpuEvidence?,
    /**
     * The SHA-256 of the public key of the TLS certificate that the document
     * endorses, lowercase hex, or null if it endorses none. Unverified.
     */
    public val tlsPublicKeyFingerprint: String?,
    /**
     * The SHA-256 of the HPKE public key that the document endorses,
     * lowercase hex, or null if it endorses none. It is a fingerprint, never
     * the key. Unverified.
     */
    public val hpkePublicKeyFingerprint: String?,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (
            other is MeasuredFacts &&
                cpu == other.cpu &&
                tlsPublicKeyFingerprint == other.tlsPublicKeyFingerprint &&
                hpkePublicKeyFingerprint == other.hpkePublicKeyFingerprint
            )

    override fun hashCode(): Int = Objects.hash(cpu, tlsPublicKeyFingerprint, hpkePublicKeyFingerprint)

    override fun toString(): String =
        "MeasuredFacts(cpu=$cpu, tlsPublicKeyFingerprint=$tlsPublicKeyFingerprint, " +
            "hpkePublicKeyFingerprint=$hpkePublicKeyFingerprint)"
}

/** What the CPU's authenticated hardware evidence proves. */
public class CpuEvidence internal constructor(
    /** Every register that the hardware measured, in its platform's layout. */
    public val measurement: Measurement,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is CpuEvidence && measurement == other.measurement)

    override fun hashCode(): Int = measurement.hashCode()

    override fun toString(): String = "CpuEvidence(measurement=$measurement)"
}

/**
 * The outcome of one attempt to verify an enclave: [Passed], with the
 * attempt's report, or [Failed], with the exception that the client reported
 * for it. A client hands these to its `onVerification` option and returns
 * the last from `lastVerification()`. More may not be added: an attempt
 * passes or fails.
 */
public sealed class VerificationAttempt {
    /** The report of an attempt that passed, whose verified facts are set; null for one that failed. */
    public abstract val report: VerificationReport?

    /**
     * The exception of an attempt that failed; null for one that passed. When
     * the verifier rejected the attestation document, it is an
     * [AttestationException] whose cause is a [VerificationException], which
     * carries the report.
     */
    public abstract val error: TinfoilException?

    /** An attempt that passed. */
    public class Passed internal constructor(
        override val report: VerificationReport,
    ) : VerificationAttempt() {
        override val error: TinfoilException? get() = null

        override fun equals(other: Any?): Boolean = this === other || (other is Passed && report == other.report)

        override fun hashCode(): Int = report.hashCode()

        override fun toString(): String = "Passed(report=$report)"
    }

    /** An attempt that failed. */
    public class Failed internal constructor(
        override val error: TinfoilException,
    ) : VerificationAttempt() {
        override val report: VerificationReport? get() = null

        // Exceptions compare by identity, and so do these.
        override fun equals(other: Any?): Boolean = this === other || (other is Failed && error === other.error)

        override fun hashCode(): Int = System.identityHashCode(error)

        override fun toString(): String = "Failed(error=$error)"
    }
}

/**
 * The verifier's rejection of an attestation document, with the
 * [report] of the verification that rejected it.
 *
 * The client never throws it by itself: it reaches a caller as the
 * [cause][Throwable.cause] of the [AttestationException] that the client
 * throws, so that a caller can show what happened. Decide what to do from
 * that [AttestationException], never from this or its [report].
 */
public class VerificationException internal constructor(
    message: String,
    /** The layer of the verifier that rejected the document. */
    public val layer: VerificationLayer,
    /**
     * The verification's report: the step for [layer] failed, and it has
     * [partial facts][VerificationReport.partialFacts] and no verified facts.
     */
    public val report: VerificationReport,
) : Exception(message)
