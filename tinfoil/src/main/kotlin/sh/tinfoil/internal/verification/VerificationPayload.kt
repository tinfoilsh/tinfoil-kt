package sh.tinfoil.internal.verification

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import sh.tinfoil.ArtifactVerification
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigVerification
import sh.tinfoil.CpuEvidence
import sh.tinfoil.CryptoMaterial
import sh.tinfoil.ExpectedFacts
import sh.tinfoil.MeasuredFacts
import sh.tinfoil.Measurement
import sh.tinfoil.PartialFacts
import sh.tinfoil.ReferenceSource
import sh.tinfoil.SoftwareIdentity
import sh.tinfoil.Step
import sh.tinfoil.StepStatus
import sh.tinfoil.VerificationException
import sh.tinfoil.VerificationLayer
import sh.tinfoil.VerificationMetadata
import sh.tinfoil.VerificationReport
import sh.tinfoil.VerifiedFacts
import sh.tinfoil.internal.SdkIdentity
import sh.tinfoil.internal.nullIfEmpty
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * Decodes the result JSON in which the verifier library reports a
 * verification that ran: the report of a document that it accepted, or the
 * report and the error of one that it rejected.
 *
 * A payload that cannot be read in full, or that contradicts itself, is an
 * [AttestationException]: a result that is not understood is not a
 * verification.
 */
internal object VerificationPayload {
    /**
     * The schema that this decoder reads. The version changes when a member
     * is removed or changes its meaning; members may be added within one.
     */
    const val SUPPORTED_SCHEMA_VERSION: Int = 2

    /**
     * The report of an accepted document, whose verified facts are set.
     *
     * @throws AttestationException for a rejected document, with a
     *   [VerificationException] that carries the report as its cause; and
     *   for a payload that cannot be read.
     */
    @Throws(AttestationException::class)
    fun decode(payload: String): VerificationReport {
        // The version is read alone first, so that a payload in another
        // schema is reported as such rather than as a missing member.
        val version = read(SchemaVersion.serializer(), payload).schemaVersion
        if (version != SUPPORTED_SCHEMA_VERSION) {
            throw AttestationException(
                "unsupported verification schema version $version; " +
                    "this SDK reads version $SUPPORTED_SCHEMA_VERSION",
            )
        }
        val decoded = read(Result.serializer(), payload)
        val rejection = decoded.error
        val report = decoded.report
        val steps = report.steps.map { it.step() }
        val metadata = VerificationMetadata(
            // The payload names no verifier; the SDK records itself.
            verifier = SoftwareIdentity(SdkIdentity.NAME, SdkIdentity.VERSION),
            verifiedAt = instant(report.metadata.verifiedAt, "metadata.verified_at"),
        )
        if (rejection == null) {
            // Only a report in which every step passed or was skipped, with
            // verified facts and nothing else, is a verification.
            val facts = report.verifiedFacts
                ?: throw AttestationException("verification payload has neither an error nor verified facts")
            if (report.partialFacts != null) {
                throw AttestationException("verification payload has both verified and partial facts")
            }
            if (steps.isEmpty()) {
                throw AttestationException("verification payload has no steps")
            }
            steps.firstOrNull { it.status != StepStatus.PASSED && it.status != StepStatus.SKIPPED }?.let {
                throw AttestationException("verification payload has verified facts, but its ${it.layer} step ${it.status}")
            }
            return VerificationReport(steps, facts.facts(), partialFacts = null, metadata)
        }
        if (report.verifiedFacts != null) {
            throw AttestationException("verification payload has both an error and verified facts")
        }
        val partial = report.partialFacts
            ?: throw AttestationException("verification payload has an error but no partial facts")
        val layer = VerificationLayer(required(rejection.layer, "error.layer"))
        val message = required(rejection.message, "error.message")
        val rejected = VerificationException(
            message,
            layer,
            VerificationReport(steps, verifiedFacts = null, partial.facts(), metadata),
        )
        // The message leads with the type and the layer, as the library's
        // errors do; the exception keeps the same detail as one of those.
        val detail = message.removePrefix(VerifierErrors.VERIFICATION_PREFIX)
        throw AttestationException(detail, layer, rejected)
    }

    // A member that this schema does not name is ignored, since members may
    // be added within a schema version. Everything else is strict: a member
    // of the wrong type, or a required member that is missing or null, fails.
    private val json = Json { ignoreUnknownKeys = true }

    private fun <T> read(strategy: DeserializationStrategy<T>, payload: String): T =
        try {
            json.decodeFromString(strategy, payload)
        } catch (e: SerializationException) {
            throw AttestationException("unreadable verification payload", cause = e)
        } catch (e: IllegalArgumentException) {
            throw AttestationException("unreadable verification payload", cause = e)
        }

    /** A member that every verification has, so an empty one is refused. */
    private fun required(value: String, member: String): String {
        if (value.isEmpty()) {
            throw AttestationException("verification payload has an empty $member")
        }
        return value
    }

    /** An RFC 3339 instant in UTC, with or without a fraction of a second. */
    private fun instant(value: String, member: String): Instant =
        try {
            Instant.parse(value)
        } catch (e: DateTimeParseException) {
            throw AttestationException("verification payload has an invalid $member: $value", cause = e)
        }

    /** An absent time is left out of the payload, or empty. */
    private fun optionalInstant(value: String?, member: String): Instant? =
        value.nullIfEmpty()?.let { instant(it, member) }

    @Serializable
    private class SchemaVersion(@SerialName("schema_version") val schemaVersion: Int)

    @Serializable
    private class Result(
        val report: ReportPayload,
        val error: ErrorPayload? = null,
    )

    @Serializable
    private class ErrorPayload(val layer: String, val message: String)

    @Serializable
    private class ReportPayload(
        val steps: List<StepPayload>,
        @SerialName("verified_facts") val verifiedFacts: VerifiedFactsPayload? = null,
        @SerialName("partial_facts") val partialFacts: PartialFactsPayload? = null,
        val metadata: MetadataPayload,
    )

    @Serializable
    private class StepPayload(val layer: String, val status: String, val message: String? = null) {
        fun step(): Step = Step(
            layer = VerificationLayer(required(layer, "steps.layer")),
            status = StepStatus(required(status, "steps.status")),
            message = message.nullIfEmpty(),
        )
    }

    @Serializable
    private class MetadataPayload(@SerialName("verified_at") val verifiedAt: String)

    @Serializable
    private class VerifiedFactsPayload(
        @SerialName("config_repo") val configRepo: String,
        @SerialName("code_digest") val codeDigest: String,
        @SerialName("code_tag") val codeTag: String? = null,
        @SerialName("code_measurement") val codeMeasurement: MeasurementPayload? = null,
        @SerialName("enclave_measurement") val enclaveMeasurement: MeasurementPayload? = null,
        val config: ConfigPayload? = null,
        val runtime: ArtifactPayload? = null,
        val platform: ArtifactPayload? = null,
        @SerialName("tls_public_key_fp") val tlsPublicKeyFp: String,
        @SerialName("hpke_public_key") val hpkePublicKey: String? = null,
        @SerialName("crypto_material") val cryptoMaterial: List<CryptoMaterialPayload>,
        @SerialName("freshness_expires_at") val freshnessExpiresAt: String,
    ) {
        fun facts(): VerifiedFacts = VerifiedFacts(
            configRepo = configRepo.nullIfEmpty(),
            codeDigest = required(codeDigest, "code_digest"),
            codeTag = codeTag.nullIfEmpty(),
            codeMeasurement = codeMeasurement?.measurement(),
            enclaveMeasurement = enclaveMeasurement?.measurement(),
            config = config?.verification("config"),
            runtime = runtime?.verification("runtime"),
            platform = platform?.verification("platform"),
            tlsPublicKeyFingerprint = tlsPublicKeyFp.nullIfEmpty(),
            hpkePublicKey = hpkePublicKey.nullIfEmpty(),
            cryptoMaterial = cryptoMaterial.map { CryptoMaterial(it.id, it.format, it.data) },
            freshnessExpiresAt = instant(freshnessExpiresAt, "freshness_expires_at"),
        )
    }

    @Serializable
    private class PartialFactsPayload(
        val expected: ExpectedFactsPayload? = null,
        val measured: MeasuredFactsPayload? = null,
    ) {
        fun facts(): PartialFacts = PartialFacts(expected?.facts(), measured?.facts())
    }

    @Serializable
    private class ExpectedFactsPayload(
        @SerialName("config_repo") val configRepo: String,
        val artifact: ArtifactPayload,
        val config: ConfigPayload? = null,
        val platform: ArtifactPayload? = null,
        @SerialName("code_measurement") val codeMeasurement: MeasurementPayload? = null,
        val measurement: MeasurementPayload? = null,
    ) {
        fun facts(): ExpectedFacts = ExpectedFacts(
            configRepo = configRepo.nullIfEmpty(),
            artifact = artifact.verification("partial_facts.expected.artifact"),
            config = config?.verification("partial_facts.expected.config"),
            platform = platform?.verification("partial_facts.expected.platform"),
            codeMeasurement = codeMeasurement?.measurement(),
            measurement = measurement?.measurement(),
        )
    }

    @Serializable
    private class MeasuredFactsPayload(
        @SerialName("cpu_measurement") val cpuMeasurement: MeasurementPayload? = null,
        @SerialName("tls_public_key_fp") val tlsPublicKeyFp: String? = null,
        @SerialName("hpke_public_key_fp") val hpkePublicKeyFp: String? = null,
    ) {
        fun facts(): MeasuredFacts = MeasuredFacts(
            cpu = cpuMeasurement?.let { CpuEvidence(it.measurement()) },
            tlsPublicKeyFingerprint = tlsPublicKeyFp.nullIfEmpty(),
            hpkePublicKeyFingerprint = hpkePublicKeyFp.nullIfEmpty(),
        )
    }

    @Serializable
    private class MeasurementPayload(val type: String, val registers: List<String>) {
        fun measurement(): Measurement = Measurement(type, registers)
    }

    @Serializable
    private class CryptoMaterialPayload(val id: String, val format: String, val data: String)

    @Serializable
    private class ConfigPayload(
        val source: String,
        val name: String? = null,
        val digest: String,
        val reference: String? = null,
        @SerialName("signing_key_hint") val signingKeyHint: String? = null,
        @SerialName("approval_time") val approvalTime: String? = null,
        @SerialName("registry_id") val registryId: String? = null,
        @SerialName("signature_time") val signatureTime: String? = null,
    ) {
        /** [member] is the config's member in the payload, which errors name. */
        fun verification(member: String): ConfigVerification = ConfigVerification(
            source = ReferenceSource(required(source, "$member.source")),
            name = name.nullIfEmpty(),
            digest = required(digest, "$member.digest"),
            reference = reference.nullIfEmpty(),
            signingKeyHint = signingKeyHint.nullIfEmpty(),
            approvalTime = optionalInstant(approvalTime, "$member.approval_time"),
            registryId = registryId.nullIfEmpty(),
            signatureTime = optionalInstant(signatureTime, "$member.signature_time"),
        )
    }

    @Serializable
    private class ArtifactPayload(
        val source: String,
        val repo: String? = null,
        val tag: String? = null,
        val digest: String,
        val name: String? = null,
        val commit: String? = null,
        @SerialName("approval_time") val approvalTime: String? = null,
    ) {
        /** [member] is the artifact's member in the payload, which errors name. */
        fun verification(member: String): ArtifactVerification = ArtifactVerification(
            source = ReferenceSource(required(source, "$member.source")),
            repo = repo.nullIfEmpty(),
            tag = tag.nullIfEmpty(),
            digest = required(digest, "$member.digest"),
            name = name.nullIfEmpty(),
            commit = commit.nullIfEmpty(),
            approvalTime = optionalInstant(approvalTime, "$member.approval_time"),
        )
    }
}
