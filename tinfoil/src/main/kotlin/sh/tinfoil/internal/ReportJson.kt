package sh.tinfoil.internal

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import sh.tinfoil.ArtifactVerification
import sh.tinfoil.ConfigVerification
import sh.tinfoil.CryptoMaterial
import sh.tinfoil.ExpectedFacts
import sh.tinfoil.MeasuredFacts
import sh.tinfoil.Measurement
import sh.tinfoil.PartialFacts
import sh.tinfoil.Step
import sh.tinfoil.VerificationMetadata
import sh.tinfoil.VerificationReport
import sh.tinfoil.VerifiedFacts
import java.time.Instant

/**
 * The JSON form of a verification report that every Tinfoil SDK writes, and
 * that the verifier library's result carries. [VerificationReport.toJson]
 * writes it from these classes, and the result's decoder reads the report
 * of the verifier library into them.
 *
 * The serializers are internal, and the public types are not serializable,
 * so that no public API reads the form back into a report or into verified
 * facts: anyone can write verified facts in JSON, so facts that were read
 * from it could be forged.
 *
 * Member names are snake_case. A member that is null is left out, never
 * written as null, and the conversions below never write an empty string.
 */
internal object ReportJson {
    /** The version of the form that this SDK writes and reads. */
    const val SCHEMA_VERSION: Int = 1

    /** The platform of an AMD SEV-SNP measurement, and its one register. */
    const val SEV_SNP: String = "sev-snp"

    /** The platform of an Intel TDX measurement, and its five registers. */
    const val TDX: String = "tdx"

    /** The predicate type of a [Measurement] of [SEV_SNP]: one register, `launch`. */
    const val SEV_SNP_TYPE: String = "https://tinfoil.sh/predicate/sev-snp-guest/v2"

    /** The predicate type of a [Measurement] of [TDX]: `mrtd`, `rtmr0` to `rtmr3`. */
    const val TDX_TYPE: String = "https://tinfoil.sh/predicate/tdx-guest/v2"

    // A null member is left out. Nothing here has a default other than
    // null, so nothing else is left out.
    private val writer = Json { explicitNulls = false }

    /** [report] in the JSON form. */
    fun encode(report: VerificationReport): String = writer.encodeToString(ReportForm.serializer(), form(report))

    private fun form(report: VerificationReport): ReportForm = ReportForm(
        schemaVersion = SCHEMA_VERSION,
        steps = report.steps.map(::form),
        verifiedFacts = report.verifiedFacts?.let(::form),
        partialFacts = report.partialFacts?.let(::form),
        metadata = form(report.metadata),
    )

    private fun form(step: Step): StepForm = StepForm(step.layer.value, step.status.value, step.message.nullIfEmpty())

    private fun form(metadata: VerificationMetadata): MetadataForm = MetadataForm(
        verifiedAt = time(metadata.verifiedAt),
        verifier = VerifierForm(metadata.verifier.name, metadata.verifier.version),
    )

    private fun form(facts: VerifiedFacts): VerifiedFactsForm = VerifiedFactsForm(
        configRepo = facts.configRepo.nullIfEmpty(),
        codeDigest = facts.codeDigest,
        codeTag = facts.codeTag.nullIfEmpty(),
        codeMeasurement = facts.codeMeasurement?.let(::codeMeasurement),
        enclaveMeasurement = facts.enclaveMeasurement?.let(::measurement),
        config = facts.config?.let(::form),
        runtime = facts.runtime?.let(::form),
        platform = facts.platform?.let(::form),
        cryptoMaterial = facts.cryptoMaterial.map(::form),
        freshnessExpiresAt = time(facts.freshnessExpiresAt),
    )

    private fun form(facts: PartialFacts): PartialFactsForm =
        PartialFactsForm(facts.expected?.let(::form), facts.measured?.let(::form))

    private fun form(facts: ExpectedFacts): ExpectedFactsForm = ExpectedFactsForm(
        configRepo = facts.configRepo.nullIfEmpty(),
        artifact = form(facts.artifact),
        config = facts.config?.let(::form),
        platform = facts.platform?.let(::form),
        codeMeasurement = facts.codeMeasurement?.let(::codeMeasurement),
        measurement = facts.measurement?.let(::measurement),
    )

    private fun form(facts: MeasuredFacts): MeasuredFactsForm = MeasuredFactsForm(
        cpuMeasurement = facts.cpu?.measurement?.let(::measurement),
        tlsPublicKeyFp = facts.tlsPublicKeyFingerprint.nullIfEmpty(),
        hpkePublicKeyFp = facts.hpkePublicKeyFingerprint.nullIfEmpty(),
    )

    private fun form(item: CryptoMaterial): CryptoMaterialForm = CryptoMaterialForm(item.id, item.format, item.data)

    private fun form(config: ConfigVerification): ConfigForm = ConfigForm(
        source = config.source.value,
        name = config.name.nullIfEmpty(),
        digest = config.digest,
        reference = config.reference.nullIfEmpty(),
        signingKeyHint = config.signingKeyHint.nullIfEmpty(),
        approvalTime = config.approvalTime?.let(::time),
        registryId = config.registryId.nullIfEmpty(),
        signatureTime = config.signatureTime?.let(::time),
    )

    private fun form(artifact: ArtifactVerification): ArtifactForm = ArtifactForm(
        source = artifact.source.value,
        repo = artifact.repo.nullIfEmpty(),
        tag = artifact.tag.nullIfEmpty(),
        digest = artifact.digest,
        name = artifact.name.nullIfEmpty(),
        commit = artifact.commit.nullIfEmpty(),
        approvalTime = artifact.approvalTime?.let(::time),
    )

    /**
     * The registers that a release fixes, without the ones that it leaves
     * to the platform, which are empty in [measurement]; or null when it
     * fixes none, so that such a code measurement is left out.
     */
    private fun codeMeasurement(measurement: Measurement): MeasurementForm? =
        measurement(measurement).takeIf { it.registers().any { register -> register != null } }

    /**
     * [measurement] with its registers named by its platform. Only the
     * result's decoder makes the measurements of a report, from these two
     * platforms, so another type is a bug.
     */
    private fun measurement(measurement: Measurement): MeasurementForm {
        val registers = measurement.registers.map { it.nullIfEmpty() }
        return when (measurement.type) {
            SEV_SNP_TYPE -> {
                check(registers.size == 1) { "an SEV-SNP measurement has one register, not ${registers.size}" }
                MeasurementForm(SEV_SNP, launch = registers[0])
            }
            TDX_TYPE -> {
                check(registers.size == 5) { "a TDX measurement has five registers, not ${registers.size}" }
                MeasurementForm(
                    TDX,
                    mrtd = registers[0],
                    rtmr0 = registers[1],
                    rtmr1 = registers[2],
                    rtmr2 = registers[3],
                    rtmr3 = registers[4],
                )
            }
            else -> error("a report has no measurement of the type ${measurement.type}")
        }
    }

    /** RFC 3339 in UTC, with the offset written as `Z`. */
    private fun time(instant: Instant): String = instant.toString()

    @Serializable
    class ResultForm(
        @SerialName("schema_version") val schemaVersion: Int,
        val report: ReportForm,
        val error: ErrorForm? = null,
    )

    @Serializable
    class ErrorForm(val layer: String, val message: String)

    @Serializable
    class ReportForm(
        @SerialName("schema_version") val schemaVersion: Int,
        val steps: List<StepForm>,
        @SerialName("verified_facts") val verifiedFacts: VerifiedFactsForm? = null,
        @SerialName("partial_facts") val partialFacts: PartialFactsForm? = null,
        val metadata: MetadataForm,
    )

    @Serializable
    class StepForm(val layer: String, val status: String, val message: String? = null)

    @Serializable
    class MetadataForm(
        @SerialName("verified_at") val verifiedAt: String,
        val verifier: VerifierForm? = null,
    )

    @Serializable
    class VerifierForm(val name: String, val version: String)

    @Serializable
    class VerifiedFactsForm(
        @SerialName("config_repo") val configRepo: String? = null,
        @SerialName("code_digest") val codeDigest: String,
        @SerialName("code_tag") val codeTag: String? = null,
        @SerialName("code_measurement") val codeMeasurement: MeasurementForm? = null,
        @SerialName("enclave_measurement") val enclaveMeasurement: MeasurementForm? = null,
        val config: ConfigForm? = null,
        val runtime: ArtifactForm? = null,
        val platform: ArtifactForm? = null,
        @SerialName("crypto_material") val cryptoMaterial: List<CryptoMaterialForm>,
        @SerialName("freshness_expires_at") val freshnessExpiresAt: String,
    )

    @Serializable
    class PartialFactsForm(
        val expected: ExpectedFactsForm? = null,
        val measured: MeasuredFactsForm? = null,
    )

    @Serializable
    class ExpectedFactsForm(
        @SerialName("config_repo") val configRepo: String? = null,
        val artifact: ArtifactForm,
        val config: ConfigForm? = null,
        val platform: ArtifactForm? = null,
        @SerialName("code_measurement") val codeMeasurement: MeasurementForm? = null,
        val measurement: MeasurementForm? = null,
    )

    @Serializable
    class MeasuredFactsForm(
        @SerialName("cpu_measurement") val cpuMeasurement: MeasurementForm? = null,
        @SerialName("tls_public_key_fp") val tlsPublicKeyFp: String? = null,
        @SerialName("hpke_public_key_fp") val hpkePublicKeyFp: String? = null,
    )

    /** A measurement's platform, and its registers by name; a register that is null is unconstrained. */
    @Serializable
    class MeasurementForm(
        val platform: String,
        val launch: String? = null,
        val mrtd: String? = null,
        val rtmr0: String? = null,
        val rtmr1: String? = null,
        val rtmr2: String? = null,
        val rtmr3: String? = null,
    ) {
        /** Every register member, in the order of the members. */
        fun registers(): List<String?> = listOf(launch, mrtd, rtmr0, rtmr1, rtmr2, rtmr3)
    }

    @Serializable
    class CryptoMaterialForm(val id: String, val format: String, val data: String)

    @Serializable
    class ConfigForm(
        val source: String,
        val name: String? = null,
        val digest: String,
        val reference: String? = null,
        @SerialName("signing_key_hint") val signingKeyHint: String? = null,
        @SerialName("approval_time") val approvalTime: String? = null,
        @SerialName("registry_id") val registryId: String? = null,
        @SerialName("signature_time") val signatureTime: String? = null,
    )

    @Serializable
    class ArtifactForm(
        val source: String,
        val repo: String? = null,
        val tag: String? = null,
        val digest: String,
        val name: String? = null,
        val commit: String? = null,
        @SerialName("approval_time") val approvalTime: String? = null,
    )
}
