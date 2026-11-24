package sh.tinfoil.internal.verification

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
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
import sh.tinfoil.internal.ReportJson
import sh.tinfoil.internal.ReportJson.ArtifactForm
import sh.tinfoil.internal.ReportJson.ConfigForm
import sh.tinfoil.internal.ReportJson.ExpectedFactsForm
import sh.tinfoil.internal.ReportJson.MeasuredFactsForm
import sh.tinfoil.internal.ReportJson.MeasurementForm
import sh.tinfoil.internal.ReportJson.ResultForm
import sh.tinfoil.internal.ReportJson.StepForm
import sh.tinfoil.internal.ReportJson.VerifiedFactsForm
import sh.tinfoil.internal.SdkIdentity
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * Decodes the result JSON in which the verifier library reports a
 * verification that ran: `{"schema_version", "report", "error"}`, whose
 * report is in the JSON form that [VerificationReport.toJson] writes. It
 * holds the report of a document that the library accepted, or the report
 * and the error of one that it rejected.
 *
 * A payload that cannot be read in full, that is in a version that this
 * decoder does not know, that breaks a rule of the form, or that contradicts
 * itself, is an [AttestationException]: a result that is not understood is
 * not a verification.
 */
internal object VerificationPayload {
    /**
     * The version of the result's wrapper that this decoder reads. It changes
     * when a member is removed or changes its meaning; members may be added
     * within one. The report in it has its own version,
     * [ReportJson.SCHEMA_VERSION].
     */
    const val SUPPORTED_SCHEMA_VERSION: Int = 3

    /**
     * The report of an accepted document, whose verified facts are set.
     *
     * @throws AttestationException for a rejected document, with a
     *   [VerificationException] that carries the report as its cause; and
     *   for a payload that cannot be read.
     */
    @Throws(AttestationException::class)
    fun decode(payload: String): VerificationReport {
        val tree = parse(payload)
        // The versions are read alone first, so that a payload in another
        // version is reported as such rather than as a missing member.
        val version = version(tree)
        if (version != SUPPORTED_SCHEMA_VERSION) {
            throw AttestationException(
                "unsupported verification schema version $version; " +
                    "this SDK reads version $SUPPORTED_SCHEMA_VERSION",
            )
        }
        val reportVersion = (tree["report"] as? JsonObject)?.let(::version)
            ?: throw AttestationException("unreadable verification payload: it has no report object")
        if (reportVersion != ReportJson.SCHEMA_VERSION) {
            throw AttestationException(
                "unsupported verification report schema version $reportVersion; " +
                    "this SDK reads version ${ReportJson.SCHEMA_VERSION}",
            )
        }
        val decoded = read(tree)
        val rejection = decoded.error
        val report = decoded.report
        val steps = steps(report.steps)
        val metadata = VerificationMetadata(
            // The library names no verifier of its own, or one that only
            // describes the library; the SDK records itself.
            verifier = SoftwareIdentity(SdkIdentity.NAME, SdkIdentity.VERSION),
            verifiedAt = instant(report.metadata.verifiedAt, "metadata.verified_at"),
        )
        val failed = steps.filter { it.status == StepStatus.FAILED }
        if (rejection == null) {
            // Only a report in which every step passed or was skipped, with
            // verified facts and nothing else, is a verification.
            val facts = report.verifiedFacts
                ?: throw AttestationException("verification payload has neither an error nor verified facts")
            if (report.partialFacts != null) {
                throw AttestationException("verification payload has both verified and partial facts")
            }
            steps.firstOrNull { it.status != StepStatus.PASSED && it.status != StepStatus.SKIPPED }?.let {
                throw AttestationException("verification payload has verified facts, but its ${it.layer} step ${it.status}")
            }
            return VerificationReport(steps, verifiedFacts(facts), partialFacts = null, metadata)
        }
        if (report.verifiedFacts != null) {
            throw AttestationException("verification payload has both an error and verified facts")
        }
        val partial = report.partialFacts
            ?: throw AttestationException("verification payload has an error but no partial facts")
        val layer = VerificationLayer(text(rejection.layer, "error.layer"))
        val message = text(rejection.message, "error.message")
        // The step of the error's layer failed, and no other did.
        if (failed.map { it.layer } != listOf(layer)) {
            throw AttestationException(
                "verification payload has an error at $layer, but its failed steps are ${failed.map { it.layer }}",
            )
        }
        // The message leads with the type and the layer, as the library's
        // errors do; the exception keeps the same detail as one of those.
        val lead = "${VerifierErrors.VERIFICATION_PREFIX}$layer: "
        if (!message.startsWith(lead)) {
            throw AttestationException("verification payload has an error.message that does not lead with \"$lead\"")
        }
        val rejected = VerificationException(
            message,
            layer,
            VerificationReport(
                steps,
                verifiedFacts = null,
                PartialFacts(partial.expected?.let(::expectedFacts), partial.measured?.let(::measuredFacts)),
                metadata,
            ),
        )
        val detail = message.removePrefix(VerifierErrors.VERIFICATION_PREFIX)
        throw AttestationException(detail, rejected)
    }

    // A member that the form does not name is ignored, since members may be
    // added within a version. Everything else is strict: a member of the
    // wrong type, or a required member that is missing, fails.
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * The payload as one JSON object in which no member is null: the form
     * leaves out what is absent, so a null is not the form.
     */
    private fun parse(payload: String): JsonObject {
        val tree = try {
            json.parseToJsonElement(payload)
        } catch (e: SerializationException) {
            throw AttestationException("unreadable verification payload", cause = e)
        }
        if (tree !is JsonObject) {
            throw AttestationException("unreadable verification payload: it is not a JSON object")
        }
        // Walked with a stack rather than by recursion.
        val pending = ArrayDeque<JsonElement>(listOf(tree))
        while (pending.isNotEmpty()) {
            when (val element = pending.removeLast()) {
                is JsonNull -> throw AttestationException("verification payload has a null member")
                is JsonObject -> pending.addAll(element.values)
                is JsonArray -> pending.addAll(element)
                is JsonPrimitive -> Unit
            }
        }
        return tree
    }

    /** The integer `schema_version` of [tree]. */
    private fun version(tree: JsonObject): Int {
        val member = tree["schema_version"] as? JsonPrimitive
        return member?.takeUnless { it.isString }?.intOrNull
            ?: throw AttestationException("unreadable verification payload: it has no integer schema_version")
    }

    private fun read(tree: JsonObject): ResultForm =
        try {
            json.decodeFromJsonElement(ResultForm.serializer(), tree)
        } catch (e: SerializationException) {
            throw AttestationException("unreadable verification payload", cause = e)
        } catch (e: IllegalArgumentException) {
            throw AttestationException("unreadable verification payload", cause = e)
        }

    /** Every step, each of a layer of its own. */
    private fun steps(forms: List<StepForm>): List<Step> {
        if (forms.isEmpty()) {
            throw AttestationException("verification payload has no steps")
        }
        val steps = forms.map {
            Step(
                layer = VerificationLayer(text(it.layer, "steps.layer")),
                status = StepStatus(text(it.status, "steps.status")),
                message = optionalText(it.message, "steps.message"),
            )
        }
        val layers = steps.map { it.layer }
        if (layers.toSet().size != layers.size) {
            throw AttestationException("verification payload has two steps of one layer")
        }
        // Every step is always present; a layer may be added, but none removed.
        KNOWN_LAYERS.firstOrNull { it !in layers }?.let {
            throw AttestationException("verification payload has no $it step")
        }
        return steps
    }

    private fun verifiedFacts(form: VerifiedFactsForm): VerifiedFacts {
        val cryptoMaterial = form.cryptoMaterial.map {
            CryptoMaterial(
                id = text(it.id, "crypto_material.id"),
                format = text(it.format, "crypto_material.format"),
                data = text(it.data, "crypto_material.data"),
            )
        }
        // A channel key is looked up by its id, so an id names one item.
        if (cryptoMaterial.map { it.id }.toSet().size != cryptoMaterial.size) {
            throw AttestationException("verification payload has two crypto_material items with one id")
        }
        for (item in cryptoMaterial) {
            val isChannelKey = (item.id == Attestor.TLS_KEY_ID && item.format == Attestor.TLS_KEY_FORMAT) ||
                (item.id == Attestor.HPKE_KEY_ID && item.format == Attestor.HPKE_KEY_FORMAT)
            if (isChannelKey) {
                hex(item.data, "crypto_material.data", length = KEY_HEX_LENGTH)
            }
        }
        return VerifiedFacts(
            configRepo = optionalText(form.configRepo, "config_repo"),
            codeDigest = hex(form.codeDigest, "code_digest"),
            codeTag = optionalText(form.codeTag, "code_tag"),
            codeMeasurement = form.codeMeasurement?.let { measurement(it, "code_measurement", full = false) },
            enclaveMeasurement = measurement(
                form.enclaveMeasurement ?: throw AttestationException("verification payload has no enclave_measurement"),
                "enclave_measurement",
                full = true,
            ),
            config = form.config?.let { config(it, "config") },
            runtime = form.runtime?.let { artifact(it, "runtime") },
            platform = form.platform?.let { artifact(it, "platform") },
            cryptoMaterial = cryptoMaterial,
            freshnessExpiresAt = instant(form.freshnessExpiresAt, "freshness_expires_at"),
        )
    }

    private fun expectedFacts(form: ExpectedFactsForm): ExpectedFacts {
        val member = "partial_facts.expected"
        return ExpectedFacts(
            configRepo = optionalText(form.configRepo, "$member.config_repo"),
            artifact = artifact(form.artifact, "$member.artifact"),
            config = form.config?.let { config(it, "$member.config") },
            platform = form.platform?.let { artifact(it, "$member.platform") },
            codeMeasurement = form.codeMeasurement?.let { measurement(it, "$member.code_measurement", full = false) },
            measurement = form.measurement?.let { measurement(it, "$member.measurement", full = true) },
        )
    }

    private fun measuredFacts(form: MeasuredFactsForm): MeasuredFacts {
        val member = "partial_facts.measured"
        return MeasuredFacts(
            cpu = form.cpuMeasurement?.let { CpuEvidence(measurement(it, "$member.cpu_measurement", full = true)) },
            tlsPublicKeyFingerprint = form.tlsPublicKeyFp?.let { hex(it, "$member.tls_public_key_fp", KEY_HEX_LENGTH) },
            hpkePublicKeyFingerprint = form.hpkePublicKeyFp?.let { hex(it, "$member.hpke_public_key_fp", KEY_HEX_LENGTH) },
        )
    }

    /**
     * A measurement with its registers named by its platform, in the
     * platform's order, with an empty register for one that is absent. A
     * [full] measurement has every register of its platform; a code
     * measurement has at least one. A platform that this SDK does not know
     * is refused, since its registers could not be read.
     */
    private fun measurement(form: MeasurementForm, member: String, full: Boolean): Measurement {
        val (type, names, registers) = when (form.platform) {
            ReportJson.SEV_SNP -> {
                if (listOf(form.mrtd, form.rtmr0, form.rtmr1, form.rtmr2, form.rtmr3).any { it != null }) {
                    throw AttestationException("verification payload has a TDX register in the SEV-SNP $member")
                }
                Triple(ReportJson.SEV_SNP_TYPE, listOf("launch"), listOf(form.launch))
            }
            ReportJson.TDX -> {
                if (form.launch != null) {
                    throw AttestationException("verification payload has an SEV-SNP register in the TDX $member")
                }
                Triple(
                    ReportJson.TDX_TYPE,
                    listOf("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"),
                    listOf(form.mrtd, form.rtmr0, form.rtmr1, form.rtmr2, form.rtmr3),
                )
            }
            else -> throw AttestationException("verification payload has an unsupported $member.platform: ${form.platform}")
        }
        if (full && registers.any { it == null }) {
            throw AttestationException("verification payload has a $member without every register of its platform")
        }
        if (registers.all { it == null }) {
            throw AttestationException("verification payload has a $member without a register")
        }
        return Measurement(
            type,
            registers.zip(names).map { (value, name) -> value?.let { hex(it, "$member.$name", REGISTER_HEX_LENGTH) } ?: "" },
        )
    }

    /** [member] is the config's member in the payload, which errors name. */
    private fun config(form: ConfigForm, member: String): ConfigVerification = ConfigVerification(
        source = ReferenceSource(text(form.source, "$member.source")),
        name = optionalText(form.name, "$member.name"),
        digest = hex(form.digest, "$member.digest"),
        reference = optionalText(form.reference, "$member.reference"),
        signingKeyHint = optionalText(form.signingKeyHint, "$member.signing_key_hint"),
        approvalTime = form.approvalTime?.let { instant(it, "$member.approval_time") },
        registryId = optionalText(form.registryId, "$member.registry_id"),
        signatureTime = form.signatureTime?.let { instant(it, "$member.signature_time") },
    )

    /** [member] is the artifact's member in the payload, which errors name. */
    private fun artifact(form: ArtifactForm, member: String): ArtifactVerification = ArtifactVerification(
        source = ReferenceSource(text(form.source, "$member.source")),
        repo = optionalText(form.repo, "$member.repo"),
        tag = optionalText(form.tag, "$member.tag"),
        digest = hex(form.digest, "$member.digest"),
        name = optionalText(form.name, "$member.name"),
        commit = form.commit?.let { hex(it, "$member.commit") },
        approvalTime = form.approvalTime?.let { instant(it, "$member.approval_time") },
    )

    /** A string that the form never writes empty: an absent one is left out. */
    private fun text(value: String, member: String): String {
        if (value.isEmpty()) {
            throw AttestationException("verification payload has an empty $member")
        }
        return value
    }

    private fun optionalText(value: String?, member: String): String? = value?.let { text(it, member) }

    /** Lowercase hex, of [length] characters if it is given. */
    private fun hex(value: String, member: String, length: Int? = null): String {
        text(value, member)
        val valid = value.length % 2 == 0 && value.all { it in '0'..'9' || it in 'a'..'f' } &&
            (length == null || value.length == length)
        if (!valid) {
            val expected = if (length == null) "lowercase hex" else "$length lowercase hex digits"
            throw AttestationException("verification payload has a $member that is not $expected")
        }
        return value
    }

    /** An RFC 3339 instant in UTC, written with `Z`, with or without a fraction of a second. */
    private fun instant(value: String, member: String): Instant {
        if (!value.endsWith("Z")) {
            throw AttestationException("verification payload has a $member that is not in UTC: $value")
        }
        return try {
            Instant.parse(value)
        } catch (e: DateTimeParseException) {
            throw AttestationException("verification payload has an invalid $member: $value", cause = e)
        }
    }

    /** A SHA-256 fingerprint or an X25519 key, in hex. */
    private const val KEY_HEX_LENGTH = 64

    /** A 48-byte register, in hex. */
    private const val REGISTER_HEX_LENGTH = 96

    /** The layers that every report has a step for. */
    private val KNOWN_LAYERS = listOf(
        VerificationLayer.ENVELOPE,
        VerificationLayer.PROVENANCE,
        VerificationLayer.QUOTE,
        VerificationLayer.POLICY,
    )
}
