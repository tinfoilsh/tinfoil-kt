package sh.tinfoil.internal.verification

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import sh.tinfoil.ArtifactVerification
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigVerification
import sh.tinfoil.CryptoMaterial
import sh.tinfoil.Measurement
import sh.tinfoil.ReferenceSource
import sh.tinfoil.SoftwareIdentity
import sh.tinfoil.Verification
import sh.tinfoil.VerificationMetadata
import sh.tinfoil.internal.SdkIdentity
import sh.tinfoil.internal.nullIfEmpty
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * Decodes the JSON in which the verifier library reports what a document
 * proved. Any payload that cannot be read in full is an
 * [AttestationException]: a result that is not understood is not a
 * verification.
 */
internal object VerificationPayload {
    /**
     * The schema that this decoder reads. The version changes when a member
     * is removed or changes its meaning; members may be added within one.
     */
    const val SUPPORTED_SCHEMA_VERSION: Int = 1

    @Throws(AttestationException::class)
    fun decode(payload: String): Verification {
        // The version is read alone first, so that a payload in another
        // schema is reported as such rather than as a missing member.
        val version = read(SchemaVersion.serializer(), payload).schemaVersion
        if (version != SUPPORTED_SCHEMA_VERSION) {
            throw AttestationException(
                "unsupported verification schema version $version; " +
                    "this SDK reads version $SUPPORTED_SCHEMA_VERSION",
            )
        }
        val decoded = read(Payload.serializer(), payload)
        return Verification(
            configRepo = decoded.configRepo.nullIfEmpty(),
            codeDigest = required(decoded.codeDigest, "code_digest"),
            codeTag = decoded.codeTag.nullIfEmpty(),
            codeMeasurement = decoded.codeMeasurement?.measurement(),
            enclaveMeasurement = decoded.enclaveMeasurement?.measurement(),
            config = decoded.config?.verification(),
            runtime = decoded.runtime?.verification("runtime"),
            platform = decoded.platform?.verification("platform"),
            tlsPublicKeyFingerprint = decoded.tlsPublicKeyFp.nullIfEmpty(),
            hpkePublicKey = decoded.hpkePublicKey.nullIfEmpty(),
            cryptoMaterial = decoded.cryptoMaterial.map { CryptoMaterial(it.id, it.format, it.data) },
            freshnessExpiresAt = instant(decoded.freshnessExpiresAt, "freshness_expires_at"),
            metadata = VerificationMetadata(
                // The payload names no verifier; the SDK records itself.
                verifier = SoftwareIdentity(SdkIdentity.NAME, SdkIdentity.VERSION),
                verifiedAt = instant(decoded.verifiedAt, "verified_at"),
            ),
        )
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
    private class Payload(
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
        @SerialName("verified_at") val verifiedAt: String,
    )

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
        fun verification(): ConfigVerification = ConfigVerification(
            source = ReferenceSource(required(source, "config.source")),
            name = name.nullIfEmpty(),
            digest = required(digest, "config.digest"),
            reference = reference.nullIfEmpty(),
            signingKeyHint = signingKeyHint.nullIfEmpty(),
            approvalTime = optionalInstant(approvalTime, "config.approval_time"),
            registryId = registryId.nullIfEmpty(),
            signatureTime = optionalInstant(signatureTime, "config.signature_time"),
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
