package sh.tinfoil

import sh.tinfoil.internal.immutableCopy
import sh.tinfoil.internal.verification.Attestor
import java.time.Instant
import java.util.Objects

/**
 * What a verified attestation document proved about an enclave: the facts
 * of a [VerificationReport] whose every step passed or was skipped. It holds
 * no host: a document verifies the same whichever host serves it, so the
 * client records where it was fetched from.
 *
 * They are the only source of the keys that a channel is bound to: the
 * client binds TLS and request bodies only to the keys here, never to the
 * fingerprints of [PartialFacts].
 *
 * A fact that the verification did not establish is null, never an empty
 * string. Instances are immutable and compare by value.
 */
public class VerifiedFacts internal constructor(
    /**
     * The repository that the code provenance was authenticated against,
     * without a tag or digest, or null when the verification names none.
     */
    public val configRepo: String?,
    /** SHA-256 of the verified code release or runtime artifact, lowercase hex. */
    public val codeDigest: String,
    /** The release tag of the verified code or runtime, or null. */
    public val codeTag: String?,
    /**
     * The registers that the release fixes, in the layout of
     * [enclaveMeasurement], with an empty register for one that the release
     * leaves open; or null if the release fixes none on that platform.
     */
    public val codeMeasurement: Measurement?,
    /** The hardware quote's authenticated registers. */
    public val enclaveMeasurement: Measurement?,
    /**
     * The config bound to the hardware. Null for an enclave verified against
     * a code release, which has no config.
     */
    public val config: ConfigVerification?,
    /** The runtime that a config-based verification accepted. */
    public val runtime: ArtifactVerification?,
    /** The platform endorsements that a config-based verification accepted. */
    public val platform: ArtifactVerification?,
    cryptoMaterial: List<CryptoMaterial>,
    /** No new request may be authorized at or after this instant. */
    public val freshnessExpiresAt: Instant,
) {
    /**
     * Every key that the enclave endorses, in the document's order,
     * including the two that [tlsPublicKeyFingerprint] and [hpkePublicKey]
     * look up.
     */
    public val cryptoMaterial: List<CryptoMaterial> = cryptoMaterial.immutableCopy()

    /**
     * SHA-256 of the public key of the enclave's TLS certificate, lowercase
     * hex: the [cryptoMaterial] item `tls` in the format
     * `https://tinfoil.sh/key/spki-fp-sha256/v1`. Null for an enclave that
     * endorses no such item; a connection cannot be bound to such an enclave
     * over TLS.
     */
    public val tlsPublicKeyFingerprint: String?
        get() = keyData(Attestor.TLS_KEY_ID, Attestor.TLS_KEY_FORMAT)

    /**
     * The X25519 key that request bodies are encrypted to, lowercase hex:
     * the [cryptoMaterial] item `hpke` in the format
     * `https://tinfoil.sh/key/x25519-hpke/v1`. Null for an enclave that
     * endorses no such item, such as one that endorses only a TLS key.
     */
    public val hpkePublicKey: String?
        get() = keyData(Attestor.HPKE_KEY_ID, Attestor.HPKE_KEY_FORMAT)

    /** The data of the item with exactly [id] and [format], or null if there is none. */
    private fun keyData(id: String, format: String): String? =
        cryptoMaterial.firstOrNull { it.id == id && it.format == format }?.data

    override fun equals(other: Any?): Boolean =
        this === other || (
            other is VerifiedFacts &&
                configRepo == other.configRepo &&
                codeDigest == other.codeDigest &&
                codeTag == other.codeTag &&
                codeMeasurement == other.codeMeasurement &&
                enclaveMeasurement == other.enclaveMeasurement &&
                config == other.config &&
                runtime == other.runtime &&
                platform == other.platform &&
                cryptoMaterial == other.cryptoMaterial &&
                freshnessExpiresAt == other.freshnessExpiresAt
            )

    override fun hashCode(): Int = Objects.hash(
        configRepo, codeDigest, codeTag, codeMeasurement, enclaveMeasurement, config, runtime, platform,
        cryptoMaterial, freshnessExpiresAt,
    )

    override fun toString(): String =
        "VerifiedFacts(configRepo=$configRepo, codeDigest=$codeDigest, codeTag=$codeTag, " +
            "codeMeasurement=$codeMeasurement, enclaveMeasurement=$enclaveMeasurement, config=$config, " +
            "runtime=$runtime, platform=$platform, cryptoMaterial=$cryptoMaterial, " +
            "freshnessExpiresAt=$freshnessExpiresAt)"
}

/**
 * A measurement: the predicate type that names its platform, and its
 * registers in that platform's order as lowercase hex.
 *
 * As a [Policy]'s pinned registers, an empty register is one that is not
 * pinned. In [VerifiedFacts] and [ExpectedFacts], an empty register of a code
 * measurement is one that the release leaves open.
 */
public class Measurement(
    /**
     * The predicate type, such as
     * `https://tinfoil.sh/predicate/sev-snp-guest/v2` (one register) or
     * `https://tinfoil.sh/predicate/tdx-guest/v2` (five registers).
     */
    public val type: String,
    registers: List<String>,
) {
    /** The register values, lowercase hex, in the platform's order. */
    public val registers: List<String> = registers.immutableCopy()

    override fun equals(other: Any?): Boolean =
        this === other || (other is Measurement && type == other.type && registers == other.registers)

    override fun hashCode(): Int = Objects.hash(type, registers)

    override fun toString(): String = "Measurement(type=$type, registers=$registers)"
}

/** A key that the enclave endorses, bound into its hardware evidence. */
public class CryptoMaterial internal constructor(
    /** The item's name in the document, such as `tls` or `hpke`. */
    public val id: String,
    /**
     * A URI that names what the item is and how [data] encodes it, such as
     * `https://tinfoil.sh/key/spki-fp-sha256/v1` for the fingerprint of a TLS
     * key or `https://tinfoil.sh/key/x25519-hpke/v1` for an HPKE key; both
     * are lowercase hex.
     */
    public val format: String,
    /** The item, encoded as [format] says. */
    public val data: String,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is CryptoMaterial && id == other.id && format == other.format && data == other.data)

    override fun hashCode(): Int = Objects.hash(id, format, data)

    override fun toString(): String = "CryptoMaterial(id=$id, format=$format, data=$data)"
}

/**
 * Why a verification accepted a component's reference values. More sources
 * may be added, so handle the ones that you know and tolerate any other.
 */
@JvmInline
public value class ReferenceSource(
    /** The source's name. */
    public val value: String,
) {
    override fun toString(): String = value

    public companion object {
        /** An endorsement in the document, verified against the trust policy. */
        public val ENDORSEMENT: ReferenceSource = ReferenceSource("endorsement")

        /**
         * A value that the caller embedded: a [Trust.EmbeddedConfig] config,
         * or an artifact of [ArtifactTrust.EmbeddedArtifacts].
         */
        public val EMBEDDED: ReferenceSource = ReferenceSource("embedded")

        /** A config that the [ConfigAuthorizer] of a [Trust.AuthorizedBy] approved. */
        public val POLICY: ReferenceSource = ReferenceSource("policy")
    }
}

/**
 * The config bound to the hardware, or the config that a verification
 * expected. Only an endorsed config has a reference,
 * a signing key hint, a registry ID and times; they are null otherwise.
 */
public class ConfigVerification internal constructor(
    /** Why the config was accepted. */
    public val source: ReferenceSource,
    /** The config's `/org/project/revision` identity, or null. */
    public val name: String?,
    /** SHA-256 of the config, lowercase hex. */
    public val digest: String,
    /**
     * Identifies the endorsement: `sha256:` and the lowercase hex SHA-256 of
     * its signed statement.
     */
    public val reference: String?,
    /**
     * Identifies the key that signed the approval: the standard base64
     * SHA-256 of its DER `SubjectPublicKeyInfo`.
     */
    public val signingKeyHint: String?,
    /** When the config was approved, from the approval's authenticated timestamp. */
    public val approvalTime: Instant?,
    /**
     * The registry that approved the config, as its URI. For an approval
     * signed with a certificate, the certificate authenticates it;
     * [Verifier.PUBLIC_REGISTRY_ID] is Tinfoil's public registry.
     */
    public val registryId: String?,
    /**
     * When a certificate-signed approval was signed, from its authenticated
     * timestamp; null for an approval signed with a pinned key.
     */
    public val signatureTime: Instant?,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (
            other is ConfigVerification &&
                source == other.source &&
                name == other.name &&
                digest == other.digest &&
                reference == other.reference &&
                signingKeyHint == other.signingKeyHint &&
                approvalTime == other.approvalTime &&
                registryId == other.registryId &&
                signatureTime == other.signatureTime
            )

    override fun hashCode(): Int =
        Objects.hash(source, name, digest, reference, signingKeyHint, approvalTime, registryId, signatureTime)

    override fun toString(): String =
        "ConfigVerification(source=$source, name=$name, digest=$digest, reference=$reference, " +
            "signingKeyHint=$signingKeyHint, approvalTime=$approvalTime, registryId=$registryId, " +
            "signatureTime=$signatureTime)"
}

/**
 * A code release, or a runtime or platform artifact that a config-based
 * verification accepted. An embedded artifact has no name, commit or approval
 * time, and an embedded platform has only a digest.
 */
public class ArtifactVerification internal constructor(
    /** Why the artifact was accepted. */
    public val source: ReferenceSource,
    /** The `owner/name` repository that the artifact was released from, or null. */
    public val repo: String?,
    /** The release tag, such as `v0.15.0`, or null. */
    public val tag: String?,
    /** SHA-256 of the artifact, lowercase hex. */
    public val digest: String,
    /** The artifact's name in its endorsement, or null. */
    public val name: String?,
    /** The source commit that the artifact was built from, lowercase hex, or null. */
    public val commit: String?,
    /**
     * When the artifact was approved, from its endorsement's authenticated
     * timestamp, or null.
     */
    public val approvalTime: Instant?,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (
            other is ArtifactVerification &&
                source == other.source &&
                repo == other.repo &&
                tag == other.tag &&
                digest == other.digest &&
                name == other.name &&
                commit == other.commit &&
                approvalTime == other.approvalTime
            )

    override fun hashCode(): Int = Objects.hash(source, repo, tag, digest, name, commit, approvalTime)

    override fun toString(): String =
        "ArtifactVerification(source=$source, repo=$repo, tag=$tag, digest=$digest, name=$name, " +
            "commit=$commit, approvalTime=$approvalTime)"
}

/**
 * How a verification was performed, whether it passed or failed. The SDK
 * fills it in from its own state; none of it is attested by the document or
 * checked against it.
 */
public class VerificationMetadata internal constructor(
    /** The SDK that performed the verification. */
    public val verifier: SoftwareIdentity,
    /** When the document was appraised. It is not a freshness guarantee. */
    public val verifiedAt: Instant,
) {
    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is VerificationMetadata && verifier == other.verifier && verifiedAt == other.verifiedAt)

    override fun hashCode(): Int = Objects.hash(verifier, verifiedAt)

    override fun toString(): String = "VerificationMetadata(verifier=$verifier, verifiedAt=$verifiedAt)"
}

/** Identifies the software that performed a verification. */
public class SoftwareIdentity internal constructor(
    /** The SDK's name, such as `tinfoil-kt`. */
    public val name: String,
    /** The SDK's version. */
    public val version: String,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is SoftwareIdentity && name == other.name && version == other.version)

    override fun hashCode(): Int = Objects.hash(name, version)

    override fun toString(): String = "SoftwareIdentity(name=$name, version=$version)"
}
