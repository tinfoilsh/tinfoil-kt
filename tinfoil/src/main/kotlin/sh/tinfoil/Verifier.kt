package sh.tinfoil

import sh.tinfoil.internal.nullIfEmpty
import sh.tinfoil.internal.requireNotEmpty
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.internal.verification.GoAttestationVerifier
import sh.tinfoil.internal.verification.VerifierOptions
import java.util.Objects
import kotlin.time.Duration

/**
 * The trust policy that attestation documents are appraised under. Every
 * client takes one; without it, a client uses the defaults: Tinfoil's public
 * config registry, Tinfoil's signing keys and a freshness bound of seven days.
 *
 * The constructor checks the options, including the conflicts between trust
 * sources, and throws a [ConfigurationException] for an invalid combination,
 * so that a client never starts with a policy that cannot verify. It reaches
 * no network. It does call into the native verifier library, and the first
 * verifier that is constructed in a process loads that library, of about
 * 20 MB, from the app's files: construct a verifier off the main thread. A
 * client that is given no verifier constructs the default one by itself, on
 * a background thread.
 *
 * A verifier is immutable and safe to share between clients and threads.
 */
public class Verifier private constructor(
    /** What appraises documents under this policy. */
    @get:JvmSynthetic
    internal val backend: AttestationVerifier,
) {
    /**
     * @param pinnedRegisters Register values that the enclave's measurement
     *   must also match. An empty register keeps its default check.
     * @param freshnessMaxAge The age of the oldest freshness witness that is
     *   accepted. Null keeps the default of seven days; a value must be
     *   positive and finite, and at most about 292 years.
     * @param configRegistryIds The config registries that are accepted,
     *   replacing the public registry; list [PUBLIC_REGISTRY_ID] to keep it.
     *   Must not be empty.
     * @param configSigningKeysPem PEM `PUBLIC KEY` blocks, one key each, that
     *   config approvals must be signed with, replacing registry trust. Must
     *   not be empty.
     * @param freshnessSigningKeysPem PEM `PUBLIC KEY` blocks, one key each,
     *   for Tinfoil's runtime and platform approvals, replacing the built-in
     *   keys. Must not be empty.
     * @param embeddedReferences Caller-trusted components that replace their
     *   endorsements. At least one component must be set.
     * @param configAuthorizer Decides which configs are authorized, replacing
     *   their endorsements. A client with one needs an explicit enclave, and
     *   the pin that names nothing, [Pin.NONE].
     * @throws ConfigurationException if an option is invalid or two trust
     *   sources conflict.
     */
    public constructor(
        pinnedRegisters: Measurement? = null,
        freshnessMaxAge: Duration? = null,
        configRegistryIds: List<String>? = null,
        configSigningKeysPem: List<String>? = null,
        freshnessSigningKeysPem: List<String>? = null,
        embeddedReferences: EmbeddedReferences? = null,
        configAuthorizer: ConfigAuthorizer? = null,
    ) : this(
        GoAttestationVerifier.create(
            optionsJson = VerifierOptions.encode(
                pinnedRegisters = pinnedRegisters,
                freshnessMaxAge = freshnessMaxAge,
                configRegistryIds = configRegistryIds,
                configSigningKeysPem = configSigningKeysPem,
                freshnessSigningKeysPem = freshnessSigningKeysPem,
                embeddedReferences = embeddedReferences,
            ),
            configAuthorizer = configAuthorizer,
        ),
    )

    public companion object {
        /**
         * A verifier that appraises with [backend], for tests that run where
         * the native library cannot load. Whatever [backend] accepts is
         * trusted, so this is not part of the public API.
         */
        @JvmSynthetic
        internal fun appraisingWith(backend: AttestationVerifier): Verifier = Verifier(backend)

        /**
         * Tinfoil's public config registry. To accept configs from a private
         * registry as well as public ones, list both in `configRegistryIds`.
         */
        // A compile-time constant of the verifier library, so reading it
        // does not load the library. It is a `const` here too: the ID is
        // part of the protocol and does not change between versions.
        public const val PUBLIC_REGISTRY_ID: String = sh.tinfoil.go.mobile.Mobile.PublicRegistryID
    }
}

/**
 * Decides whether a deployment's config is authorized, in place of verifying
 * the config's endorsement.
 *
 * Return to authorize the config. Throw to reject it: the document then fails
 * verification with an [AttestationException] at the
 * [provenance][VerificationLayer.PROVENANCE] layer that carries the thrown
 * exception's message. The runtime, the platform and the hardware are still
 * verified, but approving a config authenticates no registry, name or
 * approval time.
 *
 * An authorizer is called synchronously during verification, possibly from
 * several threads at once, so it must be thread-safe and fast.
 */
public fun interface ConfigAuthorizer {
    /**
     * @param endorsement The config material from the attestation document,
     *   which is untrusted.
     * @throws Exception to reject the config.
     */
    @Throws(Exception::class)
    public fun authorize(endorsement: ConfigEndorsement)
}

/**
 * A deployment's config material, as the attestation document carries it. It
 * is untrusted: a [ConfigAuthorizer] decides whether to accept it.
 *
 * Instances are immutable and compare by content; the byte arrays are copied
 * on the way in and on each read.
 */
public class ConfigEndorsement(
    config: ByteArray,
    reference: String? = null,
    sigstoreBundle: ByteArray? = null,
    issuerCertificate: ByteArray? = null,
) {
    private val configBytes: ByteArray = config.copyOf()
    private val sigstoreBundleBytes: ByteArray? = sigstoreBundle?.copyOf()
    private val issuerCertificateBytes: ByteArray? = issuerCertificate?.copyOf()

    /** The config's bytes. */
    public val config: ByteArray get() = configBytes.copyOf()

    /** The endorsement's `sha256:<hex>` reference; null for a plain config. */
    public val reference: String? = reference.nullIfEmpty()

    /**
     * The endorsement's Sigstore bundle, as the exact JSON bytes from the
     * document; null for a plain config.
     */
    public val sigstoreBundle: ByteArray? get() = sigstoreBundleBytes?.copyOf()

    /** The registry's issuer certificate, DER; null unless the config is certified. */
    public val issuerCertificate: ByteArray? get() = issuerCertificateBytes?.copyOf()

    override fun equals(other: Any?): Boolean =
        this === other || (
            other is ConfigEndorsement &&
                configBytes.contentEquals(other.configBytes) &&
                reference == other.reference &&
                sigstoreBundleBytes.contentEquals(other.sigstoreBundleBytes) &&
                issuerCertificateBytes.contentEquals(other.issuerCertificateBytes)
            )

    override fun hashCode(): Int = Objects.hash(
        configBytes.contentHashCode(),
        reference,
        sigstoreBundleBytes.contentHashCode(),
        issuerCertificateBytes.contentHashCode(),
    )

    override fun toString(): String =
        "ConfigEndorsement(config=${configBytes.size} bytes, reference=$reference, " +
            "sigstoreBundle=${sigstoreBundleBytes.describeSize()}, " +
            "issuerCertificate=${issuerCertificateBytes.describeSize()})"
}

/**
 * Caller-trusted components that replace their endorsements. Only the
 * components that are set are replaced; the hardware is always verified, and
 * so are the bindings between components and any pinned registers. These
 * values must come from trusted client configuration. Set at least one.
 *
 * Instances are immutable and compare by content; the byte arrays are copied
 * on the way in and on each read.
 */
public class EmbeddedReferences(
    /** The deployment's config. */
    public val config: EmbeddedConfig? = null,
    runtime: ByteArray? = null,
    platform: ByteArray? = null,
) {
    private val runtimeBytes: ByteArray? = runtime?.copyOf()
    private val platformBytes: ByteArray? = platform?.copyOf()

    /** The exact runtime manifest that the config pins. */
    public val runtime: ByteArray? get() = runtimeBytes?.copyOf()

    /** A platform policy artifact. */
    public val platform: ByteArray? get() = platformBytes?.copyOf()

    override fun equals(other: Any?): Boolean =
        this === other || (
            other is EmbeddedReferences &&
                config == other.config &&
                runtimeBytes.contentEquals(other.runtimeBytes) &&
                platformBytes.contentEquals(other.platformBytes)
            )

    override fun hashCode(): Int =
        Objects.hash(config, runtimeBytes.contentHashCode(), platformBytes.contentHashCode())

    override fun toString(): String =
        "EmbeddedReferences(config=$config, runtime=${runtimeBytes.describeSize()}, " +
            "platform=${platformBytes.describeSize()})"
}

/**
 * A caller-trusted config: its exact bytes ([Bytes]), or its digest and the
 * runtime that it pins ([Reference]).
 */
public sealed interface EmbeddedConfig {
    /**
     * The config's `/org/project/revision` identity, which a client's [Pin]
     * is then checked against, or null. An empty name is refused with a
     * [ConfigurationException] by the constructors of both kinds.
     */
    public val name: String?

    /**
     * The config itself, authorized without a registry endorsement. The bytes
     * are copied on the way in and on each read.
     */
    public class Bytes(
        bytes: ByteArray,
        name: String? = null,
    ) : EmbeddedConfig {
        private val content: ByteArray = bytes.copyOf()

        /** The config's exact bytes. */
        public val bytes: ByteArray get() = content.copyOf()

        override val name: String? = requireNotEmpty(name, "the embedded config's name")

        override fun equals(other: Any?): Boolean =
            this === other || (other is Bytes && content.contentEquals(other.content) && name == other.name)

        override fun hashCode(): Int = Objects.hash(content.contentHashCode(), name)

        override fun toString(): String = "EmbeddedConfig.Bytes(bytes=${content.size} bytes, name=$name)"
    }

    /** An exact pair of a config, by its digest, and the runtime that it runs. */
    public class Reference(
        /** SHA-256 of the config, lowercase hex. */
        public val digest: String,
        /** The runtime release that the config pins. */
        public val runtime: RuntimeReference,
        name: String? = null,
    ) : EmbeddedConfig {
        override val name: String? = requireNotEmpty(name, "the embedded config's name")

        override fun equals(other: Any?): Boolean =
            this === other ||
                (other is Reference && digest == other.digest && runtime == other.runtime && name == other.name)

        override fun hashCode(): Int = Objects.hash(digest, runtime, name)

        override fun toString(): String = "EmbeddedConfig.Reference(digest=$digest, runtime=$runtime, name=$name)"
    }
}

/** A runtime release: its repository, tag and digest. */
public class RuntimeReference(
    /** The `owner/name` repository that the runtime is released from. */
    public val repo: String,
    /** The release tag. */
    public val tag: String,
    /** SHA-256 of the runtime artifact, lowercase hex. */
    public val digest: String,
) {
    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is RuntimeReference && repo == other.repo && tag == other.tag && digest == other.digest)

    override fun hashCode(): Int = Objects.hash(repo, tag, digest)

    override fun toString(): String = "RuntimeReference(repo=$repo, tag=$tag, digest=$digest)"
}

private fun ByteArray?.describeSize(): String = if (this == null) "null" else "$size bytes"
