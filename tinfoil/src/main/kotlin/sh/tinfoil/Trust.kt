package sh.tinfoil

import sh.tinfoil.internal.immutableCopy
import java.util.Objects

/**
 * Names who vouches for the config that an enclave runs: the required
 * argument of [EnclaveHttpClient.create]. It is one of [RepoPin],
 * [ProjectPin], [SignedBy], [AuthorizedBy], [EmbeddedConfig] or
 * [EitherPin]. Only [RepoPin] and [EitherPin] accept
 * `attestation-collaterals/v2`; every other variant requires
 * `attestation-collaterals/v3`.
 *
 * A variant checks nothing when it is constructed: [EnclaveHttpClient.create]
 * checks it, before any network I/O, and refuses one that no verification
 * could pass with a [ConfigurationException]. The variants are immutable:
 * the lists and byte arrays that they are given are copied on the way in,
 * and a byte array again on each read.
 */
public sealed interface Trust {
    /**
     * Trusts `attestation-collaterals/v2` for [repo], a GitHub repository
     * `owner/name[@tag][@sha256:digest]`, which must not be empty.
     */
    public class RepoPin(
        /** The repository, `owner/name[@tag][@sha256:digest]`. */
        public val repo: String,
    ) : Trust {
        override fun equals(other: Any?): Boolean = this === other || (other is RepoPin && repo == other.repo)

        override fun hashCode(): Int = repo.hashCode()

        override fun toString(): String = "RepoPin(repo=$repo)"
    }

    /**
     * Trusts `attestation-collaterals/v3` for [project], a config registry
     * project `org/project[@revision][@sha256:digest]`, which must not be
     * empty, that one of the trusted registries endorses.
     *
     * [registryIds] selects those registries, and null and empty differ:
     * - null trusts Tinfoil's public registry, [PUBLIC_REGISTRY_ID], alone;
     * - a list that is not empty trusts exactly the registries that it
     *   names, in place of the public registry: to trust a private
     *   registry alongside the public one, list [PUBLIC_REGISTRY_ID] too;
     * - an empty list is refused, so that an empty list that the
     *   application computed fails closed rather than silently widening
     *   trust to the public registry.
     */
    public class ProjectPin(
        /** The project, `org/project[@revision][@sha256:digest]`. */
        public val project: String,
        registryIds: List<String>? = null,
    ) : Trust {
        /** The trusted registries, or null for the public registry alone. */
        public val registryIds: List<String>? = registryIds?.immutableCopy()

        override fun equals(other: Any?): Boolean =
            this === other || (other is ProjectPin && project == other.project && registryIds == other.registryIds)

        override fun hashCode(): Int = Objects.hash(project, registryIds)

        override fun toString(): String = "ProjectPin(project=$project, registryIds=$registryIds)"
    }

    /**
     * Trusts `attestation-collaterals/v3` configs whose endorsements the
     * caller's [keys] sign, in place of Tinfoil's registry root. [keys]
     * must not be empty. [project], a config registry project
     * `org/project[@revision][@sha256:digest]`, restricts the configs that
     * are accepted; null or empty accepts any config that [keys] sign.
     */
    public class SignedBy(
        keys: List<String>,
        /** The project that the configs must belong to, or null for any. */
        public val project: String? = null,
    ) : Trust {
        /** PEM `PUBLIC KEY` blocks, one key each. */
        public val keys: List<String> = keys.immutableCopy()

        override fun equals(other: Any?): Boolean =
            this === other || (other is SignedBy && keys == other.keys && project == other.project)

        override fun hashCode(): Int = Objects.hash(keys, project)

        override fun toString(): String = "SignedBy(keys=${keys.size} keys, project=$project)"
    }

    /**
     * Trusts `attestation-collaterals/v3` configs that [authorize] accepts,
     * in place of a registry endorsement. The runtime, the platform and the
     * hardware are still verified. Approval authenticates no registry name
     * or approval time, so this variant has no pin.
     */
    public class AuthorizedBy(
        /** Decides which configs are authorized; see [ConfigAuthorizer]. */
        public val authorize: ConfigAuthorizer,
    ) : Trust {
        override fun equals(other: Any?): Boolean =
            this === other || (other is AuthorizedBy && authorize === other.authorize)

        override fun hashCode(): Int = System.identityHashCode(authorize)

        override fun toString(): String = "AuthorizedBy(authorize=$authorize)"
    }

    /**
     * Trusts `attestation-collaterals/v3` for exactly the config [bytes]
     * that the caller supplies, which must come from trusted client
     * configuration and must not be empty. [name] optionally associates
     * them with a `/org/project/revision` identity; null or empty names
     * none. This variant has no pin, because a pin would only compare the
     * caller's input against the caller's input.
     */
    public class EmbeddedConfig(
        bytes: ByteArray,
        /** The config's `/org/project/revision` identity, or null. */
        public val name: String? = null,
    ) : Trust {
        private val content: ByteArray = bytes.copyOf()

        /** The config's exact bytes. */
        public val bytes: ByteArray get() = content.copyOf()

        override fun equals(other: Any?): Boolean =
            this === other || (other is EmbeddedConfig && content.contentEquals(other.content) && name == other.name)

        override fun hashCode(): Int = Objects.hash(content.contentHashCode(), name)

        override fun toString(): String = "EmbeddedConfig(bytes=${content.size} bytes, name=$name)"
    }

    /**
     * Trusts `attestation-collaterals/v2` for [repo] or
     * `attestation-collaterals/v3` for [project], as [RepoPin] and
     * [ProjectPin] do. Both must be set. It exists for the migration from
     * v2 to v3 collateral and will be removed with v2.
     */
    public class EitherPin(
        /** The repository, `owner/name[@tag][@sha256:digest]`. */
        public val repo: String,
        /** The project, `org/project[@revision][@sha256:digest]`. */
        public val project: String,
    ) : Trust {
        override fun equals(other: Any?): Boolean =
            this === other || (other is EitherPin && repo == other.repo && project == other.project)

        override fun hashCode(): Int = Objects.hash(repo, project)

        override fun toString(): String = "EitherPin(repo=$repo, project=$project)"
    }

    public companion object {
        /**
         * Tinfoil's public config registry. To accept configs from a
         * private registry as well as public ones, list both in
         * [ProjectPin.registryIds].
         */
        // A compile-time constant of the verifier library, so reading it
        // does not load the library. It is a `const` here too: the ID is
        // part of the protocol and does not change between versions.
        public const val PUBLIC_REGISTRY_ID: String = sh.tinfoil.go.mobile.Mobile.PublicRegistryID
    }
}

/**
 * Decides whether a deployment's config is authorized, in place of verifying
 * the config's endorsement; see [Trust.AuthorizedBy].
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
    public val reference: String? = if (reference.isNullOrEmpty()) null else reference

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

internal fun ByteArray?.describeSize(): String = if (this == null) "null" else "$size bytes"
