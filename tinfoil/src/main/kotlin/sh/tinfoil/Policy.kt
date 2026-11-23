package sh.tinfoil

import sh.tinfoil.internal.immutableCopy
import java.util.Objects
import kotlin.time.Duration

/**
 * The checks that a client applies on top of what it trusts for configs:
 * the [Trust] argument of [EnclaveHttpClient.create], or the route's own
 * trust on the router and gateway routes. The default policy keeps every
 * default: no register pins, the seven-day freshness bound, and runtime and
 * platform artifacts that Tinfoil's public keys endorse.
 *
 * It is plain data: a client builds its verifier from it, and checks it
 * before any network I/O, so a mistake in it is a [ConfigurationException]
 * from the client's `create`.
 */
public data class Policy(
    /**
     * Register values that the enclave's measurement must also match. Each
     * register that is not empty fills one that the release leaves open,
     * and must equal one that the release fixes; an empty register keeps
     * its default check. Pins for one platform reject every enclave on the
     * other. Null pins nothing.
     */
    public val pinnedRegisters: Measurement? = null,
    /**
     * How old an authenticated freshness witness may be. Zero selects the
     * default of seven days, rather than a bound that rejects every
     * witness; a negative age is refused, and so is one that is infinite
     * or longer than about 292 years.
     */
    public val freshnessMaxAge: Duration = Duration.ZERO,
    /** Who vouches for the runtime and platform artifacts. */
    public val artifacts: ArtifactTrust = ArtifactTrust.EndorsedArtifacts(),
)

/**
 * Who vouches for an enclave's runtime and platform artifacts: Tinfoil's
 * endorsements, [EndorsedArtifacts], or the caller's own artifacts,
 * [EmbeddedArtifacts]. The variants are immutable: the lists and byte
 * arrays that they are given are copied on the way in, and a byte array
 * again on each read.
 */
public sealed interface ArtifactTrust {
    /**
     * Artifacts that endorsements authenticate. [freshnessKeys] are PEM
     * `PUBLIC KEY` blocks, one key each, that replace Tinfoil's public
     * artifact signing keys; null keeps Tinfoil's, and an empty list is
     * refused.
     */
    public class EndorsedArtifacts(
        freshnessKeys: List<String>? = null,
    ) : ArtifactTrust {
        /** The keys that approve artifacts, or null for Tinfoil's. */
        public val freshnessKeys: List<String>? = freshnessKeys?.immutableCopy()

        override fun equals(other: Any?): Boolean =
            this === other || (other is EndorsedArtifacts && freshnessKeys == other.freshnessKeys)

        override fun hashCode(): Int = Objects.hashCode(freshnessKeys)

        override fun toString(): String =
            "EndorsedArtifacts(freshnessKeys=${freshnessKeys?.let { "${it.size} keys" } ?: "Tinfoil's"})"
    }

    /**
     * The caller's own [runtime] manifest, [platform] policy artifact or
     * both, which replace their endorsements and must come from trusted
     * client configuration. At least one must be set, and neither may be
     * empty. [freshnessKeys] approve the artifact that the caller does not
     * supply, as [EndorsedArtifacts] describes; with both supplied there is
     * no such artifact, and keys are refused.
     */
    public class EmbeddedArtifacts(
        runtime: ByteArray? = null,
        platform: ByteArray? = null,
        freshnessKeys: List<String>? = null,
    ) : ArtifactTrust {
        private val runtimeBytes: ByteArray? = runtime?.copyOf()
        private val platformBytes: ByteArray? = platform?.copyOf()

        /** The exact runtime manifest that the config pins, or null. */
        public val runtime: ByteArray? get() = runtimeBytes?.copyOf()

        /** A platform policy artifact, or null. */
        public val platform: ByteArray? get() = platformBytes?.copyOf()

        /** The keys that approve the artifact that is not supplied, or null for Tinfoil's. */
        public val freshnessKeys: List<String>? = freshnessKeys?.immutableCopy()

        override fun equals(other: Any?): Boolean =
            this === other || (
                other is EmbeddedArtifacts &&
                    runtimeBytes.contentEquals(other.runtimeBytes) &&
                    platformBytes.contentEquals(other.platformBytes) &&
                    freshnessKeys == other.freshnessKeys
                )

        override fun hashCode(): Int =
            Objects.hash(runtimeBytes.contentHashCode(), platformBytes.contentHashCode(), freshnessKeys)

        override fun toString(): String =
            "EmbeddedArtifacts(runtime=${runtimeBytes.describeSize()}, platform=${platformBytes.describeSize()}, " +
                "freshnessKeys=${freshnessKeys?.let { "${it.size} keys" } ?: "Tinfoil's"})"
    }
}
