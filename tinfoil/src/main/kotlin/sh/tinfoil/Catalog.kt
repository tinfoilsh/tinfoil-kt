package sh.tinfoil

import sh.tinfoil.internal.immutableCopy
import java.util.Collections
import java.util.Objects

/**
 * What a gateway's catalog says of one model: the repository that the
 * model's replicas run, and where the replicas are.
 *
 * None of it is trusted. A catalog only proposes: each replica is verified
 * against the repository before a request is sealed to it.
 *
 * Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.
 */
@ExperimentalTinfoilApi
public class CatalogEntry(
    /** The `owner/name` repository that the model's replicas run, as the gateway reports it. */
    public val repo: String,
    hosts: List<String>,
) {
    /** The replicas: each a host with an optional port. */
    public val hosts: List<String> = hosts.immutableCopy()

    override fun equals(other: Any?): Boolean =
        this === other || (other is CatalogEntry && repo == other.repo && hosts == other.hosts)

    override fun hashCode(): Int = Objects.hash(repo, hosts)

    override fun toString(): String = "CatalogEntry(repo=$repo, hosts=$hosts)"
}

/**
 * A gateway's catalog: the models that the gateway routes, by the name that
 * a request gives its model, each with a [CatalogEntry].
 *
 * It is not trusted; see [CatalogEntry]. A catalog is immutable: it keeps a
 * copy of the entries that it was made from.
 *
 * Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.
 */
@ExperimentalTinfoilApi
public class Catalog(entries: Map<String, CatalogEntry>) {
    /** The entries, by model name, in the order in which they were given. */
    public val entries: Map<String, CatalogEntry> = Collections.unmodifiableMap(LinkedHashMap(entries))

    /** The entry of [model], or null if the catalog does not list it. */
    public operator fun get(model: String): CatalogEntry? = entries[model]

    override fun equals(other: Any?): Boolean = this === other || (other is Catalog && entries == other.entries)

    override fun hashCode(): Int = entries.hashCode()

    override fun toString(): String = "Catalog($entries)"
}

/**
 * Pins a model of the gateway to the repository that its replicas must run.
 *
 * Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.
 */
@ExperimentalTinfoilApi
public class ModelPin(
    /**
     * The repository, `tinfoilsh/name[@tag][@sha256:digest]`. With a tag or
     * a digest, only that release of it is accepted.
     */
    public val repo: String,
    /**
     * The trust policy for this model's replicas. Null uses the policy of
     * the client that the pin is given to.
     */
    public val verifier: Verifier? = null,
) {
    override fun toString(): String =
        "ModelPin(repo=$repo, verifier=${if (verifier == null) "the client's" else "its own"})"
}

/**
 * The last successful verification of one replica that a [GatewayHttpClient]
 * has used.
 *
 * Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.
 */
@ExperimentalTinfoilApi
public class ReplicaVerification internal constructor(
    /** The replica: a host with an optional port, as the gateway named it. */
    public val host: String,
    models: List<String>,
    /** What the replica was verified against: a repository, with the tag or digest of a pin that has one. */
    public val reference: String,
    /** The model whose [ModelPin] the replica was verified under, or null for a model that is not pinned. */
    public val pinnedModel: String?,
    /** The verification. It may have expired or been rejected since. */
    public val verification: Verification,
) {
    /**
     * The models that requests sent to the replica named, sorted. They are
     * what the client's callers asked for, not identities that the replica
     * attested.
     */
    public val models: List<String> = models.immutableCopy()

    override fun equals(other: Any?): Boolean =
        this === other || (
            other is ReplicaVerification && host == other.host && models == other.models &&
                reference == other.reference && pinnedModel == other.pinnedModel && verification == other.verification
            )

    override fun hashCode(): Int = Objects.hash(host, models, reference, pinnedModel, verification)

    override fun toString(): String =
        "ReplicaVerification(host=$host, models=$models, reference=$reference, pinnedModel=$pinnedModel, " +
            "verification=$verification)"
}
