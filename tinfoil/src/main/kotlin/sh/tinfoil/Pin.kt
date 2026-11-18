package sh.tinfoil

import sh.tinfoil.internal.nullIfEmpty

/**
 * Names the workload that a caller trusts.
 *
 * [repo] and [project] are separate namespaces with unrelated owners, so
 * neither is satisfied by the other's collateral. Setting both accepts either.
 * A pin with neither accepts any config that the verifier's trust authorizes,
 * and is a [ConfigurationException] under the default config trust.
 *
 * Null and the empty string both mean "not set"; an empty string is stored as
 * null.
 */
public class Pin(
    repo: String? = null,
    project: String? = null,
) {
    /** A GitHub repository, `owner/name[@tag][@sha256:digest]`, or null. */
    public val repo: String? = repo.nullIfEmpty()

    /**
     * A config registry project, `org/project[@revision][@sha256:digest]`, or
     * null.
     */
    public val project: String? = project.nullIfEmpty()

    override fun equals(other: Any?): Boolean =
        this === other || (other is Pin && repo == other.repo && project == other.project)

    override fun hashCode(): Int = 31 * repo.hashCode() + project.hashCode()

    override fun toString(): String = "Pin(repo=$repo, project=$project)"
}
