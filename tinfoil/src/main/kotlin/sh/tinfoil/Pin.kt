package sh.tinfoil

/**
 * What each verification is made against: a GitHub repository, a config
 * registry project, both or neither. [repo] and [project] are separate
 * namespaces with unrelated owners, so neither is satisfied by the other's
 * collateral. A client derives its pin from its [Trust] argument, or from
 * its route.
 */
internal class Pin(
    /** A GitHub repository, `owner/name[@tag][@sha256:digest]`, or null. */
    val repo: String? = null,
    /** A config registry project, `org/project[@revision][@sha256:digest]`, or null. */
    val project: String? = null,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is Pin && repo == other.repo && project == other.project)

    override fun hashCode(): Int = 31 * repo.hashCode() + project.hashCode()

    override fun toString(): String = "Pin(repo=$repo, project=$project)"

    companion object {
        /** The pin that names no workload, for a config that the caller supplies or approves. */
        val NONE: Pin = Pin()
    }
}
