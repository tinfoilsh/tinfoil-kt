package sh.tinfoil

/**
 * Names the workload that a caller trusts.
 *
 * [repo] and [project] are separate namespaces with unrelated owners, so
 * neither is satisfied by the other's collateral. Setting both accepts either.
 * A pin with neither accepts any config that the verifier's trust authorizes,
 * and is a [ConfigurationException] under the default config trust.
 *
 * Only null means "not set". A part that is empty or blank is a mistake, and
 * the constructor refuses it; any other text is kept as it is given, and is
 * checked when a client is created with the pin.
 *
 * @throws ConfigurationException if [repo] or [project] is empty or blank.
 */
public class Pin(
    repo: String? = null,
    project: String? = null,
) {
    /** A GitHub repository, `owner/name[@tag][@sha256:digest]`, or null. */
    public val repo: String? = named(repo, "repo")

    /**
     * A config registry project, `org/project[@revision][@sha256:digest]`, or
     * null.
     */
    public val project: String? = named(project, "project")

    override fun equals(other: Any?): Boolean =
        this === other || (other is Pin && repo == other.repo && project == other.project)

    override fun hashCode(): Int = 31 * repo.hashCode() + project.hashCode()

    override fun toString(): String = "Pin(repo=$repo, project=$project)"
}

/** [value], given as the [part] of a pin: null, or text that names something. */
private fun named(value: String?, part: String): String? {
    if (value != null && value.isBlank()) {
        throw ConfigurationException("Pin.$part must not be empty or blank: leave it null to not set it")
    }
    return value
}
