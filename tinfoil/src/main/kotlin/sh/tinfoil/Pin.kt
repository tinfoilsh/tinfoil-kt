package sh.tinfoil

/**
 * Names the workload that a caller trusts.
 *
 * [repo] and [project] are separate namespaces with unrelated owners, so
 * neither is satisfied by the other's collateral. Setting both accepts either.
 *
 * A pin names at least one of the two. Only null means "not set": a part
 * that is empty or blank is a mistake, and the constructor refuses it; any
 * other text is kept as it is given, and is checked when a client is created
 * with the pin. A pin that names nothing is never what a forgotten argument
 * makes: it is [NONE], and is asked for by name.
 */
public class Pin private constructor(
    /** A GitHub repository, `owner/name[@tag][@sha256:digest]`, or null. */
    public val repo: String?,
    /**
     * A config registry project, `org/project[@revision][@sha256:digest]`, or
     * null.
     */
    public val project: String?,
    // Tells this constructor, which checks nothing, from the public one.
    @Suppress("UNUSED_PARAMETER") unchecked: Unit,
) {
    /**
     * A pin that names [repo], [project] or both.
     *
     * @throws ConfigurationException if neither is given, or if one is empty
     *   or blank.
     */
    public constructor(repo: String? = null, project: String? = null) :
        this(named(repo, "repo"), named(project, "project"), Unit) {
        if (repo == null && project == null) {
            throw ConfigurationException(
                "a pin must name a repo or a project: for a pin that names nothing, use Pin.NONE",
            )
        }
    }

    override fun equals(other: Any?): Boolean =
        this === other || (other is Pin && repo == other.repo && project == other.project)

    override fun hashCode(): Int = 31 * repo.hashCode() + project.hashCode()

    override fun toString(): String = "Pin(repo=$repo, project=$project)"

    public companion object {
        /**
         * The pin that names no workload: its [repo] and its [project] are
         * null. It is accepted only together with a [Verifier] that
         * authorizes the config by itself, with an embedded config or a
         * config authorizer. Under the default config trust it would accept
         * any config of the public registry, so a client refuses it, with a
         * [ConfigurationException], before any I/O.
         */
        public val NONE: Pin = Pin(null, null, Unit)
    }
}

/** [value], given as the [part] of a pin: null, or text that names something. */
private fun named(value: String?, part: String): String? {
    if (value != null && value.isBlank()) {
        throw ConfigurationException("Pin.$part must not be empty or blank: leave it null to not set it")
    }
    return value
}
