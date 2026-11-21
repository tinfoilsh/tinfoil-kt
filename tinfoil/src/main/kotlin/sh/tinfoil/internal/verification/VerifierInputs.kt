package sh.tinfoil.internal.verification

import sh.tinfoil.ArtifactTrust
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Pin
import sh.tinfoil.Policy
import sh.tinfoil.Trust

/**
 * What a [Trust] argument asks of the verifier: the config trust that it is
 * built with, and the pin that each verification is made against.
 */
internal class VerifierInputs(val config: VerifierOptions.ConfigTrust?, val pin: Pin) {
    companion object {
        /**
         * The verifier's inputs for [trust]. Only what the variant itself
         * requires is checked here; the verifier library checks the values.
         *
         * @throws ConfigurationException for a variant that lacks a value
         *   that it requires, or for an empty list of registries.
         */
        @Throws(ConfigurationException::class)
        fun of(trust: Trust): VerifierInputs = when (trust) {
            is Trust.RepoPin -> {
                if (trust.repo.isEmpty()) {
                    throw ConfigurationException("RepoPin requires a repo")
                }
                VerifierInputs(null, Pin(repo = trust.repo))
            }
            is Trust.ProjectPin -> {
                if (trust.project.isEmpty()) {
                    throw ConfigurationException("ProjectPin requires a project")
                }
                val ids = trust.registryIds
                if (ids != null && ids.isEmpty()) {
                    throw ConfigurationException(
                        "ProjectPin registryIds must not be empty: leave it null to trust the public registry",
                    )
                }
                VerifierInputs(ids?.let(VerifierOptions.ConfigTrust::Registries), Pin(project = trust.project))
            }
            is Trust.SignedBy ->
                VerifierInputs(VerifierOptions.ConfigTrust.SigningKeys(trust.keys), Pin(project = trust.project.nullIfEmpty()))
            is Trust.AuthorizedBy -> VerifierInputs(VerifierOptions.ConfigTrust.Authorizer(trust.authorize), Pin.NONE)
            is Trust.EmbeddedConfig ->
                VerifierInputs(VerifierOptions.ConfigTrust.EmbeddedConfig(trust.name.nullIfEmpty(), trust.bytes), Pin.NONE)
            is Trust.EitherPin -> {
                if (trust.repo.isEmpty() || trust.project.isEmpty()) {
                    throw ConfigurationException("EitherPin requires both a repo and a project")
                }
                VerifierInputs(null, Pin(repo = trust.repo, project = trust.project))
            }
        }

        /**
         * [policy] as the verifier library takes it.
         *
         * @throws ConfigurationException for a freshness bound that is
         *   negative or has no count of nanoseconds.
         */
        @Throws(ConfigurationException::class)
        fun policy(policy: Policy): VerifierOptions.Policy = VerifierOptions.Policy(
            pinnedRegisters = policy.pinnedRegisters,
            freshnessMaxAgeNs = VerifierOptions.freshnessNanoseconds(policy.freshnessMaxAge),
            artifacts = when (val artifacts = policy.artifacts) {
                is ArtifactTrust.EndorsedArtifacts ->
                    // Tinfoil's keys are the library's default.
                    artifacts.freshnessKeys?.let(VerifierOptions.Artifacts::Endorsed)
                is ArtifactTrust.EmbeddedArtifacts ->
                    VerifierOptions.Artifacts.Embedded(artifacts.runtime, artifacts.platform, artifacts.freshnessKeys)
            },
        )

        private fun String?.nullIfEmpty(): String? = if (isNullOrEmpty()) null else this
    }
}
