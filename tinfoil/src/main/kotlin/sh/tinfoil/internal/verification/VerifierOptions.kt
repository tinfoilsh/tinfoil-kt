package sh.tinfoil.internal.verification

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import sh.tinfoil.ConfigAuthorizer
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Measurement
import java.util.Base64
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Encodes what a verifier trusts as the JSON that the verifier library
 * takes: a tagged config trust and a policy. The library checks the values
 * themselves; only what it could not tell from a default is checked here.
 */
internal object VerifierOptions {
    /**
     * Who vouches for a config, in place of Tinfoil's public registry, which
     * null selects.
     */
    sealed interface ConfigTrust {
        /** Exactly these registries. */
        class Registries(val ids: List<String>) : ConfigTrust

        /** Configs whose endorsements these PEM `PUBLIC KEY` blocks sign. */
        class SigningKeys(val keysPem: List<String>) : ConfigTrust

        /** Exactly this config, which the caller supplies. */
        class EmbeddedConfig(val name: String?, val bytes: ByteArray) : ConfigTrust

        /** Exactly the config with this digest, and the runtime that it pins. */
        class EmbeddedConfigReference(
            val name: String?,
            val digest: String,
            val runtimeRepo: String,
            val runtimeTag: String,
            val runtimeDigest: String,
        ) : ConfigTrust

        /** The configs that [authorizer] approves. */
        class Authorizer(val authorizer: ConfigAuthorizer) : ConfigTrust
    }

    /** Who vouches for the runtime and platform artifacts. */
    sealed interface Artifacts {
        /** Endorsed artifacts, approved by these PEM keys or, for null, Tinfoil's. */
        class Endorsed(val freshnessKeysPem: List<String>?) : Artifacts

        /** The caller's own artifacts, and keys for one that it leaves out. */
        class Embedded(
            val runtime: ByteArray?,
            val platform: ByteArray?,
            val freshnessKeysPem: List<String>?,
        ) : Artifacts
    }

    /** The checks that apply on top of the config trust. Null members keep their defaults. */
    class Policy(
        val pinnedRegisters: Measurement? = null,
        /** Whole nanoseconds, from [freshnessNanoseconds]; null keeps the default. */
        val freshnessMaxAgeNs: Long? = null,
        val artifacts: Artifacts? = null,
    )

    /**
     * The options JSON that the library's `newVerifier` takes, for [config]
     * and [policy]. A config authorizer is not encoded: it crosses as an
     * object, with [encodePolicy] alone.
     *
     * A present value is passed on as it is, so that an empty list or an
     * empty byte string reaches the library and is refused there rather
     * than read as a default.
     */
    fun encode(config: ConfigTrust?, policy: Policy): String {
        require(config !is ConfigTrust.Authorizer) { "a config authorizer is not encoded" }
        val options = Options(config?.let(::configTrustOption), policyOption(policy))
        return json.encodeToString(Options.serializer(), options)
    }

    /** The policy JSON that the library's `newVerifierWithConfigAuthorizer` takes. */
    fun encodePolicy(policy: Policy): String = json.encodeToString(PolicyOption.serializer(), policyOption(policy))

    /**
     * The age as the whole nanoseconds that the library takes, or null for
     * zero, which selects the default of seven days. An age that is
     * negative, or that has no such count, such as an infinite one or one
     * over about 292 years, is refused rather than clamped; so is a positive
     * age under half a nanosecond, which would round to zero and so select
     * the default.
     */
    @Throws(ConfigurationException::class)
    fun freshnessNanoseconds(age: Duration): Long? {
        if (age == Duration.ZERO) {
            return null
        }
        val nanoseconds = age.inWholeNanoseconds
        // inWholeNanoseconds clamps an age that is out of range, which the
        // round trip detects.
        if (!age.isFinite() || nanoseconds <= 0 || nanoseconds.nanoseconds != age) {
            throw ConfigurationException(
                "freshness maximum age must be zero, for the default, or positive, finite and at most about " +
                    "292 years, not $age",
            )
        }
        return nanoseconds
    }

    private fun configTrustOption(config: ConfigTrust): ConfigTrustOption = when (config) {
        is ConfigTrust.Registries -> ConfigTrustOption(type = "registries", ids = config.ids)
        is ConfigTrust.SigningKeys -> ConfigTrustOption(type = "signing_keys", keysPem = config.keysPem)
        is ConfigTrust.EmbeddedConfig ->
            ConfigTrustOption(type = "embedded_config", name = config.name, bytes = base64(config.bytes))
        is ConfigTrust.EmbeddedConfigReference -> ConfigTrustOption(
            type = "embedded_config_reference",
            name = config.name,
            digest = config.digest,
            runtime = RuntimeReferenceOption(config.runtimeRepo, config.runtimeTag, config.runtimeDigest),
        )
        is ConfigTrust.Authorizer -> error("a config authorizer is not encoded")
    }

    private fun policyOption(policy: Policy): PolicyOption = PolicyOption(
        pinnedRegisters = policy.pinnedRegisters?.let { MeasurementOption(it.type, it.registers) },
        freshnessMaxAgeNs = policy.freshnessMaxAgeNs,
        artifacts = when (val artifacts = policy.artifacts) {
            null -> null
            is Artifacts.Endorsed -> ArtifactsOption(type = "endorsed", freshnessKeysPem = artifacts.freshnessKeysPem)
            is Artifacts.Embedded -> ArtifactsOption(
                type = "embedded",
                runtime = artifacts.runtime?.let(::base64),
                platform = artifacts.platform?.let(::base64),
                freshnessKeysPem = artifacts.freshnessKeysPem,
            )
        },
    )

    /** Standard base64 with padding, which is what the library reads. */
    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    // Members that are null are left out: a member equal to its default is
    // not encoded.
    private val json = Json { encodeDefaults = false }

    @Serializable
    private class Options(
        @SerialName("config_trust") val configTrust: ConfigTrustOption? = null,
        val policy: PolicyOption? = null,
    )

    @Serializable
    private class ConfigTrustOption(
        val type: String,
        val ids: List<String>? = null,
        @SerialName("keys_pem") val keysPem: List<String>? = null,
        val name: String? = null,
        val bytes: String? = null,
        val digest: String? = null,
        val runtime: RuntimeReferenceOption? = null,
    )

    @Serializable
    private class RuntimeReferenceOption(val repo: String, val tag: String, val digest: String)

    @Serializable
    private class PolicyOption(
        @SerialName("pinned_registers") val pinnedRegisters: MeasurementOption? = null,
        @SerialName("freshness_max_age_ns") val freshnessMaxAgeNs: Long? = null,
        val artifacts: ArtifactsOption? = null,
    )

    @Serializable
    private class MeasurementOption(val type: String, val registers: List<String>)

    @Serializable
    private class ArtifactsOption(
        val type: String,
        val runtime: String? = null,
        val platform: String? = null,
        @SerialName("freshness_keys_pem") val freshnessKeysPem: List<String>? = null,
    )
}
