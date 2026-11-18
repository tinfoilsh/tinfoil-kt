package sh.tinfoil.internal.verification

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EmbeddedConfig
import sh.tinfoil.EmbeddedReferences
import sh.tinfoil.Measurement
import java.util.Base64
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Encodes a trust policy as the options JSON that the verifier library
 * takes. The library checks the options themselves; only what it could not
 * tell from a default is checked here.
 */
internal object VerifierOptions {
    /**
     * The options JSON for a policy. A null option is left out, which keeps
     * its default; a present one is passed on as it is, so that an empty list
     * or an empty byte string reaches the library and is refused there.
     */
    @Throws(ConfigurationException::class)
    fun encode(
        pinnedRegisters: Measurement? = null,
        freshnessMaxAge: Duration? = null,
        configRegistryIds: List<String>? = null,
        configSigningKeysPem: List<String>? = null,
        freshnessSigningKeysPem: List<String>? = null,
        embeddedReferences: EmbeddedReferences? = null,
    ): String {
        // The library reads options without any embedded component as "no
        // embedded references", so an empty set would silently keep the
        // defaults.
        if (embeddedReferences != null && embeddedReferences.config == null &&
            embeddedReferences.runtime == null && embeddedReferences.platform == null
        ) {
            throw ConfigurationException("embedded references must contain at least one component")
        }
        val options = Options(
            pinnedRegisters = pinnedRegisters?.let { MeasurementOption(it.type, it.registers) },
            freshnessMaxAgeNs = freshnessMaxAge?.let(::freshnessNanoseconds),
            configRegistryIds = configRegistryIds,
            configSigningKeysPem = configSigningKeysPem,
            freshnessSigningKeysPem = freshnessSigningKeysPem,
            embeddedConfig = embeddedReferences?.config?.let(::embeddedConfigOption),
            embeddedRuntime = embeddedReferences?.runtime?.let(::base64),
            embeddedPlatform = embeddedReferences?.platform?.let(::base64),
        )
        return json.encodeToString(Options.serializer(), options)
    }

    /**
     * The age as the whole nanoseconds that the library takes. The library
     * reads zero as "keep the default", so an age that is not positive would
     * silently select the default of seven days, and null is the way to ask
     * for that. An age with no such count, such as an infinite one or one
     * over about 292 years, is refused rather than clamped.
     */
    @Throws(ConfigurationException::class)
    fun freshnessNanoseconds(age: Duration): Long {
        val nanoseconds = age.inWholeNanoseconds
        // inWholeNanoseconds clamps an age that is out of range, which the
        // round trip detects.
        if (!age.isFinite() || nanoseconds <= 0 || nanoseconds.nanoseconds != age) {
            throw ConfigurationException(
                "freshness maximum age must be positive, finite and at most about 292 years, not $age",
            )
        }
        return nanoseconds
    }

    private fun embeddedConfigOption(config: EmbeddedConfig): EmbeddedConfigOption = when (config) {
        is EmbeddedConfig.Bytes -> EmbeddedConfigOption(name = config.name, bytes = base64(config.bytes))
        is EmbeddedConfig.Reference -> EmbeddedConfigOption(
            name = config.name,
            digest = config.digest,
            runtime = RuntimeReferenceOption(config.runtime.repo, config.runtime.tag, config.runtime.digest),
        )
    }

    /** Standard base64 with padding, which is what the library reads. */
    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    // Members that are null are left out: a member equal to its default is
    // not encoded.
    private val json = Json { encodeDefaults = false }

    @Serializable
    private class Options(
        @SerialName("pinned_registers") val pinnedRegisters: MeasurementOption? = null,
        @SerialName("freshness_max_age_ns") val freshnessMaxAgeNs: Long? = null,
        @SerialName("config_registry_ids") val configRegistryIds: List<String>? = null,
        @SerialName("config_signing_keys_pem") val configSigningKeysPem: List<String>? = null,
        @SerialName("freshness_signing_keys_pem") val freshnessSigningKeysPem: List<String>? = null,
        @SerialName("embedded_config") val embeddedConfig: EmbeddedConfigOption? = null,
        @SerialName("embedded_runtime") val embeddedRuntime: String? = null,
        @SerialName("embedded_platform") val embeddedPlatform: String? = null,
    )

    @Serializable
    private class MeasurementOption(val type: String, val registers: List<String>)

    @Serializable
    private class EmbeddedConfigOption(
        val name: String? = null,
        val bytes: String? = null,
        val digest: String? = null,
        val runtime: RuntimeReferenceOption? = null,
    )

    @Serializable
    private class RuntimeReferenceOption(val repo: String, val tag: String, val digest: String)
}
