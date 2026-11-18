package sh.tinfoil.internal.verification

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EmbeddedConfig
import sh.tinfoil.EmbeddedReferences
import sh.tinfoil.Measurement
import sh.tinfoil.RuntimeReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

class VerifierOptionsTest {
    private fun parse(options: String): JsonObject = Json.parseToJsonElement(options).jsonObject

    private fun json(text: String): JsonObject = parse(text)

    @Test
    fun theDefaultPolicyHasNoMembers() {
        assertEquals("{}", VerifierOptions.encode())
    }

    @Test
    fun encodesEveryOption() {
        val options = VerifierOptions.encode(
            pinnedRegisters = Measurement("https://tinfoil.sh/predicate/tdx-guest/v2", listOf("", "", "", "", "ab")),
            freshnessMaxAge = 1.hours,
            configRegistryIds = listOf("https://registry.example/scopes/a", "https://registry.example/scopes/b"),
            configSigningKeysPem = listOf("config key"),
            freshnessSigningKeysPem = listOf("freshness key"),
            embeddedReferences = EmbeddedReferences(
                config = EmbeddedConfig.Bytes(byteArrayOf(0, 1, 2), name = "/org/project/v1"),
                runtime = byteArrayOf(0xfb.toByte(), 0xff.toByte()),
                platform = byteArrayOf(1),
            ),
        )
        assertEquals(
            json(
                """
                {
                  "pinned_registers": {
                    "type": "https://tinfoil.sh/predicate/tdx-guest/v2",
                    "registers": ["", "", "", "", "ab"]
                  },
                  "freshness_max_age_ns": 3600000000000,
                  "config_registry_ids": ["https://registry.example/scopes/a", "https://registry.example/scopes/b"],
                  "config_signing_keys_pem": ["config key"],
                  "freshness_signing_keys_pem": ["freshness key"],
                  "embedded_config": {"name": "/org/project/v1", "bytes": "AAEC"},
                  "embedded_runtime": "+/8=",
                  "embedded_platform": "AQ=="
                }
                """,
            ),
            parse(options),
        )
    }

    @Test
    fun encodesAnEmbeddedConfigReference() {
        val reference = EmbeddedConfig.Reference(
            digest = "c0",
            runtime = RuntimeReference("tinfoilsh/cvmimage", "v0.15.0", "r0"),
        )
        assertEquals(
            json("""{"embedded_config":{"digest":"c0","runtime":{"repo":"tinfoilsh/cvmimage","tag":"v0.15.0","digest":"r0"}}}"""),
            parse(VerifierOptions.encode(embeddedReferences = EmbeddedReferences(config = reference))),
        )
        val named = EmbeddedConfig.Reference("c0", RuntimeReference("tinfoilsh/cvmimage", "v0.15.0", "r0"), "/org/project/v1")
        assertEquals(
            JsonPrimitive("/org/project/v1"),
            parse(VerifierOptions.encode(embeddedReferences = EmbeddedReferences(config = named)))
                .getValue("embedded_config").jsonObject["name"],
        )
    }

    @Test
    fun anEmptyNameIsLeftOut() {
        val options = VerifierOptions.encode(
            embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Bytes(byteArrayOf(1), name = "")),
        )
        assertEquals(json("""{"embedded_config":{"bytes":"AQ=="}}"""), parse(options))
    }

    /** What is empty is passed on, so that the library refuses it instead of keeping a default. */
    @Test
    fun emptyValuesReachTheLibrary() {
        assertEquals(json("""{"config_registry_ids":[]}"""), parse(VerifierOptions.encode(configRegistryIds = emptyList())))
        assertEquals(
            json("""{"config_signing_keys_pem":[]}"""),
            parse(VerifierOptions.encode(configSigningKeysPem = emptyList())),
        )
        assertEquals(
            json("""{"freshness_signing_keys_pem":[]}"""),
            parse(VerifierOptions.encode(freshnessSigningKeysPem = emptyList())),
        )
        assertEquals(
            json("""{"embedded_config":{"bytes":""},"embedded_runtime":"","embedded_platform":""}"""),
            parse(
                VerifierOptions.encode(
                    embeddedReferences = EmbeddedReferences(EmbeddedConfig.Bytes(ByteArray(0)), ByteArray(0), ByteArray(0)),
                ),
            ),
        )
    }

    @Test
    fun embeddedReferencesWithoutAComponentAreRefused() {
        val error = assertFailsWith<ConfigurationException> {
            VerifierOptions.encode(embeddedReferences = EmbeddedReferences())
        }
        assertTrue(error.detail.contains("at least one component"), error.detail)
    }

    @Test
    fun stringsAreEscaped() {
        val key = "-----BEGIN PUBLIC KEY-----\nab\"c\\d\n-----END PUBLIC KEY-----\n"
        val decoded = parse(VerifierOptions.encode(configSigningKeysPem = listOf(key)))
        assertEquals(json("""{"config_signing_keys_pem":["-----BEGIN PUBLIC KEY-----\nab\"c\\d\n-----END PUBLIC KEY-----\n"]}"""), decoded)
    }

    @Test
    fun anAgeCrossesAsWholeNanoseconds() {
        assertEquals(1L, VerifierOptions.freshnessNanoseconds(1.nanoseconds))
        assertEquals(1_500_000L, VerifierOptions.freshnessNanoseconds(1.5.milliseconds))
        assertEquals(7 * 24 * 3600 * 1_000_000_000L, VerifierOptions.freshnessNanoseconds(7.days))
        // Beyond about 146 years a duration is kept in milliseconds, and
        // still has an exact count of nanoseconds up to about 292 years.
        assertEquals(200L * 365 * 24 * 3600 * 1_000_000_000L, VerifierOptions.freshnessNanoseconds((200 * 365).days))
        assertEquals(json("""{"freshness_max_age_ns":1}"""), parse(VerifierOptions.encode(freshnessMaxAge = 1.nanoseconds)))
    }

    @Test
    fun anAgeThatIsNotPositiveOrHasNoCountOfNanosecondsIsRefused() {
        val refused = listOf(
            Duration.ZERO,
            // A positive age under half a nanosecond rounds to zero, which
            // would otherwise select the default.
            0.4.nanoseconds,
            1e-10.seconds,
            (-1).nanoseconds,
            (-1).seconds,
            (-0.4).nanoseconds,
            Duration.INFINITE,
            -Duration.INFINITE,
            (300 * 365).days,
            1e300.seconds,
            Long.MAX_VALUE.milliseconds,
        )
        for (age in refused) {
            val error = assertFailsWith<ConfigurationException>(age.toString()) {
                VerifierOptions.encode(freshnessMaxAge = age)
            }
            assertTrue(error.detail.contains("freshness maximum age"), error.detail)
        }
    }
}
