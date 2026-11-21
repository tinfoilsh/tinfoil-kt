package sh.tinfoil.internal.verification

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import sh.tinfoil.ConfigAuthorizer
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Measurement
import sh.tinfoil.internal.verification.VerifierOptions.Artifacts
import sh.tinfoil.internal.verification.VerifierOptions.ConfigTrust
import sh.tinfoil.internal.verification.VerifierOptions.Policy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

class VerifierOptionsTest {
    private fun parse(options: String): JsonObject = Json.parseToJsonElement(options).jsonObject

    private fun json(text: String): JsonObject = parse(text)

    @Test
    fun theDefaultsHaveNoMembers() {
        assertEquals(json("""{"policy":{}}"""), parse(VerifierOptions.encode(null, Policy())))
        assertEquals("{}", VerifierOptions.encodePolicy(Policy()))
    }

    @Test
    fun encodesAPolicy() {
        val policy = Policy(
            pinnedRegisters = Measurement("https://tinfoil.sh/predicate/tdx-guest/v2", listOf("", "", "", "", "ab")),
            freshnessMaxAgeNs = 3_600_000_000_000,
            artifacts = Artifacts.Embedded(byteArrayOf(0xfb.toByte(), 0xff.toByte()), null, listOf("freshness key")),
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
                  "artifacts": {"type": "embedded", "runtime": "+/8=", "freshness_keys_pem": ["freshness key"]}
                }
                """,
            ),
            parse(VerifierOptions.encodePolicy(policy)),
        )
        assertEquals(
            json("""{"policy":{"artifacts":{"type":"endorsed","freshness_keys_pem":["k"]}}}"""),
            parse(VerifierOptions.encode(null, Policy(artifacts = Artifacts.Endorsed(listOf("k"))))),
        )
        assertEquals(
            json("""{"artifacts":{"type":"endorsed"}}"""),
            parse(VerifierOptions.encodePolicy(Policy(artifacts = Artifacts.Endorsed(null)))),
        )
        assertEquals(
            json("""{"artifacts":{"type":"embedded","platform":"AQ=="}}"""),
            parse(VerifierOptions.encodePolicy(Policy(artifacts = Artifacts.Embedded(null, byteArrayOf(1), null)))),
        )
    }

    @Test
    fun encodesEachConfigTrust() {
        assertEquals(
            json("""{"config_trust":{"type":"registries","ids":["a","b"]},"policy":{}}"""),
            parse(VerifierOptions.encode(ConfigTrust.Registries(listOf("a", "b")), Policy())),
        )
        assertEquals(
            json("""{"config_trust":{"type":"signing_keys","keys_pem":["k"]},"policy":{}}"""),
            parse(VerifierOptions.encode(ConfigTrust.SigningKeys(listOf("k")), Policy())),
        )
        assertEquals(
            json("""{"config_trust":{"type":"embedded_config","name":"/org/project/v1","bytes":"AAEC"},"policy":{}}"""),
            parse(VerifierOptions.encode(ConfigTrust.EmbeddedConfig("/org/project/v1", byteArrayOf(0, 1, 2)), Policy())),
        )
        assertEquals(
            json("""{"config_trust":{"type":"embedded_config","bytes":"AQ=="},"policy":{}}"""),
            parse(VerifierOptions.encode(ConfigTrust.EmbeddedConfig(null, byteArrayOf(1)), Policy())),
        )
    }

    @Test
    fun aConfigAuthorizerIsNotEncoded() {
        assertFailsWith<IllegalArgumentException> {
            VerifierOptions.encode(ConfigTrust.Authorizer(ConfigAuthorizer { }), Policy())
        }
    }

    /** What is empty is passed on, so that the library refuses it instead of keeping a default. */
    @Test
    fun emptyValuesReachTheLibrary() {
        assertEquals(
            json("""{"config_trust":{"type":"registries","ids":[]},"policy":{}}"""),
            parse(VerifierOptions.encode(ConfigTrust.Registries(emptyList()), Policy())),
        )
        assertEquals(
            json("""{"config_trust":{"type":"signing_keys","keys_pem":[]},"policy":{}}"""),
            parse(VerifierOptions.encode(ConfigTrust.SigningKeys(emptyList()), Policy())),
        )
        assertEquals(
            json("""{"artifacts":{"type":"endorsed","freshness_keys_pem":[]}}"""),
            parse(VerifierOptions.encodePolicy(Policy(artifacts = Artifacts.Endorsed(emptyList())))),
        )
        assertEquals(
            json("""{"artifacts":{"type":"embedded","runtime":"","platform":""}}"""),
            parse(VerifierOptions.encodePolicy(Policy(artifacts = Artifacts.Embedded(ByteArray(0), ByteArray(0), null)))),
        )
    }

    @Test
    fun stringsAreEscaped() {
        val key = "-----BEGIN PUBLIC KEY-----\nab\"c\\d\n-----END PUBLIC KEY-----\n"
        val decoded = parse(VerifierOptions.encode(ConfigTrust.SigningKeys(listOf(key)), Policy()))
        assertEquals(
            json(
                """{"config_trust":{"type":"signing_keys","keys_pem":["-----BEGIN PUBLIC KEY-----\nab\"c\\d\n-----END PUBLIC KEY-----\n"]},"policy":{}}""",
            ),
            decoded,
        )
    }

    @Test
    fun anAgeCrossesAsWholeNanoseconds() {
        assertNull(VerifierOptions.freshnessNanoseconds(Duration.ZERO))
        assertEquals(1L, VerifierOptions.freshnessNanoseconds(1.nanoseconds))
        assertEquals(1_500_000L, VerifierOptions.freshnessNanoseconds(1.5.milliseconds))
        assertEquals(7 * 24 * 3600 * 1_000_000_000L, VerifierOptions.freshnessNanoseconds(7.days))
        // Beyond about 146 years a duration is kept in milliseconds, and
        // still has an exact count of nanoseconds up to about 292 years.
        assertEquals(200L * 365 * 24 * 3600 * 1_000_000_000L, VerifierOptions.freshnessNanoseconds((200 * 365).days))
        assertEquals(
            json("""{"freshness_max_age_ns":1}"""),
            parse(VerifierOptions.encodePolicy(Policy(freshnessMaxAgeNs = 1))),
        )
    }

    @Test
    fun anAgeThatIsNegativeOrHasNoCountOfNanosecondsIsRefused() {
        val refused = listOf(
            (-1).nanoseconds,
            (-1).seconds,
            Duration.INFINITE,
            -Duration.INFINITE,
            (300 * 365).days,
            1e300.seconds,
            Long.MAX_VALUE.milliseconds,
        )
        for (age in refused) {
            val error = assertFailsWith<ConfigurationException>(age.toString()) {
                VerifierOptions.freshnessNanoseconds(age)
            }
            assertTrue(error.detail.contains("freshness maximum age"), error.detail)
        }
    }
}
