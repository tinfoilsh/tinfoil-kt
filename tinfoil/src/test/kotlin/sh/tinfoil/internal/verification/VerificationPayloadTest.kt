package sh.tinfoil.internal.verification

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import sh.tinfoil.ArtifactVerification
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigVerification
import sh.tinfoil.CryptoMaterial
import sh.tinfoil.Measurement
import sh.tinfoil.ReferenceSource
import sh.tinfoil.Verification
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Pins this SDK's side of the payload in which the verifier library reports a verification. */
class VerificationPayloadTest {
    private val tdx = "https://tinfoil.sh/predicate/tdx-guest/v2"

    /** A code-release verification, with [changes] applied; a null change removes the member. */
    private fun payload(changes: Map<String, JsonElement?> = emptyMap()): String {
        val fields = buildJsonObject {
            put("schema_version", 1)
            put("config_repo", "tinfoilsh/confidential-model-router")
            put("code_digest", "abc123")
            put("code_tag", "v1.2.3")
            putJsonObject("code_measurement") {
                put("type", tdx)
                putJsonArray("registers") { listOf("", "", "bb", "cc", "").forEach { add(JsonPrimitive(it)) } }
            }
            putJsonObject("enclave_measurement") {
                put("type", tdx)
                putJsonArray("registers") { listOf("dd", "ee").forEach { add(JsonPrimitive(it)) } }
            }
            put("tls_public_key_fp", "deadbeef")
            put("hpke_public_key", "cafebabe")
            putJsonArray("crypto_material") {
                add(material("tls", "https://tinfoil.sh/key/spki-fp-sha256/v1", "deadbeef"))
                add(material("hpke", "https://tinfoil.sh/key/x25519-hpke/v1", "cafebabe"))
            }
            put("freshness_expires_at", "2026-10-03T12:00:00.5Z")
            put("verified_at", "2026-09-26T12:00:00Z")
        }.toMutableMap()
        for ((member, value) in changes) {
            if (value == null) fields.remove(member) else fields[member] = value
        }
        return JsonObject(fields).toString()
    }

    private fun material(id: String, format: String, data: String): JsonObject = buildJsonObject {
        put("id", id)
        put("format", format)
        put("data", data)
    }

    private fun obj(vararg members: Pair<String, String>): JsonObject =
        JsonObject(members.associate { (name, value) -> name to JsonPrimitive(value) })

    private fun decode(vararg changes: Pair<String, JsonElement?>): Verification =
        VerificationPayload.decode(payload(mapOf(*changes)))

    private fun assertRejected(expected: String, vararg changes: Pair<String, JsonElement?>): AttestationException =
        assertRejectedPayload(expected, payload(mapOf(*changes)))

    private fun assertRejectedPayload(expected: String, payload: String): AttestationException {
        val error = assertFailsWith<AttestationException> { VerificationPayload.decode(payload) }
        assertTrue(error.detail.contains(expected), "${error.detail} should mention $expected")
        assertNull(error.layer, "A payload that cannot be read was rejected by no layer of the verifier.")
        return error
    }

    @Test
    fun decodesACodeReleaseVerification() {
        val verification = decode()

        assertEquals("tinfoilsh/confidential-model-router", verification.configRepo)
        assertEquals("abc123", verification.codeDigest)
        assertEquals("v1.2.3", verification.codeTag)
        assertEquals(Measurement(tdx, listOf("", "", "bb", "cc", "")), verification.codeMeasurement)
        assertEquals(Measurement(tdx, listOf("dd", "ee")), verification.enclaveMeasurement)
        assertEquals("deadbeef", verification.tlsPublicKeyFingerprint)
        assertEquals("cafebabe", verification.hpkePublicKey)
        assertEquals(
            listOf(
                CryptoMaterial("tls", "https://tinfoil.sh/key/spki-fp-sha256/v1", "deadbeef"),
                CryptoMaterial("hpke", "https://tinfoil.sh/key/x25519-hpke/v1", "cafebabe"),
            ),
            verification.cryptoMaterial,
        )
        assertEquals(Instant.ofEpochSecond(1_791_028_800, 500_000_000), verification.freshnessExpiresAt)
        assertEquals(Instant.ofEpochSecond(1_790_424_000), verification.metadata.verifiedAt)
        assertEquals("tinfoil-kt", verification.metadata.verifier.name)
        assertTrue(verification.metadata.verifier.version.isNotEmpty())
        assertNull(verification.config, "A code-release verification has no config.")
        assertNull(verification.runtime)
        assertNull(verification.platform)
    }

    @Test
    fun absentMembersDecodeAsNull() {
        val verification = decode(
            "code_tag" to null,
            "code_measurement" to null,
            "enclave_measurement" to null,
            "hpke_public_key" to null,
        )
        assertNull(verification.codeTag)
        assertNull(verification.codeMeasurement)
        assertNull(verification.enclaveMeasurement)
        assertNull(verification.hpkePublicKey, "An enclave that endorses only a TLS key has no HPKE key.")
    }

    @Test
    fun emptyAndNullMembersDecodeAsNull() {
        val empty = decode(
            "config_repo" to JsonPrimitive(""),
            "code_tag" to JsonPrimitive(""),
            "tls_public_key_fp" to JsonPrimitive(""),
            "hpke_public_key" to JsonPrimitive(""),
        )
        assertNull(empty.configRepo)
        assertNull(empty.codeTag)
        assertNull(empty.tlsPublicKeyFingerprint)
        assertNull(empty.hpkePublicKey)

        val nulls = decode(
            "code_tag" to JsonNull,
            "code_measurement" to JsonNull,
            "hpke_public_key" to JsonNull,
            "config" to JsonNull,
        )
        assertNull(nulls.codeTag)
        assertNull(nulls.codeMeasurement)
        assertNull(nulls.hpkePublicKey)
        assertNull(nulls.config)
    }

    @Test
    fun decodesConfigFacts() {
        val verification = decode(
            "config" to obj(
                "source" to "endorsement", "name" to "/org/project/v1", "digest" to "c0",
                "reference" to "sha256:c0", "signing_key_hint" to "hint",
                "approval_time" to "2026-09-20T08:00:00Z", "registry_id" to "registry",
                "signature_time" to "2026-09-20T08:01:00.5Z",
            ),
            "runtime" to obj(
                "source" to "endorsement", "repo" to "tinfoilsh/cvmimage", "tag" to "v0.15.0",
                "digest" to "r0", "name" to "runtime", "commit" to "abc",
                "approval_time" to "2026-09-20T08:00:00Z",
            ),
            "platform" to obj("source" to "embedded", "digest" to "p0"),
        )
        val approved = Instant.ofEpochSecond(1_789_891_200)
        assertEquals(
            ConfigVerification(
                source = ReferenceSource.ENDORSEMENT, name = "/org/project/v1", digest = "c0",
                reference = "sha256:c0", signingKeyHint = "hint", approvalTime = approved,
                registryId = "registry", signatureTime = approved.plusMillis(60_500),
            ),
            verification.config,
        )
        assertEquals(
            ArtifactVerification(
                source = ReferenceSource.ENDORSEMENT, repo = "tinfoilsh/cvmimage", tag = "v0.15.0",
                digest = "r0", name = "runtime", commit = "abc", approvalTime = approved,
            ),
            verification.runtime,
        )
        assertEquals(
            ArtifactVerification(
                source = ReferenceSource.EMBEDDED, repo = null, tag = null, digest = "p0",
                name = null, commit = null, approvalTime = null,
            ),
            verification.platform,
            "Facts that an embedded platform lacks are null.",
        )
    }

    @Test
    fun aConfigThatAnAuthorizerApprovedHasOnlyItsDigest() {
        val verification = decode("config" to obj("source" to "policy", "digest" to "c0"))
        assertEquals(
            ConfigVerification(
                source = ReferenceSource.POLICY, name = null, digest = "c0", reference = null,
                signingKeyHint = null, approvalTime = null, registryId = null, signatureTime = null,
            ),
            verification.config,
        )
    }

    @Test
    fun emptyConfigFactsDecodeAsNull() {
        val verification = decode(
            "config" to obj(
                "source" to "embedded", "name" to "", "digest" to "c0", "reference" to "",
                "signing_key_hint" to "", "approval_time" to "", "registry_id" to "", "signature_time" to "",
            ),
            "runtime" to obj(
                "source" to "embedded", "repo" to "", "tag" to "", "digest" to "r0", "name" to "",
                "commit" to "", "approval_time" to "",
            ),
        )
        assertEquals(
            ConfigVerification(ReferenceSource.EMBEDDED, null, "c0", null, null, null, null, null),
            verification.config,
        )
        assertEquals(
            ArtifactVerification(ReferenceSource.EMBEDDED, null, null, "r0", null, null, null),
            verification.runtime,
        )
    }

    @Test
    fun aSourceThisSdkDoesNotNameIsCarried() {
        val verification = decode("config" to obj("source" to "witness", "digest" to "c0"))
        assertEquals(ReferenceSource("witness"), verification.config?.source)
    }

    @Test
    fun membersThisSdkDoesNotReadAreIgnored() {
        val verification = decode(
            "verifier" to obj("name" to "another", "version" to "devel"),
            "config" to obj("source" to "policy", "digest" to "c0", "later_addition" to "x"),
        )
        assertEquals("tinfoil-kt", verification.metadata.verifier.name, "The SDK records itself as the verifier.")
        assertEquals("c0", verification.config?.digest)
    }

    @Test
    fun timesWithAndWithoutAFractionOfASecond() {
        val cases = mapOf(
            "2026-10-03T12:00:00Z" to Instant.ofEpochSecond(1_791_028_800),
            "2026-10-03T12:00:00.5Z" to Instant.ofEpochSecond(1_791_028_800, 500_000_000),
            "2026-10-03T12:00:00.123456789Z" to Instant.ofEpochSecond(1_791_028_800, 123_456_789),
        )
        for ((value, expected) in cases) {
            assertEquals(expected, decode("freshness_expires_at" to JsonPrimitive(value)).freshnessExpiresAt, value)
        }
    }

    @Test
    fun rejectsAnotherSchemaVersion() {
        assertRejectedPayload("unsupported verification schema version 2", """{"schema_version":2}""")
        assertRejected("unsupported verification schema version 0", "schema_version" to JsonPrimitive(0))
        // The version is read first, so a later schema is reported as such
        // even when it is otherwise readable.
        assertRejected("unsupported verification schema version 3", "schema_version" to JsonPrimitive(3))
    }

    @Test
    fun rejectsAPayloadWithoutAUsableSchemaVersion() {
        assertRejected("unreadable verification payload", "schema_version" to null)
        assertRejected("unreadable verification payload", "schema_version" to JsonNull)
        assertRejected("unreadable verification payload", "schema_version" to JsonPrimitive("one"))
        assertRejected("unreadable verification payload", "schema_version" to JsonPrimitive(1.5))
    }

    @Test
    fun rejectsAMissingRequiredMember() {
        for (member in listOf(
            "config_repo", "code_digest", "tls_public_key_fp", "crypto_material", "freshness_expires_at", "verified_at",
        )) {
            assertRejected("unreadable verification payload", member to null)
            assertRejected("unreadable verification payload", member to JsonNull)
        }
        assertRejected("unreadable verification payload", "config" to obj("source" to "policy"))
        assertRejected("unreadable verification payload", "runtime" to obj("digest" to "r0"))
        assertRejected(
            "unreadable verification payload",
            "crypto_material" to buildJsonArray { add(obj("id" to "tls", "format" to "f")) },
        )
        assertRejected("unreadable verification payload", "code_measurement" to obj("type" to tdx))
    }

    @Test
    fun rejectsAMemberOfTheWrongType() {
        assertRejected("unreadable verification payload", "code_digest" to JsonPrimitive(7))
        assertRejected("unreadable verification payload", "code_digest" to JsonPrimitive(true))
        assertRejected("unreadable verification payload", "crypto_material" to JsonPrimitive("tls"))
        assertRejected("unreadable verification payload", "config" to JsonPrimitive("policy"))
        assertRejected("unreadable verification payload", "freshness_expires_at" to JsonPrimitive(1_791_028_800))
    }

    @Test
    fun rejectsAnEmptyFactThatEveryVerificationHas() {
        assertRejected("empty code_digest", "code_digest" to JsonPrimitive(""))
        assertRejected("empty config.digest", "config" to obj("source" to "policy", "digest" to ""))
        assertRejected("empty config.source", "config" to obj("source" to "", "digest" to "c0"))
        assertRejected("empty runtime.digest", "runtime" to obj("source" to "embedded", "digest" to ""))
        assertRejected("empty platform.source", "platform" to obj("source" to "", "digest" to "p0"))
    }

    @Test
    fun rejectsAnInvalidTime() {
        assertRejected("freshness_expires_at", "freshness_expires_at" to JsonPrimitive("next week"))
        assertRejected("freshness_expires_at", "freshness_expires_at" to JsonPrimitive(""))
        assertRejected("verified_at", "verified_at" to JsonPrimitive("2026-09-26"))
        assertRejected(
            "config.approval_time",
            "config" to obj("source" to "endorsement", "digest" to "c0", "approval_time" to "yesterday"),
        )
        assertRejected(
            "config.signature_time",
            "config" to obj("source" to "endorsement", "digest" to "c0", "signature_time" to "yesterday"),
        )
        assertRejected(
            "runtime.approval_time",
            "runtime" to obj("source" to "endorsement", "digest" to "r0", "approval_time" to "yesterday"),
        )
        assertRejected(
            "platform.approval_time",
            "platform" to obj("source" to "endorsement", "digest" to "p0", "approval_time" to "yesterday"),
        )
    }

    @Test
    fun rejectsWhatIsNotAJsonObject() {
        for (malformed in listOf("", " ", "null", "[]", "1", "\"schema_version\"", "{", """{"schema_version":1""", "not json")) {
            assertRejectedPayload("unreadable verification payload", malformed)
        }
    }

    @Test
    fun verificationsCompareByValue() {
        val one = decode()
        assertEquals(one, decode())
        assertEquals(one.hashCode(), decode().hashCode())
        assertNotEquals(one, decode("code_digest" to JsonPrimitive("other")))
        assertNotEquals(one, decode("hpke_public_key" to null))
        assertNotEquals(one, decode("freshness_expires_at" to JsonPrimitive("2026-10-03T12:00:01Z")))
        assertNotEquals(one, decode("crypto_material" to buildJsonArray { }))
        assertNotEquals(one, decode("config" to obj("source" to "policy", "digest" to "c0")))
        assertTrue(one.toString().contains("codeDigest=abc123"), one.toString())
    }

    @Test
    fun theCryptoMaterialCannotBeChanged() {
        val verification = decode()
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (verification.cryptoMaterial as MutableList<CryptoMaterial>).clear()
        }
        assertFalse(verification.cryptoMaterial.isEmpty())
    }
}
