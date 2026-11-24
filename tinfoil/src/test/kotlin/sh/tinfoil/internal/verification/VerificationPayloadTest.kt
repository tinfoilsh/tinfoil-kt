package sh.tinfoil.internal.verification

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import sh.tinfoil.ArtifactVerification
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigVerification
import sh.tinfoil.CpuEvidence
import sh.tinfoil.CryptoMaterial
import sh.tinfoil.ExpectedFacts
import sh.tinfoil.MeasuredFacts
import sh.tinfoil.Measurement
import sh.tinfoil.PartialFacts
import sh.tinfoil.ReferenceSource
import sh.tinfoil.Step
import sh.tinfoil.StepStatus
import sh.tinfoil.VerificationException
import sh.tinfoil.VerificationLayer
import sh.tinfoil.VerificationReport
import sh.tinfoil.VerifiedFacts
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Pins this SDK's side of the result JSON in which the verifier library reports a verification. */
class VerificationPayloadTest {
    private val tdx = "https://tinfoil.sh/predicate/tdx-guest/v2"
    private val snp = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
    private val tlsFormat = "https://tinfoil.sh/key/spki-fp-sha256/v1"
    private val hpkeFormat = "https://tinfoil.sh/key/x25519-hpke/v1"

    /** A 48-byte register, every byte [byte]. */
    private fun register(byte: Int): String = "%02x".format(byte).repeat(48)

    private val digest = "ab".repeat(32)
    private val tlsKey = "aa".repeat(32)
    private val hpkeKey = "bb".repeat(32)

    private fun steps(vararg statuses: String): JsonElement = buildJsonArray {
        listOf("envelope", "provenance", "quote", "policy").zip(statuses).forEach { (layer, status) ->
            add(obj("layer" to layer, "status" to status))
        }
    }

    private val passedSteps = steps("passed", "passed", "passed", "passed")

    private fun tdxMeasurement(vararg registers: Pair<String, String>): JsonObject =
        obj("platform" to "tdx", *registers)

    private val fullTdx = tdxMeasurement(
        "mrtd" to register(1), "rtmr0" to register(2), "rtmr1" to register(3), "rtmr2" to register(4), "rtmr3" to register(5),
    )

    /**
     * The result of a code-release verification that passed, with
     * [changes] applied to its verified facts; a null change removes the
     * member. The changes `schema_version`, `report_schema_version`,
     * `steps`, `partial_facts`, `error`, `verified_at` and `metadata_verifier`
     * apply to the result, the report and its metadata instead.
     */
    private fun payload(changes: Map<String, JsonElement?> = emptyMap()): String {
        val outer = setOf(
            "schema_version", "report_schema_version", "steps", "verified_facts", "partial_facts", "error",
            "verified_at", "metadata_verifier",
        )
        val facts = buildJsonObject {
            put("config_repo", "tinfoilsh/confidential-model-router")
            put("code_digest", digest)
            put("code_tag", "v1.2.3")
            put("code_measurement", tdxMeasurement("rtmr1" to register(3), "rtmr2" to register(4)))
            put("enclave_measurement", fullTdx)
            putJsonArray("crypto_material") {
                add(material("tls", tlsFormat, tlsKey))
                add(material("hpke", hpkeFormat, hpkeKey))
            }
            put("freshness_expires_at", "2026-10-03T12:00:00.5Z")
        }.toMutableMap()
        for ((member, value) in changes) {
            if (member in outer) continue
            if (value == null) facts.remove(member) else facts[member] = value
        }
        val metadata = mutableMapOf<String, JsonElement>("verified_at" to JsonPrimitive("2026-09-26T12:00:00Z"))
        val report = mutableMapOf(
            "schema_version" to JsonPrimitive(1),
            "steps" to passedSteps,
            "verified_facts" to JsonObject(facts),
        )
        val result = mutableMapOf<String, JsonElement>("schema_version" to JsonPrimitive(3))
        for ((member, value) in changes) {
            val (target, name) = when (member) {
                "verified_at" -> metadata to member
                "metadata_verifier" -> metadata to "verifier"
                "steps", "verified_facts", "partial_facts" -> report to member
                "report_schema_version" -> report to "schema_version"
                "schema_version", "error" -> result to member
                else -> continue
            }
            if (value == null) target.remove(name) else target[name] = value
        }
        report["metadata"] = JsonObject(metadata)
        result["report"] = JsonObject(report)
        return JsonObject(result).toString()
    }

    /**
     * The result of a rejection at [layer], whose report holds [partial]
     * and has [steps], with [changes] applied to the report.
     */
    private fun rejection(
        layer: String = "quote",
        steps: JsonElement = steps("passed", "passed", "failed", "not_run"),
        partial: JsonObject = buildJsonObject { },
        message: String = "verification error: $layer: report signature is invalid",
        changes: Map<String, JsonElement?> = emptyMap(),
    ): String {
        val report = mutableMapOf(
            "schema_version" to JsonPrimitive(1),
            "steps" to steps,
            "partial_facts" to partial,
            "metadata" to obj("verified_at" to "2026-09-26T12:00:00Z"),
        )
        for ((member, value) in changes) {
            if (value == null) report.remove(member) else report[member] = value
        }
        return buildJsonObject {
            put("schema_version", 3)
            put("report", JsonObject(report))
            put("error", obj("layer" to layer, "message" to message))
        }.toString()
    }

    private fun material(id: String, format: String, data: String): JsonObject = buildJsonObject {
        put("id", id)
        put("format", format)
        put("data", data)
    }

    private fun obj(vararg members: Pair<String, String>): JsonObject =
        JsonObject(members.associate { (name, value) -> name to JsonPrimitive(value) })

    private fun decodeReport(vararg changes: Pair<String, JsonElement?>): VerificationReport =
        VerificationPayload.decode(payload(mapOf(*changes)))

    private fun decode(vararg changes: Pair<String, JsonElement?>): VerifiedFacts =
        assertNotNull(decodeReport(*changes).verifiedFacts)

    /** The verifier's rejection that [payload] reports. */
    private fun rejected(payload: String): Pair<AttestationException, VerificationException> {
        val error = assertFailsWith<AttestationException> { VerificationPayload.decode(payload) }
        return error to assertIs<VerificationException>(error.cause)
    }

    private fun assertRejected(expected: String, vararg changes: Pair<String, JsonElement?>): AttestationException =
        assertRejectedPayload(expected, payload(mapOf(*changes)))

    private fun assertRejectedPayload(expected: String, payload: String): AttestationException {
        val error = assertFailsWith<AttestationException>(payload) { VerificationPayload.decode(payload) }
        assertTrue(error.detail.contains(expected), "${error.detail} should mention $expected")
        assertNull(error.layer, "A payload that cannot be read was rejected by no layer of the verifier.")
        assertNull(error.cause as? VerificationException, "A payload that cannot be read carries no report.")
        return error
    }

    @Test
    fun decodesACodeReleaseVerification() {
        val verification = decode()

        assertEquals("tinfoilsh/confidential-model-router", verification.configRepo)
        assertEquals(digest, verification.codeDigest)
        assertEquals("v1.2.3", verification.codeTag)
        assertEquals(
            Measurement(tdx, listOf("", "", register(3), register(4), "")),
            verification.codeMeasurement,
            "A register that the release leaves to the platform is empty.",
        )
        assertEquals(
            Measurement(tdx, listOf(register(1), register(2), register(3), register(4), register(5))),
            verification.enclaveMeasurement,
        )
        assertEquals(tlsKey, verification.tlsPublicKeyFingerprint)
        assertEquals(hpkeKey, verification.hpkePublicKey)
        assertEquals(
            listOf(CryptoMaterial("tls", tlsFormat, tlsKey), CryptoMaterial("hpke", hpkeFormat, hpkeKey)),
            verification.cryptoMaterial,
        )
        assertEquals(Instant.ofEpochSecond(1_791_028_800, 500_000_000), verification.freshnessExpiresAt)
        assertNull(verification.config, "A code-release verification has no config.")
        assertNull(verification.runtime)
        assertNull(verification.platform)
    }

    @Test
    fun decodesAnSevSnpMeasurement() {
        val launch = register(7)
        val verification = decode(
            "code_measurement" to obj("platform" to "sev-snp", "launch" to launch),
            "enclave_measurement" to obj("platform" to "sev-snp", "launch" to launch),
        )
        assertEquals(Measurement(snp, listOf(launch)), verification.codeMeasurement)
        assertEquals(Measurement(snp, listOf(launch)), verification.enclaveMeasurement)
    }

    @Test
    fun absentMembersDecodeAsNull() {
        val verification = decode(
            "config_repo" to null,
            "code_tag" to null,
            "code_measurement" to null,
            "crypto_material" to buildJsonArray { add(material("tls", tlsFormat, tlsKey)) },
        )
        assertNull(verification.configRepo)
        assertNull(verification.codeTag)
        assertNull(verification.codeMeasurement)
        assertNull(verification.hpkePublicKey, "An enclave that endorses only a TLS key has no HPKE key.")
    }

    @Test
    fun theChannelKeysComeFromTheCryptoMaterialAlone() {
        // Members that an earlier schema lifted out of the crypto material
        // are not read.
        val lifted = decode(
            "tls_public_key_fp" to JsonPrimitive("cc".repeat(32)),
            "hpke_public_key" to JsonPrimitive("dd".repeat(32)),
        )
        assertEquals(tlsKey, lifted.tlsPublicKeyFingerprint)
        assertEquals(hpkeKey, lifted.hpkePublicKey)

        // A key is looked up by its id and its format.
        val otherFormats = decode(
            "crypto_material" to buildJsonArray {
                add(material("tls", "https://tinfoil.sh/key/spki-fp-sha512/v9", "cc"))
                add(material("hpke", "https://tinfoil.sh/key/other/v1", "dd"))
                add(material("other", tlsFormat, tlsKey))
            },
        )
        assertNull(otherFormats.tlsPublicKeyFingerprint)
        assertNull(otherFormats.hpkePublicKey)
        assertEquals(3, otherFormats.cryptoMaterial.size)

        val none = decode("crypto_material" to buildJsonArray { })
        assertNull(none.tlsPublicKeyFingerprint)
        assertNull(none.hpkePublicKey)
    }

    @Test
    fun decodesConfigFacts() {
        val verification = decode(
            "config" to obj(
                "source" to "endorsement", "name" to "/org/project/v1", "digest" to "c0".repeat(32),
                "reference" to "sha256:c0", "signing_key_hint" to "hint",
                "approval_time" to "2026-09-20T08:00:00Z", "registry_id" to "registry",
                "signature_time" to "2026-09-20T08:01:00.5Z",
            ),
            "runtime" to obj(
                "source" to "endorsement", "repo" to "tinfoilsh/cvmimage", "tag" to "v0.15.0",
                "digest" to "d0".repeat(32), "name" to "runtime", "commit" to "e0".repeat(20),
                "approval_time" to "2026-09-20T08:00:00Z",
            ),
            "platform" to obj("source" to "embedded", "digest" to "f0".repeat(32)),
        )
        val approved = Instant.ofEpochSecond(1_789_891_200)
        assertEquals(
            ConfigVerification(
                source = ReferenceSource.ENDORSEMENT, name = "/org/project/v1", digest = "c0".repeat(32),
                reference = "sha256:c0", signingKeyHint = "hint", approvalTime = approved,
                registryId = "registry", signatureTime = approved.plusMillis(60_500),
            ),
            verification.config,
        )
        assertEquals(
            ArtifactVerification(
                source = ReferenceSource.ENDORSEMENT, repo = "tinfoilsh/cvmimage", tag = "v0.15.0",
                digest = "d0".repeat(32), name = "runtime", commit = "e0".repeat(20), approvalTime = approved,
            ),
            verification.runtime,
        )
        assertEquals(
            ArtifactVerification(
                source = ReferenceSource.EMBEDDED, repo = null, tag = null, digest = "f0".repeat(32),
                name = null, commit = null, approvalTime = null,
            ),
            verification.platform,
            "Facts that an embedded platform lacks are null.",
        )
    }

    @Test
    fun aConfigThatAnAuthorizerApprovedHasOnlyItsDigest() {
        val verification = decode("config" to obj("source" to "policy", "digest" to "c0".repeat(32)))
        assertEquals(
            ConfigVerification(
                source = ReferenceSource.POLICY, name = null, digest = "c0".repeat(32), reference = null,
                signingKeyHint = null, approvalTime = null, registryId = null, signatureTime = null,
            ),
            verification.config,
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
            "later_addition" to obj("name" to "x"),
            "config" to obj("source" to "policy", "digest" to "c0", "later_addition" to "x"),
            "enclave_measurement" to JsonObject(fullTdx + ("later_register" to JsonPrimitive("x"))),
        )
        assertEquals("c0", verification.config?.digest)
        val report = decodeReport("metadata_verifier" to obj("name" to "another", "version" to "devel"))
        assertEquals("tinfoil-kt", report.metadata.verifier.name, "The SDK records itself as the verifier.")
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
        assertRejected("unsupported verification schema version 2", "schema_version" to JsonPrimitive(2))
        assertRejected("unsupported verification schema version 0", "schema_version" to JsonPrimitive(0))
        // The version is read first, so a later schema is reported as such
        // even when it is otherwise readable.
        assertRejected("unsupported verification schema version 4", "schema_version" to JsonPrimitive(4))
    }

    @Test
    fun rejectsAReportInAnotherSchemaVersion() {
        assertRejected("unsupported verification report schema version 2", "report_schema_version" to JsonPrimitive(2))
        assertRejected("unsupported verification report schema version 0", "report_schema_version" to JsonPrimitive(0))
        assertRejected("no integer schema_version", "report_schema_version" to null)
        assertRejected("no integer schema_version", "report_schema_version" to JsonPrimitive("1"))
        assertRejectedPayload("no report object", """{"schema_version":3}""")
        assertRejectedPayload("no report object", """{"schema_version":3,"report":[]}""")
    }

    @Test
    fun rejectsAPayloadWithoutAUsableSchemaVersion() {
        assertRejected("no integer schema_version", "schema_version" to null)
        assertRejected("no integer schema_version", "schema_version" to JsonPrimitive("3"))
        assertRejected("no integer schema_version", "schema_version" to JsonPrimitive(3.5))
        assertRejected("no integer schema_version", "schema_version" to JsonPrimitive(true))
        assertRejected("no integer schema_version", "schema_version" to obj("version" to "3"))
    }

    @Test
    fun rejectsANullAnywhere() {
        for (member in listOf("code_tag", "code_measurement", "config", "schema_version", "error", "partial_facts")) {
            assertRejected("null", member to JsonNull)
        }
        assertRejected("null", "enclave_measurement" to JsonObject(fullTdx + ("rtmr3" to JsonNull)))
        assertRejected(
            "null",
            "crypto_material" to buildJsonArray { add(JsonObject(material("tls", tlsFormat, tlsKey) + ("data" to JsonNull))) },
        )
        assertRejected("null", "crypto_material" to buildJsonArray { add(JsonNull) })
        assertRejected("null", "later_addition" to JsonNull)
    }

    @Test
    fun rejectsAMissingRequiredMember() {
        for (member in listOf("code_digest", "crypto_material", "freshness_expires_at", "verified_at", "steps")) {
            assertRejected("unreadable verification payload", member to null)
        }
        assertRejected("no enclave_measurement", "enclave_measurement" to null)
        assertRejected("unreadable verification payload", "config" to obj("source" to "policy"))
        assertRejected("unreadable verification payload", "runtime" to obj("digest" to digest))
        assertRejected(
            "unreadable verification payload",
            "crypto_material" to buildJsonArray { add(obj("id" to "tls", "format" to tlsFormat)) },
        )
        assertRejected("unreadable verification payload", "code_measurement" to obj("rtmr1" to register(1)))
        assertRejectedPayload(
            "unreadable verification payload",
            """{"schema_version":3,"report":{"schema_version":1,"steps":[],"metadata":{"verified_at":"2026-09-26T12:00:00Z"}},"error":{"layer":"quote"}}""",
        )
    }

    @Test
    fun rejectsAMemberOfTheWrongType() {
        assertRejected("unreadable verification payload", "code_digest" to JsonPrimitive(7))
        assertRejected("unreadable verification payload", "code_digest" to JsonPrimitive(true))
        assertRejected("unreadable verification payload", "crypto_material" to JsonPrimitive("tls"))
        assertRejected("unreadable verification payload", "config" to JsonPrimitive("policy"))
        assertRejected("unreadable verification payload", "freshness_expires_at" to JsonPrimitive(1_791_028_800))
        assertRejected("unreadable verification payload", "enclave_measurement" to buildJsonArray { add(JsonPrimitive(register(1))) })
    }

    @Test
    fun rejectsAnEmptyString() {
        // The form leaves out what is absent; it never writes "".
        assertRejected("empty code_digest", "code_digest" to JsonPrimitive(""))
        assertRejected("empty config_repo", "config_repo" to JsonPrimitive(""))
        assertRejected("empty code_tag", "code_tag" to JsonPrimitive(""))
        assertRejected("empty config.digest", "config" to obj("source" to "policy", "digest" to ""))
        assertRejected("empty config.source", "config" to obj("source" to "", "digest" to "c0"))
        assertRejected("empty config.name", "config" to obj("source" to "policy", "digest" to "c0", "name" to ""))
        assertRejected("empty runtime.digest", "runtime" to obj("source" to "embedded", "digest" to ""))
        assertRejected("empty platform.source", "platform" to obj("source" to "", "digest" to "f0"))
        assertRejected("empty runtime.tag", "runtime" to obj("source" to "embedded", "digest" to "f0", "tag" to ""))
        assertRejected("empty crypto_material.id", "crypto_material" to buildJsonArray { add(material("", tlsFormat, tlsKey)) })
        assertRejected("empty crypto_material.data", "crypto_material" to buildJsonArray { add(material("x", "y", "")) })
        assertRejected("empty steps.status", "steps" to buildJsonArray { add(obj("layer" to "envelope", "status" to "")) })
        assertRejected(
            "empty steps.message",
            "steps" to buildJsonArray { add(obj("layer" to "envelope", "status" to "passed", "message" to "")) },
        )
    }

    @Test
    fun rejectsHexThatIsNotLowercaseHex() {
        assertRejected("code_digest that is not lowercase hex", "code_digest" to JsonPrimitive(digest.uppercase()))
        assertRejected("code_digest that is not lowercase hex", "code_digest" to JsonPrimitive("abc"))
        assertRejected("code_digest that is not lowercase hex", "code_digest" to JsonPrimitive("0x" + digest))
        assertRejected("runtime.commit", "runtime" to obj("source" to "embedded", "digest" to "f0", "commit" to "main"))
        assertRejected(
            "enclave_measurement.rtmr3 that is not 96",
            "enclave_measurement" to JsonObject(fullTdx + ("rtmr3" to JsonPrimitive("aa"))),
        )
        assertRejected(
            "code_measurement.rtmr1 that is not 96",
            "code_measurement" to tdxMeasurement("rtmr1" to register(0xab).uppercase()),
        )
        assertRejected("empty code_measurement.rtmr1", "code_measurement" to tdxMeasurement("rtmr1" to ""))
        for (key in listOf("AA".repeat(32), "aa".repeat(31), "aa".repeat(33), "zz".repeat(32))) {
            assertRejected(
                "crypto_material.data that is not 64",
                "crypto_material" to buildJsonArray { add(material("tls", tlsFormat, key)) },
            )
            assertRejected(
                "crypto_material.data that is not 64",
                "crypto_material" to buildJsonArray { add(material("hpke", hpkeFormat, key)) },
            )
        }
    }

    @Test
    fun rejectsAMeasurementThatIsNotOfItsPlatform() {
        assertRejected(
            "unsupported enclave_measurement.platform: sev-es",
            "enclave_measurement" to obj("platform" to "sev-es", "launch" to register(1)),
        )
        assertRejected(
            "a TDX register in the SEV-SNP code_measurement",
            "code_measurement" to obj("platform" to "sev-snp", "launch" to register(1), "rtmr1" to register(2)),
        )
        assertRejected(
            "an SEV-SNP register in the TDX code_measurement",
            "code_measurement" to tdxMeasurement("launch" to register(1), "rtmr1" to register(2)),
        )
        assertRejected(
            "enclave_measurement without every register",
            "enclave_measurement" to JsonObject(fullTdx - "mrtd"),
        )
        assertRejected(
            "enclave_measurement without every register",
            "enclave_measurement" to obj("platform" to "sev-snp"),
        )
        assertRejected("code_measurement without a register", "code_measurement" to obj("platform" to "tdx"))
    }

    @Test
    fun rejectsTwoItemsOrStepsOfOneName() {
        assertRejected(
            "two crypto_material items with one id",
            "crypto_material" to buildJsonArray {
                add(material("tls", tlsFormat, tlsKey))
                add(material("tls", tlsFormat, "cc".repeat(32)))
            },
        )
        assertRejected(
            "two steps of one layer",
            "steps" to buildJsonArray {
                listOf("envelope", "provenance", "quote", "policy", "quote").forEach { add(obj("layer" to it, "status" to "passed")) }
            },
        )
    }

    @Test
    fun rejectsAReportWithoutAStepForEveryLayer() {
        val withoutPolicy = buildJsonArray {
            listOf("envelope", "provenance", "quote").forEach { add(obj("layer" to it, "status" to "passed")) }
        }
        assertRejected("no policy step", "steps" to withoutPolicy)
        val withoutQuote = buildJsonArray {
            add(obj("layer" to "envelope", "status" to "passed"))
            add(obj("layer" to "provenance", "status" to "passed"))
            add(obj("layer" to "policy", "status" to "failed", "message" to "x"))
        }
        assertRejectedPayload("no quote step", rejection("policy", withoutQuote))
    }

    @Test
    fun rejectsAnInvalidTime() {
        assertRejected("freshness_expires_at", "freshness_expires_at" to JsonPrimitive("next week"))
        assertRejected("freshness_expires_at", "freshness_expires_at" to JsonPrimitive("2026-10-03T12:00:00"))
        assertRejected("not in UTC", "freshness_expires_at" to JsonPrimitive("2026-10-03T12:00:00+00:00"))
        assertRejected("not in UTC", "freshness_expires_at" to JsonPrimitive("2026-10-03T07:00:00-05:00"))
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
            "runtime" to obj("source" to "endorsement", "digest" to "d0", "approval_time" to "yesterday"),
        )
        assertRejected(
            "platform.approval_time",
            "platform" to obj("source" to "endorsement", "digest" to "f0", "approval_time" to "yesterday"),
        )
    }

    @Test
    fun rejectsWhatIsNotAJsonObject() {
        for (malformed in listOf("", " ", "null", "[]", "1", "\"schema_version\"", "{", """{"schema_version":3""", "not json")) {
            assertRejectedPayload("unreadable verification payload", malformed)
        }
        assertRejectedPayload("unreadable verification payload", payload() + "{}")
        assertRejectedPayload("unreadable verification payload", payload().replace("\"schema_version\":3", "schema_version:3"))
    }

    @Test
    fun verificationsCompareByValue() {
        val one = decode()
        assertEquals(one, decode())
        assertEquals(one.hashCode(), decode().hashCode())
        assertNotEquals(one, decode("code_digest" to JsonPrimitive("cd".repeat(32))))
        assertNotEquals(one, decode("crypto_material" to buildJsonArray { add(material("tls", tlsFormat, tlsKey)) }))
        assertNotEquals(one, decode("freshness_expires_at" to JsonPrimitive("2026-10-03T12:00:01Z")))
        assertNotEquals(one, decode("crypto_material" to buildJsonArray { }))
        assertNotEquals(one, decode("config" to obj("source" to "policy", "digest" to "c0")))
        assertTrue(one.toString().contains("codeDigest=$digest"), one.toString())
    }

    @Test
    fun theCryptoMaterialCannotBeChanged() {
        val verification = decode()
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (verification.cryptoMaterial as MutableList<CryptoMaterial>).clear()
        }
        assertFalse(verification.cryptoMaterial.isEmpty())
        assertEquals(tlsKey, verification.tlsPublicKeyFingerprint)
    }

    // The report.

    @Test
    fun aVerificationThatPassedIsAReportWithEveryStepAndVerifiedFacts() {
        val report = decodeReport()

        assertEquals(
            listOf(VerificationLayer.ENVELOPE, VerificationLayer.PROVENANCE, VerificationLayer.QUOTE, VerificationLayer.POLICY)
                .map { Step(it, StepStatus.PASSED, null) },
            report.steps,
        )
        assertEquals(digest, report.verifiedFacts?.codeDigest)
        assertNull(report.partialFacts)
        assertNull(report.failedStep)
        assertEquals(Instant.ofEpochSecond(1_790_424_000), report.metadata.verifiedAt)
        assertEquals("tinfoil-kt", report.metadata.verifier.name)
        assertTrue(report.metadata.verifier.version.isNotEmpty())
    }

    @Test
    fun aSkippedStepIsNotAFailure() {
        val skipped = buildJsonArray {
            add(obj("layer" to "envelope", "status" to "passed"))
            add(obj("layer" to "provenance", "status" to "skipped", "message" to "every reference value is embedded"))
            add(obj("layer" to "quote", "status" to "passed"))
            add(obj("layer" to "policy", "status" to "passed"))
        }
        val report = decodeReport("steps" to skipped)
        assertEquals(
            Step(VerificationLayer.PROVENANCE, StepStatus.SKIPPED, "every reference value is embedded"),
            report.steps[1],
        )
        assertNotNull(report.verifiedFacts)
    }

    @Test
    fun aLayerThatThisSdkDoesNotNameIsCarried() {
        val more = buildJsonArray {
            listOf("envelope", "provenance", "quote", "policy", "device").forEach { add(obj("layer" to it, "status" to "passed")) }
        }
        assertEquals(VerificationLayer("device"), decodeReport("steps" to more).steps.last().layer)
    }

    @Test
    fun aResultWithoutAnErrorIsAVerificationOnlyIfNothingFailed() {
        assertRejected("its quote step failed", "steps" to steps("passed", "passed", "failed", "not_run"))
        assertRejected("its policy step not_run", "steps" to steps("passed", "passed", "passed", "not_run"))
        assertRejected("its policy step later", "steps" to steps("passed", "passed", "passed", "later"))
        assertRejected("no steps", "steps" to buildJsonArray { })
        assertRejected("neither an error nor verified facts", "verified_facts" to null)
        assertRejected("both verified and partial facts", "partial_facts" to buildJsonObject { })
    }

    @Test
    fun aRejectionCarriesItsReportAsTheCauseOfAnAttestationException() {
        val launch = register(0xaa)
        val partial = buildJsonObject {
            putJsonObject("expected") {
                put("config_repo", "tinfoilsh/repo")
                put("artifact", obj("source" to "endorsement", "repo" to "tinfoilsh/repo", "tag" to "v1", "digest" to "d0"))
                put("code_measurement", obj("platform" to "sev-snp", "launch" to launch))
            }
            put("measured", obj("tls_public_key_fp" to tlsKey, "hpke_public_key_fp" to hpkeKey))
        }

        val steps = buildJsonArray {
            add(obj("layer" to "envelope", "status" to "passed"))
            add(obj("layer" to "provenance", "status" to "passed"))
            add(obj("layer" to "quote", "status" to "failed", "message" to "report signature is invalid"))
            add(obj("layer" to "policy", "status" to "not_run"))
        }
        val (error, rejected) = rejected(rejection(steps = steps, partial = partial))

        val message = "verification error: quote: report signature is invalid"
        assertEquals("quote: report signature is invalid", error.detail)
        assertEquals(VerificationLayer.QUOTE, error.layer)
        assertEquals(message, rejected.message)
        assertEquals(VerificationLayer.QUOTE, rejected.layer)
        val report = rejected.report
        assertNull(report.verifiedFacts)
        assertEquals(
            listOf(StepStatus.PASSED, StepStatus.PASSED, StepStatus.FAILED, StepStatus.NOT_RUN),
            report.steps.map { it.status },
        )
        assertEquals(VerificationLayer.QUOTE, report.failedStep?.layer)
        // The step carries the check's message as the library gives it; only
        // the error leads with the type and the layer.
        assertEquals("report signature is invalid", report.failedStep?.message)
        assertEquals(
            PartialFacts(
                expected = ExpectedFacts(
                    configRepo = "tinfoilsh/repo",
                    artifact = ArtifactVerification(ReferenceSource.ENDORSEMENT, "tinfoilsh/repo", "v1", "d0", null, null, null),
                    config = null,
                    platform = null,
                    codeMeasurement = Measurement(snp, listOf(launch)),
                    measurement = null,
                ),
                measured = MeasuredFacts(cpu = null, tlsPublicKeyFingerprint = tlsKey, hpkePublicKeyFingerprint = hpkeKey),
            ),
            report.partialFacts,
        )
        assertEquals(Instant.ofEpochSecond(1_790_424_000), report.metadata.verifiedAt)
    }

    @Test
    fun aRejectionByThePolicyHoldsBothMeasurementsSideBySide() {
        val partial = buildJsonObject {
            putJsonObject("expected") {
                put("config_repo", "tinfoilsh/repo")
                put("artifact", obj("source" to "embedded", "digest" to "d0"))
                put("config", obj("source" to "policy", "digest" to "c0"))
                put("platform", obj("source" to "embedded", "digest" to "f0"))
                put("code_measurement", tdxMeasurement("rtmr1" to register(3), "rtmr2" to register(4)))
                put("measurement", fullTdx)
            }
            putJsonObject("measured") {
                put("cpu_measurement", JsonObject(fullTdx + ("rtmr2" to JsonPrimitive(register(9)))))
            }
        }

        val (_, rejected) = rejected(rejection("policy", steps("passed", "passed", "passed", "failed"), partial))

        val facts = assertNotNull(rejected.report.partialFacts)
        assertEquals(Measurement(tdx, listOf("", "", register(3), register(4), "")), facts.expected?.codeMeasurement)
        assertEquals(
            Measurement(tdx, listOf(register(1), register(2), register(3), register(4), register(5))),
            facts.expected?.measurement,
        )
        assertEquals(
            CpuEvidence(Measurement(tdx, listOf(register(1), register(2), register(3), register(9), register(5)))),
            facts.measured?.cpu,
        )
        assertEquals(ReferenceSource.POLICY, facts.expected?.config?.source)
        assertEquals("f0", facts.expected?.platform?.digest)
        assertNull(facts.measured?.tlsPublicKeyFingerprint)
    }

    @Test
    fun aRejectionAtTheEnvelopeHasNeitherGroupOfFacts() {
        val (error, rejected) = rejected(rejection("envelope", steps("failed", "not_run", "not_run", "not_run")))
        assertEquals(VerificationLayer.ENVELOPE, error.layer)
        assertEquals(PartialFacts(expected = null, measured = null), rejected.report.partialFacts)
    }

    @Test
    fun aRejectionThatBreaksTheFormIsUnreadable() {
        val measuredFingerprint = { fp: String -> buildJsonObject { put("measured", obj("tls_public_key_fp" to fp)) } }
        assertRejectedPayload("partial_facts.measured.tls_public_key_fp", rejection(partial = measuredFingerprint("AA".repeat(32))))
        assertRejectedPayload("partial_facts.measured.tls_public_key_fp", rejection(partial = measuredFingerprint("aa")))
        assertRejectedPayload(
            "partial_facts.expected.measurement without every register",
            rejection(
                "policy",
                steps("passed", "passed", "passed", "failed"),
                buildJsonObject {
                    putJsonObject("expected") {
                        put("artifact", obj("source" to "embedded", "digest" to "d0"))
                        put("measurement", tdxMeasurement("rtmr1" to register(1)))
                    }
                },
            ),
        )
    }

    @Test
    fun aRejectionThatContradictsItselfIsUnreadableAndCarriesNoReport() {
        val facts = Json.parseToJsonElement(payload()).jsonObject.getValue("report").jsonObject.getValue("verified_facts")
        for ((expected, payload) in listOf(
            "both an error and verified facts" to rejection(changes = mapOf("verified_facts" to facts)),
            "an error but no partial facts" to rejection(changes = mapOf("partial_facts" to null)),
            "empty error.layer" to rejection(layer = ""),
            "empty error.message" to rejection(message = ""),
            "unreadable verification payload" to rejection(changes = mapOf("metadata" to null)),
            "unreadable verification payload" to rejection(partial = obj("expected" to "x")),
            // The step of the error's layer failed, and only that step.
            "an error at policy, but its failed steps are [quote]" to rejection(layer = "policy"),
            "an error at quote, but its failed steps are []" to
                rejection(steps = steps("passed", "passed", "passed", "passed")),
            "an error at quote, but its failed steps are [provenance, quote]" to
                rejection(steps = steps("passed", "failed", "failed", "not_run")),
            // The message leads with the type and the error's layer.
            "does not lead with" to rejection(message = "quote: report signature is invalid"),
            "does not lead with" to rejection(message = "verification error: policy: report signature is invalid"),
        )) {
            assertRejectedPayload(expected, payload)
        }
    }

    @Test
    fun reportsCompareByValueAndCannotBeChanged() {
        val one = decodeReport()
        assertEquals(one, decodeReport())
        assertEquals(one.hashCode(), decodeReport().hashCode())
        assertNotEquals(one, decodeReport("verified_at" to JsonPrimitive("2026-09-26T12:00:01Z")))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (one.steps as MutableList<Step>).clear()
        }
        assertEquals(4, one.steps.size)
        val (_, first) = rejected(rejection())
        val (_, second) = rejected(rejection())
        assertEquals(first.report, second.report)
        assertSame(first.report.partialFacts?.expected, first.report.partialFacts?.expected)
    }
}
