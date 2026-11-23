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
import sh.tinfoil.VerifiedFacts
import sh.tinfoil.VerificationReport
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

    private fun steps(vararg statuses: String): JsonElement = buildJsonArray {
        listOf("envelope", "provenance", "quote", "policy").zip(statuses).forEach { (layer, status) ->
            add(obj("layer" to layer, "status" to status))
        }
    }

    private val passedSteps = steps("passed", "passed", "passed", "passed")

    /**
     * The result of a code-release verification that passed, with
     * [changes] applied to its verified facts; a null change removes the
     * member. The changes `schema_version`, `steps`, `partial_facts`,
     * `error` and `verified_at` apply to the result, the report and its
     * metadata instead.
     */
    private fun payload(changes: Map<String, JsonElement?> = emptyMap()): String {
        val outer = setOf("schema_version", "steps", "verified_facts", "partial_facts", "error", "verified_at")
        val facts = buildJsonObject {
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
        }.toMutableMap()
        for ((member, value) in changes) {
            if (member in outer) continue
            if (value == null) facts.remove(member) else facts[member] = value
        }
        val metadata = mutableMapOf<String, JsonElement>("verified_at" to JsonPrimitive("2026-09-26T12:00:00Z"))
        val report = mutableMapOf("steps" to passedSteps, "verified_facts" to JsonObject(facts))
        val result = mutableMapOf<String, JsonElement>("schema_version" to JsonPrimitive(2))
        for ((member, value) in changes) {
            val target = when (member) {
                "verified_at" -> metadata
                "steps", "verified_facts", "partial_facts" -> report
                "schema_version", "error" -> result
                else -> continue
            }
            if (value == null) target.remove(member) else target[member] = value
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
        changes: Map<String, JsonElement?> = emptyMap(),
    ): String {
        val message = "verification error: $layer: report signature is invalid"
        val report = mutableMapOf(
            "steps" to steps,
            "partial_facts" to partial,
            "metadata" to obj("verified_at" to "2026-09-26T12:00:00Z"),
        )
        for ((member, value) in changes) {
            if (value == null) report.remove(member) else report[member] = value
        }
        return buildJsonObject {
            put("schema_version", 2)
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
        assertEquals("c0", verification.config?.digest)
        val report = decodeReport("verifier" to obj("name" to "another", "version" to "devel"))
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
        assertRejectedPayload("unsupported verification schema version 1", """{"schema_version":1}""")
        assertRejected("unsupported verification schema version 1", "schema_version" to JsonPrimitive(1))
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
            "config_repo", "code_digest", "tls_public_key_fp", "crypto_material", "freshness_expires_at", "verified_at", "steps",
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
        for (malformed in listOf("", " ", "null", "[]", "1", "\"schema_version\"", "{", """{"schema_version":2""", """{"schema_version":2}""", "not json")) {
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

    // The report.

    @Test
    fun aVerificationThatPassedIsAReportWithEveryStepAndVerifiedFacts() {
        val report = decodeReport()

        assertEquals(
            listOf(VerificationLayer.ENVELOPE, VerificationLayer.PROVENANCE, VerificationLayer.QUOTE, VerificationLayer.POLICY)
                .map { Step(it, StepStatus.PASSED, null) },
            report.steps,
        )
        assertEquals("abc123", report.verifiedFacts?.codeDigest)
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
        assertRejected("empty steps.status", "steps" to buildJsonArray { add(obj("layer" to "envelope", "status" to "")) })
    }

    @Test
    fun aRejectionCarriesItsReportAsTheCauseOfAnAttestationException() {
        val launch = "aa".repeat(48)
        val partial = buildJsonObject {
            putJsonObject("expected") {
                put("config_repo", "tinfoilsh/repo")
                put("artifact", obj("source" to "endorsement", "repo" to "tinfoilsh/repo", "tag" to "v1", "digest" to "d0"))
                putJsonObject("code_measurement") {
                    put("type", snp)
                    putJsonArray("registers") { add(JsonPrimitive(launch)) }
                }
            }
            put("measured", obj("tls_public_key_fp" to "aa", "hpke_public_key_fp" to "bb"))
        }

        val (error, rejected) = rejected(rejection(partial = partial))

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
                measured = MeasuredFacts(cpu = null, tlsPublicKeyFingerprint = "aa", hpkePublicKeyFingerprint = "bb"),
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
                put("platform", obj("source" to "embedded", "digest" to "p0"))
                putJsonObject("code_measurement") {
                    put("type", tdx)
                    putJsonArray("registers") { listOf("", "", "bb", "cc", "").forEach { add(JsonPrimitive(it)) } }
                }
                putJsonObject("measurement") {
                    put("type", tdx)
                    putJsonArray("registers") { listOf("aa", "ab", "bb", "cc", "dd").forEach { add(JsonPrimitive(it)) } }
                }
            }
            putJsonObject("measured") {
                putJsonObject("cpu_measurement") {
                    put("type", tdx)
                    putJsonArray("registers") { listOf("aa", "ab", "bb", "ff", "dd").forEach { add(JsonPrimitive(it)) } }
                }
            }
        }

        val (_, rejected) = rejected(rejection("policy", steps("passed", "passed", "passed", "failed"), partial))

        val facts = assertNotNull(rejected.report.partialFacts)
        assertEquals(Measurement(tdx, listOf("aa", "ab", "bb", "cc", "dd")), facts.expected?.measurement)
        assertEquals(CpuEvidence(Measurement(tdx, listOf("aa", "ab", "bb", "ff", "dd"))), facts.measured?.cpu)
        assertEquals(ReferenceSource.POLICY, facts.expected?.config?.source)
        assertEquals("p0", facts.expected?.platform?.digest)
        assertNull(facts.measured?.tlsPublicKeyFingerprint)
    }

    @Test
    fun aRejectionAtTheEnvelopeHasNeitherGroupOfFacts() {
        val (error, rejected) = rejected(rejection("envelope", steps("failed", "not_run", "not_run", "not_run")))
        assertEquals(VerificationLayer.ENVELOPE, error.layer)
        assertEquals(PartialFacts(expected = null, measured = null), rejected.report.partialFacts)
    }

    @Test
    fun aRejectionThatContradictsItselfIsUnreadableAndCarriesNoReport() {
        val facts = Json.parseToJsonElement(payload()).jsonObject.getValue("report").jsonObject.getValue("verified_facts")
        for ((expected, payload) in listOf(
            "both an error and verified facts" to rejection(changes = mapOf("verified_facts" to facts)),
            "an error but no partial facts" to rejection(changes = mapOf("partial_facts" to null)),
            "empty error.layer" to rejection(layer = ""),
            "unreadable verification payload" to rejection(changes = mapOf("metadata" to null)),
            "unreadable verification payload" to rejection(partial = obj("expected" to "x")),
        )) {
            val error = assertRejectedPayload(expected, payload)
            assertNull(error.cause as? VerificationException, payload)
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
