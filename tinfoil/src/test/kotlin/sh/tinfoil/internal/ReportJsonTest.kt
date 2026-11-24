package sh.tinfoil.internal

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
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
import sh.tinfoil.SoftwareIdentity
import sh.tinfoil.Step
import sh.tinfoil.StepStatus
import sh.tinfoil.VerificationException
import sh.tinfoil.VerificationLayer
import sh.tinfoil.VerificationMetadata
import sh.tinfoil.VerificationReport
import sh.tinfoil.VerifiedFacts
import sh.tinfoil.internal.verification.VerificationPayload
import java.io.File
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Pins the JSON form that [VerificationReport.toJson] writes.
 *
 * The golden files in `testdata/report-json` are copied unchanged from
 * tinfoil-go's `verify/testdata/report-json`, where its own encoder is
 * checked against them; see the README there. Each one's report is read
 * here as the verifier library would return it, and written again with
 * [VerificationReport.toJson]. The conformance tests check the files that
 * name a vector against a verification of that vector.
 */
class ReportJsonTest {
    private val goldenDirectory = File("testdata/report-json")

    private fun goldenFiles(): List<File> =
        goldenDirectory.listFiles { file -> file.name.endsWith(".json") }.orEmpty().sortedBy { it.name }

    /**
     * The verifier library's result for [report]: the report alone, or with
     * the error of the step that failed.
     */
    private fun result(report: JsonObject): String {
        val failed = report.getValue("steps").jsonArray.map { it.jsonObject }
            .singleOrNull { it.getValue("status").jsonPrimitive.content == "failed" }
        return buildJsonObject {
            put("schema_version", VerificationPayload.SUPPORTED_SCHEMA_VERSION)
            put("report", report)
            if (failed != null) {
                val layer = failed.getValue("layer").jsonPrimitive.content
                val message = failed.getValue("message").jsonPrimitive.content
                put("error", buildJsonObject {
                    put("layer", layer)
                    put("message", "verification error: $layer: $message")
                })
            }
        }.toString()
    }

    /** What [result] decodes to: the report, or the report of the rejection. */
    private fun decode(result: String): VerificationReport =
        try {
            VerificationPayload.decode(result)
        } catch (e: AttestationException) {
            assertIs<VerificationException>(e.cause, e.message).report
        }

    @Test
    fun theGoldenFilesAreAllHere() {
        val files = goldenFiles()
        assertEquals(10, files.size, "golden files in ${goldenDirectory.absolutePath}")
        val withVectors = files.count { Json.parseToJsonElement(it.readText()).jsonObject.containsKey("vector") }
        assertEquals(7, withVectors, "golden files that name a conformance vector")
    }

    @Test
    fun everyGoldenReportIsWrittenAsItWasRead() {
        for (file in goldenFiles()) {
            val golden = Json.parseToJsonElement(file.readText()).jsonObject.getValue("report").jsonObject
            val report = decode(result(golden))
            val written = Json.parseToJsonElement(report.toJson()).jsonObject

            assertEquals(comparable(golden), comparable(written), file.name)
            // What the comparison leaves out: the step messages pass through
            // unchanged, and the metadata names this SDK.
            assertEquals(golden.getValue("steps"), written.getValue("steps"), file.name)
            val metadata = written.getValue("metadata").jsonObject
            assertEquals(
                Instant.parse(golden.getValue("metadata").jsonObject.getValue("verified_at").jsonPrimitive.content),
                Instant.parse(metadata.getValue("verified_at").jsonPrimitive.content),
                file.name,
            )
            assertEquals(
                buildJsonObject {
                    put("name", SdkIdentity.NAME)
                    put("version", SdkIdentity.VERSION)
                },
                metadata["verifier"],
                file.name,
            )
            assertEncoding(written, file.name)
        }
    }

    // A report that the client builds itself, rather than from the library.

    private val tdx = ReportJson.TDX_TYPE
    private val snp = ReportJson.SEV_SNP_TYPE

    private fun register(byte: Int): String = "%02x".format(byte).repeat(48)

    private val layers = listOf(VerificationLayer.ENVELOPE, VerificationLayer.PROVENANCE, VerificationLayer.QUOTE, VerificationLayer.POLICY)

    private val metadata = VerificationMetadata(SoftwareIdentity("tinfoil-kt", "1.2.0"), Instant.ofEpochSecond(1_790_424_000, 5))

    private fun facts(
        codeMeasurement: Measurement? = Measurement(tdx, listOf("", "", register(3), register(4), "")),
        config: ConfigVerification? = null,
    ): VerifiedFacts = VerifiedFacts(
        configRepo = "tinfoilsh/confidential-model-router",
        codeDigest = "ab".repeat(32),
        codeTag = "v1.2.3",
        codeMeasurement = codeMeasurement,
        enclaveMeasurement = Measurement(tdx, listOf(register(1), register(2), register(3), register(4), register(5))),
        config = config,
        runtime = null,
        platform = null,
        cryptoMaterial = listOf(
            CryptoMaterial("tls", "https://tinfoil.sh/key/spki-fp-sha256/v1", "aa".repeat(32)),
            CryptoMaterial("hpke", "https://tinfoil.sh/key/x25519-hpke/v1", "bb".repeat(32)),
        ),
        freshnessExpiresAt = Instant.ofEpochSecond(1_791_028_800),
    )

    private fun passed(facts: VerifiedFacts): VerificationReport =
        VerificationReport(layers.map { Step(it, StepStatus.PASSED, null) }, facts, partialFacts = null, metadata)

    private fun failedAt(layer: VerificationLayer, partial: PartialFacts): VerificationReport {
        val failed = layers.indexOf(layer)
        val steps = layers.mapIndexed { i, it ->
            when {
                i < failed -> Step(it, StepStatus.PASSED, null)
                i == failed -> Step(it, StepStatus.FAILED, "it failed")
                else -> Step(it, StepStatus.NOT_RUN, null)
            }
        }
        return VerificationReport(steps, verifiedFacts = null, partial, metadata)
    }

    private fun json(report: VerificationReport): JsonObject =
        Json.parseToJsonElement(report.toJson()).jsonObject.also { assertEncoding(it, "$report") }

    @Test
    fun aReportThatPassedHasVerifiedFactsAndTheKeysOnlyInTheCryptoMaterial() {
        val written = json(passed(facts()))

        assertEquals(1, written.getValue("schema_version").jsonPrimitive.int)
        assertFalse("partial_facts" in written)
        val facts = written.getValue("verified_facts").jsonObject
        assertEquals(
            setOf(
                "config_repo", "code_digest", "code_tag", "code_measurement", "enclave_measurement",
                "crypto_material", "freshness_expires_at",
            ),
            facts.keys,
        )
        assertEquals(
            Json.parseToJsonElement("""{"platform":"tdx","rtmr1":"${register(3)}","rtmr2":"${register(4)}"}"""),
            facts["code_measurement"],
            "A register that the release leaves to the platform is left out.",
        )
        assertEquals(
            listOf("platform", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"),
            facts.getValue("enclave_measurement").jsonObject.keys.toList(),
        )
        assertEquals(JsonPrimitive("2026-10-03T12:00:00Z"), facts["freshness_expires_at"])
        assertEquals(
            Json.parseToJsonElement("""{"verified_at":"2026-09-26T12:00:00.000000005Z","verifier":{"name":"tinfoil-kt","version":"1.2.0"}}"""),
            written["metadata"],
        )
        assertEquals(
            Json.parseToJsonElement("""[{"layer":"envelope","status":"passed"},{"layer":"provenance","status":"passed"},""" +
                """{"layer":"quote","status":"passed"},{"layer":"policy","status":"passed"}]"""),
            written["steps"],
        )
    }

    @Test
    fun aCodeMeasurementWithoutARegisterIsLeftOut() {
        val open = json(passed(facts(codeMeasurement = Measurement(tdx, listOf("", "", "", "", "")))))
        assertFalse("code_measurement" in open.getValue("verified_facts").jsonObject)
        val none = json(passed(facts(codeMeasurement = null)))
        assertFalse("code_measurement" in none.getValue("verified_facts").jsonObject)
        val snpCode = json(passed(facts(codeMeasurement = Measurement(snp, listOf(register(7))))))
        assertEquals(
            Json.parseToJsonElement("""{"platform":"sev-snp","launch":"${register(7)}"}"""),
            snpCode.getValue("verified_facts").jsonObject["code_measurement"],
        )
    }

    @Test
    fun aRecordHasOnlyTheMembersThatItsSourceSupplies() {
        val config = ConfigVerification(ReferenceSource.POLICY, null, "c0".repeat(32), null, null, null, null, null)
        val written = json(passed(facts(config = config)))
        assertEquals(
            Json.parseToJsonElement("""{"source":"policy","digest":"${"c0".repeat(32)}"}"""),
            written.getValue("verified_facts").jsonObject["config"],
        )
    }

    @Test
    fun aRejectionAtTheEnvelopeHasEmptyPartialFacts() {
        val written = json(failedAt(VerificationLayer.ENVELOPE, PartialFacts(expected = null, measured = null)))
        assertEquals(JsonObject(emptyMap()), written["partial_facts"])
        assertFalse("verified_facts" in written)
        assertEquals(
            Json.parseToJsonElement("""{"layer":"envelope","status":"failed","message":"it failed"}"""),
            written.getValue("steps").jsonArray[0],
        )
    }

    @Test
    fun anEstablishedFactThatHoldsNothingStays() {
        val written = json(
            failedAt(VerificationLayer.PROVENANCE, PartialFacts(expected = null, measured = MeasuredFacts(null, null, null))),
        )
        assertEquals(Json.parseToJsonElement("""{"measured":{}}"""), written["partial_facts"])
    }

    @Test
    fun aRejectionHoldsTheMeasurementsSideBySide() {
        val expected = ExpectedFacts(
            configRepo = "tinfoilsh/repo",
            artifact = ArtifactVerification(ReferenceSource.EMBEDDED, null, null, "d0".repeat(32), null, null, null),
            config = null,
            platform = null,
            codeMeasurement = Measurement(snp, listOf(register(1))),
            measurement = Measurement(snp, listOf(register(1))),
        )
        val measured = MeasuredFacts(CpuEvidence(Measurement(snp, listOf(register(2)))), "aa".repeat(32), "bb".repeat(32))
        val written = json(failedAt(VerificationLayer.POLICY, PartialFacts(expected, measured)))
        assertEquals(
            Json.parseToJsonElement(
                """{"expected":{"config_repo":"tinfoilsh/repo","artifact":{"source":"embedded","digest":"${"d0".repeat(32)}"},""" +
                    """"code_measurement":{"platform":"sev-snp","launch":"${register(1)}"},""" +
                    """"measurement":{"platform":"sev-snp","launch":"${register(1)}"}},""" +
                    """"measured":{"cpu_measurement":{"platform":"sev-snp","launch":"${register(2)}"},""" +
                    """"tls_public_key_fp":"${"aa".repeat(32)}","hpke_public_key_fp":"${"bb".repeat(32)}"}}""",
            ),
            written["partial_facts"],
        )
    }

    @Test
    fun thePublicTypesCannotBeReadFromJson() {
        // A serializable class has a generated serializer; none of the public
        // types may have one, so that no public API reads the form back.
        val types = listOf(
            VerificationReport::class, Step::class, VerifiedFacts::class, PartialFacts::class, ExpectedFacts::class,
            MeasuredFacts::class, CpuEvidence::class, Measurement::class, CryptoMaterial::class,
            ConfigVerification::class, ArtifactVerification::class, VerificationMetadata::class, SoftwareIdentity::class,
        )
        for (type in types) {
            val generated = type.java.declaredClasses.map { it.simpleName }
            assertFalse("\$serializer" in generated, "${type.simpleName} is serializable")
            assertTrue(type.java.methods.none { it.name == "serializer" }, "${type.simpleName} has a serializer")
        }
    }

    /**
     * [report] without what the golden files' README leaves out of a
     * comparison, the step messages and the metadata, and with its times as
     * instants.
     */
    private fun comparable(report: JsonObject): JsonElement {
        val steps = report.getValue("steps").jsonArray.map { step -> JsonObject(step.jsonObject - "message") }
        return times(JsonObject(report - "metadata" + ("steps" to JsonArray(steps))))
    }

    private fun times(element: JsonElement): JsonElement = when (element) {
        is JsonObject -> JsonObject(
            element.mapValues { (name, value) ->
                if (name in TIMES) JsonPrimitive(Instant.parse(value.jsonPrimitive.content).toString()) else times(value)
            },
        )
        is JsonArray -> JsonArray(element.map(::times))
        else -> element
    }

    /** The rules of the form's encoding that every written report keeps. */
    private fun assertEncoding(element: JsonElement, what: String) {
        when (element) {
            is JsonObject -> element.forEach { (name, value) ->
                assertTrue(Regex("[a-z0-9_]+").matches(name), "$what: the member $name is not snake_case")
                if (name in TIMES) {
                    val time = value.jsonPrimitive.content
                    assertTrue(time.endsWith("Z"), "$what: $name is not in UTC: $time")
                }
                assertEncoding(value, what)
            }
            is JsonArray -> element.forEach { assertEncoding(it, what) }
            is JsonNull -> throw AssertionError("$what: a member is null")
            is JsonPrimitive -> assertFalse(element.isString && element.content.isEmpty(), "$what: a member is \"\"")
        }
        if (element is JsonObject && "verified_facts" in element) {
            val facts = element.getValue("verified_facts").jsonObject
            assertTrue(LIFTED_KEYS.none { it in facts }, "$what: verified facts hold a key outside crypto_material")
        }
    }

    private companion object {
        val TIMES = setOf("verified_at", "freshness_expires_at", "approval_time", "signature_time")
        /** Channel keys or their fingerprints, which verified facts hold only in crypto_material. */
        val LIFTED_KEYS = setOf("tls_public_key_fp", "hpke_public_key", "hpke_public_key_fp")
    }
}
