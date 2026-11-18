package sh.tinfoil.internal.verification

import android.content.res.AssetManager
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.runner.RunWith
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Measurement
import sh.tinfoil.NetworkException
import sh.tinfoil.TinfoilException
import sh.tinfoil.Verification
import sh.tinfoil.VerificationLayer
import sh.tinfoil.go.mobile.Mobile
import java.time.Instant
import java.util.Base64
import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Runs every full-verify vector of the shared conformance suite through the
 * verifier library and this SDK's side of its boundary: the verification
 * payload decoded into a [Verification], and each error classified into a
 * [TinfoilException]. The verdict, the rejection's layer and the verified
 * facts must be the ones that the vector expects.
 *
 * It is compiled only in the conformance build (`TINFOIL_CONFORMANCE=1`),
 * against a verifier library built with
 * `MOBILE_BUILD_TAGS=tinfoil_conformance`, whose test-only entry points take
 * a vector's trust anchors and clock. The build packages the vectors as
 * assets of the test APK; nothing here reaches the network.
 */
@RunWith(AndroidJUnit4::class)
class ConformanceVectorTest {
    @Serializable
    private class Vector(val id: String, val stage: String, val input: Input, val expected: Expected)

    // Every member that a vector may carry is named here, and an unknown one
    // fails the decoding: an input that is not passed on, or an expectation
    // that is not compared, would otherwise go unnoticed.
    @Serializable
    private class Input(
        @SerialName("schema_version") val schemaVersion: String,
        @SerialName("document_b64") val documentB64: String,
        @SerialName("nonce_hex") val nonceHex: String,
        val repo: String = "",
        val project: String = "",
        @SerialName("verification_time_unix") val verificationTimeUnix: Long,
        @SerialName("sigstore_trusted_root_json_b64") val sigstoreTrustedRootJsonB64: String? = null,
        @SerialName("amd_root_ca_pem") val amdRootCaPem: String? = null,
        @SerialName("ask_pem") val askPem: String? = null,
        @SerialName("intel_sgx_root_pem") val intelSgxRootPem: String? = null,
    )

    @Serializable
    private class Expected(
        val accepted: Boolean,
        val code: String? = null,
        @SerialName("code_digest") val codeDigest: String? = null,
        @SerialName("code_measurement") val codeMeasurement: ExpectedMeasurement? = null,
        @SerialName("enclave_measurement") val enclaveMeasurement: ExpectedMeasurement? = null,
        @SerialName("tls_public_key_fp") val tlsPublicKeyFp: String? = null,
        @SerialName("hpke_public_key") val hpkePublicKey: String? = null,
    )

    @Serializable
    private class ExpectedMeasurement(val type: String, val registers: List<String>)

    /** What one vector came to; [failures] is empty when it is as expected. */
    private class Result(val id: String, val outcome: String, val failures: List<String>)

    private val assets: AssetManager = InstrumentationRegistry.getInstrumentation().context.assets

    @Test
    fun fullVerifyVectors() {
        val pin = Properties().apply { assets.open(PIN).use(::load) }
        val pinned = checkNotNull(pin.getProperty("fullVerifyVectors")?.toIntOrNull()) { "$PIN names no vector count" }
        val files = vectorFiles(VECTORS)

        val results = files.map { file ->
            // A vector that cannot be read fails the run here; it is never
            // left out.
            val vector = strict.decodeFromString(Vector.serializer(), assets.open(file).use { it.readBytes() }.decodeToString())
            assertEquals(FULL_VERIFY_STAGE, vector.stage, "$file is packaged but is not a full-verify vector")
            val result = try {
                check(vector)
            } catch (e: Exception) {
                Result(vector.id, "could not run", listOf("${e.javaClass.simpleName}: ${e.message}"))
            }
            Log.i(TAG, "${result.id}: ${result.outcome}" + result.failures.joinToString("") { "\n    FAILED: $it" })
            result
        }

        val failed = results.filter { it.failures.isNotEmpty() }
        val summary = results.groupingBy { it.outcome.substringBefore(':') }.eachCount().toSortedMap()
        Log.i(TAG, "${results.size} vectors from ${pin.getProperty("commit")}: $summary, ${failed.size} failed")
        if (failed.isNotEmpty()) {
            fail(
                "${failed.size} of ${results.size} vectors failed:\n" +
                    failed.joinToString("\n") { result -> result.failures.joinToString("\n") { "${result.id}: $it" } },
            )
        }
        // An empty or half-read directory must not pass.
        assertEquals(pinned, results.size, "full-verify vectors run")
        assertEquals(results.size, results.map { it.id }.toSet().size, "vector IDs are unique")
        val unseen = REJECTED_AT_EXPIRY - results.map { it.id }.toSet()
        assertTrue(unseen.isEmpty(), "the known divergences $unseen name no vector; remove them")
    }

    /** Every file under [directory] in the assets, in a stable order. */
    private fun vectorFiles(directory: String): List<String> =
        assets.list(directory).orEmpty().sorted().flatMap { name ->
            val path = "$directory/$name"
            if (name.endsWith(".json")) listOf(path) else vectorFiles(path)
        }

    private fun check(vector: Vector): Result {
        val id = vector.id
        val input = vector.input
        val expected = vector.expected
        val failures = mutableListOf<String>()
        fun <T> same(what: String, want: T, got: T) {
            if (want != got) {
                failures += "$what: expected $want, got $got"
            }
        }

        same("input schema version", "1", input.schemaVersion)
        if (expected.accepted == (expected.code != null)) {
            failures += "the vector must expect either acceptance or a rejection code"
        }
        val roots = buildJsonObject {
            input.sigstoreTrustedRootJsonB64?.let { put("sigstore_trusted_root_json_b64", it) }
            input.amdRootCaPem?.let { put("amd_root_ca_pem", it) }
            input.askPem?.let { put("ask_pem", it) }
            input.intelSgxRootPem?.let { put("intel_sgx_root_pem", it) }
        }
        val verifier = checkNotNull(Mobile.newDangerousTestOnlyVerifier(roots.toString())) { "no verifier" }
        val document = Base64.getDecoder().decode(input.documentB64)
        val nonce = hex(input.nonceHex)
        val at = input.verificationTimeUnix
        check(at != 0L) { "every full-verify vector is frozen at a time" }

        val outcome: Any = try {
            GoAttestationVerifier.verification {
                verifier.dangerousTestOnlyVerifyAt(document, nonce, input.repo, input.project, at)
            }
        } catch (e: TinfoilException) {
            e
        }

        if (id in REJECTED_AT_EXPIRY) {
            // If the verifier library and the verifier come to agree at this
            // instant, this fails, and the exception is to be removed.
            same("the vector's verdict", true, expected.accepted)
            if (outcome is AttestationException) {
                same("layer", VerificationLayer.PROVENANCE, outcome.layer)
                if (outcome.message?.contains("freshness witnesses expired") != true) {
                    failures += "expected the expiry of the freshness witnesses, got: ${outcome.message}"
                }
            } else {
                failures += "expected the library's rejection at the freshness deadline, got $outcome"
            }
            return Result(id, "known divergence: rejected at the freshness deadline", failures)
        }

        when (outcome) {
            is TinfoilException -> {
                val code = code(outcome)
                if (expected.accepted) {
                    failures += "rejected with $code where acceptance was expected: ${outcome.message}"
                } else {
                    same("rejection code (${outcome.message})", expected.code, code)
                }
                return Result(id, "rejected: $code", failures)
            }
            is Verification -> {
                // The suite's adapter refuses a document without both channel
                // keys at the envelope; the library reports such a document
                // as verified, with the keys absent.
                if (outcome.tlsPublicKeyFingerprint == null || outcome.hpkePublicKey == null) {
                    same("verdict of a document without both channel keys", false, expected.accepted)
                    same("rejection code of a document without both channel keys", "ENVELOPE_REJECTED", expected.code)
                    return Result(id, "verified without both channel keys: ENVELOPE_REJECTED", failures)
                }
                if (!expected.accepted) {
                    failures += "accepted where ${expected.code} was expected"
                    return Result(id, "accepted", failures)
                }
                expected.codeDigest?.let { same("code digest", it, outcome.codeDigest) }
                expected.tlsPublicKeyFp?.let { same("TLS key fingerprint", it, outcome.tlsPublicKeyFingerprint) }
                expected.hpkePublicKey?.let { same("HPKE key", it, outcome.hpkePublicKey) }
                expected.codeMeasurement?.let { same("code measurement", Measurement(it.type, it.registers), outcome.codeMeasurement) }
                expected.enclaveMeasurement?.let {
                    same("enclave measurement", Measurement(it.type, it.registers), outcome.enclaveMeasurement)
                }
                // The times are the library's, read through this SDK's
                // decoding: appraised at the vector's time, and still fresh.
                val appraisedAt = Instant.ofEpochSecond(at)
                same("time of verification", appraisedAt, outcome.metadata.verifiedAt)
                if (!appraisedAt.isBefore(outcome.freshnessExpiresAt)) {
                    failures += "accepted at $appraisedAt with the freshness deadline ${outcome.freshnessExpiresAt}"
                }
                return Result(id, "accepted", failures)
            }
            else -> error("unreachable")
        }
    }

    /** The suite's rejection code for an exception, from its type and layer. */
    private fun code(error: TinfoilException): String = when (error) {
        is ConfigurationException -> "MALFORMED_INPUT"
        is AttestationException -> error.layer?.let { "${it.value.uppercase()}_REJECTED" } ?: "an attestation error without a layer"
        is NetworkException -> "a network error"
    }

    private fun hex(text: String): ByteArray {
        require(text.length % 2 == 0 && text.all { it in '0'..'9' || it in 'a'..'f' }) { "not lowercase hex: $text" }
        return ByteArray(text.length / 2) { text.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    private companion object {
        const val TAG = "TinfoilConformance"
        const val PIN = "conformance/pin.properties"
        const val VECTORS = "conformance/vectors"
        const val FULL_VERIFY_STAGE = "verify-attestation-v3"

        /** Unknown members are refused, and nothing is read leniently. */
        val strict = Json

        /**
         * The verifier library rejects a result that is no longer fresh, and
         * a result is expired at the instant of its freshness deadline. The
         * suite's verifier accepts a freshness witness that is exactly at its
         * maximum age, so the two part at the one instant that only a frozen
         * clock can hit, and this vector replays it.
         */
        val REJECTED_AT_EXPIRY = setOf("fr2-pos-at-max-age")
    }
}
