package sh.tinfoil.internal.verification

import sh.tinfoil.ConfigAuthorizer
import sh.tinfoil.ConfigEndorsement
import sh.tinfoil.ConfigurationException
import sh.tinfoil.internal.verification.ConfigAuthorization.Rejection
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class ConfigAuthorizationTest {
    private fun b64(text: String): String = Base64.getEncoder().encodeToString(text.toByteArray())

    private val plain = """{"config":"${b64("cvm-version: x")}"}"""

    /** Records what it was asked, and throws [failure] if there is one. */
    private class Recorder(private val failure: Throwable? = null) : ConfigAuthorizer {
        val seen = mutableListOf<ConfigEndorsement>()

        override fun authorize(endorsement: ConfigEndorsement) {
            seen += endorsement
            failure?.let { throw it }
        }
    }

    @Test
    fun decodesAPlainConfig() {
        val endorsement = ConfigAuthorization.decodeEndorsement(plain)
        assertEquals(ConfigEndorsement("cvm-version: x".toByteArray()), endorsement)
        assertNull(endorsement.reference)
        assertNull(endorsement.sigstoreBundle)
        assertNull(endorsement.issuerCertificate)
    }

    @Test
    fun decodesACertifiedConfigWithItsExactBytes() {
        val bundle = """{"k": 1, "a":2}"""
        val endorsement = ConfigAuthorization.decodeEndorsement(
            """{"config":"${b64("c")}","reference":"sha256:ab","sigstore_bundle":"${b64(bundle)}","issuer_certificate_der":"AQI="}""",
        )
        assertEquals(
            ConfigEndorsement("c".toByteArray(), "sha256:ab", bundle.toByteArray(), byteArrayOf(1, 2)),
            endorsement,
        )
    }

    @Test
    fun emptyAndNullMembersAreAbsent() {
        val endorsement = ConfigAuthorization.decodeEndorsement(
            """{"config":"","reference":"","sigstore_bundle":"","issuer_certificate_der":null,"later_addition":1}""",
        )
        assertEquals(ConfigEndorsement(ByteArray(0)), endorsement)
    }

    @Test
    fun anApprovalReturns() {
        val recorder = Recorder()
        ConfigAuthorization.authorize(recorder, plain)
        assertEquals(listOf(ConfigEndorsement("cvm-version: x".toByteArray())), recorder.seen)
    }

    @Test
    fun whateverTheAuthorizerThrowsRejectsWithItsMessage() {
        val thrown = listOf<Pair<Throwable, String>>(
            IllegalStateException("config is not on the allow list") to "config is not on the allow list",
            ConfigurationException("not allowed") to "configuration error: not allowed",
            RuntimeException() to "java.lang.RuntimeException",
            RuntimeException("") to "java.lang.RuntimeException",
            InterruptedException("interrupted") to "interrupted",
            AssertionError("an error, not an exception") to "an error, not an exception",
            StackOverflowError() to "java.lang.StackOverflowError",
            object : RuntimeException() {
                override val message: String get() = throw IllegalStateException("no message for you")
            } to "",
        )
        for ((failure, expected) in thrown) {
            val rejection = assertFailsWith<Rejection>(failure.javaClass.name) {
                ConfigAuthorization.authorize(Recorder(failure), plain)
            }
            if (expected.isNotEmpty()) {
                assertEquals(expected, rejection.message)
            }
            assertFalse(rejection.message.isNullOrEmpty())
            assertNull(rejection.cause)
        }
    }

    @Test
    fun aPayloadThatCannotBeReadRejectsWithoutAskingTheAuthorizer() {
        val unreadable = listOf(
            null,
            "",
            "null",
            "[]",
            "{}",
            """{"reference":"sha256:ab"}""",
            """{"config":null}""",
            """{"config":7}""",
            """{"config":"${b64("c")}","reference":7}""",
            """{"config":"${b64("c")}"""",
            """{"config":"not base64!"}""",
            """{"config":"${b64("c")}","sigstore_bundle":"not base64!"}""",
            """{"config":"${b64("c")}","issuer_certificate_der":"not base64!"}""",
        )
        for (payload in unreadable) {
            val recorder = Recorder()
            assertFailsWith<Rejection>(payload) { ConfigAuthorization.authorize(recorder, payload) }
            assertEquals(emptyList(), recorder.seen, payload)
        }
    }

    @Test
    fun rejectionsNameTheMemberAndNeverQuoteThePayload() {
        val marker = "c2VjcmV0LWxvb2tpbmc"
        val malformed = listOf(
            """{"config":"$marker!"}""" to "config endorsement has an invalid config",
            """{"config":"","sigstore_bundle":"$marker!"}""" to "config endorsement has an invalid sigstore_bundle",
            """{"config":"","issuer_certificate_der":"$marker!"}""" to "config endorsement has an invalid issuer_certificate_der",
            """{"config":"$marker","reference":[}""" to "unreadable config endorsement",
            """{"config":["$marker"]}""" to "unreadable config endorsement",
        )
        for ((payload, expected) in malformed) {
            val rejection = assertFailsWith<Rejection> { ConfigAuthorization.decodeEndorsement(payload) }
            assertEquals(expected, rejection.message)
            assertNull(rejection.cause, "The cause could quote the payload.")
        }
    }
}
