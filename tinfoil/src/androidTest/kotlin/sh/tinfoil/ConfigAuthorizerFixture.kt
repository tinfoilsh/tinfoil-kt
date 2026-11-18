package sh.tinfoil

import java.security.MessageDigest

/**
 * An attestation document with plain config collateral and a quote that no
 * hardware signed, together with the runtime manifest and the platform policy
 * that its config pins. Verifying it with these two embedded and a config
 * authorizer reaches the authorizer, and then fails at the quote.
 *
 * The document, `fixtures/config-authorizer-document.json`, was generated
 * with the verifier library's own document builder for the all-zero nonce,
 * and is committed as generated.
 */
internal object ConfigAuthorizerFixture {
    private val zeros = "00".repeat(48)

    /** The smallest runtime manifest that the verifier accepts. */
    val runtime: ByteArray = (
        """{"version":"v0.15.0","igvm":{"format_version":1,""" +
            """"snp_launch":{"measurement":"${"ab".repeat(48)}"},""" +
            """"tdx_launch":{"mrtd":"${"cd".repeat(48)}","rtmr0":"$zeros","rtmr1":"$zeros",""" +
            """"rtmr2":"$zeros","rtmr3":"$zeros"}}}"""
        ).toByteArray()

    /** A platform policy that lists no machine. */
    val platform: ByteArray =
        """{"format":"https://tinfoil.sh/predicate/platform-endorsements/v2","machines":{},"policies":{}}"""
            .toByteArray()

    /** The config in the document, which pins [runtime] by its digest. */
    val config: ByteArray = "cvm-version: 0.15.0@sha256:${sha256Hex(runtime)}\n".toByteArray()

    /** The nonce that the document answers. */
    val nonce: ByteArray = ByteArray(32)

    val document: ByteArray = checkNotNull(
        ConfigAuthorizerFixture::class.java.classLoader
            ?.getResourceAsStream("fixtures/config-authorizer-document.json"),
    ) { "the fixture document is not packaged with the tests" }.use { it.readBytes() }

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
