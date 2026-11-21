package sh.tinfoil.internal.verification

import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Pin
import sh.tinfoil.Verification

/**
 * What makes every trust decision about an attestation document. It performs
 * no I/O: the caller fetches each document itself, from [attestationUrl] with
 * a nonce from [newNonce], and passes the bytes to [verify]. Code built on a
 * verifier depends on this interface, so that it can be tested with a
 * stand-in where the native library cannot load.
 *
 * Implementations are safe to use from several threads at once.
 */
internal interface AttestationVerifier {
    /**
     * A fresh random challenge for one attestation fetch. The same bytes go
     * to [attestationUrl] and to [verify], and are never reused.
     */
    @Throws(AttestationException::class)
    fun newNonce(): ByteArray

    /**
     * The HTTPS URL to GET [host]'s attestation document from with [nonce],
     * through [relay] when it is not null. Both are a host with an optional
     * port, not a URL.
     */
    @Throws(ConfigurationException::class, AttestationException::class)
    fun attestationUrl(host: String, relay: String?, nonce: ByteArray): String

    /**
     * Throws the [ConfigurationException] that [verify] would throw for
     * [pin] whatever the document, so that a client can refuse a pin before
     * any I/O. [verify] can still refuse a pin that passed, once it has the
     * document.
     */
    @Throws(ConfigurationException::class, AttestationException::class)
    fun checkPinVerifiability(pin: Pin)

    /**
     * Appraises [document], fetched with [nonce], against [pin], and returns
     * what it proved. A document that must not be trusted is an
     * [AttestationException], including one whose result is already past its
     * freshness deadline; an unusable argument is a [ConfigurationException].
     */
    @Throws(ConfigurationException::class, AttestationException::class)
    fun verify(document: ByteArray, nonce: ByteArray, pin: Pin): Verification
}
