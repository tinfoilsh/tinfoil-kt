package sh.tinfoil.internal.verification

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.NetworkException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import java.time.Instant
import kotlin.coroutines.coroutineContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Verifies an enclave: it fetches the enclave's attestation document and has
 * the verifier appraise it, which makes every trust decision. It keeps no
 * state; its caller decides when to verify again.
 */
internal class Attestor(
    private val verifier: AttestationVerifier,
    private val fetch: suspend (HttpUrl) -> ByteArray,
    private val check: VerificationCheck? = null,
    private val clock: () -> Instant = Instant::now,
    private val retryDelay: Duration = RETRY_DELAY,
) {
    /**
     * Throws for a [host], [relay] or [pin] that no verification could
     * succeed with. It performs no I/O.
     */
    @Throws(TinfoilException::class)
    fun checkOptions(host: String, relay: String?, pin: Pin) {
        attestationUrl(host, relay, verifier.newNonce())
        verifier.checkPinVerifiability(pin)
    }

    /**
     * A verification of [host] against [pin], fetched through [relay] when
     * it is not null. The result is fresh, endorses a TLS key, and has passed
     * the caller's check.
     *
     * A failed fetch or a rejected document is tried once more, against
     * fresh evidence, after a short wait. An invalid option is not, and
     * neither is a rejection by the caller's check, which is a decision
     * about the evidence rather than a fault in getting it.
     */
    @Throws(TinfoilException::class)
    suspend fun attest(host: String, relay: String?, pin: Pin): Verification {
        val first = try {
            return attempt(host, relay, pin)
        } catch (e: Final) {
            throw e.error
        } catch (e: ConfigurationException) {
            throw e
        } catch (e: NetworkException) {
            e
        } catch (e: AttestationException) {
            e
        }
        delay(retryDelay)
        try {
            return attempt(host, relay, pin)
        } catch (e: Final) {
            throw e.error.apply { addSuppressed(first) }
        } catch (e: TinfoilException) {
            throw e.apply { addSuppressed(first) }
        }
    }

    private suspend fun attempt(host: String, relay: String?, pin: Pin): Verification {
        val nonce = verifier.newNonce()
        val document = fetch(attestationUrl(host, relay, nonce))
        coroutineContext.ensureActive()
        val verification = verifier.verify(document, nonce, pin)
        requireTransportKeys(verification)
        requireFresh(verification, host)
        try {
            check?.check(verification)
        } catch (e: Exception) {
            // A cancelled verification is not the check's rejection.
            if (e is CancellationException) {
                coroutineContext.ensureActive()
            }
            throw Final(
                AttestationException(
                    "verification check rejected $host: ${e.message ?: e.javaClass.simpleName}",
                    cause = e,
                ),
            )
        }
        // The check may have run past the deadline; a retry fetches fresh
        // evidence.
        requireFresh(verification, host)
        return verification
    }

    private fun attestationUrl(host: String, relay: String?, nonce: ByteArray): HttpUrl {
        val url = verifier.attestationUrl(host, relay, nonce).toHttpUrlOrNull()
        if (url == null || !url.isHttps) {
            throw AttestationException("the verifier returned no usable attestation URL")
        }
        return url
    }

    /** A result is expired at the instant of its deadline, not only after it. */
    private fun requireFresh(verification: Verification, host: String) {
        if (!clock().isBefore(verification.freshnessExpiresAt)) {
            throw AttestationException("the verification of $host is past its freshness deadline")
        }
    }

    /**
     * Requires the keys that a transport binds traffic to, in the formats
     * that this SDK reads: a TLS key, and an HPKE key when one is endorsed.
     */
    private fun requireTransportKeys(verification: Verification) {
        requireFormat(verification, TLS_KEY_ID, TLS_KEY_FORMAT)
        if (verification.tlsPublicKeyFingerprint == null) {
            throw AttestationException("the attestation document endorses no \"$TLS_KEY_ID\" key")
        }
        requireFormat(verification, HPKE_KEY_ID, HPKE_KEY_FORMAT)
    }

    private fun requireFormat(verification: Verification, id: String, format: String) {
        val other = verification.cryptoMaterial.firstOrNull { it.id == id && it.format != format } ?: return
        throw AttestationException("the endorsed \"$id\" key has the format \"${other.format}\", not \"$format\"")
    }

    /** An error that ends a verification without another attempt. */
    private class Final(val error: AttestationException) : Exception()

    internal companion object {
        val RETRY_DELAY: Duration = 1.seconds

        const val TLS_KEY_ID: String = "tls"
        const val TLS_KEY_FORMAT: String = "https://tinfoil.sh/key/spki-fp-sha256/v1"
        const val HPKE_KEY_ID: String = "hpke"
        const val HPKE_KEY_FORMAT: String = "https://tinfoil.sh/key/x25519-hpke/v1"
    }
}
