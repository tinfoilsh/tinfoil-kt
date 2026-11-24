package sh.tinfoil.internal.verification

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.NetworkException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.VerificationReport
import sh.tinfoil.VerifiedFacts
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
    /** Obtains a document, and reports a failure as a [TinfoilException]. */
    private val fetch: DocumentSource,
    private val check: VerificationCheck? = null,
    private val clock: () -> Instant = Instant::now,
    private val retryDelay: Duration = RETRY_DELAY,
) {
    /**
     * Throws for a [host] or [pin] that no verification could succeed with.
     * It performs no I/O.
     */
    @Throws(TinfoilException::class)
    fun checkOptions(host: String, pin: Pin) {
        verifier.attestationUrl(host, verifier.newNonce())
        verifier.checkPinVerifiability(pin)
    }

    /**
     * The report of a verification of [host] against [pin], from a document
     * that [fetch] obtains. Its verified facts are fresh, endorse a TLS key,
     * and have passed the caller's check.
     *
     * A failed fetch or a rejected document is tried once more, against
     * fresh evidence, after a short wait. An invalid option is not, and
     * neither is a rejection by the caller's check, which is a decision
     * about the evidence rather than a fault in getting it. [retried] is
     * given the failure of an attempt that is tried again, before the wait;
     * the outcome of the last attempt is this function's.
     */
    @Throws(TinfoilException::class)
    suspend fun attest(host: String, pin: Pin, retried: (TinfoilException) -> Unit = {}): VerificationReport {
        val first = try {
            return attempt(host, pin)
        } catch (e: Final) {
            throw e.error
        } catch (e: ConfigurationException) {
            throw e
        } catch (e: NetworkException) {
            e
        } catch (e: AttestationException) {
            e
        }
        retried(first)
        delay(retryDelay)
        try {
            return attempt(host, pin)
        } catch (e: Final) {
            throw e.error.apply { addSuppressed(first) }
        } catch (e: TinfoilException) {
            throw e.apply { addSuppressed(first) }
        }
    }

    /**
     * A report as [attest] returns it, from one attempt: a failure is not
     * tried again. It is for a caller that has other hosts to try.
     */
    @Throws(TinfoilException::class)
    suspend fun attestOnce(host: String, pin: Pin): VerificationReport =
        try {
            attempt(host, pin)
        } catch (e: Final) {
            throw e.error
        }

    private suspend fun attempt(host: String, pin: Pin): VerificationReport {
        val nonce = verifier.newNonce()
        val document = fetch(host, nonce)
        coroutineContext.ensureActive()
        val report = verifier.verify(document, nonce, pin)
        val facts = report.verifiedFacts
            ?: throw AttestationException("the verifier passed $host without verified facts")
        requireTransportKeys(facts)
        requireFresh(facts, host)
        try {
            check?.check(facts)
        } catch (e: Throwable) {
            // A cancelled verification is not the check's rejection.
            if (e is CancellationException) {
                coroutineContext.ensureActive()
            }
            // Anything else that the check throws rejects the enclave, an
            // Error included: a check that cannot finish has not accepted.
            throw Final(
                AttestationException(
                    "verification check rejected $host: ${e.message ?: e.javaClass.simpleName}",
                    cause = e,
                ),
            )
        }
        // The check may have run past the deadline; a retry fetches fresh
        // evidence.
        requireFresh(facts, host)
        return report
    }

    /** A result is expired at the instant of its deadline, not only after it. */
    private fun requireFresh(facts: VerifiedFacts, host: String) {
        if (!clock().isBefore(facts.freshnessExpiresAt)) {
            throw AttestationException("the verification of $host is past its freshness deadline")
        }
    }

    /**
     * Requires the keys that a transport binds traffic to, in the formats
     * that this SDK reads: a TLS key, and an HPKE key when one is endorsed.
     */
    private fun requireTransportKeys(facts: VerifiedFacts) {
        requireFormat(facts, TLS_KEY_ID, TLS_KEY_FORMAT)
        if (facts.tlsPublicKeyFingerprint == null) {
            throw AttestationException("the attestation document endorses no \"$TLS_KEY_ID\" key")
        }
        requireFormat(facts, HPKE_KEY_ID, HPKE_KEY_FORMAT)
    }

    private fun requireFormat(facts: VerifiedFacts, id: String, format: String) {
        val other = facts.cryptoMaterial.firstOrNull { it.id == id && it.format != format } ?: return
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
