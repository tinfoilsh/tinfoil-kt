package sh.tinfoil.internal.verification

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import sh.tinfoil.AttestationException
import sh.tinfoil.AttestationFetcher
import sh.tinfoil.AttestationRelay
import sh.tinfoil.NetworkException
import sh.tinfoil.TinfoilException
import kotlin.time.Duration

/** Obtains an enclave's attestation document for a nonce. */
internal typealias DocumentSource = suspend (host: String, nonce: ByteArray) -> ByteArray

/** Where a client obtains attestation documents, as its option says. */
internal object DocumentSources {
    /**
     * The source for [option]: the enclave itself when it is null, a
     * relay's URL fetched with [fetcher] for an [AttestationRelay], and
     * otherwise the caller's own function, whose failures are classified
     * here.
     */
    fun of(option: AttestationFetcher?, verifier: AttestationVerifier, fetcher: () -> DocumentFetcher): DocumentSource =
        when (option) {
            null -> { host, nonce ->
                val url = direct(verifier, host, nonce)
                fetcher().fetch(url)
            }
            is AttestationRelay -> { host, nonce ->
                val url = option.documentUrl(host, nonce)
                fetcher().fetch(url, allowLoopbackHttp = true)
            }
            else -> { host, nonce -> fromCaller(option, host, nonce) }
        }

    private fun direct(verifier: AttestationVerifier, host: String, nonce: ByteArray) =
        verifier.attestationUrl(host, nonce).toHttpUrlOrNull()?.takeIf { it.isHttps }
            ?: throw AttestationException("the verifier returned no usable attestation URL")

    /**
     * The document that the caller's [fetcher] returns for [host] and
     * [nonce], within [timeout]. A [TinfoilException] that it throws keeps
     * its category, and anything else that it throws, or the end of its
     * time, is a [NetworkException] that keeps it as its cause. The
     * cancellation of the coroutine that this runs in, which is the
     * client's, passes through; a [CancellationException] that the fetcher
     * throws while that coroutine is active is the fetcher's own failure.
     */
    suspend fun fromCaller(
        fetcher: AttestationFetcher,
        host: String,
        nonce: ByteArray,
        timeout: Duration = DocumentFetcher.TIMEOUT,
        maxBytes: Long = DocumentFetcher.MAX_BODY_BYTES,
    ): ByteArray {
        val document = try {
            // A copy, so that nothing the fetcher does to it reaches the
            // nonce that the document is verified against.
            withTimeout(timeout) { fetcher.fetchAttestation(host, nonce.copyOf()) }
        } catch (e: TinfoilException) {
            throw e
        } catch (e: CancellationException) {
            // The client's own cancellation, as when it closes, passes
            // through. Anything else, its timeout included, is the fetch's
            // failure.
            currentCoroutineContext().ensureActive()
            val what = if (e is TimeoutCancellationException) "timed out after $timeout" else "was cancelled"
            throw NetworkException("fetching the attestation document of $host $what", cause = e)
        } catch (e: Exception) {
            throw NetworkException(
                "fetching the attestation document of $host: ${e.message ?: e.javaClass.simpleName}",
                cause = e,
            )
        }
        // A function that Java calls can return null whatever its type says.
        @Suppress("SENSELESS_COMPARISON")
        if (document == null) {
            throw NetworkException("fetching the attestation document of $host returned no document")
        }
        if (document.size > maxBytes) {
            throw NetworkException("the attestation document of $host exceeds $maxBytes bytes")
        }
        return document
    }
}
