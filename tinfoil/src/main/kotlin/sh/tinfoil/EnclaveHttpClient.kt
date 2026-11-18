package sh.tinfoil

import kotlinx.coroutines.CancellationException
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.internal.EnclaveConnection
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.transport.AttestedCall
import java.io.IOException

/**
 * Decides whether an enclave whose attestation has verified may be used.
 *
 * It is called with each verification that passes the [Verifier], before the
 * client uses the enclave's keys: when the client is created and every time
 * it verifies again. Return to accept the enclave. Throw to reject it: the
 * verification then fails with an [AttestationException] that keeps the
 * thrown exception as its cause, and is not tried again.
 *
 * Requests wait while it runs, so keep it fast. It may be called from
 * several threads at once. It runs inside the verification that it judges,
 * so it must not call back into the client: `ensureVerified`, `reverify` or
 * a request made from it would wait for the verification that is waiting
 * for it. Anything that it throws rejects the enclave, an [Error] included.
 */
public fun interface VerificationCheck {
    /**
     * @param verification What the enclave's attestation proved.
     * @throws Exception to reject the enclave.
     */
    @Throws(Exception::class)
    public fun check(verification: Verification)
}

/**
 * An HTTP client whose requests reach only one attested enclave.
 *
 * [create] verifies the enclave before it returns a client. From then on,
 * every request waits for a verification that is valid at that moment, and
 * goes out only on a connection whose TLS certificate carries the key that
 * the verification endorses. The client verifies again by itself when a
 * verification reaches its freshness deadline or the enclave stops
 * presenting the verified key.
 *
 * Send requests with [execute], or hand the client, which is an OkHttp
 * [Call.Factory], to a library that is built on OkHttp. Both follow the same
 * rules; see [execute].
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 */
public class EnclaveHttpClient private constructor(
    private val connection: EnclaveConnection,
) : Call.Factory, AutoCloseable {
    /**
     * The enclave that the client verifies: its host, with a port when one
     * was given.
     */
    public val enclave: String get() = connection.enclave

    /** What the enclave is verified against. */
    public val pin: Pin get() = connection.pin

    /**
     * The URL that requests are sent under: the base URL that the client was
     * created with, or the enclave's own origin, `https://<enclave>/`.
     * Resolve request paths against it, as in `baseUrl.resolve("v1/models")`.
     */
    public val baseUrl: HttpUrl get() = connection.baseUrl

    /** How the client protects its requests. */
    public val transportMode: TransportMode get() = connection.transportMode

    /**
     * The last successful verification, without checking it. It may have
     * expired or been rejected since; use [ensureVerified] for one that is
     * valid.
     */
    public val current: Verification? get() = connection.current

    /**
     * Returns a verification that is valid now, verifying first only if the
     * last one has reached its freshness deadline or the enclave has
     * rejected its key. Returning means that requests can be sent.
     *
     * Callers that need a verification while one is running share it, its
     * failure included. Cancelling the coroutine ends only this caller's
     * wait: the shared verification still completes for the others.
     *
     * @throws ConfigurationException if the client is closed.
     * @throws NetworkException if the attestation document cannot be fetched.
     * @throws AttestationException if the enclave is not to be trusted.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun ensureVerified(): Verification = connection.ensureVerified()

    /**
     * Verifies the enclave again, even if the last verification is still
     * valid, and returns the new verification.
     *
     * A failure here, whether the document could not be fetched or the
     * enclave was rejected, does not withdraw the last verification: while
     * that one is before its freshness deadline, requests keep going out
     * under it, to connections that still present its key. To stop using an
     * enclave whose new verification was rejected, [close] the client.
     *
     * A call made while a verification is running shares that one.
     * Cancellation and errors are those of [ensureVerified].
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun reverify(): Verification = connection.reverify()

    /**
     * Sends [request] to the enclave and returns the response as soon as its
     * headers arrive. The body streams as it is read, and the caller closes
     * the response.
     *
     * Before any network I/O, the request is refused with a
     * [ConfigurationException] if
     * - its URL is not on [baseUrl]'s origin, which is to say its scheme,
     *   host and port, so that credentials in its headers go nowhere else;
     * - its URL is not HTTPS, or carries a user name or a password;
     * - it sets the `Host` header; or
     * - the client is closed.
     *
     * The request then waits for a verification that is valid now, as
     * [ensureVerified] returns it, and is written only to a connection that
     * the platform's TLS validation accepts and whose certificate carries the
     * attested key. If the enclave presents another key, which shows before
     * any of the request is written to that connection, the client verifies
     * the enclave again and sends the request once more, headers included,
     * unless its body can be sent only once. If that is the case, or the new
     * verification's key is refused too, the request fails with an
     * [AttestationException]. Cancelling the coroutine before the request is
     * sent again prevents it.
     *
     * A redirect is not followed and an authentication challenge is not
     * answered: the response is returned as it is. No cookies are kept and
     * nothing is cached.
     *
     * The HTTP client may send a request again by itself, always to the same
     * URL and only over a connection that passes the same checks: when a
     * connection fails, which can be after part or all of the request was
     * written to it; on a `408` response; and on a `503` response with
     * `Retry-After: 0`. The enclave can therefore receive a request twice,
     * a `POST` included. A request whose body can be written only once
     * ([okhttp3.RequestBody.isOneShot]) is never sent again once any of it
     * has been written, nor after a `408` or a `503`. A response may go ten minutes without a byte
     * before the request fails; bound the whole exchange with a coroutine
     * timeout.
     *
     * Cancelling the coroutine while it waits cancels the request. Once the
     * response is returned, closing it ends the exchange.
     *
     * @throws ConfigurationException for a request that is refused.
     * @throws NetworkException if the enclave has to be verified again and
     *   its attestation document cannot be fetched.
     * @throws AttestationException if the enclave is not to be trusted, or
     *   does not hold the verified key.
     * @throws IOException for any other failure to exchange the request,
     *   as the HTTP client reports it.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun execute(request: Request): Response = connection.send(request)

    /**
     * Prepares [request] as a call that follows the rules of [execute], for
     * code that is written against OkHttp. Nothing is checked or sent until
     * the call is executed or enqueued.
     *
     * Every failure of the call, a refused request included, is an
     * [IOException]: this SDK's errors are [TinfoilException]s. A blocking
     * [Call.execute] blocks its thread while the enclave is verified, too.
     * [Call.cancel] works at any point, and [Call.timeout], which is unset
     * by default, spans the wait for a verification, the request and the
     * reading of the response body. As with [execute], the HTTP client may
     * send a request again by itself over a connection that passes the same
     * checks, unless its body can be written only once.
     */
    override fun newCall(request: Request): Call = AttestedCall(connection, request)

    /**
     * Closes the client. Later requests and verifications fail with a
     * [ConfigurationException]. A verification in progress is cancelled, and
     * its waiters fail in the same way. Requests in flight are cancelled:
     * one that is waiting for its response fails with an [IOException], and
     * so does the next read of a response body that is still open. Every
     * connection is closed. Closing again does nothing.
     */
    override fun close() {
        connection.close()
    }

    public companion object {
        /**
         * Creates a client for [enclave] and verifies the enclave against
         * [pin] before returning.
         *
         * Every argument is checked before any network I/O, so a
         * misconfigured client fails with a [ConfigurationException] without
         * contacting anything; an enclave that does not verify fails here
         * rather than on the first request.
         *
         * @param enclave The enclave's host, with an optional port, such as
         *   `inference.tinfoil.sh`. Not a URL.
         * @param pin What the enclave must be running. A pin that names
         *   nothing is refused unless [verifier] authorizes configs by
         *   itself, with an embedded config or a config authorizer.
         * @param transportMode How requests are protected. Only
         *   [TransportMode.Tls] is available in this version.
         * @param baseUrl Where requests are sent, when it is not the root of
         *   the enclave's origin: an absolute HTTPS URL without user
         *   information, a query or a fragment. With [TransportMode.Tls] it
         *   must be on the enclave's own origin, because a pinned connection
         *   cannot pass through a proxy.
         * @param attestationRelay A host, with an optional port, that fetches
         *   the enclave's attestation document on the client's behalf. It is
         *   not trusted: the document is verified whoever delivers it.
         * @param verifier The trust policy. Null selects the defaults.
         * @param verificationCheck Called with each verification that passes
         *   [verifier], before the enclave's keys are used; it throws to
         *   reject the enclave. It must not call back into the client.
         * @param onVerificationResult Called with the outcome of every
         *   verification that the client runs, here and later: the
         *   verification, or the [TinfoilException] that it failed with. It
         *   only observes, so anything that it throws is ignored. It is
         *   called once the verification is over, on a thread of the
         *   client's: requests that waited for the verification, and this
         *   function itself, may already have gone on by then. It may call
         *   back into the client, and may be called from several threads.
         * @throws ConfigurationException if an argument is invalid.
         * @throws NetworkException if the attestation document cannot be
         *   fetched.
         * @throws AttestationException if the enclave is not to be trusted.
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            enclave: String,
            pin: Pin,
            transportMode: TransportMode = TransportMode.Tls,
            baseUrl: String? = null,
            attestationRelay: String? = null,
            verifier: Verifier? = null,
            verificationCheck: VerificationCheck? = null,
            onVerificationResult: ((Result<Verification>) -> Unit)? = null,
        ): EnclaveHttpClient = create(
            enclave, pin, transportMode, baseUrl, attestationRelay, verifier, verificationCheck,
            onVerificationResult, Internals(),
        )

        /** [create] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun create(
            enclave: String,
            pin: Pin,
            transportMode: TransportMode,
            baseUrl: String?,
            attestationRelay: String?,
            verifier: Verifier?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            internals: Internals,
        ): EnclaveHttpClient {
            val client = unverified(
                enclave, pin, transportMode, baseUrl, attestationRelay, verifier, verificationCheck,
                onVerificationResult, internals,
            )
            try {
                client.ensureVerified()
            } catch (e: Throwable) {
                client.close()
                throw e
            }
            return client
        }

        /** A client that is checked but not yet verified. It performs no I/O. */
        @JvmSynthetic
        internal fun unverified(
            enclave: String,
            pin: Pin,
            transportMode: TransportMode,
            baseUrl: String?,
            attestationRelay: String?,
            verifier: Verifier?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            internals: Internals,
        ): EnclaveHttpClient = EnclaveHttpClient(
            EnclaveConnection.create(
                enclave, pin, transportMode, baseUrl, attestationRelay, verifier ?: Verifier(), verificationCheck,
                onVerificationResult, internals,
            ),
        )
    }
}
