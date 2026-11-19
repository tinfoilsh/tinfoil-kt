package sh.tinfoil

import kotlinx.coroutines.CancellationException
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.internal.EnclaveConnection
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.transport.AttestedCall
import sh.tinfoil.internal.transport.UserCacheSecret
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
 * goes out under the keys that the verification endorses: with
 * [TransportMode.Tls], only on a connection whose TLS certificate carries
 * the attested key; with [TransportMode.Ehbp], with its body sealed to the
 * attested HPKE key. The client verifies again by itself when a
 * verification reaches its freshness deadline or the enclave stops
 * holding the verified key.
 *
 * Send requests with [execute], or hand the client, which is an OkHttp
 * [Call.Factory], to a library that is built on OkHttp. Both follow the same
 * rules; see [execute].
 *
 * A client holds threads and connections until it is [closed][close]. It is
 * safe to use from several threads and coroutines at once.
 *
 * **Threads.** The suspending functions, [create] included, and [close] are
 * safe to call from a thread that must not block or touch the network, such
 * as Android's main thread: what they do there is brief, and the rest runs
 * on background threads. A response's body is another matter: reading it,
 * and closing it before it has been read to its end, is network I/O on the
 * thread that does it. So is a blocking [Call.execute] on a call from
 * [newCall].
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
     * created with, which with [TransportMode.Ehbp] may be a proxy's, or the
     * enclave's own origin, `https://<enclave>/`. Resolve request paths
     * against it, as in `baseUrl.resolve("v1/models")`.
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
     * wait: the shared verification still completes for the others. It is
     * safe to call from the main thread.
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
     * Cancellation and errors are those of [ensureVerified]. It is safe to
     * call from the main thread.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun reverify(): Verification = connection.reverify()

    /**
     * Sends [request] to the enclave and returns the response as soon as its
     * headers arrive. The body streams as it is read, and the caller closes
     * the response.
     *
     * It is safe to call from the main thread: a request body is read and
     * sent on background threads. The response's body is not read here, and
     * reading it blocks on the network, as does closing a response whose
     * body has not been read to its end: do both off the main thread.
     *
     * This describes a client with [TransportMode.Tls]; what
     * [TransportMode.Ehbp] changes follows it.
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
     * A request body is asked once for its length, its content type and
     * whether it can be written again, and is held to those answers: a body
     * that writes another number of bytes than the length that it declared
     * fails the request with an [IOException].
     *
     * When the client has a user cache secret, it is added to the body of a
     * `POST` whose path ends in `/chat/completions`, `/completions` or
     * `/responses`, as the member `user_cache_secret`, if the body is one
     * JSON object in which that member is absent or the empty string. The
     * rest of the body is sent byte for byte as it was given, and the
     * request's `Content-Length` is that of the new body. Only a member
     * with exactly that name counts: one whose name differs from it only by
     * case, such as `User_Cache_Secret`, is left as it was written, and the
     * client's member is added beside it. A non-empty
     * `user_cache_secret` string in the body is the request's own scope and
     * is kept. Any other body is sent unchanged: one that is not a JSON
     * object in UTF-8, one that names the member more than once or with a
     * value that is not a string,
     * and a body of more than 64 MiB that declares its length or can be
     * written again, which a router refuses for its size. To decide, the
     * body is read into memory before the request is sent: it is written
     * once, then, and what it wrote is what is sent. A request
     * to one of those paths whose body cannot be examined is refused with a
     * [ConfigurationException] before anything is sent, so that it does not
     * land in the cache that the API key's other clients share: a duplex
     * body, and a body that declares no length, can be written only once
     * and is longer than 64 MiB.
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
     * **With [TransportMode.Ehbp]**, connections are not pinned. They are
     * validated as the platform validates any HTTPS connection to
     * [baseUrl]'s host, which may be a proxy, and the request's body is
     * sealed to the attested HPKE key instead. The attestation shows what
     * holds that key; it does not show that [baseUrl]'s host is the
     * enclave. So this mode trusts the host that the client was created
     * with, the proxy's or else the enclave's own, and whoever holds a
     * certificate for it that the platform accepts, with everything that is
     * not sealed:
     * - Only bodies are sealed. Whatever ends the TLS connection reads the
     *   method, the URL and the headers of every request, and can change
     *   them, and the same goes for the status and the headers of every
     *   response.
     * - A request with a body is sent with the body sealed, as it is
     *   written, and its response's body is opened as it is read, one piece
     *   at a time. A piece that does not authenticate, or a body that ends
     *   inside a piece, fails the read with an [IOException], and nothing
     *   is delivered after that; what was delivered before is a true
     *   beginning of the enclave's response.
     * - **A body that ends between two pieces ends without an error.** The
     *   protocol does not mark the last piece, so whatever ends the TLS
     *   connection can end a sealed body early, after any piece, and the
     *   read cannot tell that from the enclave's own end. Reading a body to
     *   its end therefore shows that all of it is the enclave's, and not
     *   that it is all that the enclave sent. Only the content can show
     *   that: the `[DONE]` event that ends a stream of events, or text that
     *   parses as the one JSON value that it should be. Look for that end
     *   before acting on a response whose beginning alone could mislead.
     * - A request without a body, or with one that declares a length of
     *   zero, is not sealed, and neither is its response: the protocol
     *   cannot protect them. Nothing but the TLS connection to [baseUrl]'s
     *   host authenticates such a response. A body that declared a length
     *   of zero is sent as no bytes, whatever it writes.
     * - A response to a sealed request that reports success without being
     *   sealed fails with an [IOException], and so does a redirect. That a
     *   response is sealed has to show, whatever its status: the header
     *   that marks it as sealed is not sealed itself, so the read of the
     *   body fails if the body ends before it has yielded a byte. A sealed
     *   response with an empty body, an error included, is therefore not
     *   accepted in this mode, and neither is a status of 204 or 205.
     *   A response with an error status of 400 or above that is not marked
     *   as sealed is returned as it is: a proxy or a load balancer answers
     *   so when the request never reached the enclave. Nothing
     *   authenticates such a response, so treat it as a hint of what went
     *   wrong, and never as the enclave's answer. [executeRecoverable]
     *   returns no token for it.
     * - If the enclave answers that it cannot open the body, which it does
     *   before it reads any of it, it no longer holds the attested key: the
     *   client verifies the enclave again and sends the request once more,
     *   sealed to the new key, on the terms above. The first body was sent,
     *   sealed to a key that nothing holds any more; the headers were sent
     *   both times. That answer is not authenticated either, so a proxy can
     *   make the client verify again and send a request twice, without
     *   being able to read it.
     * - The HTTP client never sends a sealed body again by itself; a
     *   request without a body may be sent again as described above.
     * - The user cache secret is added to a body before it is sealed.
     * - A request is also refused before any I/O if it asks for a protocol
     *   upgrade, with an `Upgrade` header or `Connection: upgrade`, or is a
     *   `CONNECT`; if it sets a header whose name starts with `Ehbp-`, or
     *   `X-Tinfoil-Enclave-Url`; or if its body is duplex. Its URL is HTTP
     *   only if [baseUrl] is.
     * - When [baseUrl] is a proxy, each request carries the header
     *   `X-Tinfoil-Enclave-Url: https://<enclave>`, so that the proxy can
     *   forward it to the enclave that the client verified.
     *
     * @throws ConfigurationException for a request that is refused.
     * @throws NetworkException if the enclave has to be verified again and
     *   its attestation document cannot be fetched.
     * @throws AttestationException if the enclave is not to be trusted, or
     *   does not hold the verified key.
     * @throws IOException for any other failure to exchange the request,
     *   as the HTTP client or the sealing protocol reports it.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun execute(request: Request): Response = connection.send(request)

    /**
     * Sends [request] as [execute] does, and returns the response together
     * with its session recovery token: the key material that can open this
     * one response again later, without this client. Use it for a response
     * that the server keeps and that can be fetched again after an
     * interruption: store the token before reading the body.
     *
     * It requires [TransportMode.Ehbp]: with [TransportMode.Tls] no body is
     * sealed, there is no token, and the call fails with a
     * [ConfigurationException] before any network I/O.
     *
     * The token is this request's own, whatever else the client is sending.
     * If the request was sent again after the enclave rejected the key, it
     * is the token of the request that was answered. It is null when the
     * response is not sealed: the request had no body, or the response is
     * an error that something answered before the request reached the
     * enclave. A token does not show by itself that the enclave answered:
     * the body does, by being read without a failure. A token is known only
     * once the response's headers arrive.
     *
     * **The token is secret key material**; see [SessionRecoveryToken].
     *
     * Errors and cancellation are those of [execute].
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun executeRecoverable(request: Request): RecoverableResponse = connection.sendRecoverable(request)

    /**
     * Prepares [request] as a call that follows the rules of [execute], for
     * code that is written against OkHttp. Nothing is checked or sent until
     * the call is executed or enqueued.
     *
     * Every failure of the call, a refused request included, is an
     * [IOException]: this SDK's errors are [TinfoilException]s. A blocking
     * [Call.execute] blocks its thread for the whole exchange, and while
     * the enclave is verified, too, so it is never for the main thread;
     * [Call.enqueue] is.
     * [Call.cancel] works at any point, and [Call.timeout], which is unset
     * by default, spans the wait for a verification, the request and the
     * reading of the response body. As with [execute], the HTTP client may
     * send a request again by itself over a connection that passes the same
     * checks, unless its body can be written only once or is sealed.
     */
    override fun newCall(request: Request): Call = AttestedCall(connection, request)

    /**
     * Closes the client. Later requests and verifications fail with a
     * [ConfigurationException]. A verification in progress is cancelled, and
     * its waiters fail in the same way. Requests in flight are cancelled:
     * one that is waiting for its response fails with an [IOException], and
     * so does the next read of a response body that is still open. Every
     * connection is closed. Closing again does nothing.
     *
     * It is safe to call from any thread, the main thread included, and
     * returns at once. The client refuses requests from the moment this
     * returns; the requests in flight are cancelled and the connections
     * closed on a background thread, right afterwards.
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
         * It is safe to call from the main thread: the options are checked,
         * which loads the native verifier library the first time, and
         * everything is fetched and verified on background threads. A
         * caller that is cancelled just as the client is made does not
         * receive it, and the client is closed.
         *
         * @param enclave The enclave's host, with an optional port, such as
         *   `inference.tinfoil.sh`. Not a URL.
         * @param pin What the enclave must be running. A pin that names
         *   nothing is refused unless [verifier] authorizes configs by
         *   itself, with an embedded config or a config authorizer.
         * @param transportMode How requests are protected.
         *   [TransportMode.Tls], the default, protects the whole exchange on
         *   a direct connection; [TransportMode.Ehbp] protects only bodies,
         *   and works through a proxy.
         * @param baseUrl Where requests are sent, when it is not the root of
         *   the enclave's origin: an absolute URL without user information,
         *   a query or a fragment. With [TransportMode.Tls] it must be on
         *   the enclave's own HTTPS origin, because a pinned connection
         *   cannot pass through a proxy. With [TransportMode.Ehbp] it may
         *   also be a proxy on another origin, which forwards each request
         *   to the enclave that the request's `X-Tinfoil-Enclave-Url` header
         *   names. A proxy reads everything that is not sealed, so it must
         *   use HTTPS; `http://` is accepted only for `localhost` or a
         *   loopback IP address, on any port, for a proxy on the same
         *   machine. With [TransportMode.Ehbp], requests to a base URL on
         *   `localhost` or a loopback IP address, over HTTP or HTTPS, are
         *   sent there directly, whatever HTTP proxy the system is
         *   configured with: such a proxy would otherwise be handed them.
         *   On Android, cleartext HTTP also has to be permitted by the
         *   app's network security configuration.
         * @param attestationRelay A host, with an optional port, that fetches
         *   the enclave's attestation document on the client's behalf. It is
         *   not trusted: the document is verified whoever delivers it.
         * @param verifier The trust policy. Null selects the defaults.
         * @param userCacheSecret The prompt-cache scope of the client's
         *   requests, for an enclave that is one of Tinfoil's routers; other
         *   enclaves do not read it. Null or empty sends none. It is added
         *   to the JSON body of a `POST` to a chat, completions or responses
         *   path, and such a request is refused if its body cannot be
         *   examined; see [execute]. Use an opaque random value, not a user
         *   ID or an API key.
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
         * @throws AttestationException if the enclave is not to be trusted,
         *   or endorses no key for [transportMode]: no HPKE key, for
         *   [TransportMode.Ehbp].
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            enclave: String,
            pin: Pin,
            transportMode: TransportMode = TransportMode.Tls,
            baseUrl: String? = null,
            attestationRelay: String? = null,
            verifier: Verifier? = null,
            userCacheSecret: String? = null,
            verificationCheck: VerificationCheck? = null,
            onVerificationResult: ((Result<Verification>) -> Unit)? = null,
        ): EnclaveHttpClient = create(
            enclave, pin, transportMode, baseUrl, attestationRelay, verifier, userCacheSecret, verificationCheck,
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
            userCacheSecret: String?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            internals: Internals,
        ): EnclaveHttpClient = Background.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            val client = unverified(
                enclave, pin, transportMode, baseUrl, attestationRelay, verifier, userCacheSecret, verificationCheck,
                onVerificationResult, internals,
            )
            try {
                client.ensureVerified()
            } catch (e: Throwable) {
                client.close()
                throw e
            }
            return@creating client
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
            userCacheSecret: String?,
            verificationCheck: VerificationCheck?,
            onVerificationResult: ((Result<Verification>) -> Unit)?,
            internals: Internals,
        ): EnclaveHttpClient = EnclaveHttpClient(
            EnclaveConnection.create(
                enclave, pin, transportMode, baseUrl, attestationRelay, verifier ?: Verifier(),
                UserCacheSecret.of(userCacheSecret), verificationCheck, onVerificationResult, internals,
            ),
        )
    }
}
