package sh.tinfoil

import kotlinx.coroutines.CancellationException
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.internal.EnclaveConnection
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.RouteSettings
import sh.tinfoil.internal.transport.AttestedCall
import sh.tinfoil.internal.verification.VerifierInputs
import java.io.IOException

/**
 * Decides whether an enclave whose attestation has verified may be used.
 *
 * It is called with the verified facts of each verification that passes the
 * trust and the policy, before the client uses the enclave's keys: when the
 * client is created and every time it verifies again. It is never called
 * for a verification that fails, and never sees a report or partial facts. Return to accept the enclave. Throw to reject it: the
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
     * @param facts What the enclave's attestation proved.
     * @throws Exception to reject the enclave.
     */
    @Throws(Exception::class)
    public fun check(facts: VerifiedFacts)
}

/**
 * An HTTP client whose requests reach only one attested enclave.
 *
 * [create] verifies the enclave before it returns a client. From then on,
 * every request waits for a verification that is valid at that moment, and
 * goes out under the keys that the verification endorses: with
 * [Transport.Tls], only on a connection whose TLS certificate carries
 * the attested key; with [Transport.Ehbp], with its body sealed to the
 * attested HPKE key. The client verifies again by itself when a
 * verification reaches its freshness deadline, when the enclave stops
 * holding the verified key, and after a verification that was to replace
 * it has been rejected.
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
    /**
     * What the enclave is verified under: the trust argument that the
     * client was created with. It is immutable, so it is the caller's to
     * keep.
     */
    public val trust: Trust,
) : AttestedHttpClient {
    /**
     * The enclave that the client verifies: its host, with a port when one
     * was given.
     */
    public val enclave: String get() = connection.enclave

    /**
     * The URL that requests are sent under: the proxy URL of a
     * [Transport.Ehbp], ending with `/`, or the enclave's own origin,
     * `https://<enclave>/`. Resolve request paths against it, as in
     * `baseUrl.resolve("v1/models")`.
     */
    override val baseUrl: HttpUrl get() = connection.baseUrl

    /** How the client protects its requests, as it was created with. */
    public val transport: Transport get() = connection.transport

    /**
     * Returns the report of the verification that the client's requests are
     * sent under now, without any I/O: the latest verification that passed,
     * while it is before its freshness deadline and has not been withdrawn.
     * It is null before the first verification passes, once the
     * verification has reached its freshness deadline, after the enclave
     * refused its key, and after a verification that was to replace it
     * failed with an [AttestationException], such as a [reverify] that the
     * verifier rejected, until a later verification passes. A [reverify]
     * that fails in any other way, such as with a [NetworkException],
     * leaves it as it was while it is fresh, though
     * [lastVerificationAttempt] then returns the failure.
     *
     * The client does not verify again in the background, so once the
     * verification has reached its freshness deadline this returns null
     * until the next request or [ensureVerified] verifies the enclave
     * again; that is not a failure. What it returns holds when it is
     * called: the verification can reach its deadline right afterwards. Use
     * [ensureVerified] to find out whether requests can be sent, verifying
     * when that is needed.
     */
    public fun currentVerification(): VerificationReport? = connection.currentVerification

    /**
     * Returns the outcome of the most recent attempt to verify the enclave,
     * without any I/O: [VerificationAttempt.Passed] with the report of an
     * attempt that passed, or [VerificationAttempt.Failed] with the
     * [TinfoilException] that the client reported for one that failed, the
     * same as [EnclaveOptions.onVerificationAttempt] was given. It is null
     * before the first attempt has an outcome.
     *
     * Every attempt counts: the first verification, one that is tried
     * again, and each that a refused key, a freshness deadline or
     * [reverify] starts. A failure is never hidden behind an earlier
     * success. When the verifier rejected the attestation document, the
     * failure is an [AttestationException] whose cause is a
     * [VerificationException], which carries the report with the step
     * that failed and the partial facts.
     *
     * A report that it returns is not checked: it may have reached its
     * freshness deadline or been withdrawn since. [currentVerification]
     * returns the verification that requests are sent under now.
     */
    public fun lastVerificationAttempt(): VerificationAttempt? = connection.lastVerificationAttempt

    /**
     * Returns the report of a verification that is valid now, verifying
     * first only if the last one has reached its freshness deadline, the
     * enclave has rejected its key, or a verification that was to replace
     * it has failed with an [AttestationException]. Returning means that
     * requests can be sent. The report's verified facts are set.
     *
     * Callers that need a verification while one is running share it, its
     * failure included. Cancelling the coroutine ends only this caller's
     * wait: the shared verification still completes for the others. It is
     * safe to call from the main thread.
     *
     * @throws ConfigurationException if the client is closed.
     * @throws NetworkException if the attestation document cannot be fetched.
     * @throws AttestationException if the enclave is not to be trusted. When
     *   the verifier rejected the document, its cause is a
     *   [VerificationException] with the report.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun ensureVerified(): VerificationReport = connection.ensureVerified()

    /**
     * Verifies the enclave again, even if the last verification is still
     * valid, and returns the new verification's report.
     *
     * A failure is thrown here, and what happens to the last verification
     * depends on its kind:
     * - An [AttestationException], which says that the enclave is not to be
     *   trusted now, withdraws the last verification even if it is still
     *   before its freshness deadline. No request that starts afterwards is
     *   sent under it, and its idle connections are closed; requests that
     *   are already in flight may complete. The next request, or
     *   [ensureVerified], verifies the enclave again: it fails if the
     *   enclave still does not pass, and goes through if it does.
     * - A [NetworkException] or a [ConfigurationException] says nothing
     *   about the enclave, so the last verification stays in use until its
     *   freshness deadline.
     *
     * Cancelling the coroutine ends only this caller's wait, and changes
     * nothing: the verification runs on, and its outcome applies as above.
     *
     * A call made while a verification is running shares that one.
     * Cancellation and errors are those of [ensureVerified]. It is safe to
     * call from the main thread.
     */
    @Throws(IOException::class, CancellationException::class)
    public suspend fun reverify(): VerificationReport = connection.reverify()

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
     * This describes a client with [Transport.Tls]; what
     * [Transport.Ehbp] changes follows it.
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
     * The client never adds or changes a `user_cache_secret` member: a
     * request to Tinfoil's router that should have a prompt-cache scope of
     * its own carries one in its body.
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
     * **With [Transport.Ehbp]**, connections are not pinned. They are
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
     * - A request without a body, or with an empty one, is not sealed, and
     *   neither is its response: the protocol cannot protect them. Nothing
     *   but the TLS connection to [baseUrl]'s host authenticates such a
     *   response. A body is empty if it declares a length of zero; none of
     *   its bytes are sent, and if it writes some after all, the request
     *   fails. A body that does not declare its length is empty if it
     *   writes nothing: it is asked to write before the request is sent,
     *   on a thread of the sealing library's, and is sealed from its first
     *   byte on.
     * - A response to a sealed request with a status below 400 that is
     *   not sealed fails with an [IOException], and so does a redirect,
     *   sealed or not. That a response is sealed has to show, whatever
     *   its status: the header that marks it as sealed is not sealed
     *   itself, so the read of the body fails unless a piece of the body
     *   authenticates. Below a status of 400, a piece that seals no bytes
     *   is enough, which is what the enclave sends for an empty body: such
     *   a response is read as empty. From 400 on, the body has to yield a
     *   byte, so a sealed error with an empty body is not accepted in this
     *   mode. Neither is a status of 204 or 205, which cannot have a body.
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
     * It requires [Transport.Ehbp]: with [Transport.Tls] no body is
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
         * Creates a client for [enclave] and verifies the enclave under
         * [trust] and the [policy][EnclaveOptions.policy] before returning.
         *
         * Everything else is an option, set in the block that [options] is
         * and described by [EnclaveOptions]:
         *
         * ```
         * val client = EnclaveHttpClient.create("enclave.example.com", Trust.RepoPin("org/repo")) {
         *     transport = Transport.Ehbp(proxyUrl = "https://proxy.example.com/")
         * }
         * ```
         *
         * Every argument and option is checked before any network I/O, so a
         * misconfigured client fails with a [ConfigurationException] without
         * contacting anything; an enclave that does not verify fails here
         * rather than on the first request.
         *
         * It is safe to call from the main thread. [options] runs once, on
         * the calling thread, before anything else, and what it set is
         * copied as it returns; what it throws is thrown from here as it
         * is, and nothing is contacted. The options are then checked, which
         * loads the native verifier library the first time, and everything
         * is fetched and verified on background threads. A caller that is
         * cancelled just as the client is made does not receive it, and
         * the client is closed.
         *
         * @param enclave The enclave's host, with an optional port, such as
         *   `inference.tinfoil.sh`. Not a URL.
         * @param trust Who vouches for the config that the enclave runs;
         *   see [Trust]. A variant that no verification could pass, such as
         *   a [Trust.RepoPin] with an empty or malformed repository, is
         *   refused before any network I/O. A null from Java throws the
         *   [NullPointerException] that names the parameter.
         * @param options Sets the options; see [EnclaveOptions]. Without
         *   it, every option has its default.
         * @throws ConfigurationException if an argument or an option is
         *   invalid.
         * @throws NetworkException if the attestation document cannot be
         *   fetched.
         * @throws AttestationException if the enclave is not to be trusted,
         *   or endorses no key for the transport mode: no HPKE key, for
         *   [Transport.Ehbp].
         */
        @Throws(IOException::class, CancellationException::class)
        public suspend fun create(
            enclave: String,
            trust: Trust,
            options: EnclaveOptions.() -> Unit = {},
        ): EnclaveHttpClient = create(enclave, trust, Internals(), options)

        /** [create] with the parts that tests replace. */
        @JvmSynthetic
        internal suspend fun create(
            enclave: String,
            trust: Trust,
            internals: Internals,
            options: EnclaveOptions.() -> Unit,
        ): EnclaveHttpClient = create(enclave, trust, enclaveSettings(options), internals)

        /** [create] with options that were read already. */
        @JvmSynthetic
        internal suspend fun create(
            enclave: String,
            trust: Trust,
            settings: RouteSettings,
            internals: Internals,
        ): EnclaveHttpClient = Background.creating {
            // Checking the options, which calls into the verifier library,
            // and everything after it run on a background thread, so that
            // any thread may call this.
            val client = unverified(enclave, trust, settings, internals)
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
            trust: Trust,
            settings: RouteSettings,
            internals: Internals,
        ): EnclaveHttpClient {
            val inputs = VerifierInputs.of(trust)
            val verifier = internals.newVerifier(inputs.config, VerifierInputs.policy(settings.policy))
            return EnclaveHttpClient(
                EnclaveConnection.create(
                    enclave, inputs.pin, settings.transport, settings.fetchAttestation,
                    // The client never adds or changes a request's cache secret.
                    verifier, null,
                    settings.verificationCheck, settings.onVerificationAttempt, internals,
                    refuseProxyOnEnclaveOrigin = true,
                ),
                trust,
            )
        }
    }
}
