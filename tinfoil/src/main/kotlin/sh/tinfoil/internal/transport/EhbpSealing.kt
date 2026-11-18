package sh.tinfoil.internal.transport

import okhttp3.Authenticator
import okhttp3.Call
import okhttp3.Callback
import okhttp3.ConnectionPool
import okhttp3.ConnectionSpec
import okhttp3.CookieJar
import okhttp3.Dispatcher
import okhttp3.EventListener
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.Timeout
import okio.buffer
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.SessionRecoveryToken
import sh.tinfoil.TransportMode
import sh.tinfoil.Verification
import sh.tinfoil.ehbp.client.Transport
import sh.tinfoil.ehbp.client.newTransportWithIdentity
import sh.tinfoil.ehbp.identity.Identity
import sh.tinfoil.ehbp.identity.fromPublicKeyHex
import sh.tinfoil.ehbp.identity.isKeyConfigError
import sh.tinfoil.ehbp.protocol.EncapsulatedKeyHeader
import sh.tinfoil.ehbp.protocol.ResponseNonceHeader
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ProtocolException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Seals request and response bodies to the HPKE key that a verification
 * endorses, with the EHBP client library, which owns the cryptography and
 * the framing. The connections that carry the sealed bodies are validated as
 * the platform validates any HTTPS connection. Whatever they end at sees the
 * method, the URL and the headers of every request, and the whole of a
 * request that has no body, so where they end matters:
 * - Unpinned, they end at the base URL's host, whoever holds a certificate
 *   for it: a proxy, or an enclave that the caller named. That host is the
 *   caller's choice, and is trusted with the headers.
 * - Pinned, they must also present the TLS key that the verification
 *   endorses, as with [PinnedTls]. That is for a direct connection to an
 *   enclave whose host the caller did not choose: an attestation document
 *   is not tied to the host that served it, so without the pin a host with
 *   a certificate of its own could pass on a genuine enclave's document and
 *   then be sent the headers.
 *
 * Its transports each have connections of their own and share the threads
 * that calls run on.
 */
internal class EhbpSealing(
    /**
     * Whether requests go out over cleartext HTTP, which is so only for a
     * base URL on a loopback host. Otherwise every connection is TLS.
     */
    private val cleartext: Boolean,
    /**
     * What tells a proxy where to forward a request: the verified enclave's
     * origin, when the base URL is on another origin; otherwise null.
     */
    private val enclaveUrl: String?,
    /**
     * Whether connections must present the attested TLS key as well. It is
     * for connections that go to the enclave itself, never to a proxy.
     */
    private val pinned: Boolean,
    private val settings: HttpSettings = HttpSettings(),
) : TransportProtocol {
    override val mode: TransportMode = TransportMode.Ehbp

    private val calls = ActiveCalls()
    private val dispatcher = Dispatcher()

    // The sealing client blocks a thread for each exchange until the
    // response's headers arrive. Calls beyond the limit wait their turn.
    private val threads = AtomicInteger()
    private val executor = ThreadPoolExecutor(
        MAX_CONCURRENT_REQUESTS,
        MAX_CONCURRENT_REQUESTS,
        IDLE_THREAD_SECONDS,
        TimeUnit.SECONDS,
        LinkedBlockingQueue(),
    ) { task -> Thread(task, "tinfoil-ehbp-${threads.incrementAndGet()}").apply { isDaemon = true } }
        .apply { allowCoreThreadTimeOut(true) }

    override fun checkRequest(request: Request) = checkRequest(request, cleartext)

    override fun bind(verification: Verification): EhbpTransport =
        EhbpTransport(
            identityOf(verification.hpkePublicKey),
            if (pinned) LeafKeyPin.of(verification.tlsPublicKeyFingerprint) else null,
            enclaveUrl, cleartext, dispatcher, executor, calls, settings,
        )

    override fun close() {
        calls.close()
        // Calls that are waiting for a thread still run, and end as cancelled.
        executor.shutdown()
    }

    internal companion object {
        /** The header that tells a proxy which enclave a sealed request is for. */
        const val ENCLAVE_URL_HEADER = "X-Tinfoil-Enclave-Url"

        /**
         * Throws for a request that sealing cannot protect, for a transport
         * that sends over cleartext HTTP or does not, as [cleartext] says.
         */
        @Throws(ConfigurationException::class)
        fun checkRequest(request: Request, cleartext: Boolean) {
            if (request.method.equals("CONNECT", ignoreCase = true) || request.header("Upgrade") != null ||
                request.headers("Connection").any { value -> value.split(',').any { it.trim().equals("upgrade", ignoreCase = true) } }
            ) {
                throw ConfigurationException(
                    "TransportMode.Ehbp seals only request and response bodies, so it cannot protect a protocol " +
                        "upgrade, such as a WebSocket, or a CONNECT tunnel; use TransportMode.Tls on a direct connection",
                )
            }
            for (name in request.headers.names()) {
                if (name.startsWith(PROTOCOL_HEADER_PREFIX, ignoreCase = true)) {
                    throw ConfigurationException("requests must not set an Ehbp- header: the sealing protocol owns them")
                }
                if (name.equals(ENCLAVE_URL_HEADER, ignoreCase = true)) {
                    throw ConfigurationException(
                        "requests must not set the $ENCLAVE_URL_HEADER header, which names the verified enclave",
                    )
                }
            }
            if (request.body?.isDuplex() == true) {
                throw ConfigurationException("TransportMode.Ehbp cannot seal a duplex request body")
            }
            if (request.isHttps == cleartext) {
                throw ConfigurationException(
                    if (cleartext) {
                        "the client's base URL is HTTP, and so must its requests be"
                    } else {
                        "TransportMode.Ehbp requires an HTTPS request, unless the client's base URL is HTTP on this machine"
                    },
                )
            }
        }

        private const val PROTOCOL_HEADER_PREFIX = "Ehbp-"
        private const val MAX_CONCURRENT_REQUESTS = 64
        private const val IDLE_THREAD_SECONDS = 60L
        private const val KEY_LENGTH = 64

        /**
         * The key to seal to, from the attested [key]: a raw X25519 public
         * key in lowercase hex. A missing or malformed key is refused: there
         * is then nothing to seal a body to.
         */
        @Throws(AttestationException::class)
        fun identityOf(key: String?): Identity {
            if (key.isNullOrEmpty()) {
                throw AttestationException(
                    "the attestation endorses no HPKE key, so no request body can be sealed to it; " +
                        "TransportMode.Ehbp cannot be used with this enclave",
                )
            }
            if (key.length != KEY_LENGTH || !key.all { it in '0'..'9' || it in 'a'..'f' }) {
                throw AttestationException("the attested HPKE key is not an X25519 public key in lowercase hex")
            }
            return try {
                fromPublicKeyHex(key)
            } catch (e: IOException) {
                throw AttestationException("the attested HPKE key is not an X25519 public key in lowercase hex", cause = e)
            }
        }
    }
}

/**
 * An HTTP client, with a connection pool of its own, whose requests have
 * their bodies sealed to one attested HPKE key.
 *
 * Each request is sealed by a sealing client of its own, made for that key
 * and for no other, so that one request's session recovery token is never
 * another's and each request can be cancelled and timed by itself. A request
 * with a body leaves sealed or not at all. A request without a body, and its
 * response, are not sealed: the protocol cannot protect them.
 *
 * With a [pin], every connection must also present that TLS key, checked as
 * [PinnedTlsTransport] checks it, so that nothing of a request, its headers
 * included, is written to a host that does not hold the key.
 */
internal class EhbpTransport(
    private val identity: Identity,
    private val pin: LeafKeyPin?,
    private val enclaveUrl: String?,
    private val cleartext: Boolean,
    dispatcher: Dispatcher,
    private val executor: ThreadPoolExecutor,
    private val calls: ActiveCalls,
    settings: HttpSettings,
) : BoundTransport {
    private val pool = ConnectionPool()

    @Volatile
    private var retired = false

    private val client: OkHttpClient = OkHttpClient.Builder()
        .dispatcher(dispatcher)
        .connectionPool(pool)
        // One or the other, never a choice: cleartext only for a base URL
        // on a loopback host, and then nothing else.
        .connectionSpecs(listOf(if (cleartext) ConnectionSpec.CLEARTEXT else ConnectionSpec.MODERN_TLS))
        // A response is handed to the caller as it is: a redirect or an
        // authentication challenge is never acted on. The sealing client
        // turns redirects off as well.
        .followRedirects(false)
        .followSslRedirects(false)
        .authenticator(Authenticator.NONE)
        .proxyAuthenticator(Authenticator.NONE)
        .cookieJar(CookieJar.NO_COOKIES)
        .cache(null)
        // A sealed body can be written only once, so the HTTP client never
        // sends one again: a retry happens only before any of it is written.
        .retryOnConnectionFailure(true)
        .readTimeout(READ_TIMEOUT_MINUTES, TimeUnit.MINUTES)
        .apply {
            pin?.let { pinnedTo(it) }
            settings.trust?.let { sslSocketFactory(it.socketFactory, it.trustManager) }
            settings.proxy?.let { proxy(it) }
        }
        .build()

    /** How many connections are open, in use or kept for later. */
    val connectionCount: Int get() = pool.connectionCount()

    override fun newCall(request: Request): Call {
        val call = EhbpCall(request)
        calls.add(call)
        return call
    }

    override fun keyRejection(failure: IOException): String? = when {
        isKeyConfigError(failure) -> "the enclave does not hold the attested HPKE key"
        // Without a pin, a certificate that is refused says nothing about
        // the enclave's keys: the connection may be a proxy's.
        pin != null -> pinRejection(failure)
        else -> null
    }

    override suspend fun probe(url: HttpUrl) {
        if (pin == null) {
            return
        }
        var probing: Call? = null
        try {
            client.probePin(url) { call ->
                calls.add(call)
                probing = call
            }
        } finally {
            probing?.let(::finished)
        }
    }

    override fun retire() {
        retired = true
        pool.evictAll()
    }

    private fun finished(call: Call) {
        calls.remove(call)
        if (retired || calls.isClosed) {
            pool.evictAll()
        }
    }

    /**
     * One request and its response, as a call. The sealing client blocks
     * until the response's headers arrive, so the call runs on a thread of
     * the protocol's when it is enqueued. Cancelling it, at any point,
     * cancels the HTTP call that carries the sealed request, which also ends
     * a read of the response body; its [timeout] spans the wait for a
     * thread, the exchange and the reading of the response body.
     */
    private inner class EhbpCall(private val original: Request) : Call, RecoverableCall {
        private val executed = AtomicBoolean()
        private val timeout = Timeout()
        private val lock = Any()

        // Guarded by lock.
        private var canceled = false
        private var carrier: Call? = null

        // Written by the thread that runs the exchange, while it runs.
        private var sealed = false

        // The sealing client of an exchange that was answered. It holds the
        // exchange's token, and drops it once the response has been read or
        // has failed, so no copy of the token is kept here.
        @Volatile
        private var answered: Transport? = null

        override val recoveryToken: SessionRecoveryToken?
            get() = answered?.getSessionRecoveryToken()?.let(SessionRecoveryToken::of)

        override fun request(): Request = original

        override fun timeout(): Timeout = timeout

        override fun isExecuted(): Boolean = executed.get()

        override fun isCanceled(): Boolean = synchronized(lock) { canceled }

        override fun clone(): Call = newCall(original)

        override fun cancel() {
            val call = synchronized(lock) {
                canceled = true
                carrier
            }
            call?.cancel()
        }

        override fun execute(): Response {
            start()
            return exchange(endNanos())
        }

        override fun enqueue(responseCallback: Callback) {
            start()
            val end = endNanos()
            try {
                executor.execute { deliver(end, responseCallback) }
            } catch (e: RejectedExecutionException) {
                // The client closed after it admitted the call.
                finished(this)
                responseCallback.onFailure(this, IOException(CANCELED, e))
            }
        }

        private fun start() {
            check(executed.compareAndSet(false, true)) { "Already Executed" }
        }

        /** When the call's time runs out, from its timeout and its deadline as they are when it starts. */
        private fun endNanos(): Long? {
            val now = System.nanoTime()
            val byTimeout = timeout.timeoutNanos().takeIf { it > 0 }?.let { now + it }
            val byDeadline = if (timeout.hasDeadline()) timeout.deadlineNanoTime() else null
            return listOfNotNull(byTimeout, byDeadline).minByOrNull { it - now }
        }

        private fun deliver(endNanos: Long?, callback: Callback) {
            val response = try {
                exchange(endNanos)
            } catch (e: IOException) {
                callback.onFailure(this, e)
                return
            } catch (e: Throwable) {
                callback.onFailure(this, IOException("canceled due to $e", e))
                throw e
            }
            try {
                callback.onResponse(this, response)
            } catch (_: IOException) {
                // The callback's own failure to read the response is its to
                // handle; the call itself succeeded.
                response.closeQuietly()
            } catch (e: Throwable) {
                cancel()
                throw e
            }
        }

        /** Seals and sends the request, and returns the response with its body still to be read. */
        private fun exchange(endNanos: Long?): Response {
            var response: Response? = null
            try {
                if (isCanceled()) {
                    throw IOException(CANCELED)
                }
                if (original.isHttps == cleartext) {
                    throw ProtocolException("the request's scheme is not the one that this transport sends")
                }
                val carrying = client.newBuilder()
                    .apply {
                        if (endNanos != null) {
                            val left = endNanos - System.nanoTime()
                            if (left <= 0) {
                                throw InterruptedIOException("timeout")
                            }
                            // The HTTP call that carries the request enforces
                            // what is left, through the reading of the body.
                            callTimeout(
                                TimeUnit.NANOSECONDS.toMillis(left).coerceIn(1L, Int.MAX_VALUE.toLong()),
                                TimeUnit.MILLISECONDS,
                            )
                        }
                    }
                    .eventListenerFactory { call ->
                        adopt(call)
                        Tracker()
                    }
                    .addInterceptor(Interceptor { chain -> guard(chain) })
                    .build()
                val sealing = newTransportWithIdentity(identity, carrying)
                val outgoing = if (enclaveUrl == null) {
                    original
                } else {
                    original.newBuilder().header(EhbpSealing.ENCLAVE_URL_HEADER, enclaveUrl).build()
                }
                var returned = sealing.roundTrip(outgoing)
                response = returned
                if (sealed) {
                    refuseUnusable(returned)
                    val body = returned.body
                    if (returned.code < REDIRECTS.first && body != null) {
                        returned = returned.newBuilder().body(ProvenBody(body)).build()
                        response = returned
                    }
                }
                // The sealing client is this request's alone, so its token
                // is this request's. It has none for a response that is not
                // sealed.
                answered = sealing
                return returned
            } catch (e: Throwable) {
                response?.closeQuietly()
                finished(this)
                throw e
            }
        }

        /**
         * Sees the request as it is about to be sent. A request with a body
         * must have been sealed by now: one that was not is stopped here,
         * before any of it is written.
         */
        private fun guard(chain: Interceptor.Chain): Response {
            val outgoing = chain.request()
            sealed = outgoing.header(EncapsulatedKeyHeader) != null
            val body = outgoing.body
            if (!sealed && body != null && body.contentLength() != 0L) {
                throw IOException("refusing to send a request body that is not sealed")
            }
            return chain.proceed(outgoing)
        }

        /**
         * Refuses the answers to a sealed request that the sealing client
         * would hand on although nothing authenticates them: a redirect,
         * whose `Location` is not sealed; an informational status without
         * the header that a sealed response carries; and a status that
         * reports success and cannot have a body.
         */
        private fun refuseUnusable(response: Response) {
            val code = response.code
            if (code in REDIRECTS) {
                throw ProtocolException("UNEXPECTED_REDIRECT: status $code in response to a sealed request")
            }
            if (code < SUCCESS && response.header(ResponseNonceHeader) == null) {
                throw ProtocolException("MISSING_RESPONSE_NONCE: status $code in response to a sealed request")
            }
            if (code == NO_CONTENT || code == RESET_CONTENT) {
                throw ProtocolException("FRAMING_TRUNCATED: status $code cannot carry a sealed body")
            }
        }

        private fun adopt(call: Call) {
            val alreadyCanceled = synchronized(lock) {
                carrier = call
                canceled
            }
            if (alreadyCanceled) {
                call.cancel()
            }
        }

        /** Forgets the call once its exchange is over, the response body included. */
        private inner class Tracker : EventListener() {
            override fun callEnd(call: Call) = finished(this@EhbpCall)

            override fun callFailed(call: Call, ioe: IOException) = finished(this@EhbpCall)
        }
    }

    /**
     * The body of a sealed response that reports success. The header that
     * marks a response as sealed proves nothing by itself: any value passes
     * for one, and a body without a sealed piece leaves nothing to check it
     * against. So the body has to yield at least one byte, which the sealing
     * client releases only once the piece that carries it has authenticated;
     * a body that ends before that fails the read.
     */
    private class ProvenBody(private val sealed: ResponseBody) : ResponseBody() {
        private val source: BufferedSource = object : ForwardingSource(sealed.source()) {
            private var proven = false

            override fun read(sink: Buffer, byteCount: Long): Long {
                val read = super.read(sink, byteCount)
                if (read > 0) {
                    proven = true
                } else if (read == -1L && !proven) {
                    throw ProtocolException("FRAMING_TRUNCATED: the response ended before any of it authenticated")
                }
                return read
            }
        }.buffer()

        override fun contentType(): MediaType? = sealed.contentType()

        override fun contentLength(): Long = -1L

        override fun source(): BufferedSource = source
    }

    private companion object {
        const val CANCELED = "Canceled"
        const val SUCCESS = 200
        const val NO_CONTENT = 204
        const val RESET_CONTENT = 205
        val REDIRECTS = 300..399

        // How long a response may go without sending a byte. Generous,
        // because an inference request can work for minutes before it
        // answers; a call's own timeout bounds the whole exchange.
        const val READ_TIMEOUT_MINUTES = 10L
    }
}

/** A call that can say which session recovery token its response has. */
internal interface RecoverableCall {
    /**
     * The token of the sealed response that the call returned, while that
     * response is still being read; null before then, afterwards, and for a
     * response that is not sealed.
     */
    val recoveryToken: SessionRecoveryToken?
}
