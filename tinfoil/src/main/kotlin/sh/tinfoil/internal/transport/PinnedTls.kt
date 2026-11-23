package sh.tinfoil.internal.transport

import okhttp3.Authenticator
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.ConnectionSpec
import okhttp3.CookieJar
import okhttp3.Dispatcher
import okhttp3.EventListener
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.internal.tls.OkHostnameVerifier
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.TransportMode
import sh.tinfoil.VerifiedFacts
import sh.tinfoil.internal.Background
import java.io.IOException
import java.net.ProtocolException
import java.net.Proxy
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.util.Collections
import java.util.WeakHashMap
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * What tests replace in the HTTP clients that this SDK builds. Production
 * code passes none of it, which leaves the platform's trust and proxy
 * selection in place.
 */
internal class HttpSettings(
    /** The roots to validate server chains against, with their socket factory. */
    val trust: TlsTrust? = null,
    /** The proxy for attested requests. */
    val proxy: Proxy? = null,
)

/** A trust manager and a socket factory that validates with it. */
internal class TlsTrust(
    val socketFactory: SSLSocketFactory,
    val trustManager: X509TrustManager,
)

/**
 * The key that a server's leaf certificate must carry: the SHA-256 of the
 * certificate's DER `SubjectPublicKeyInfo`, as an attestation endorses it.
 */
internal class LeafKeyPin private constructor(private val expected: ByteArray) {
    /** Whether [leaf] carries the pinned key. No certificate matches nothing. */
    fun matches(leaf: Certificate?): Boolean {
        val key = leaf?.publicKey?.encoded ?: return false
        // Constant time, so that a failed comparison says nothing about how
        // much of the fingerprint matched.
        return MessageDigest.isEqual(expected, sha256(key))
    }

    companion object {
        private const val FINGERPRINT_LENGTH = 64

        /**
         * The pin for an attested [fingerprint], lowercase hex. A missing or
         * malformed fingerprint is refused: there is then no key to bind a
         * connection to.
         */
        @Throws(AttestationException::class)
        fun of(fingerprint: String?): LeafKeyPin {
            if (fingerprint.isNullOrEmpty()) {
                throw AttestationException("the attestation endorses no TLS key, so no connection can be bound to it")
            }
            if (fingerprint.length != FINGERPRINT_LENGTH || !fingerprint.all { it in '0'..'9' || it in 'a'..'f' }) {
                throw AttestationException("the attested TLS key fingerprint is not a SHA-256 digest in lowercase hex")
            }
            return LeafKeyPin(ByteArray(FINGERPRINT_LENGTH / 2) { fingerprint.substring(2 * it, 2 * it + 2).toInt(16).toByte() })
        }

        /** The fingerprint of [certificate]'s key, in the form that an attestation endorses. */
        fun fingerprint(certificate: Certificate): String =
            sha256(certificate.publicKey.encoded).joinToString("") { "%02x".format(it) }

        private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}

/**
 * Pins every connection to the TLS key that a verification endorses. Its
 * transports each have connections of their own and share the threads that
 * calls run on.
 */
internal class PinnedTls(private val settings: HttpSettings = HttpSettings()) : TransportProtocol {
    override val mode: TransportMode = TransportMode.TLS

    private val calls = ActiveCalls()

    // Every request is to one host, so the per-host limit is the limit.
    private val dispatcher = Dispatcher().apply {
        maxRequests = MAX_CONCURRENT_REQUESTS
        maxRequestsPerHost = MAX_CONCURRENT_REQUESTS
    }

    override fun checkRequest(request: Request) {
        if (!request.isHttps) {
            throw ConfigurationException("TransportMode.TLS requires an HTTPS request")
        }
    }

    override fun bind(verification: VerifiedFacts): PinnedTlsTransport =
        PinnedTlsTransport(LeafKeyPin.of(verification.tlsPublicKeyFingerprint), dispatcher, calls, settings)

    override fun refuse() = calls.refuse()

    override fun close() {
        calls.close()
        // Calls that are running end as cancelled; nothing new is accepted.
        dispatcher.executorService.shutdown()
    }

    private companion object {
        const val MAX_CONCURRENT_REQUESTS = 64
    }
}

/**
 * The calls in flight on every transport of one client, so that closing the
 * client ends them all, whichever verification they were sent under.
 */
internal class ActiveCalls {
    private val lock = Any()

    // Calls are held weakly, so that the HTTP client can still find a
    // response that was dropped without being closed.
    private val calls: MutableSet<Call> = Collections.newSetFromMap(WeakHashMap())
    private var closed = false

    val isClosed: Boolean get() = synchronized(lock) { closed }

    /** Admits [call], or refuses it once the client is closed. */
    @Throws(ConfigurationException::class)
    fun add(call: Call) {
        synchronized(lock) {
            if (closed) {
                throw ConfigurationException("the client is closed")
            }
            calls.add(call)
        }
    }

    fun remove(call: Call) {
        synchronized(lock) { calls.remove(call) }
    }

    /** Admits no call from now on. It touches no connection. */
    fun refuse() {
        synchronized(lock) { closed = true }
    }

    /** Admits no call from now on, and cancels those in flight, which closes their sockets. */
    fun close() {
        val cancelled = synchronized(lock) {
            closed = true
            calls.toList().also { calls.clear() }
        }
        cancelled.forEach(Call::cancel)
    }
}

/**
 * An HTTP client, with a connection pool of its own, whose every connection
 * must present one attested key.
 *
 * The key is checked twice. When a connection is set up, after the platform
 * has validated the certificate chain and the default hostname check has
 * passed, the leaf certificate must carry the key, or the connection is
 * closed before it is used; this holds for a resumed TLS session too, whose
 * certificates are those of its first handshake. Then, before each request
 * is written, the connection that will carry it is checked again. The pin
 * adds to the platform's validation and replaces none of it.
 *
 * A certificate pinner that accepts a match anywhere in the chain would not
 * do: the attested key is the enclave's own, so only the leaf may carry it.
 */
internal class PinnedTlsTransport(
    private val pin: LeafKeyPin,
    dispatcher: Dispatcher,
    private val calls: ActiveCalls,
    settings: HttpSettings,
) : BoundTransport {
    private val pool = ConnectionPool()

    @Volatile
    private var retired = false

    private val client: OkHttpClient = OkHttpClient.Builder()
        .dispatcher(dispatcher)
        .connectionPool(pool)
        // No cleartext, whatever the request's scheme.
        .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
        .pinnedTo(pin)
        .eventListener(CallTracker())
        // A response is the enclave's or nothing: a redirect or an
        // authentication challenge is handed to the caller, never acted on.
        .followRedirects(false)
        .followSslRedirects(false)
        .authenticator(Authenticator.NONE)
        .proxyAuthenticator(Authenticator.NONE)
        .cookieJar(CookieJar.NO_COOKIES)
        .cache(null)
        // A retry goes to the same URL over a connection that passes the
        // same checks.
        .retryOnConnectionFailure(true)
        .readTimeout(READ_TIMEOUT_MINUTES, TimeUnit.MINUTES)
        .apply {
            settings.trust?.let { sslSocketFactory(it.socketFactory, it.trustManager) }
            settings.proxy?.let { proxy(it) }
        }
        .build()

    /** How many connections are open, in use or kept for later. */
    val connectionCount: Int get() = pool.connectionCount()

    override fun newCall(request: Request): Call {
        val call = client.newCall(request)
        calls.add(call)
        return call
    }

    override fun keyRejection(failure: IOException): String? = pinRejection(failure)

    // The call is tracked like any other, so closing the client ends it.
    override suspend fun probe(url: HttpUrl) = client.probePin(url, calls::add)

    override fun retire() {
        retired = true
        pool.evictAll()
    }

    /** Forgets finished calls, and closes the connections that they free once none are kept. */
    private inner class CallTracker : EventListener() {
        override fun callEnd(call: Call) = finished(call)

        override fun callFailed(call: Call, ioe: IOException) = finished(call)

        private fun finished(call: Call) {
            calls.remove(call)
            if (retired || calls.isClosed) {
                // A call ends on the thread that closes its response, which
                // is the caller's, and sockets are not closed there.
                Background.run { pool.evictAll() }
            }
        }
    }

    private companion object {
        // How long a response may go without sending a byte. Generous,
        // because an inference request can work for minutes before it
        // answers; a call's own timeout bounds the whole exchange.
        const val READ_TIMEOUT_MINUTES = 10L
    }
}

/**
 * Holds every connection of the client that is being built to [pin]: a
 * connection is accepted only if its leaf certificate carries the pinned
 * key, and each request is written only to a connection that does. See
 * [PinnedTlsTransport] for when the key is checked.
 */
internal fun OkHttpClient.Builder.pinnedTo(pin: LeafKeyPin): OkHttpClient.Builder =
    hostnameVerifier(PinningHostnameVerifier(pin))
        .addInterceptor(MismatchReporter)
        .addNetworkInterceptor(RequestPinCheck(pin))

/**
 * Why [failure], of a call on a client that is [pinnedTo] a key, means that
 * the server did not present that key or a certificate that the platform
 * accepts, which shows before any of the request is written; or null for
 * any other failure.
 */
internal fun pinRejection(failure: IOException): String? {
    var cause: Throwable? = failure
    repeat(MAX_CAUSE_DEPTH) {
        when (val e = cause ?: return null) {
            is PinMismatchException -> return "the enclave's certificate does not carry the attested TLS key"
            is SSLPeerUnverifiedException -> return "the enclave's certificate was refused: ${e.message}"
            is SSLHandshakeException ->
                if (e.hasCause<CertificateException>()) {
                    return "the enclave's certificate was refused: ${e.message}"
                }
            else -> Unit
        }
        cause = cause?.cause
    }
    return null
}

/**
 * Opens a connection to [url]'s host with this client, which is [pinnedTo]
 * a key, and gives it up once the connection has passed every check that a
 * request's connection passes and before any of a request is written to it.
 * [admit] is handed the call before it starts.
 *
 * @throws IOException if no such connection can be opened; [pinRejection]
 *   says whether the key is why.
 */
@Throws(IOException::class)
internal suspend fun OkHttpClient.probePin(url: HttpUrl, admit: (Call) -> Unit) {
    // Network interceptors run in the order in which they were added, so
    // this one runs after the check of the connection's key.
    val call = newBuilder().addNetworkInterceptor(ProbeEnd).build().newCall(Request.Builder().url(url).build())
    admit(call)
    try {
        call.await().closeQuietly()
    } catch (_: ProbeComplete) {
        return
    }
    throw ProtocolException("a connection that was only to be opened carried a request")
}

/**
 * Ends a probe where its request would be written. It is a protocol error
 * for the HTTP client, which therefore does not try the request again.
 */
private class ProbeComplete : ProtocolException("the connection was opened only to check its key")

private object ProbeEnd : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response = throw ProbeComplete()
}

private const val MAX_CAUSE_DEPTH = 8

private inline fun <reified T : Throwable> Throwable.hasCause(): Boolean {
    var cause = this.cause
    repeat(MAX_CAUSE_DEPTH) {
        when (cause) {
            null -> return false
            is T -> return true
            else -> cause = cause?.cause
        }
    }
    return false
}

/** A connection whose leaf certificate does not carry the pinned key. */
private class PinMismatchException(cause: Throwable? = null) :
    SSLPeerUnverifiedException("the server's certificate does not carry the attested TLS key") {
    init {
        if (cause != null) {
            initCause(cause)
        }
    }
}

/**
 * Accepts a new connection only if the default hostname check passes and the
 * leaf certificate carries the pinned key. The HTTP client calls it for every
 * TLS connection once the handshake, with the platform's chain validation,
 * has succeeded, and closes a connection that it refuses before using it.
 */
private class PinningHostnameVerifier(private val pin: LeafKeyPin) : HostnameVerifier {
    override fun verify(hostname: String, session: SSLSession): Boolean {
        if (!OkHostnameVerifier.verify(hostname, session)) {
            return false
        }
        val leaf = try {
            session.peerCertificates.firstOrNull()
        } catch (_: SSLException) {
            null
        }
        if (pin.matches(leaf)) {
            return true
        }
        MismatchReporter.note()
        return false
    }
}

/**
 * Names a pin mismatch as such. A refused connection reaches the caller as a
 * failed hostname check, whatever was refused; the connection is set up on
 * the thread that runs the call's interceptors, so the verifier's note of a
 * mismatch is still there when the failure passes through here. Should that
 * ever not hold, the failure keeps its original, less specific, type: what
 * is refused does not depend on this.
 */
private object MismatchReporter : Interceptor {
    private val mismatch = ThreadLocal<Boolean>()

    fun note() {
        mismatch.set(true)
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        mismatch.remove()
        try {
            return chain.proceed(chain.request())
        } catch (e: SSLPeerUnverifiedException) {
            throw if (mismatch.get() == true && e !is PinMismatchException) PinMismatchException(e) else e
        } finally {
            mismatch.remove()
        }
    }
}

/**
 * Checks the connection that is about to carry a request, before any of the
 * request is written to it. Every connection was checked when it was set up;
 * this repeats the check where the request meets its connection, so that no
 * route to a connection, such as a pooled one or a tunnel through a proxy,
 * can carry a request without it.
 */
private class RequestPinCheck(private val pin: LeafKeyPin) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val connection = chain.connection()
        // A connection without a handshake is not TLS, and matches nothing.
        if (!pin.matches(connection?.handshake()?.peerCertificates?.firstOrNull())) {
            try {
                connection?.socket()?.close()
            } catch (_: IOException) {
                // The connection is unusable either way.
            }
            throw PinMismatchException()
        }
        return chain.proceed(chain.request())
    }
}
