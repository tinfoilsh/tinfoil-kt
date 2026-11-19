package sh.tinfoil.internal.verification

import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.ConnectionPool
import okhttp3.ConnectionSpec
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okio.Buffer
import sh.tinfoil.ConfigurationException
import sh.tinfoil.NetworkException
import sh.tinfoil.TinfoilException
import sh.tinfoil.internal.Background
import sh.tinfoil.internal.SdkIdentity
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.internal.transport.awaitAndRead
import java.io.IOException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Fetches attestation documents. A document proves itself, so the fetch
 * trusts nothing that it reads; its limits keep a hostile server from costing
 * more than a bounded wait and a bounded amount of memory: HTTPS only, every
 * redirect included; a bounded number of redirects; one timeout for the whole
 * fetch; and a cap on the body that is enforced while it streams, whatever
 * length the server declares.
 *
 * Each fetch has a connection pool of its own, which is emptied afterwards:
 * a fetch never shares a connection with attested traffic, and never reuses
 * one that may still reach an instance that has since been replaced.
 */
internal class AttestationFetcher(
    settings: HttpSettings = HttpSettings(),
    private val timeout: Duration = TIMEOUT,
    private val maxBodyBytes: Long = MAX_BODY_BYTES,
    /** The statuses whose bodies are returned; any other fails the fetch. */
    private val accepted: IntRange = SUCCESS,
) {
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
        // Redirects are followed here, one checked step at a time.
        .followRedirects(false)
        .followSslRedirects(false)
        .cookieJar(CookieJar.NO_COOKIES)
        .cache(null)
        .apply { settings.trust?.let { sslSocketFactory(it.socketFactory, it.trustManager) } }
        .build()

    /**
     * The body of a GET of [url], which must be HTTPS. A failure to get it
     * is a [NetworkException] that keeps its cause, with the status when a
     * server answered with one that is not accepted. Cancelling the coroutine cancels
     * the fetch. Any thread may call it: the fetch, and the closing of its
     * connections, run on background threads.
     */
    @Throws(TinfoilException::class)
    suspend fun fetch(url: HttpUrl): ByteArray {
        if (!url.isHttps) {
            throw ConfigurationException("attestation must be fetched over HTTPS")
        }
        return withContext(Background.dispatcher) {
            val pool = ConnectionPool()
            val fetching = client.newBuilder().connectionPool(pool).build()
            try {
                withTimeoutOrNull(timeout) { follow(fetching, url) }
                    ?: throw NetworkException("GET ${describe(url)} timed out after $timeout")
            } finally {
                pool.evictAll()
            }
        }
    }

    /**
     * Stops the threads that fetches ran on. Fetches in flight fail. It
     * closes their sockets, so it is for a background thread.
     */
    fun close() {
        client.dispatcher.cancelAll()
        client.dispatcher.executorService.shutdown()
    }

    private suspend fun follow(client: OkHttpClient, start: HttpUrl): ByteArray {
        var url = start
        var redirects = 0
        while (true) {
            val request = Request.Builder()
                .url(url)
                .header(SDK_NAME_HEADER, SdkIdentity.NAME)
                .header(SDK_VERSION_HEADER, SdkIdentity.VERSION)
                .build()
            val step = try {
                client.newCall(request).awaitAndRead { response -> read(response, url) }
            } catch (e: TinfoilException) {
                throw e
            } catch (e: IOException) {
                throw NetworkException("GET ${describe(url)}: ${e.message ?: e.javaClass.simpleName}", cause = e)
            }
            when (step) {
                is Step.Body -> return step.bytes
                is Step.Redirect -> {
                    if (redirects >= MAX_REDIRECTS) {
                        throw NetworkException("GET ${describe(start)} stopped after $MAX_REDIRECTS redirects")
                    }
                    redirects++
                    url = step.target
                }
            }
        }
    }

    private fun read(response: Response, url: HttpUrl): Step {
        val location = response.header("Location")
        if (response.code in REDIRECT_STATUSES && location != null) {
            // A target that is not an http or https URL does not resolve.
            val target = url.resolve(location)
            if (target == null || !target.isHttps) {
                throw NetworkException("GET ${describe(url)}: refusing a redirect to a URL that is not HTTPS")
            }
            return Step.Redirect(target)
        }
        if (response.code !in accepted) {
            throw NetworkException("GET ${describe(url)}: HTTP ${response.code}", status = response.code)
        }
        val source = response.body?.source()
            ?: throw NetworkException("GET ${describe(url)}: the response has no body")
        val body = Buffer()
        // Reading one byte past the cap tells a body of exactly the cap
        // from one that is too large.
        while (body.size <= maxBodyBytes) {
            if (source.read(body, minOf(READ_SIZE, maxBodyBytes + 1 - body.size)) == -1L) {
                return Step.Body(body.readByteArray())
            }
        }
        throw NetworkException("GET ${describe(url)}: the response exceeds $maxBodyBytes bytes")
    }

    /** Where a fetch went, without the query. */
    private fun describe(url: HttpUrl): String = "${url.scheme}://${url.host}:${url.port}${url.encodedPath}"

    private sealed interface Step {
        class Body(val bytes: ByteArray) : Step

        class Redirect(val target: HttpUrl) : Step
    }

    internal companion object {
        const val SDK_NAME_HEADER: String = "Tinfoil-SDK"
        const val SDK_VERSION_HEADER: String = "Tinfoil-SDK-Version"
        const val MAX_REDIRECTS: Int = 10
        const val MAX_BODY_BYTES: Long = 32L shl 20
        val TIMEOUT: Duration = 30.seconds
        val SUCCESS: IntRange = 200..299

        private const val READ_SIZE = 64L * 1024
        private val REDIRECT_STATUSES = setOf(301, 302, 303, 307, 308)
    }
}
