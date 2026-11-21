@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil

import android.os.Looper
import android.os.NetworkOnMainThreadException
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.Response
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.RouterDiscovery
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.internal.transport.LeafKeyPin
import sh.tinfoil.internal.transport.TlsTrust
import sh.tinfoil.internal.verification.AttestationVerifier
import sh.tinfoil.testing.MainThread
import java.io.IOException
import java.net.InetAddress
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Uses the HTTP clients from Android's main thread, as an app does that creates
 * one in a coroutine on `Dispatchers.Main` and closes it in a lifecycle
 * callback. The platform refuses network work on that thread, the closing
 * of a TLS socket included, so nothing that a client does there may reach a
 * socket.
 *
 * The first tests talk to a server on the device and always run. The others
 * reach production, so they run only when the instrumentation argument
 * `tinfoilIntegration` is `true`.
 */
@RunWith(AndroidJUnit4::class)
class MainThreadSafetyTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val root = HeldCertificate.Builder().certificateAuthority(0).build()
    private val leaf = HeldCertificate.Builder().addSubjectAlternativeName("localhost").signedBy(root).build()
    private val trust = HandshakeCertificates.Builder().addTrustedCertificate(root.certificate).build()
        .let { TlsTrust(it.sslSocketFactory(), it.trustManager) }
    private val requests = AtomicInteger()

    /** Requests that arrived and are never answered. */
    private val unanswered = AtomicInteger()
    private val server = MockWebServer().apply {
        useHttps(HandshakeCertificates.Builder().heldCertificate(leaf).build().sslSocketFactory(), false)
        dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                if (request.path!!.startsWith("/.well-known/tinfoil-attestation")) {
                    MockResponse().setBody("document")
                } else if (request.path == "/v1/slow") {
                    unanswered.incrementAndGet()
                    MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE)
                } else {
                    requests.incrementAndGet()
                    MockResponse().setBody("answer")
                }
        }
        start()
    }
    private val host = "localhost:${server.port}"

    /** Endorses the server's own keys, whatever the document says. */
    private val verifier = object : AttestationVerifier {
        override fun newNonce(): ByteArray = ByteArray(32)

        override fun attestationUrl(host: String, nonce: ByteArray): String =
            "https://$host/.well-known/tinfoil-attestation"

        override fun checkPinVerifiability(pin: Pin) = Unit

        override fun verify(document: ByteArray, nonce: ByteArray, pin: Pin): Verification = Verification(
            configRepo = "tinfoilsh/example",
            codeDigest = "ab".repeat(32),
            codeTag = null,
            codeMeasurement = null,
            enclaveMeasurement = null,
            config = null,
            runtime = null,
            platform = null,
            tlsPublicKeyFingerprint = LeafKeyPin.fingerprint(leaf.certificate),
            hpkePublicKey = "cd".repeat(32),
            cryptoMaterial = emptyList(),
            freshnessExpiresAt = Instant.now().plusSeconds(3600),
            metadata = VerificationMetadata(SoftwareIdentity("test", "0"), Instant.now()),
        )
    }

    @After
    fun shutDown() {
        server.shutdown()
    }

    private fun requireLive() {
        val enabled = InstrumentationRegistry.getArguments().getString("tinfoilIntegration")
        assumeTrue("live tests run only with the instrumentation argument tinfoilIntegration=true", enabled == "true")
    }

    private val main = MainThread(instrumentation)

    private fun onMain(block: () -> Unit) = main.onMain(block)

    private fun <T> fromMain(block: suspend () -> T): T = main.fromMain(block)

    private fun answerTo(send: suspend (Request) -> Response, request: Request): Pair<Int, String> = main.answerTo(send, request)

    @Test
    fun thePlatformRefusesNetworkWorkOnTheMainThread() {
        // What makes the other tests mean something: this is the policy
        // that the platform gives the main thread of every app.
        assertFailsWith<NetworkOnMainThreadException> { onMain { InetAddress.getByName("tinfoil.invalid") } }
    }

    @Test
    fun anEnclaveClientIsCreatedUsedAndClosedOnTheMainThreadInBothModes() {
        for (mode in listOf(Transport.Tls, Transport.Ehbp())) {
            val before = requests.get()
            val blockRanOn = ArrayList<Thread>()
            val client = fromMain {
                EnclaveHttpClient.create(
                    host,
                    Trust.RepoPin("tinfoilsh/example"),
                    Internals(http = HttpSettings(trust = trust), newVerifier = { _, _ -> verifier }),
                ) {
                    blockRanOn += Thread.currentThread()
                    transport = mode
                }
            }
            assertEquals(listOf(Looper.getMainLooper().thread), blockRanOn, "the options block runs once, on the caller's thread")
            val request = Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build()
            assertEquals(200 to "answer", answerTo(client::execute, request), "$mode")
            fromMain { client.ensureVerified() }
            fromMain { client.reverify() }
            assertEquals(200 to "answer", answerTo(client::execute, request), "$mode")
            assertEquals(before + 2, requests.get())

            // A request whose coroutine is cancelled on the main thread
            // while it waits for its answer, which closes its connection.
            val slow = Request.Builder().url(client.baseUrl.resolve("v1/slow")!!).build()
            val waiting = unanswered.get()
            assertNull(fromMain { withTimeoutOrNull(2.seconds) { client.execute(slow) } }, "$mode")
            assertEquals(waiting + 1, unanswered.get(), "$mode: the request was not sent before it was cancelled")

            // A connection is open and idle now, and a request is waiting
            // for its answer: closing the client closes the one and cancels
            // the other.
            val outcome = CompletableFuture<Result<Int>>()
            client.newCall(slow).enqueue(
                object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        outcome.complete(Result.failure(e))
                    }

                    override fun onResponse(call: Call, response: Response) {
                        response.use { outcome.complete(Result.success(it.code)) }
                    }
                },
            )
            while (unanswered.get() < waiting + 2) {
                Thread.sleep(10)
            }
            onMain { client.close() }
            onMain { client.close() }

            assertTrue(outcome.get(30, TimeUnit.SECONDS).exceptionOrNull() is IOException, "$mode: the request in flight was not cancelled")

            assertFailsWith<ConfigurationException>("$mode") { fromMain { client.execute(request) } }
        }
    }

    @Test
    fun aRouterClientCreatedOnTheMainThreadIsGivenARouterFromTheList() {
        requireLive()
        // A fallback that cannot be reached: the client can only have come
        // from the list.
        val internals = Internals(discovery = RouterDiscovery.Settings(fallback = "fallback.invalid"))

        val client = fromMain { RouterHttpClient.create(internals) { } }

        Log.i(TAG, "created on the main thread: ${client.enclave}")
        assertNotEquals("fallback.invalid", client.enclave)
        val models = Request.Builder().url(client.baseUrl.resolve("v1/models")!!).build()
        assertEquals(200, answerTo(client::execute, models).first)
        onMain { client.close() }
    }

    @Test
    fun aGatewayClientIsCreatedUsedAndClosedOnTheMainThread() {
        requireLive()
        val client = fromMain { GatewayHttpClient.create() }
        val model = fromMain { client.models() }.first()
        fromMain { client.ensureVerified(model) }
        val chat = Request.Builder()
            .url(client.baseUrl.resolve("chat/completions")!!)
            .post("""{"model":"$model","messages":[{"role":"user","content":"hello"}],"max_tokens":8}""".toRequestBody("application/json".toMediaType()))
            .build()
        val (code, _) = answerTo(client::execute, chat)
        assertTrue(code in 400..499, "HTTP $code")
        val calls: Call.Factory = client
        runBlocking { withContext(Dispatchers.IO) { runCatching { calls.newCall(chat).execute().close() } } }

        onMain { client.close() }

        fromMain { GatewayHttpClient.fetchCatalog("inference-gateway.tinfoil.sh") }
    }

    private companion object {
        const val TAG = "TinfoilLive"
    }
}
