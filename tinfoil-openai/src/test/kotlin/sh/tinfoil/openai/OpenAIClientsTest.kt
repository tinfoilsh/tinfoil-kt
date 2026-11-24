package sh.tinfoil.openai

import com.openai.core.ClientOptions
import com.openai.core.DataResidency
import com.openai.core.JsonValue
import com.openai.core.RequestOptions
import com.openai.core.Sleeper
import com.openai.core.http.HttpClient
import com.fasterxml.jackson.databind.json.JsonMapper
import com.openai.auth.SubjectTokenProvider
import com.openai.auth.SubjectTokenType
import com.openai.auth.WorkloadIdentity
import com.openai.core.http.HttpRequest
import com.openai.core.http.HttpRequestAuthenticator
import com.openai.credential.BearerTokenCredential
import com.openai.core.http.HttpResponse
import com.openai.errors.InternalServerException
import com.openai.errors.OpenAIException
import com.openai.errors.OpenAIIoException
import com.openai.errors.UnauthorizedException
import com.openai.models.chat.completions.ChatCompletionCreateParams
import com.openai.models.files.FileCreateParams
import com.openai.models.files.FilePurpose
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.future.await
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Request
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.NetworkException
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.Trust
import sh.tinfoil.Transport
import sh.tinfoil.VerificationException
import sh.tinfoil.VerificationLayer
import sh.tinfoil.openai.internal.TinfoilEvents
import sh.tinfoil.testing.RawTlsServer
import sh.tinfoil.testing.SealingDispatcher
import sh.tinfoil.testing.SealingKey
import sh.tinfoil.testing.TestEnclave
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.containsText
import sh.tinfoil.testing.fingerprint
import sh.tinfoil.testing.httpsServer
import sh.tinfoil.testing.rejection
import sh.tinfoil.tinfoilException
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InterruptedIOException
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The OpenAI clients: everything that the OpenAI SDK sends goes through the attested client, and nowhere else. */
class OpenAIClientsTest {
    private val enclave = TestEnclave()
    private val closeables = CopyOnWriteArrayList<AutoCloseable>()

    /** A server that no client is bound to, and that the test authority vouches for. */
    private val elsewhere: MockWebServer = httpsServer(enclave.authority.issue()).also { server ->
        closeables += AutoCloseable { server.shutdown() }
    }

    @AfterTest
    fun shutDown() {
        closeables.reversed().forEach { it.close() }
        enclave.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

    /** An enclave client for the test enclave, which the test closes. */
    private suspend fun enclaveHttp(host: String = enclave.host, transport: Transport = Transport.Tls): EnclaveHttpClient =
        enclave.connections().enclave(host, Trust.RepoPin("tinfoilsh/example")) {
            this.transport = transport
            fetchAttestation = enclave.relayFetcher
        }.also { closeables += it }

    private suspend fun enclaveClient(
        host: String = enclave.host,
        transport: Transport = Transport.Tls,
        apiKey: String = KEY,
        tinfoilEvents: Set<TinfoilEvent> = emptySet(),
        configure: (ClientOptions.Builder.() -> Unit)? = null,
        http: EnclaveHttpClient? = null,
    ): Client = Client.create(http ?: enclaveHttp(host, transport), apiKey) {
        this.tinfoilEvents = tinfoilEvents
        configure?.let { openAI(it) }
    }.also { closeables += it }

    /** What the drop-in client makes its router client with: the test enclave, when the list names none that verifies. */
    private fun dropInConnection(listUrl: okhttp3.HttpUrl = elsewhere.url("/routers")): suspend () -> RouterHttpClient =
        { enclave.routerConnections(listUrl).router() }

    private suspend fun routerClient(
        userCacheSecret: String? = null,
        configure: (ClientOptions.Builder.() -> Unit)? = null,
    ): Client {
        val http = enclave.routerConnections().router {
            fetchAttestation = enclave.relayFetcher
            this.userCacheSecret = userCacheSecret
        }.also { closeables += it }
        return Client.create(http, KEY) { configure?.let { openAI(it) } }.also { closeables += it }
    }

    private val Client.enclaveHttp: EnclaveHttpClient get() = httpClient as EnclaveHttpClient

    private fun params(prompt: String = "hello") =
        ChatCompletionCreateParams.builder().model("a-model").addUserMessage(prompt).build()

    private fun json(body: String, code: Int = 200): MockResponse =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    private fun completion(text: String = "hi there"): MockResponse = json(completionJson(text))

    private fun answerEverythingWith(response: () -> MockResponse) {
        enclave.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = response()
        }
    }

    /** Sleeps for no time, and counts how often the OpenAI SDK waited before sending again. */
    private class NoSleep(private val before: () -> Unit = {}) : Sleeper {
        val sleeps = AtomicInteger()

        override fun sleep(duration: Duration) {
            sleeps.incrementAndGet()
            before()
        }

        override fun sleepAsync(duration: Duration): CompletableFuture<Void> {
            sleep(duration)
            return CompletableFuture.completedFuture(null)
        }

        override fun close() {}
    }

    /** An HTTP client of the caller's own, which must never be used. */
    private class Recording : HttpClient {
        val requests = AtomicInteger()

        override fun execute(request: HttpRequest, requestOptions: RequestOptions): HttpResponse {
            requests.incrementAndGet()
            throw IllegalStateException("the caller's HTTP client was used")
        }

        override fun executeAsync(request: HttpRequest, requestOptions: RequestOptions): CompletableFuture<HttpResponse> {
            requests.incrementAndGet()
            throw IllegalStateException("the caller's HTTP client was used")
        }

        override fun close() {}
    }

    private fun Throwable.allText(): String =
        generateSequence(this) { it.cause }.take(16).joinToString("\n") { "$it ${it.suppressed.toList()}" }

    // Requests.

    @Test
    fun aChatCompletionGoesThroughTheEnclaveClientToItsApi() = test {
        val client = enclaveClient()
        enclave.server.enqueue(completion())

        val answer = client.openAI.chat().completions().create(params("a prompt"))

        assertEquals("hi there", answer.choices().single().message().content().get())
        assertEquals(1, enclave.server.requestCount)
        val request = enclave.server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/v1/chat/completions", request.path)
        assertEquals(listOf("Bearer $KEY"), request.headers.values("Authorization"))
        assertEquals("application/json", request.getHeader("Content-Type"))
        val body = request.body.readUtf8()
        assertTrue(body.contains("\"model\":\"a-model\"") && body.contains("a prompt"), body)
        // The body's length is declared, as the OpenAI SDK knows it.
        assertEquals(body.length.toString(), request.getHeader("Content-Length"))
        assertNull(request.getHeader("Transfer-Encoding"))
        assertNull(request.getHeader(TinfoilEvents.HEADER))
        assertFalse(body.contains("user_cache_secret"), "an enclave client has no cache secret unless it is given one")
    }

    @Test
    fun anAsyncChatCompletionGoesThroughTheEnclaveClient() = test {
        val client = enclaveClient()
        enclave.server.enqueue(completion("async"))

        val answer = client.openAIAsync.chat().completions().create(params()).await()

        assertEquals("async", answer.choices().single().message().content().get())
        val request = enclave.server.takeRequest()
        assertEquals("/v1/chat/completions", request.path)
        assertEquals("Bearer $KEY", request.getHeader("Authorization"))
    }

    @Test
    fun theOpenAiApiIsUnderTheEnclavesOrigin() = test {
        val client = enclaveClient()
        enclave.server.enqueue(completion())

        client.openAI.chat().completions().create(params())

        assertEquals("/v1/chat/completions", enclave.server.takeRequest().path)
    }

    @Test
    fun theRouterClientSendsToTheRoutersApiWithTheCacheSecretSpliced() = test {
        val client = routerClient(userCacheSecret = "scope-0123456789")
        enclave.server.enqueue(completion())
        enclave.server.enqueue(completion())
        enclave.server.enqueue(json("""{"object":"list","data":[]}"""))

        client.openAI.chat().completions().create(params())
        val own = params().toBuilder().putAdditionalBodyProperty("user_cache_secret", JsonValue.from("its-own-scope")).build()
        client.openAI.chat().completions().create(own)
        client.openAI.models().list()

        assertEquals(enclave.host, (client.httpClient as RouterHttpClient).enclave)
        val first = enclave.server.takeRequest()
        assertEquals("/v1/chat/completions", first.path)
        assertEquals("Bearer $KEY", first.getHeader("Authorization"))
        val body = first.body.readUtf8()
        assertTrue(body.endsWith(""","user_cache_secret":"scope-0123456789"}"""), body)
        assertTrue(body.contains("\"model\":\"a-model\""), body)
        assertEquals(body.length.toString(), first.getHeader("Content-Length"), "the new body's length is declared")

        val second = enclave.server.takeRequest().body.readUtf8()
        assertTrue(second.contains(""""user_cache_secret":"its-own-scope""""), second)
        assertFalse(second.contains("scope-0123456789"), second)

        val models = enclave.server.takeRequest()
        assertEquals("GET", models.method)
        assertEquals("/v1/models", models.path)
        assertEquals(0, elsewhere.requestCount)
    }

    @Test
    fun aRouterClientWithoutASecretScopesRequestsToTheProcess() = test {
        val client = routerClient()
        enclave.server.enqueue(completion())
        enclave.server.enqueue(completion())

        client.openAI.chat().completions().create(params())
        client.openAIAsync.chat().completions().create(params()).await()

        val secret = Regex(""","user_cache_secret":"([^"]{16,})"}$""")
        val first = assertNotNull(secret.find(enclave.server.takeRequest().body.readUtf8())).groupValues[1]
        val second = assertNotNull(secret.find(enclave.server.takeRequest().body.readUtf8())).groupValues[1]
        assertEquals(first, second)
    }

    @Test
    fun theDropInClientDiscoversARouterAndSendsOnlyToIt() = test {
        // The router serves its own attestation document, as a router that
        // is found on the list does.
        val served = CopyOnWriteArrayList<RecordedRequest>()
        enclave.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                if (request.path!!.startsWith("/.well-known/tinfoil-attestation")) {
                    MockResponse().setBody("document")
                } else {
                    served += request
                    if (request.path == "/v1/models") json("""{"object":"list","data":[]}""") else completion("from the router")
                }
        }
        elsewhere.enqueue(MockResponse().setBody("""["${enclave.host}"]"""))

        val client = Client.create(KEY, dropInConnection()) {
            openAI { maxRetries(0) }
        }
        closeables += client

        assertEquals("https://${enclave.host}/v1/", client.baseUrl.toString())
        assertEquals("/routers", elsewhere.takeRequest().path)
        assertNull(elsewhere.takeRequest(10, TimeUnit.MILLISECONDS), "only the list is fetched from its server")

        val answer = client.openAI.chat().completions().create(params())
        assertEquals("from the router", answer.choices().single().message().content().get())
        client.openAIAsync.models().list().await()
        client.httpClient.newCall(Request.Builder().url(client.baseUrl.resolve("models")!!).build()).execute().close()

        assertEquals(listOf("/v1/chat/completions", "/v1/models", "/v1/models"), served.map { it.path })
        assertEquals("Bearer $KEY", served[0].getHeader("Authorization"))
        assertTrue(served[0].body.readUtf8().contains("\"user_cache_secret\":\""), "the route's cache secret is added")
        assertNull(served[2].getHeader("Authorization"), "the HTTP client adds no credentials of its own")
        assertFalse(client.toString().contains(KEY))

        client.close()
        client.close()
        val closed = assertFailsWith<OpenAIException> { client.openAI.models().list() }
        assertIs<ConfigurationException>(closed.tinfoilException)
    }

    @Test
    fun aPageAfterTheFirstIsFetchedFromTheSameApi() = test {
        val client = enclaveClient()
        enclave.server.enqueue(json("""{"object":"list","data":[{"id":"file-1","object":"file"}],"has_more":true}"""))
        enclave.server.enqueue(json("""{"object":"list","data":[],"has_more":false}"""))

        val page = client.openAI.files().list()
        assertTrue(page.hasNextPage())
        page.nextPage()

        assertEquals("/v1/files", enclave.server.takeRequest().path)
        val next = enclave.server.takeRequest()
        assertEquals("/v1/files?after=file-1", next.path)
        assertEquals("Bearer $KEY", next.getHeader("Authorization"))
    }

    @Test
    fun anUploadIsStreamedAndSentOnce() = test {
        val sleeper = NoSleep()
        val client = enclaveClient(configure = { sleeper(sleeper) })
        answerEverythingWith { json("""{"error":{"message":"no"}}""", code = 500) }
        val content = ByteArray(256 * 1024) { 'u'.code.toByte() }
        val upload: InputStream = ByteArrayInputStream(content).buffered()

        assertFailsWith<InternalServerException> {
            client.openAI.files().create(
                FileCreateParams.builder().file(upload).purpose(FilePurpose.USER_DATA).build(),
            )
        }

        assertEquals(1, enclave.server.requestCount, "a body that can be written only once is not sent again")
        assertEquals(0, sleeper.sleeps.get())
        val request = enclave.server.takeRequest()
        assertEquals("/v1/files", request.path)
        assertTrue(request.getHeader("Content-Type")!!.startsWith("multipart/form-data"), request.getHeader("Content-Type"))
        assertNull(request.getHeader("Content-Length"), "a stream of unknown length is not buffered to measure it")
        assertTrue(request.body.size > content.size)
    }

    // Nothing but the attested client carries a request.

    @Test
    fun theOpenAiSdksOwnHttpClientIsNotOnTheClasspath() {
        for (name in listOf("com.openai.client.okhttp.OpenAIOkHttpClient", "com.openai.client.okhttp.OkHttpClient")) {
            assertFailsWith<ClassNotFoundException> { Class.forName(name) }
        }
    }

    @Test
    fun theCallersOptionsCannotReplaceTheHttpClientOrTheBaseUrl() = test {
        val theirs = Recording()
        val client = enclaveClient(
            configure = {
                httpClient(theirs)
                baseUrl(elsewhere.url("/v1/").toString())
                maxRetries(0)
                putHeader("X-Callers-Own", "kept")
            },
        )
        enclave.server.enqueue(completion())
        enclave.server.enqueue(completion())

        client.openAI.chat().completions().create(params())
        client.openAIAsync.chat().completions().create(params()).await()

        assertEquals(0, theirs.requests.get(), "the caller's HTTP client is replaced")
        assertEquals(0, elsewhere.requestCount, "the caller's base URL is replaced")
        assertEquals(2, enclave.server.requestCount)
        val request = enclave.server.takeRequest()
        assertEquals("/v1/chat/completions", request.path)
        assertEquals("kept", request.getHeader("X-Callers-Own"), "the caller's other options apply")
    }

    @Test
    fun aRequestOffTheClientsOriginIsRefusedAndNotRetried() = test {
        val sleeper = NoSleep()
        val client = enclaveClient(configure = { sleeper(sleeper) })
        val derived = client.openAI.withOptions { it.baseUrl(elsewhere.url("/v1/").toString()) }

        val error = assertFailsWith<OpenAIException> { derived.chat().completions().create(params()) }
        val async = assertFailsWith<OpenAIException> { derived.async().chat().completions().create(params()).await() }

        for (e in listOf(error, async)) {
            assertEquals(OpenAIException::class.java, e.javaClass, "not an exception that the OpenAI SDK retries")
            val refusal = assertIs<ConfigurationException>(e.tinfoilException)
            assertTrue(refusal.detail.contains("refusing to send a request"), refusal.detail)
            assertFalse(e.allText().contains(KEY), e.allText())
        }
        assertSame(error.tinfoilException, error.cause, "the refusal is the cause of what a blocking call throws")
        assertEquals(0, sleeper.sleeps.get())
        assertEquals(0, elsewhere.requestCount, "nothing, and no API key, is sent off the origin")
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun nothingIsTakenFromSystemProperties() = test {
        val properties = mapOf(
            "openai.baseUrl" to elsewhere.url("/v1/").toString(),
            "openai.apiKey" to "a-key-from-a-system-property",
            "openai.orgId" to "an-org-from-a-system-property",
            "openai.projectId" to "a-project-from-a-system-property",
            "openai.adminKey" to "an-admin-key-from-a-system-property",
            "openai.disableTelemetry" to "true",
        )
        properties.forEach { (name, value) -> System.setProperty(name, value) }
        try {
            // Without an API key of its own, a client is refused rather
            // than given the one in the properties.
            val http = enclaveHttp()
            val fetchesBefore = enclave.fetches
            val refused = assertFailsWith<ConfigurationException> { enclaveClient(apiKey = "", http = http) }
            assertTrue(refused.detail.contains("API key"), refused.detail)
            assertEquals(fetchesBefore, enclave.fetches, "the OpenAI options are checked before any I/O")

            val client = enclaveClient()
            enclave.server.enqueue(completion())
            client.openAI.chat().completions().create(params())

            val request = enclave.server.takeRequest()
            assertEquals(listOf("Bearer $KEY"), request.headers.values("Authorization"))
            assertNull(request.getHeader("OpenAI-Organization"))
            assertNull(request.getHeader("OpenAI-Project"))
            assertEquals("java", request.getHeader("X-Stainless-Lang"), "the telemetry switch is not read either")
            assertEquals(0, elsewhere.requestCount)
        } finally {
            properties.keys.forEach { System.clearProperty(it) }
        }
    }

    @Test
    fun anEmptyOrBlankApiKeyIsRefusedWithoutAnyIoWhateverTheOptionsSet() = test {
        val http = enclaveHttp()
        for (key in listOf("", " ", "\t\n ")) {
            for (configure in listOf<(ClientOptions.Builder.() -> Unit)?>(null, { apiKey("set-in-the-options") })) {
                val refused = assertFailsWith<ConfigurationException> { enclaveClient(apiKey = key, configure = configure, http = http) }
                assertEquals("the API key is empty or blank", refused.detail)
            }
        }
        val dropIn = assertFailsWith<ConfigurationException> { Client.create(" ", dropInConnection()) { } }
        assertEquals("the API key is empty or blank", dropIn.detail)

        assertEquals(1, enclave.fetches, "only the HTTP client verified")
        assertEquals(1, enclave.verifications)
        assertEquals(0, enclave.server.requestCount + elsewhere.requestCount, "the drop-in client discovered nothing")
    }

    @Test
    fun aCredentialFromTheCallersOptionsReplacesTheApiKey() = test {
        val client = enclaveClient(configure = { apiKey("set-in-the-options") })
        val other = enclaveClient(configure = { credential(BearerTokenCredential.create("a-credential-in-the-options")) })
        enclave.server.enqueue(completion())
        enclave.server.enqueue(completion())

        client.openAI.chat().completions().create(params())
        other.openAI.chat().completions().create(params())

        assertEquals(listOf("Bearer set-in-the-options"), enclave.server.takeRequest().headers.values("Authorization"))
        assertEquals(listOf("Bearer a-credential-in-the-options"), enclave.server.takeRequest().headers.values("Authorization"))
    }

    @Test
    fun aCredentialOfAnotherKindInTheCallersOptionsIsRefusedWithTheApiKeyWithoutAnyIo() = test {
        val http = enclaveHttp()
        val error = assertFailsWith<ConfigurationException> {
            enclaveClient(
                http = http,
                configure = {
                    httpRequestAuthenticator(
                        object : HttpRequestAuthenticator {
                            override fun authenticate(request: HttpRequest): HttpRequest = request
                        },
                    )
                },
            )
        }
        val provider = object : SubjectTokenProvider {
            override fun tokenType(): SubjectTokenType = SubjectTokenType.JWT

            override fun getToken(httpClient: HttpClient, jsonMapper: JsonMapper): String = "a-token"

            override fun getTokenAsync(httpClient: HttpClient, jsonMapper: JsonMapper): CompletableFuture<String> =
                CompletableFuture.completedFuture("a-token")
        }
        val identity = WorkloadIdentity.builder().clientId("a-client").identityProviderId("a-provider")
            .serviceAccountId("an-account").provider(provider).build()
        val withAnIdentity = assertFailsWith<ConfigurationException> {
            enclaveClient(http = http, configure = { workloadIdentity(identity) })
        }

        for (refusal in listOf(error, withAnIdentity)) {
            assertTrue(refusal.detail.startsWith("the OpenAI options do not make a client"), refusal.detail)
            assertFalse(refusal.allText().contains(KEY), refusal.allText())
        }
        assertEquals(1, enclave.fetches, "only the HTTP client verified")
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun optionsThatSelectADestinationOfTheirOwnAreRefusedWithoutAnyIo() = test {
        val http = enclaveHttp()
        val error = assertFailsWith<ConfigurationException> {
            enclaveClient(http = http, configure = { dataResidency(DataResidency.EU) })
        }

        assertTrue(error.detail.startsWith("the OpenAI options do not make a client"), error.detail)
        assertEquals(1, enclave.fetches, "only the HTTP client verified")
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aFailedCreationLeavesNothingOpen() = test {
        enclave.verifyWith { _, _ -> throw rejection(VerificationLayer.POLICY, "not this enclave") }

        val error = assertFailsWith<AttestationException> { enclaveClient() }

        assertEquals(VerificationLayer.POLICY, assertIs<VerificationException>(error.cause).layer)
        assertEquals(0, enclave.server.requestCount)
    }

    // Tinfoil events.

    @Test
    fun theEventsHeaderListsTheEventsInOrderAndIsLeftOutWhenThereAreNone() {
        assertNull(TinfoilEvents.headerValue(emptySet()))
        assertEquals("web_search", TinfoilEvents.headerValue(setOf(TinfoilEvent.WEB_SEARCH)))
        assertEquals(TinfoilEvent.entries.map { it.value }.sorted().joinToString(","), TinfoilEvents.headerValue(TinfoilEvent.entries.toSet()))
        assertEquals("web_search", TinfoilEvent.WEB_SEARCH.value)
    }

    @Test
    fun everyRequestAsksForTheClientsEventsUnlessItNamesItsOwn() = test {
        val client = enclaveClient(tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH))
        repeat(3) { enclave.server.enqueue(completion()) }
        enclave.server.enqueue(json("""{"object":"list","data":[]}"""))

        client.openAI.chat().completions().create(params())
        client.openAIAsync.chat().completions().create(params()).await()
        client.openAI.chat().completions().create(params().toBuilder().putAdditionalHeader("x-tinfoil-events", "its_own").build())
        client.openAI.withOptions { it.headers(emptyMap()) }.models().list()

        assertEquals(listOf("web_search"), enclave.server.takeRequest().headers.values(TinfoilEvents.HEADER))
        assertEquals(listOf("web_search"), enclave.server.takeRequest().headers.values(TinfoilEvents.HEADER))
        assertEquals(listOf("its_own"), enclave.server.takeRequest().headers.values(TinfoilEvents.HEADER))
        assertEquals(listOf("web_search"), enclave.server.takeRequest().headers.values(TinfoilEvents.HEADER))
    }

    // Streaming.

    private fun chunk(text: String): String =
        """data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"a-model",""" +
            """"choices":[{"index":0,"delta":{"content":"$text"},"finish_reason":null}]}""" + "\n\n"

    /**
     * An enclave that streams a chat completion: it sends the first event at
     * once, and the rest only when [release] is counted down.
     */
    private fun streamingEnclave(release: CountDownLatch, requests: CopyOnWriteArrayList<String>): RawTlsServer {
        val certificate = enclave.authority.issue()
        enclave.endorsed = { certificate.fingerprint }
        return RawTlsServer(certificate) { socket ->
            val input = socket.inputStream.bufferedReader()
            val head = generateSequence { input.readLine() }.takeWhile { it.isNotEmpty() }.toList()
            requests += head.first()
            val length = head.first { it.startsWith("Content-Length:", ignoreCase = true) }.substringAfter(":").trim().toInt()
            repeat(length) { input.read() }
            val output = socket.outputStream
            fun send(text: String) {
                output.write("${text.length.toString(16)}\r\n$text\r\n".toByteArray())
                output.flush()
                bytesSent.addAndGet(text.length.toLong())
            }
            output.write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray())
            send(chunk("one"))
            if (!release.await(30, TimeUnit.SECONDS)) {
                return@RawTlsServer
            }
            send(chunk("two"))
            send("data: [DONE]\n\n")
            output.write("0\r\n\r\n".toByteArray())
            output.flush()
            // Stays until the client is done with the connection.
            socket.soTimeout = 30_000
            while (socket.inputStream.read() >= 0) {
                // Nothing more is expected.
            }
        }.also { closeables += it }
    }

    private fun texts(chunks: List<com.openai.models.chat.completions.ChatCompletionChunk>): List<String> =
        chunks.flatMap { it.choices() }.mapNotNull { it.delta().content().orElse(null) }

    @Test
    fun aStreamedCompletionArrivesAsItIsSentAndStoppingItsCollectionCancelsTheRequest() = test {
        val release = CountDownLatch(1)
        val requests = CopyOnWriteArrayList<String>()
        val server = streamingEnclave(release, requests)
        val client = enclaveClient(host = "localhost:${server.port}")

        // The first event is delivered while the enclave has yet to send
        // the second: nothing waits for the whole response.
        val first = client.openAIAsync.chat().completions().createStreaming(params()).asFlow().first()

        assertEquals(listOf("one"), texts(listOf(first)))
        assertEquals(listOf("POST /v1/chat/completions HTTP/1.1"), requests)
        // Taking only the first event ended the collection, which ended
        // the exchange: the enclave's connection is closed under it.
        release.countDown()
        awaitUntil { server.finished.get() == 1 }
        assertEquals(1, server.handshakes.get())
    }

    @Test
    fun aStreamedCompletionIsCollectedToItsEnd() = test {
        val release = CountDownLatch(1)
        val server = streamingEnclave(release, CopyOnWriteArrayList())
        val client = enclaveClient(host = "localhost:${server.port}")
        release.countDown()

        val flow = client.openAIAsync.chat().completions().createStreaming(params()).asFlow()

        assertEquals(listOf("one", "two"), texts(flow.toList()))
        assertFailsWith<IllegalStateException>("a response is collected once") { flow.toList() }
    }

    @Test
    fun closingABlockingStreamCancelsItsRequest() = test {
        val release = CountDownLatch(1)
        val server = streamingEnclave(release, CopyOnWriteArrayList())
        val client = enclaveClient(host = "localhost:${server.port}")

        val stream = client.openAI.chat().completions().createStreaming(params())
        val first = stream.stream().iterator().next()
        assertEquals(listOf("one"), texts(listOf(first)))
        stream.close()

        // The enclave was still holding the rest back. A connection whose
        // exchange had not been cancelled would be kept for the next
        // request; this one is gone.
        release.countDown()
        awaitUntil { server.finished.get() == 1 }
        assertEquals(1, server.handshakes.get())
    }

    @Test
    fun aFailureBeforeAStreamStartsReachesTheCollector() = test {
        val client = enclaveClient(configure = { maxRetries(0) })
        enclave.server.enqueue(json("""{"error":{"message":"no key","type":"invalid_request_error"}}""", code = 401))

        val error = assertFailsWith<UnauthorizedException> {
            client.openAIAsync.chat().completions().createStreaming(params()).asFlow().toList()
        }

        assertEquals(401, error.statusCode())
        assertNull(error.tinfoilException)
    }

    // Failures and retries.

    @Test
    fun anEnclaveThatFailsItsVerificationIsNotTriedAgainByTheOpenAiSdk() = test {
        val sleeper = NoSleep()
        val client = enclaveClient(configure = { sleeper(sleeper) })
        enclave.verifyWith { _, _ -> throw rejection(VerificationLayer.QUOTE, "the quote is forged") }
        enclave.clock.advance(enclave.lifetimeSeconds + 1)

        // What one request costs when it is sent directly.
        val before = enclave.fetches
        assertFailsWith<AttestationException> { client.enclaveHttp.execute(enclave.get("/v1/models")) }
        val perRequest = enclave.fetches - before
        assertTrue(perRequest >= 1)

        val blocking = assertFailsWith<OpenAIException> { client.openAI.chat().completions().create(params()) }
        assertEquals(2 * perRequest, enclave.fetches - before, "one request, one round of verification")
        val async = assertFailsWith<OpenAIException> { client.openAIAsync.chat().completions().create(params()).await() }
        assertEquals(3 * perRequest, enclave.fetches - before)
        val streamed = assertFailsWith<OpenAIException> {
            client.openAIAsync.chat().completions().createStreaming(params()).asFlow().toList()
        }
        assertEquals(4 * perRequest, enclave.fetches - before)

        for (e in listOf(blocking, async, streamed)) {
            assertEquals(OpenAIException::class.java, e.javaClass)
            val failure = assertIs<AttestationException>(e.tinfoilException)
            assertEquals(VerificationLayer.QUOTE, assertIs<VerificationException>(failure.cause).layer)
            assertTrue(e.message!!.startsWith("attestation error: "), e.message)
            assertFalse(e.allText().contains(KEY), e.allText())
        }
        assertSame(blocking.tinfoilException, blocking.cause)
        assertEquals(0, sleeper.sleeps.get(), "the OpenAI SDK did not wait to send again")
        assertEquals(0, enclave.server.requestCount, "nothing was sent to an enclave that does not verify")
    }

    @Test
    fun anEnclaveThatCannotBeReachedForItsVerificationIsTriedAgainAsANetworkFailure() = test {
        val sleeper = NoSleep()
        val client = enclaveClient(configure = { sleeper(sleeper) })
        enclave.relay.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = MockResponse().setResponseCode(503)
        }
        enclave.clock.advance(enclave.lifetimeSeconds + 1)

        val error = assertFailsWith<OpenAIIoException> { client.openAI.chat().completions().create(params()) }

        val failure = assertIs<NetworkException>(error.tinfoilException)
        assertEquals(503, failure.status)
        assertEquals(2, sleeper.sleeps.get(), "the OpenAI SDK's own two retries")
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun aKeyRotationUnderARequestIsAnsweredByVerifyingAgainAndSendingOnce() = test {
        val sleeper = NoSleep()
        // The enclave's key is the server's throughout; the verification in
        // the middle endorses another, as one from before a rotation would.
        val held = enclave.certificate.fingerprint
        val stale = enclave.authority.issue().fingerprint
        val endorsements = ArrayDeque(listOf(held, stale, held))
        enclave.endorsed = { endorsements.removeFirst() }
        val client = enclaveClient(configure = { sleeper(sleeper) })
        enclave.server.enqueue(completion("before"))
        client.openAI.chat().completions().create(params())
        client.enclaveHttp.reverify()
        assertEquals(stale, client.enclaveHttp.lastVerification()?.report?.verifiedFacts?.tlsPublicKeyFingerprint)

        enclave.server.enqueue(completion("after"))
        val answer = client.openAI.chat().completions().create(params())

        assertEquals("after", answer.choices().single().message().content().get())
        assertEquals(3, enclave.fetches, "the enclave was verified again")
        assertEquals(held, client.enclaveHttp.lastVerification()?.report?.verifiedFacts?.tlsPublicKeyFingerprint)
        assertEquals(2, enclave.server.requestCount, "the second request reached the enclave once, under the held key")
        assertEquals(0, sleeper.sleeps.get(), "the attested client sent it again, not the OpenAI SDK")
        enclave.server.takeRequest()
        val request = enclave.server.takeRequest()
        assertEquals("0", request.getHeader("X-Stainless-Retry-Count"))
        assertFalse(request.body.readUtf8().contains("user_cache_secret"), "an enclave client adds no cache secret")
    }

    @Test
    fun aServerErrorIsSentThreeTimesByDefaultAndReportedWithItsType() = test {
        val sleeper = NoSleep()
        val client = enclaveClient(configure = { sleeper(sleeper) })
        answerEverythingWith { json("""{"error":{"message":"overloaded"}}""", code = 500) }

        assertFailsWith<InternalServerException> { client.openAI.chat().completions().create(params()) }

        assertEquals(3, enclave.server.requestCount)
        assertEquals(2, sleeper.sleeps.get())
        assertEquals(listOf("0", "1", "2"), List(3) { enclave.server.takeRequest().getHeader("X-Stainless-Retry-Count") })
    }

    @Test
    fun theWholeRequestTimeoutOfARequestIsApplied() = test {
        val client = enclaveClient(configure = { maxRetries(0) })
        val release = CountDownLatch(1)
        enclave.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                release.await(30, TimeUnit.SECONDS)
                return completion()
            }
        }
        val started = System.nanoTime()

        val error = assertFailsWith<OpenAIIoException> {
            client.openAI.chat().completions().create(params(), RequestOptions.builder().timeout(Duration.ofMillis(300)).build())
        }

        assertIs<InterruptedIOException>(error.cause)
        assertNull(error.tinfoilException)
        assertTrue(System.nanoTime() - started < 10_000_000_000, "the request ended with its timeout")
        release.countDown()
    }

    // Secrets and closing.

    @Test
    fun anApiKeyThatCannotBeAHeaderIsRefusedWithoutBeingRepeated() = test {
        val key = "a-key-with\na-line-break-0123456789"
        val client = enclaveClient(apiKey = key)

        val error = assertFailsWith<OpenAIException> { client.openAI.chat().completions().create(params()) }

        val refusal = assertIs<ConfigurationException>(error.tinfoilException)
        assertTrue(refusal.detail.contains("Authorization"), refusal.detail)
        assertFalse(error.allText().contains("line-break"), error.allText())
        assertEquals(0, enclave.server.requestCount)
    }

    @Test
    fun theClientsDescribeThemselvesWithoutTheApiKey() = test {
        val direct = enclaveClient()
        val router = routerClient()

        for (text in listOf(direct.toString(), router.toString(), direct.httpClient.toString(), router.httpClient.toString())) {
            assertFalse(text.contains(KEY), text)
        }
        assertEquals("Client(baseUrl=https://${enclave.host}/v1/)", direct.toString())
        assertEquals("Client(baseUrl=https://${enclave.host}/v1/)", router.toString())
    }

    @Test
    fun closingClosesTheOpenAiClientAndLeavesTheCallersHttpClientOpen() = test {
        val client = enclaveClient()
        enclave.server.enqueue(completion())
        client.openAI.chat().completions().create(params())

        client.close()
        client.close()

        val error = assertFailsWith<OpenAIException> { client.openAI.chat().completions().create(params()) }
        assertEquals(OpenAIException::class.java, error.javaClass)
        assertIs<ConfigurationException>(error.tinfoilException)
        val async = assertFailsWith<OpenAIException> { client.openAIAsync.models().list().await() }
        assertIs<ConfigurationException>(async.tinfoilException)
        enclave.server.enqueue(json("""{"object":"list","data":[]}"""))
        client.enclaveHttp.execute(enclave.get("/v1/models")).close()
        client.enclaveHttp.ensureVerified()
        assertEquals(2, enclave.server.requestCount, "the HTTP client is the caller's, and stays open")
    }

    // Sealed bodies.

    @Test
    fun aChatCompletionIsSealedToTheAttestedKeyAndItsAnswerOpened() = test {
        val key = SealingKey()
        val sealing = SealingDispatcher({ key }) { it.reply(completionJson("sealed answer")) }
        enclave.endorsedHpke = { key.publicKey }
        enclave.server.dispatcher = sealing
        val client = enclaveClient(transport = Transport.Ehbp())
        val prompt = "a-prompt-that-must-not-be-seen-on-the-wire"

        val answer = client.openAI.chat().completions().create(params(prompt))

        assertEquals("sealed answer", answer.choices().single().message().content().get())
        val received = sealing.received.single()
        assertTrue(received.sealed)
        assertEquals("/v1/chat/completions", received.request.path)
        assertEquals("Bearer $KEY", received.request.getHeader("Authorization"))
        assertFalse(received.wire.containsText(prompt), "the prompt was sent in the clear")
        val text = assertNotNull(received.text)
        assertTrue(text.contains(prompt) && !text.contains("user_cache_secret"), text)
    }

    @Test
    fun aStreamedCompletionIsOpenedPieceByPiece() = test {
        val key = SealingKey()
        val events = chunk("one") + chunk("two") + chunk("three") + "data: [DONE]\n\n"
        val sealing = SealingDispatcher({ key }) { it.reply(events, pieces = 7).setHeader("Content-Type", "text/event-stream") }
        enclave.endorsedHpke = { key.publicKey }
        enclave.server.dispatcher = sealing
        val client = enclaveClient(transport = Transport.Ehbp())

        val chunks = client.openAIAsync.chat().completions().createStreaming(params()).asFlow().toList()

        assertEquals(listOf("one", "two", "three"), texts(chunks))
        assertTrue(sealing.received.single().sealed)
    }

    @Test
    fun theMostThatOneRequestIsSentIsTwiceForEachOfTheOpenAiSdksAttempts() = test {
        // The worst case: the enclave changes its key before every attempt,
        // and answers every request that it can open with an error that the
        // OpenAI SDK sends again after.
        var key = SealingKey()
        val sealing = SealingDispatcher({ key }) { it.reply("""{"error":{"message":"overloaded"}}""", code = 500) }
        enclave.endorsedHpke = { key.publicKey }
        enclave.server.dispatcher = sealing
        val sleeper = NoSleep(before = { key = SealingKey() })
        val client = enclaveClient(transport = Transport.Ehbp(), configure = { sleeper(sleeper) })
        key = SealingKey()

        assertFailsWith<InternalServerException> { client.openAI.chat().completions().create(params()) }

        assertEquals(2, sleeper.sleeps.get(), "three attempts by the OpenAI SDK")
        assertEquals(6, sealing.received.size, "each attempt was sent once to a key that was gone, and once more")
        assertEquals(3, sealing.received.count { it.plaintext != null }, "the enclave could read three")
        assertEquals(1 + 3, enclave.fetches)
    }

    private companion object {
        const val KEY = "an-api-key-0123456789abcdef"

        fun completionJson(text: String): String =
            """{"id":"c1","object":"chat.completion","created":1,"model":"a-model","choices":[{"index":0,""" +
                """"finish_reason":"stop","logprobs":null,"message":{"role":"assistant","content":"$text","refusal":null}}]}"""
    }
}
