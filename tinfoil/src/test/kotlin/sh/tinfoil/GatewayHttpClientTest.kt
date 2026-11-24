@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.mockwebserver.MockResponse
import okio.BufferedSink
import sh.tinfoil.internal.gateway.GatewayCatalog
import sh.tinfoil.internal.gateway.GatewayRouter
import sh.tinfoil.testing.ENCLAVE_URL_HEADER
import sh.tinfoil.testing.FakeVerifier
import sh.tinfoil.testing.TestGateway
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.facts
import sh.tinfoil.testing.containsText
import java.io.IOException
import java.io.InterruptedIOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/** The gateway client: what it verifies, what it seals to whom, and what it refuses. */
class GatewayHttpClientTest {
    private val gateway = TestGateway()

    @AfterTest
    fun shutDown() {
        gateway.close()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(120.seconds) { block() } }

    private fun GatewayHttpClient.post(
        body: String,
        path: String = "chat/completions",
        authorization: String? = "Bearer $API_KEY",
    ): Request = Request.Builder().url(baseUrl.resolve(path)!!).post(body.toRequestBody(JSON)).apply {
        authorization?.let { header("Authorization", it) }
    }.build()

    private fun Response.text(): String = use { it.body!!.string() }

    private fun chat(model: String = "m", prompt: String = "hello") =
        """{"model":"$model","messages":[{"role":"user","content":"$prompt"}]}"""

    private fun entries(vararg models: Pair<String, Pair<String, List<String>>>): Catalog =
        Catalog(models.associate { (model, entry) -> model to CatalogEntry(entry.first, entry.second) })

    private fun assertNoIo() {
        assertEquals(0, gateway.server.requestCount, "requests to the gateway")
        assertEquals(0, gateway.verifier.verifications.get(), "verifications")
    }

    // Options.

    @Test
    fun everyOptionIsCheckedBeforeAnyIo() = test {
        val pin = mapOf("m" to ModelPin("tinfoilsh/m"))
        val refused: List<Pair<String, suspend () -> Unit>> = listOf(
            "requires at least one model pin" to {
                gateway.track(GatewayHttpClient.create(gateway.internals()) { url = gateway.baseUrl })
            },
            "requires at least one model pin" to { gateway.client(modelPins = emptyMap()) },
            "must belong to tinfoilsh/" to { gateway.client(modelPins = mapOf("m" to ModelPin("acme/m"))) },
            "must belong to tinfoilsh/" to { gateway.client(modelPins = mapOf("m" to ModelPin(""))) },
            "must belong to tinfoilsh/" to { gateway.client(modelPins = mapOf("m" to ModelPin("Tinfoilsh/m"))) },
            "must belong to tinfoilsh/" to { gateway.client(modelPins = mapOf("m" to ModelPin(" tinfoilsh/m"))) },
            "must belong to tinfoilsh/" to { gateway.client(modelPins = mapOf("" to ModelPin("tinfoilsh/m"))) },
            "must belong to tinfoilsh/" to { gateway.client(modelPins = mapOf(" \t" to ModelPin("tinfoilsh/m"))) },
            "freshness maximum age" to { gateway.client(policy = Policy(freshnessMaxAge = (-1).seconds)) },
            // The client's policy is checked even if every pin has its own.
            "freshness maximum age" to {
                gateway.client(
                    modelPins = mapOf("m" to ModelPin("tinfoilsh/m", Policy())),
                    policy = Policy(freshnessMaxAge = (-1).seconds),
                )
            },
            "model \"m\": freshness maximum age" to {
                gateway.client(modelPins = mapOf("m" to ModelPin("tinfoilsh/m", Policy(freshnessMaxAge = (-1).seconds))))
            },
            "invalid base URL" to { gateway.client(modelPins = pin, baseUrl = "http://${gateway.host}/v1/") },
            "must use HTTPS" to { gateway.client(baseUrl = "http://localhost:${gateway.server.port}/v1/") },
            "invalid base URL" to { gateway.client(baseUrl = "${gateway.baseUrl}?x=1") },
            "invalid base URL" to { gateway.client(baseUrl = "${gateway.baseUrl}?") },
            "invalid base URL" to { gateway.client(baseUrl = "${gateway.baseUrl}#") },
            "invalid base URL" to { gateway.client(baseUrl = "https://user:secret@${gateway.host}/v1/") },
            "invalid base URL" to { gateway.client(baseUrl = "${gateway.host}/v1/") },
            "invalid base URL" to { gateway.client(baseUrl = "wss://${gateway.host}/v1/") },
            "user cache secret is not well-formed" to { gateway.client(userCacheSecret = "half\ud800") },
            "url must not be empty" to { gateway.client(baseUrl = "") },
        )
        for ((message, create) in refused) {
            val error = assertFailsWith<ConfigurationException>(message) { create() }
            assertTrue(error.detail.contains(message), "$message: ${error.detail}")
            assertFalse(error.message!!.contains("user:secret"), "a refused URL is not echoed")
        }
        assertNoIo()
    }

    @Test
    fun aPinThatNoVerificationCouldSucceedWithIsRefusedBeforeAnyIo() = test {
        val checked = CopyOnWriteArrayList<Pin>()
        gateway.verifier.checkPin = { pin ->
            checked += pin
            if (pin.repo!!.contains("@@")) {
                throw ConfigurationException("invalid release reference")
            }
        }
        val error = assertFailsWith<ConfigurationException> {
            gateway.client(modelPins = mapOf("m" to ModelPin("tinfoilsh/m@@")))
        }
        assertEquals("model \"m\": invalid release reference", error.detail)
        // The pin names the repository and the registry project alike.
        assertEquals(listOf(Pin(repo = "tinfoilsh/m@@", project = "tinfoilsh/m@@")), checked)
        assertNoIo()
    }

    @Test
    fun theDefaultBaseUrlIsTinfoilsGateway() {
        assertEquals("https://inference-gateway.tinfoil.sh/v1/", GatewayHttpClient.DEFAULT_URL)
        val client = gateway.unverified(baseUrl = null)
        assertEquals(GatewayHttpClient.DEFAULT_URL, client.baseUrl.toString())
        assertEquals("GatewayHttpClient(baseUrl=https://inference-gateway.tinfoil.sh/v1/)", client.toString())
    }

    @Test
    fun thePinsAreCopiedWhenTheClientIsCreated() = test {
        val pins = mutableMapOf("m" to ModelPin("tinfoilsh/m"))
        val client = gateway.client(modelPins = pins, catalog = { entries("m" to ("tinfoilsh/m" to listOf("a.example")), "n" to ("tinfoilsh/n" to listOf("a.example"))) })
        pins["n"] = ModelPin("tinfoilsh/n")
        pins.remove("m")
        assertEquals(listOf("m"), client.models())
    }

    @Test
    fun aBodyThatSaysItIsEmptyWhenItIsExaminedIsNotSealedAsItIsLater() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        val secret = "caller-secret-marker-77f2"
        val text = """{"model":"m","user_cache_secret":"$secret","messages":[]}"""
        for (zeros in 1..4) {
            val asked = AtomicInteger()
            val body = object : RequestBody() {
                override fun contentType(): MediaType = JSON

                override fun contentLength(): Long = if (asked.incrementAndGet() <= zeros) 0L else text.length.toLong()

                override fun writeTo(sink: BufferedSink) {
                    sink.writeUtf8(text)
                }
            }
            val request = Request.Builder().url(client.baseUrl.resolve("chat/completions")!!)
                .header("X-Tinfoil-Model", "m").post(body).build()
            try {
                client.execute(request).close()
            } catch (_: IOException) {
                // A request that fails has sent nothing that matters here.
            }
        }

        // A body that was not examined is not sent: its secret would leave
        // the device, and its members would go unchecked.
        for (received in gateway.received) {
            assertFalse(received.text.orEmpty().contains(secret), received.text)
            assertEquals(0, received.wire.size)
        }
    }

    // The catalog.

    @Test
    fun creatingAClientFetchesTheCatalogAndVerifiesNothing() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        assertEquals(1, gateway.catalogFetches.get())
        assertEquals(0, gateway.verifier.verifications.get())
        assertEquals(emptyList(), gateway.attestationFetches)
        assertEquals(emptyList(), client.replicas())
        assertEquals(gateway.baseUrl, client.baseUrl.toString())
    }

    @Test
    fun aGatewayWhoseCatalogCannotBeReadFailsTheCreation() = test {
        gateway.catalog = { MockResponse().setResponseCode(503) }
        val unavailable = assertFailsWith<NetworkException> { gateway.client() }
        assertEquals(503, unavailable.status)
        gateway.catalog = { MockResponse().setBody("[]") }
        val unreadable = assertFailsWith<NetworkException> { gateway.client() }
        assertTrue(unreadable.detail.contains("decoding gateway catalog"), unreadable.detail)
        gateway.catalog = { MockResponse().setResponseCode(204) }
        assertFailsWith<NetworkException> { gateway.client() }
    }

    @Test
    fun theModelsAreThoseOfTheCatalogThatThePolicyServes() = test {
        gateway.serve(
            "zeta" to ("tinfoilsh/zeta" to listOf("a.example")),
            "alpha" to ("tinfoilsh/alpha" to listOf("a.example")),
            "Beta" to ("tinfoilsh/beta" to listOf("a.example")),
            "moved" to ("tinfoilsh/elsewhere" to listOf("a.example")),
            "foreign" to ("acme/foreign" to listOf("a.example")),
            "tagged" to ("tinfoilsh/tagged@v1" to listOf("a.example")),
            "empty" to ("tinfoilsh/empty" to emptyList()),
        )
        val pins = mapOf(
            "alpha" to ModelPin("tinfoilsh/alpha@v1.2.3"),
            "zeta" to ModelPin("tinfoilsh/zeta"),
            "moved" to ModelPin("tinfoilsh/moved"),
            "foreign" to ModelPin("tinfoilsh/foreign"),
            "tagged" to ModelPin("tinfoilsh/tagged"),
            "empty" to ModelPin("tinfoilsh/empty"),
            "absent" to ModelPin("tinfoilsh/absent"),
        )
        // A model without a pin is not served, whatever the catalog says;
        // nor is a pin whose repository the catalog does not name, or that
        // the catalog has no usable entry for.
        assertEquals(listOf("alpha", "zeta"), gateway.client(modelPins = pins).models())
        assertEquals(emptyList(), gateway.client().models())
        assertEquals(0, gateway.verifier.verifications.get())
        assertEquals(emptyList(), gateway.attestationFetches)
    }

    @Test
    fun theCatalogIsFetchedAgainOnUseAfterTenSecondsAndAFailedFetchKeepsTheLast() = test {
        gateway.serve("old" to ("tinfoilsh/old" to listOf("a.example")))
        val client = gateway.client(modelPins = mapOf("old" to ModelPin("tinfoilsh/old"), "new" to ModelPin("tinfoilsh/new")))
        assertEquals(listOf("old"), client.models())
        gateway.serve("new" to ("tinfoilsh/new" to listOf("b.example")))

        gateway.timeSource += GatewayCatalog.REFRESH_INTERVAL - 1.nanoseconds
        assertEquals(listOf("old"), client.models())
        Thread.sleep(100)
        assertEquals(1, gateway.catalogFetches.get(), "nothing is fetched before the interval has passed")

        // The gateway is down when the interval passes.
        gateway.catalog = { MockResponse().setResponseCode(502) }
        gateway.timeSource += 1.nanoseconds
        assertEquals(listOf("old"), client.models(), "a use does not wait for the fetch that it starts")
        awaitUntil { gateway.catalogFetches.get() == 2 }
        Thread.sleep(100)
        assertEquals(listOf("old"), client.models(), "a failed fetch keeps the last catalog")
        assertEquals(2, gateway.catalogFetches.get())

        gateway.serve("new" to ("tinfoilsh/new" to listOf("b.example")))
        gateway.timeSource += GatewayCatalog.REFRESH_INTERVAL
        client.models()
        awaitUntil { runBlocking { client.models() } == listOf("new") }
        assertEquals(3, gateway.catalogFetches.get())

        // An idle client fetches nothing, however much time passes.
        gateway.timeSource += GatewayCatalog.REFRESH_INTERVAL * 1000
        Thread.sleep(200)
        assertEquals(3, gateway.catalogFetches.get())
    }

    @Test
    fun aModelThatARefreshOfTheCatalogAddsIsNotServedWithoutAPin() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        assertEquals(listOf("m"), client.models())
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")), "added" to ("tinfoilsh/added" to listOf("b.example")))
        gateway.timeSource += GatewayCatalog.REFRESH_INTERVAL
        client.models()
        awaitUntil { gateway.catalogFetches.get() == 2 }
        assertEquals(listOf("m"), client.models())

        val error = assertFailsWith<ConfigurationException> { client.ensureVerified("added") }
        assertEquals("model \"added\" is not pinned", error.detail)
        assertFailsWith<ConfigurationException> { client.execute(client.post(chat(model = "added"))) }
        assertEquals(emptyList(), gateway.attestationFetches)
        assertEquals(0, gateway.verifier.verifications.get())
        assertEquals(0, gateway.received.size)
        assertEquals(emptyList(), client.replicas())
    }

    @Test
    fun aRequestUsesTheCatalogAsItIsWhenItIsSent() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        client.execute(client.post(chat())).close()
        assertEquals("a.example", gateway.received.last().request.getHeader("X-Tinfoil-Seal"))

        gateway.serve("m" to ("tinfoilsh/m" to listOf("b.example")))
        gateway.timeSource += GatewayCatalog.REFRESH_INTERVAL
        client.models()
        awaitUntil { gateway.catalogFetches.get() == 2 }
        awaitUntil {
            runBlocking { client.execute(client.post(chat())).close() }
            gateway.received.last().request.getHeader("X-Tinfoil-Seal") == "b.example"
        }
    }

    @Test
    fun aCatalogThatTheCallerSuppliesIsReadForEveryRequestAndNeverFetched() = test {
        val reads = AtomicInteger()
        var hosts = listOf("a.example")
        val client = gateway.client(modelPins = TestGateway.PINS + ("foreign" to ModelPin("tinfoilsh/x")), catalog = {
            reads.incrementAndGet()
            entries("m" to ("tinfoilsh/m" to hosts), "foreign" to ("acme/x" to hosts))
        })
        assertEquals(1, reads.get(), "the creation reads it once")
        assertEquals(listOf("m"), client.models())
        client.execute(client.post(chat())).close()
        client.ensureVerified("m")
        assertEquals(4, reads.get())
        assertEquals("a.example", gateway.received.single().request.getHeader("X-Tinfoil-Seal"))

        hosts = listOf("b.example")
        client.execute(client.post(chat())).close()
        assertEquals("b.example", gateway.received.last().request.getHeader("X-Tinfoil-Seal"))
        gateway.timeSource += GatewayCatalog.REFRESH_INTERVAL * 10
        client.models()
        assertEquals(0, gateway.catalogFetches.get())
        // Its entries are held to the same rule as the gateway's.
        val error = assertFailsWith<ConfigurationException> { client.execute(client.post(chat(model = "foreign"))) }
        assertTrue(error.detail.contains("no valid bare tinfoilsh/ repository"), error.detail)
    }

    @Test
    fun aCatalogFunctionThatThrowsFailsTheRequestAsAConfigurationError() = test {
        var fail = false
        val client = gateway.client(catalog = {
            if (fail) throw IllegalStateException("boom")
            entries("m" to ("tinfoilsh/m" to listOf("a.example")))
        })
        fail = true
        val error = assertFailsWith<ConfigurationException> { client.execute(client.post(chat())) }
        assertIs<IllegalStateException>(error.cause)
        assertEquals(0, gateway.received.size)
    }

    // Sealing.

    @Test
    fun aRequestIsSealedToAVerifiedReplicaOfItsModelAndItsAnswerOpened() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        gateway.answer = { it.reply("the answer-0123456789", pieces = 3) }
        val client = gateway.client()
        val prompt = "a-prompt-that-must-not-be-seen-on-the-wire"

        val response = client.execute(client.post(chat(prompt = prompt)))

        assertEquals(200, response.code)
        assertEquals("the answer-0123456789", response.text())
        // The replica was verified first, through the gateway, against the
        // repository that the catalog names for the model.
        assertEquals(listOf("a.example"), gateway.attestationFetches)
        assertEquals(listOf("a.example" to Pin(repo = "tinfoilsh/m", project = "tinfoilsh/m")), gateway.verified)
        val received = gateway.received.single()
        assertTrue(received.sealed)
        assertEquals("/v1/chat/completions", received.request.path)
        assertEquals("POST", received.request.method)
        assertEquals("a.example", received.request.getHeader("X-Tinfoil-Seal"))
        assertEquals("m", received.request.getHeader("X-Tinfoil-Model"))
        assertEquals("https://a.example", received.request.getHeader(ENCLAVE_URL_HEADER))
        assertEquals("Bearer $API_KEY", received.request.getHeader("Authorization"))
        // The gateway saw only ciphertext for the body; the replica read it.
        assertFalse(received.wire.containsText(prompt), "the prompt was sent in the clear")
        assertFalse(received.wire.containsText("\"messages\""))
        assertTrue(received.text!!.contains(prompt))
    }

    @Test
    fun theCacheSecretStaysOnTheDeviceAndOnlyTheSaltIsSent() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to listOf("a.example")))
        val secret = "test-secret"
        val client = gateway.client(userCacheSecret = secret)

        client.execute(client.post(SPEC_BODY)).close()

        val received = gateway.received.single()
        assertEquals(
            """{"model":"test-model","messages":[{"role":"user","content":"hello"}],"cache_salt":"$SPEC_SALT"}""",
            received.text,
        )
        assertEquals(SPEC_PREFIX, received.request.getHeader("X-Tinfoil-Cache-Prefix"))
        val everything = received.wire + received.plaintext!! + received.request.headers.toString().toByteArray()
        assertFalse(everything.containsText(secret), "the secret left the device")
        assertFalse(everything.containsText("user_cache_secret"))
        assertFalse(received.wire.containsText(SPEC_SALT), "the salt is for the replica, not for the gateway")
    }

    @Test
    fun aSecretInTheBodyScopesItsRequestAndIsNotSentEither() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client(userCacheSecret = "client-secret-0123456789")
        val own = "end-user"
        val large = "123456789012345678901234567890"

        client.execute(client.post("""{ "n" : $large, "user_cache_secret":"$own" ,"model":"test-model", "x":1.0e+400 }""")).close()

        val received = gateway.received.single()
        assertEquals(
            """{ "n" : $large ,"model":"test-model", "x":1.0e+400 ,"cache_salt":"ok_acKhkRMWJQTyOkqE_pywND0Nl8Ha1DU8lDakAV3c"}""",
            received.text,
            "every other byte is the caller's, and an integer above 2^53 keeps its digits",
        )
        assertNull(received.request.getHeader("X-Tinfoil-Cache-Prefix"))
        val everything = received.wire + received.plaintext!! + received.request.headers.toString().toByteArray()
        assertFalse(everything.containsText("client-secret-0123456789"))
        assertFalse(everything.containsText("user_cache_secret"))
        assertFalse(received.text!!.contains("\"$own\""))
    }

    @Test
    fun clientsWithoutASecretShareTheProcessSecretAndNeverSendIt() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val salts = listOf(gateway.client(userCacheSecret = null), gateway.client(userCacheSecret = null), gateway.client(userCacheSecret = "another")).map { client ->
            client.execute(client.post(chat())).close()
            Regex("\"cache_salt\":\"([A-Za-z0-9_-]{43})\"").find(gateway.received.last().text!!)!!.groupValues[1]
        }
        assertEquals(salts[0], salts[1])
        assertNotEquals(salts[0], salts[2])
    }

    @Test
    fun aBodyOnAPathWithoutAPromptCacheIsSealedAsItIs() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        val body = """{ "model" : "m", "input" : [ 12345678901234567890 ] }"""
        client.execute(client.post(body, path = "embeddings")).close()
        val received = gateway.received.single()
        assertEquals(body, received.text)
        assertTrue(received.sealed)
        assertNull(received.request.getHeader("X-Tinfoil-Cache-Prefix"))
    }

    @Test
    fun theRecoveryTokenOfASealedResponseOpensIt() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        client.executeRecoverable(client.post(chat())).use { recoverable ->
            assertNotNull(recoverable.recoveryToken)
            assertEquals("ok", recoverable.response.body!!.string())
            assertTrue(recoverable.toString().contains("redacted"))
        }
        val unsealed = Request.Builder().url(client.baseUrl.resolve("models")!!).header("X-Tinfoil-Model", "m").build()
        client.executeRecoverable(unsealed).use { assertNull(it.recoveryToken) }
    }

    // Requests that are refused.

    @Test
    fun aBodyThatRepeatsAMemberThatTheClientReadsIsRefusedBeforeAnythingIsSent() = test {
        val reads = AtomicInteger()
        val client = gateway.unverified(catalog = {
            reads.incrementAndGet()
            entries("m" to ("tinfoilsh/m" to listOf("a.example")))
        })
        val repeats = mapOf(
            """{"model":"m","model":"other"}""" to "\"model\" member",
            """{"model":"m","mod\u0065l":"other"}""" to "\"model\" member",
            """{"model":"m","user_cache_secret":"a","user_cache_secret":"b"}""" to "\"user_cache_secret\" member",
            """{"model":"m","cache_salt":"a","c\u0061che_salt":"b"}""" to "\"cache_salt\" member",
        )
        for ((body, message) in repeats) {
            for (path in listOf("chat/completions", "embeddings")) {
                val error = assertFailsWith<ConfigurationException>(body) { client.execute(client.post(body, path)) }
                assertTrue(error.detail.contains("request body repeats the $message"), error.detail)
                val named = client.post(body, path).newBuilder().header("X-Tinfoil-Model", "m").build()
                assertFailsWith<ConfigurationException>(body) { client.execute(named) }
            }
        }
        assertEquals(0, reads.get(), "the catalog was not even read")
        assertNoIo()
    }

    @Test
    fun membersOfNestedObjectsAreNotRepeats() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        val body = """{"model":"m","n":{"model":"a","model":"b","cache_salt":1},"temperature":0,"temperature":1}"""
        client.execute(client.post(body, path = "embeddings")).close()
        assertEquals(body, gateway.received.single().text)
    }

    @Test
    fun aRequestThatNamesNoModelIsRefused() = test {
        // Both a catalog of the gateway's and one of the caller's list a
        // model without a name, with replicas of a repository of their choice.
        val nameless = "tinfoilsh/any" to listOf("evil.example")
        gateway.catalog = {
            MockResponse().setBody(
                """{"":{"repo":"tinfoilsh/any","hosts":["evil.example"]},"m":{"repo":"tinfoilsh/m","hosts":["a.example"]}}""",
            )
        }
        val reads = AtomicInteger()
        val supplied = gateway.client(
            modelPins = mapOf("m" to ModelPin("tinfoilsh/m")),
            catalog = {
                reads.incrementAndGet()
                entries("" to nameless, " " to nameless, "m" to ("tinfoilsh/m" to listOf("a.example")))
            },
        )
        for (client in listOf(gateway.client(), supplied)) {
            assertEquals(listOf("m"), client.models())
            val before = reads.get()
            val unnamed = listOf(
                Request.Builder().url(client.baseUrl.resolve("models")!!).build(),
                client.post("{}"),
                client.post("""{"model":""}"""),
                client.post("""{"model":7}"""),
                client.post("""{"messages":[{"model":"m"}]}"""),
                client.post("""[{"model":"m"}]"""),
                client.post("\"m\""),
                client.post(chat()).newBuilder().header("X-Tinfoil-Model", "").build().newBuilder().post("{}".toRequestBody(JSON)).build(),
                Request.Builder().url(client.baseUrl.resolve("chat/completions")!!).post(chat().toRequestBody("text/plain".toMediaType())).build(),
                Request.Builder().url(client.baseUrl.resolve("files/f1")!!).delete().build(),
            )
            for (request in unnamed) {
                val error = assertFailsWith<ConfigurationException>(request.toString()) { client.execute(request) }
                assertTrue(error.detail.startsWith("the request names no model"), error.detail)
            }
            for (model in listOf("", " ", "\t")) {
                val error = assertFailsWith<ConfigurationException> { client.ensureVerified(model) }
                assertTrue(error.detail.startsWith("the request names no model"), error.detail)
            }
            assertEquals(before, reads.get(), "the catalog was not even read")
        }
        assertEquals(0, gateway.received.size)
        assertEquals(emptyList(), gateway.attestationFetches)
        assertEquals(0, gateway.verifier.verifications.get())
    }

    @Test
    fun aJsonBodyThatCannotBeReadIsRefusedBeforeAnythingIsSent() = test {
        val reads = AtomicInteger()
        val client = gateway.unverified(catalog = {
            reads.incrementAndGet()
            entries("m" to ("tinfoilsh/m" to listOf("a.example")))
        })
        val bodies = listOf(
            "\ufeff{\"model\":\"m\",\"user_cache_secret\":\"the-end-users-own-secret\"}".toByteArray(),
            """{"model":"m","user_cache_secret":"the-end-users-own-secret"}""".toByteArray(Charsets.UTF_16LE),
            """{"model":"m","x":NaN,"user_cache_secret":"the-end-users-own-secret"}""".toByteArray(),
            """{"model":"m","Model":"n"}""".toByteArray(),
        )
        for (body in bodies) {
            val request = Request.Builder().url(client.baseUrl.resolve("chat/completions")!!)
                .header("X-Tinfoil-Model", "m").post(body.toRequestBody(JSON)).build()
            assertFailsWith<ConfigurationException> { client.execute(request) }
        }
        assertEquals(0, reads.get())
        assertNoIo()
    }

    @Test
    fun aRequestWithoutABodyGoesOutUnderTheModelThatItsHeaderNames() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        val request = Request.Builder().url(client.baseUrl.resolve("models")!!).header("X-Tinfoil-Model", "m").build()
        client.execute(request).close()
        val received = gateway.received.single()
        // Its replica is verified all the same, and named to the gateway.
        assertEquals(listOf("a.example"), gateway.attestationFetches)
        assertEquals("a.example", received.request.getHeader("X-Tinfoil-Seal"))
        assertEquals("m", received.request.getHeader("X-Tinfoil-Model"))
        assertFalse(received.sealed, "a request without a body has nothing to seal")
    }

    @Test
    fun aPinnedModelThatTheCatalogDoesNotListIsAConfigurationError() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")), "foreign" to ("acme/x" to listOf("a.example")))
        val pins = mapOf(
            "unknown" to ModelPin("tinfoilsh/unknown"),
            "foreign" to ModelPin("tinfoilsh/x"),
            "M" to ModelPin("tinfoilsh/m"),
            "m." to ModelPin("tinfoilsh/m"),
            "absent" to ModelPin("tinfoilsh/absent"),
        )
        val client = gateway.client(modelPins = pins)
        for (model in pins.keys) {
            val error = assertFailsWith<ConfigurationException>(model) { client.execute(client.post(chat(model = model))) }
            assertTrue(error.detail.contains("has no valid bare tinfoilsh/ repository with replicas"), error.detail)
            assertFailsWith<ConfigurationException>(model) { client.ensureVerified(model) }
        }
        assertEquals(0, gateway.received.size)
        assertEquals(emptyList(), gateway.attestationFetches)
    }

    @Test
    fun requestsThatSealingCannotProtectOrThatLeaveTheGatewayAreRefusedBeforeAnyIo() = test {
        val reads = AtomicInteger()
        val client = gateway.unverified(catalog = {
            reads.incrementAndGet()
            entries("m" to ("tinfoilsh/m" to listOf("a.example")))
        })
        val url = client.baseUrl.resolve("realtime?model=m")!!
        fun named() = Request.Builder().header("X-Tinfoil-Model", "m")
        val refused = listOf(
            named().url(url).header("Connection", "Upgrade").header("Upgrade", "websocket").build(),
            named().url(url).header("Upgrade", "h2c").build(),
            named().url(url).method("CONNECT", null).build(),
            named().url("https://elsewhere.example/v1/chat/completions").post(chat().toRequestBody(JSON)).build(),
            named().url("https://localhost:1/v1/chat/completions").post(chat().toRequestBody(JSON)).build(),
            named().url("https://user:pw@${gateway.host}/v1/chat/completions").post(chat().toRequestBody(JSON)).build(),
            named().url(url).header("Host", "elsewhere.example").build(),
            named().url(url).header("X-Tinfoil-Enclave-Url", "https://evil.example").build(),
            named().url(url).header("Ehbp-Encapsulated-Key", "00").build(),
            named().url(url).post(Duplex).build(),
        )
        for (request in refused) {
            assertFailsWith<ConfigurationException>(request.toString()) { client.execute(request) }
            val failure = assertFailsWith<IOException> { client.newCall(request).execute() }
            assertIs<ConfigurationException>(failure)
        }
        assertEquals(0, reads.get())
        assertNoIo()
    }

    private object Duplex : RequestBody() {
        override fun contentType(): MediaType = JSON

        override fun isDuplex(): Boolean = true

        override fun writeTo(sink: BufferedSink) = error("a duplex body must not be read")
    }

    // Pins and policy.

    @Test
    fun aPinnedModelIsVerifiedAgainstItsPinUnderItsOwnPolicy() = test {
        gateway.serve("pinned" to ("tinfoilsh/pinned" to listOf("a.example")), "plain" to ("tinfoilsh/plain" to listOf("a.example")))
        val own = FakeVerifier { document, _, _ -> gateway.endorsement(document.toString(Charsets.UTF_8)) }
        val ownPolicy = Policy(freshnessMaxAge = 1.hours)
        gateway.verifierFor = { policy -> own.takeIf { policy.freshnessMaxAgeNs == 3_600_000_000_000 } }
        val pins = mapOf(
            "pinned" to ModelPin("tinfoilsh/pinned@v1.2.3@sha256:${"cd".repeat(32)}", ownPolicy),
            "plain" to ModelPin("tinfoilsh/plain"),
        )
        val client = gateway.client(modelPins = pins)

        client.execute(client.post(chat(model = "pinned"))).close()
        client.execute(client.post(chat(model = "plain"))).close()

        // The pinned model's replica was appraised by the pin's verifier,
        // against the pin with its tag and digest, and by no other.
        val reference = "tinfoilsh/pinned@v1.2.3@sha256:${"cd".repeat(32)}"
        assertEquals(1, own.verifications.get())
        assertEquals(listOf("a.example" to Pin(repo = "tinfoilsh/plain", project = "tinfoilsh/plain")), gateway.verified)
        // One host, verified once as each: two verifications, two keys' worth of state.
        assertEquals(
            listOf(
                Triple("a.example", "tinfoilsh/pinned@v1.2.3@sha256:${"cd".repeat(32)}", "pinned"),
                Triple("a.example", "tinfoilsh/plain", "plain"),
            ),
            client.replicas().map { Triple(it.host, it.reference, it.pinnedModel) },
        )
        assertEquals(listOf(listOf("pinned"), listOf("plain")), client.replicas().map { it.models })
        assertTrue(own.pinChecks.get() >= 1)
        assertEquals(reference, client.replicas().first().reference)
    }

    @Test
    fun aPinWithoutAPolicyUsesTheClients() = test {
        gateway.serve("pinned" to ("tinfoilsh/pinned" to listOf("a.example")))
        val client = gateway.client(modelPins = mapOf("pinned" to ModelPin("tinfoilsh/pinned@v2")))
        client.execute(client.post(chat(model = "pinned"))).close()
        assertEquals(listOf("a.example" to Pin(repo = "tinfoilsh/pinned@v2", project = "tinfoilsh/pinned@v2")), gateway.verified)
    }

    @Test
    fun aCatalogThatNamesAnotherRepositoryForAPinnedModelIsNotFollowed() = test {
        gateway.serve("pinned" to ("tinfoilsh/something-else" to listOf("evil.example")))
        val client = gateway.client(modelPins = mapOf("pinned" to ModelPin("tinfoilsh/pinned@v1")))
        val error = assertFailsWith<AttestationException> { client.execute(client.post(chat(model = "pinned"))) }
        assertEquals(
            "model \"pinned\": expected repository \"tinfoilsh/pinned\", gateway offered \"tinfoilsh/something-else\"",
            error.detail,
        )
        assertFailsWith<AttestationException> { client.ensureVerified("pinned") }
        assertEquals(emptyList(), gateway.attestationFetches)
        assertEquals(0, gateway.received.size)
    }

    @Test
    fun aModelWithoutAPinIsRefusedBeforeAnyIo() = test {
        val reads = AtomicInteger()
        val client = gateway.unverified(
            modelPins = mapOf("pinned" to ModelPin("tinfoilsh/pinned")),
            catalog = {
                reads.incrementAndGet()
                entries("pinned" to ("tinfoilsh/pinned" to listOf("a.example")), "plain" to ("tinfoilsh/plain" to listOf("a.example")))
            },
        )
        val error = assertFailsWith<ConfigurationException> { client.execute(client.post(chat(model = "plain"))) }
        assertEquals("model \"plain\" is not pinned", error.detail)
        assertFailsWith<ConfigurationException> { client.ensureVerified("plain") }
        assertFailsWith<ConfigurationException> {
            client.execute(Request.Builder().url(client.baseUrl.resolve("models")!!).header("X-Tinfoil-Model", "plain").build())
        }
        assertNoIo()
        assertEquals(0, reads.get(), "the catalog is not read for a model without a pin")
        client.execute(client.post(chat(model = "pinned"))).close()
        assertEquals(1, gateway.received.size)
    }

    @Test
    fun theModelThatAHeaderNamesIsTheOneWhoseReplicaIsVerified() = test {
        gateway.serve("a" to ("tinfoilsh/a" to listOf("a.example")), "b" to ("tinfoilsh/b" to listOf("b.example")))
        val client = gateway.client(modelPins = mapOf("a" to ModelPin("tinfoilsh/a"), "b" to ModelPin("tinfoilsh/b")))
        val request = client.post(chat(model = "b")).newBuilder().header("X-Tinfoil-Model", "a").build()
        client.execute(request).close()
        val received = gateway.received.single()
        assertEquals("a.example", received.request.getHeader("X-Tinfoil-Seal"))
        assertEquals(listOf("a"), received.request.headers.values("X-Tinfoil-Model"))
        assertEquals(listOf("a.example" to Pin(repo = "tinfoilsh/a", project = "tinfoilsh/a")), gateway.verified)
    }

    // Choosing a replica.

    private val replicas = listOf("a.example", "b.example", "c.example", "d.example:8443", "e.example")

    @Test
    fun aConversationStaysOnTheReplicaThatItsPrefixRanksFirst() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val client = gateway.client()
        val order = GatewayRouter.rank(replicas, SPEC_PREFIX, null)
        assertEquals("d.example:8443", order.first())
        repeat(5) { turn ->
            val body = """{"model":"test-model","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"turn $turn"}]}"""
            client.execute(client.post(body)).close()
        }
        assertEquals(List(5) { "d.example:8443" }, gateway.received.map { it.request.getHeader("X-Tinfoil-Seal") })
        assertEquals(listOf("d.example:8443"), gateway.attestationFetches, "one replica was verified, once")
        assertEquals(List(5) { SPEC_PREFIX }, gateway.received.map { it.request.getHeader("X-Tinfoil-Cache-Prefix") })
        assertEquals("https://d.example:8443", gateway.received.first().request.getHeader(ENCLAVE_URL_HEADER))
    }

    @Test
    fun aReplicaThatDoesNotVerifyIsPassedOverAndNothingIsSealedToIt() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val order = GatewayRouter.rank(replicas, SPEC_PREFIX, null)
        gateway.endorse = { replica, _ -> if (replica == order[2]) gateway.endorsement(replica) else gateway.refuse() }
        val results = CopyOnWriteArrayList<VerificationAttempt>()
        val hosts = CopyOnWriteArrayList<String>()
        val client = gateway.client(onVerificationAttempt = { host, result ->
            hosts += host
            results += result
        })

        client.execute(client.post(SPEC_BODY)).close()

        // In the order of the rank, each tried twice before the next.
        assertEquals(listOf(order[0], order[0], order[1], order[1], order[2]), gateway.attestationFetches)
        assertEquals(listOf(order[2]), gateway.received.map { it.request.getHeader("X-Tinfoil-Seal") })
        assertTrue(gateway.received.single().sealed)
        // Each replica's entry holds its own last attempt, the failed ones
        // included.
        val entries = client.replicas().associateBy { it.host }
        assertEquals(setOf(order[0], order[1], order[2]), entries.keys)
        assertEquals(gateway.key(order[2]).publicKey, entries.getValue(order[2]).lastAttempt.facts?.hpkePublicKey)
        assertEquals(entries.getValue(order[2]).lastAttempt.report, entries.getValue(order[2]).current)
        assertEquals(order[2], jsonHost(entries.getValue(order[2]).current))
        for (failed in listOf(order[0], order[1])) {
            assertEquals(failed, jsonHost(rejectedReport(entries.getValue(failed).lastAttempt.error)))
            assertNull(entries.getValue(failed).current, "a replica that failed has no current verification")
            val error = assertIs<AttestationException>(entries.getValue(failed).lastAttempt.error)
            val rejected = assertIs<VerificationException>(error.cause)
            assertEquals(VerificationLayer.QUOTE, rejected.report.failedStep?.layer)
        }
        // One report for each attempt, with the replica that it verified.
        awaitUntil { results.size == 5 }
        assertEquals(listOf(order[0], order[0], order[1], order[1], order[2]), hosts)
        assertEquals(listOf(false, false, false, false, true), results.map { it.report != null })
        assertEquals(hosts, results.map { jsonHost(it.report ?: rejectedReport(it.error)) })
    }

    @Test
    fun aReplicaThatTheCallersCheckRejectsIsPassedOver() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val order = GatewayRouter.rank(replicas, SPEC_PREFIX, null)
        val rejected = gateway.key(order[0]).publicKey
        val client = gateway.client(verificationCheck = { if (it.hpkePublicKey == rejected) throw IllegalStateException("not this one") })
        client.execute(client.post(SPEC_BODY)).close()
        assertEquals(listOf(order[1]), gateway.received.map { it.request.getHeader("X-Tinfoil-Seal") })
        // A rejection is a decision, so it is not tried again.
        assertEquals(listOf(order[0], order[1]), gateway.attestationFetches)
    }

    @Test
    fun aReplicaWhoseHostCannotBeUsedIsPassedOver() = test {
        val hosts = listOf("\u00e9xample.com", "a.example/path", "user@a.example", "", "127.1", "ok.example")
        val client = gateway.client(catalog = { entries("m" to ("tinfoilsh/m" to hosts)) })
        repeat(4) { client.execute(client.post(chat())).close() }
        assertEquals(List(4) { "ok.example" }, gateway.received.map { it.request.getHeader("X-Tinfoil-Seal") })
        assertEquals(listOf("ok.example"), gateway.attestationFetches)
    }

    @Test
    fun whenNoReplicaVerifiesTheRequestFailsWithTheLastFailure() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example", "b.example")))
        gateway.endorse = { _, _ -> gateway.refuse() }
        val client = gateway.client()
        assertFailsWith<AttestationException> { client.execute(client.post(chat())) }
        assertFailsWith<AttestationException> { client.ensureVerified("m") }
        assertEquals(0, gateway.received.size)
        assertEquals(setOf("a.example", "b.example"), client.replicas().map { it.host }.toSet())
        assertTrue(client.replicas().all { it.lastAttempt.error is AttestationException })

        // A relay that has no document is a network error.
        gateway.attestation = { MockResponse().setResponseCode(502) }
        val unreachable = assertFailsWith<NetworkException> { client.execute(client.post(chat())) }
        assertEquals(502, unreachable.status)

        // And a replica that failed is tried again by the next request.
        gateway.attestation = { MockResponse().setBody(it) }
        gateway.endorse = { replica, _ -> gateway.endorsement(replica) }
        client.execute(client.post(chat())).close()
        assertEquals(1, gateway.received.size)
    }

    @Test
    fun noMoreReplicasAreTriedForOneRequestThanTheLimit() = test {
        val many = (1..40).map { "h$it.example" }
        gateway.endorse = { _, _ -> gateway.refuse() }
        val client = gateway.client(catalog = { entries("m" to ("tinfoilsh/m" to many)) })
        assertFailsWith<AttestationException> { client.execute(client.post(chat())) }
        assertEquals(GatewayRouter.MAX_REPLICAS_TRIED, gateway.attestationFetches.toSet().size)
        assertEquals(2 * GatewayRouter.MAX_REPLICAS_TRIED, gateway.attestationFetches.size)
        gateway.attestationFetches.clear()
        assertFailsWith<AttestationException> { client.ensureVerified("m") }
        assertEquals(GatewayRouter.rank(many, "m", null).take(GatewayRouter.MAX_REPLICAS_TRIED), gateway.attestationFetches.distinct())
    }

    @Test
    fun ensureVerifiedTriesReplicasInAFixedOrderAndReusesAVerification() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val order = GatewayRouter.rank(replicas, "test-model", null)
        gateway.endorse = { replica, _ -> if (replica == order[0]) gateway.refuse() else gateway.endorsement(replica) }
        val client = gateway.client()

        val verification = client.ensureVerified("test-model")

        assertEquals(gateway.key(order[1]).publicKey, verification.verifiedFacts?.hpkePublicKey)
        assertEquals(listOf(order[0], order[0], order[1]), gateway.attestationFetches)
        assertEquals(verification, client.ensureVerified("test-model"))
        // The replica that failed is asked again; the one that verified is not.
        assertEquals(listOf(order[0], order[0], order[1], order[0], order[0]), gateway.attestationFetches)
        assertIs<AttestationException>(client.replicas().single { it.host == order[0] }.lastAttempt.error)
        val current = client.replicas().single { it.host == order[1] }
        assertEquals(order[1], current.host)
        assertEquals(emptyList(), current.models, "no request has named a model to it yet")
        assertEquals("tinfoilsh/m", current.reference)
        assertEquals("test-model", current.pinnedModel)
        assertEquals(verification, current.lastAttempt.report)
        assertEquals(verification, current.current)
    }

    @Test
    fun reverifyVerifiesTheReplicaInUseAgainAndNoOther() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val order = GatewayRouter.rank(replicas, "test-model", null)
        val client = gateway.client()
        val ensured = client.ensureVerified("test-model")
        gateway.clock.advance(60)

        val reverified = client.reverify("test-model")

        assertNotSame(ensured, reverified)
        assertEquals(gateway.key(order[0]).publicKey, reverified.verifiedFacts?.hpkePublicKey)
        assertEquals(order[0], jsonHost(ensured))
        assertEquals(order[0], jsonHost(reverified))
        assertEquals(listOf(order[0], order[0]), gateway.attestationFetches, "no other replica is verified")
        val entry = client.replicas().single()
        assertEquals(order[0], entry.host)
        assertSame(reverified, entry.current)
        assertSame(reverified, entry.lastAttempt.report)
        assertSame(reverified, client.ensureVerified("test-model"))
        assertEquals(2, gateway.attestationFetches.size)
    }

    @Test
    fun reverifyThrowsAFailureThatKeepsTheReplicasVerification() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val order = GatewayRouter.rank(replicas, "test-model", null)
        val client = gateway.client()
        val ensured = client.ensureVerified("test-model")
        gateway.attestationFetches.clear()
        gateway.attestation = { if (it == order[0]) MockResponse().setResponseCode(502) else MockResponse().setBody(it) }

        val error = assertFailsWith<NetworkException> { client.reverify("test-model") }

        assertEquals(listOf(order[0], order[0]), gateway.attestationFetches, "the next replica is not tried")
        val entry = client.replicas().single()
        assertSame(ensured, entry.current, "the replica's verification is still current")
        assertSame(error, entry.lastAttempt.error, "its last attempt is the failure")
        assertSame(ensured, client.ensureVerified("test-model"), "requests for the model still go to the replica")
    }

    @Test
    fun reverifyMovesOnFromAReplicaWhoseVerificationAnAttestationFailureWithdrew() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val order = GatewayRouter.rank(replicas, "test-model", null)
        val client = gateway.client()
        client.ensureVerified("test-model")
        gateway.endorse = { replica, _ -> if (replica == order[0]) gateway.refuse() else gateway.endorsement(replica) }

        val reverified = client.reverify("test-model")

        assertEquals(gateway.key(order[1]).publicKey, reverified.verifiedFacts?.hpkePublicKey)
        val entries = client.replicas().associateBy { it.host }
        assertNull(entries.getValue(order[0]).current, "the failure withdrew the replica's verification")
        assertIs<AttestationException>(entries.getValue(order[0]).lastAttempt.error)
        assertSame(reverified, entries.getValue(order[1]).current)
        assertSame(reverified, entries.getValue(order[1]).lastAttempt.report)
        assertFalse(order[2] in entries, "the replicas after the one that passed are not verified")

        val fetches = gateway.attestationFetches.size
        assertSame(reverified, client.ensureVerified("test-model"), "ensureVerified returns the same replica")
        assertTrue(gateway.attestationFetches.size > fetches, "after it tries the first replica again")
    }

    @Test
    fun reverifyThrowsTheLastFailureWhenNoReplicaPasses() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val client = gateway.client()
        client.ensureVerified("test-model")
        gateway.endorse = { _, _ -> gateway.refuse() }

        assertFailsWith<AttestationException> { client.reverify("test-model") }

        assertEquals(replicas.toSet(), client.replicas().map { it.host }.toSet())
        assertTrue(client.replicas().all { it.current == null && it.lastAttempt.error is AttestationException })
    }

    @Test
    fun reverifyRefusesAModelWithoutAPinAndVerifiesNothing() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val client = gateway.client()

        assertFailsWith<ConfigurationException> { client.reverify("unpinned") }

        assertEquals(emptyList(), gateway.attestationFetches)
        assertEquals(emptyList(), client.replicas())
    }

    @Test
    fun aReplicasCurrentVerificationFollowsItsOwnFreshness() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val client = gateway.client()
        val ensured = client.ensureVerified("test-model")

        gateway.clock.advance(3600)

        val entry = client.replicas().single()
        assertNull(entry.current, "an expired verification is not current")
        assertSame(ensured, entry.lastAttempt.report)
    }

    @Test
    fun aVerificationThatExpiresIsRenewedBeforeTheNextRequest() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        client.execute(client.post(chat())).close()
        gateway.clock.advance(3599)
        client.execute(client.post(chat())).close()
        assertEquals(1, gateway.attestationFetches.size)
        gateway.clock.advance(1)
        client.execute(client.post(chat())).close()
        assertEquals(2, gateway.attestationFetches.size)
        assertEquals(3, gateway.received.count { it.sealed })
    }

    @Test
    fun concurrentRequestsShareOneVerificationOfAReplica() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        gateway.attestation = { MockResponse().setBody(it).setHeadersDelay(300, TimeUnit.MILLISECONDS) }
        val client = gateway.client()
        (1..8).map { async(Dispatchers.IO) { client.execute(client.post(chat(prompt = "p$it"))).text() } }.awaitAll()
        assertEquals(listOf("a.example"), gateway.attestationFetches)
        assertEquals(8, gateway.received.count { it.sealed })
    }

    @Test
    fun noMoreReplicasAreKeptThanTheLimitAndTheLeastRecentlyUsedGoesFirst() = test {
        val count = GatewayRouter.MAX_REPLICAS + 2
        val client = gateway.client(modelPins = (1..count).associate { "m$it" to ModelPin("tinfoilsh/m") }, catalog = {
            Catalog((1..count).associate { "m$it" to CatalogEntry("tinfoilsh/m", listOf("h$it.example")) })
        })
        client.ensureVerified("m1")
        client.ensureVerified("m2")
        for (i in 3..GatewayRouter.MAX_REPLICAS) {
            client.ensureVerified("m$i")
        }
        assertEquals(GatewayRouter.MAX_REPLICAS, client.replicas().size)
        // Using the first again makes the second the least recently used.
        client.ensureVerified("m1")
        client.ensureVerified("m${GatewayRouter.MAX_REPLICAS + 1}")
        assertEquals(GatewayRouter.MAX_REPLICAS, client.replicas().size)
        val kept = client.replicas().map { it.host }.toSet()
        assertTrue("h1.example" in kept && "h2.example" !in kept)
        // One that was let go is verified again when it is next needed.
        val before = gateway.attestationFetches.size
        client.ensureVerified("m2")
        assertEquals(before + 1, gateway.attestationFetches.size)
    }

    @Test
    fun aReplicaWithARequestInFlightIsNotLetGo() = test {
        val count = GatewayRouter.MAX_REPLICAS + 3
        val client = gateway.client(modelPins = (1..count).associate { "m$it" to ModelPin("tinfoilsh/m") }, catalog = {
            Catalog((1..count).associate { "m$it" to CatalogEntry("tinfoilsh/m", listOf("h$it.example")) })
        })
        gateway.answer = { it.reply("a-long-answer-".repeat(64), pieces = 8) }
        // Two replicas' responses are held open, unread, while more
        // replicas are used than the client keeps.
        val open = client.execute(client.post(chat(model = "m1")))
        val streamed = client.newCall(client.post(chat(model = "m2"))).execute()
        for (i in 3..count) {
            client.ensureVerified("m$i")
        }
        assertEquals("a-long-answer-".repeat(64), open.text())
        assertEquals("a-long-answer-".repeat(64), streamed.text())
        val kept = client.replicas().map { it.host }.toSet()
        assertTrue("h1.example" in kept && "h2.example" in kept, "the replicas in use were kept")
        assertEquals(GatewayRouter.MAX_REPLICAS, kept.size)
        // Once their responses are closed, they can go like any other.
        for (i in 3..count) {
            client.ensureVerified("m$i")
        }
        assertFalse("h1.example" in client.replicas().map { it.host })
        assertEquals(GatewayRouter.MAX_REPLICAS, client.replicas().size)
    }

    // A gateway that routes elsewhere.

    private fun routedTo(replica: String?): MockResponse =
        MockResponse().setResponseCode(412).apply { replica?.let { setHeader("X-Tinfoil-Seal", it) } }

    @Test
    fun aRequestThatTheGatewayRoutedElsewhereIsSealedAgainToThatReplicaOnceItVerifies() = test {
        gateway.serve("test-model" to ("tinfoilsh/m" to replicas))
        val order = GatewayRouter.rank(replicas, SPEC_PREFIX, null)
        val other = order[3]
        gateway.intercept = { if (it.getHeader("X-Tinfoil-Seal") == order[0]) routedTo(other) else null }
        val pinned = mapOf("test-model" to ModelPin("tinfoilsh/m@v1"))
        val client = gateway.client(modelPins = pinned)
        val prompt = PROMPT
        val body = """{"model":"test-model","messages":[{"role":"user","content":"hello"},{"role":"user","content":"$prompt"}]}"""

        assertEquals("ok", client.execute(client.post(body)).text())

        // The replica that the gateway named was verified like any other,
        // against the model's pin, before the body was sealed to its key.
        assertEquals(listOf(order[0], other), gateway.attestationFetches)
        assertEquals(setOf(Pin(repo = "tinfoilsh/m@v1", project = "tinfoilsh/m@v1")), gateway.verified.map { it.second }.toSet())
        val received = gateway.received.single()
        assertEquals(other, received.request.getHeader("X-Tinfoil-Seal"))
        assertEquals("https://$other", received.request.getHeader(ENCLAVE_URL_HEADER))
        assertEquals(setOf(order[0], other), client.replicas().map { it.host }.toSet())
        assertTrue(received.sealed)
        assertFalse(received.wire.containsText(prompt))
        assertTrue(received.text!!.contains(prompt) && received.text!!.contains("\"cache_salt\":\"$SPEC_SALT\""), received.text)
        assertEquals(SPEC_PREFIX, received.request.getHeader("X-Tinfoil-Cache-Prefix"))

        // The conversation goes to that replica first from now on, and
        // another conversation is ranked as before.
        gateway.intercept = { null }
        client.execute(client.post(body)).close()
        assertEquals(other, gateway.received.last().request.getHeader("X-Tinfoil-Seal"))
        client.execute(client.post("""{"model":"test-model","messages":["another conversation"]}""")).close()
        val another = gateway.received.last().request
        assertNotEquals(SPEC_PREFIX, another.getHeader("X-Tinfoil-Cache-Prefix"))
        assertEquals(
            GatewayRouter.rank(replicas, another.getHeader("X-Tinfoil-Cache-Prefix")!!, null).first(),
            another.getHeader("X-Tinfoil-Seal"),
        )

        // A replica that the catalog does not list is followed for the
        // request, once it verifies; the next request goes by the catalog.
        gateway.intercept = { if (it.getHeader("X-Tinfoil-Seal") == other) routedTo("z.example") else null }
        client.execute(client.post(body)).close()
        assertEquals("z.example", gateway.received.last().request.getHeader("X-Tinfoil-Seal"))
        gateway.intercept = { null }
        client.execute(client.post(body)).close()
        assertEquals(order[0], gateway.received.last().request.getHeader("X-Tinfoil-Seal"))
    }

    @Test
    fun aGatewayThatKeepsRoutingARequestAwayFailsItAsANetworkError() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("r0.example")))
        val sealedTo = CopyOnWriteArrayList<String>()
        gateway.intercept = { request ->
            val replica = request.getHeader("X-Tinfoil-Seal")!!
            sealedTo += replica
            assertFalse(request.body.clone().readByteArray().containsText(PROMPT), "a retry carried plaintext")
            routedTo("r${replica.substring(1).substringBefore('.').toInt() + 1}.example")
        }
        val client = gateway.client()

        val error = assertFailsWith<NetworkException> { client.execute(client.post(chat(prompt = PROMPT))) }

        assertEquals("gateway kept routing away from the enclave the request was sealed to (last: r4.example)", error.detail)
        assertEquals(listOf("r0.example", "r1.example", "r2.example", "r3.example"), sealedTo)
        assertEquals(sealedTo, gateway.attestationFetches, "each was verified before the request was sealed to it")
        assertEquals(0, gateway.received.size)
    }

    @Test
    fun aRouteToAReplicaThatDoesNotVerifyIsNotFollowed() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        gateway.intercept = { routedTo("evil.example") }
        gateway.endorse = { replica, _ -> if (replica == "evil.example") gateway.refuse() else gateway.endorsement(replica) }
        val client = gateway.client()
        val error = assertFailsWith<AttestationException> { client.execute(client.post(chat())) }
        assertTrue(error.detail.startsWith("following gateway route to enclave evil.example: "), error.detail)
        // The verifier's rejection stays the cause, under the added context.
        assertEquals(VerificationLayer.QUOTE, assertIs<VerificationException>(error.cause).layer)
        // A route that is not a host is refused without a fetch.
        gateway.attestationFetches.clear()
        gateway.intercept = { routedTo("evil.example/x?") }
        val invalid = assertFailsWith<ConfigurationException> { client.execute(client.post(chat())) }
        assertTrue(invalid.detail.startsWith("following gateway route to enclave evil.example/x?: invalid enclave"), invalid.detail)
        assertEquals(emptyList(), gateway.attestationFetches)
        // The replica that the route named was tried, and failed.
        assertEquals(listOf("a.example", "evil.example"), client.replicas().map { it.host })
        assertEquals(listOf(true, false), client.replicas().map { it.lastAttempt.report != null })
    }

    @Test
    fun anAnswerThatNamesNoOtherReplicaIsReturnedAsItIs() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        for (answer in listOf(routedTo(null), routedTo("a.example"), routedTo(""), MockResponse().setResponseCode(409).setHeader("X-Tinfoil-Seal", "b.example"))) {
            gateway.intercept = { answer }
            client.execute(client.post(chat())).use { response ->
                assertEquals(answer.status.split(' ')[1].toInt(), response.code)
            }
        }
        assertEquals(listOf("a.example"), gateway.attestationFetches)
    }

    @Test
    fun aBodyThatCanBeWrittenOnlyOnceIsNotSentAgain() = test {
        gateway.serve("whisper" to ("tinfoilsh/whisper" to listOf("a.example")))
        gateway.intercept = { routedTo("b.example") }
        val client = gateway.client(modelPins = mapOf("whisper" to ModelPin("tinfoilsh/whisper")))
        val upload = MultipartBody.Builder("the-boundary-0123456789").setType(MultipartBody.FORM)
            .addFormDataPart("model", "whisper").addFormDataPart("file", "a.wav", "audio".toRequestBody()).build()
        val once = object : RequestBody() {
            override fun contentType() = upload.contentType()

            override fun isOneShot() = true

            override fun writeTo(sink: BufferedSink) = upload.writeTo(sink)
        }
        val url = client.baseUrl.resolve("audio/transcriptions")!!
        // With the header, the upload is streamed, and the gateway's answer is the caller's.
        val streamed = Request.Builder().url(url).header("X-Tinfoil-Model", "whisper").post(once).build()
        client.execute(streamed).use { assertEquals(412, it.code) }
        assertEquals(listOf("a.example"), gateway.attestationFetches)
        // Without it, the upload is read to find its model, and can be sent again.
        gateway.intercept = { if (it.getHeader("X-Tinfoil-Seal") == "a.example") routedTo("b.example") else null }
        client.execute(Request.Builder().url(url).post(once).build()).use { assertEquals(200, it.code) }
        val received = gateway.received.single()
        assertEquals("b.example", received.request.getHeader("X-Tinfoil-Seal"))
        assertEquals("whisper", received.request.getHeader("X-Tinfoil-Model"))
        assertTrue(received.sealed)
        assertTrue(received.text!!.contains("name=\"model\"") && received.text!!.contains("audio"))
    }

    @Test
    fun aReplicaThatLostItsKeyIsVerifiedAgainAndTheRequestSentOnceMore() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        client.execute(client.post(chat())).close()
        gateway.rotateKey("a.example")

        assertEquals("ok", client.execute(client.post(chat(prompt = "again"))).text())

        assertEquals(listOf("a.example", "a.example"), gateway.attestationFetches)
        assertEquals(3, gateway.received.size)
        assertNull(gateway.received[1].plaintext, "the first attempt was sealed to the key that is gone")
        assertTrue(gateway.received[2].text!!.contains("again"))
        assertEquals(gateway.key("a.example").publicKey, client.replicas().single().lastAttempt.facts?.hpkePublicKey)
    }

    // Lifecycle.

    @Test
    fun aClosedClientRefusesEverything() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        client.execute(client.post(chat())).close()
        val before = client.replicas()
        client.close()
        client.close()

        for (call in listOf<suspend () -> Any>({ client.models() }, { client.ensureVerified("m") }, { client.execute(client.post(chat())) }, { client.executeRecoverable(client.post(chat())) })) {
            val error = assertFailsWith<ConfigurationException> { call() }
            assertEquals("the client is closed", error.detail)
        }
        assertIs<ConfigurationException>(assertFailsWith<IOException> { client.newCall(client.post(chat())).execute() })
        assertEquals(before, client.replicas())
        // Nothing of it runs afterwards, however much time passes.
        val requests = gateway.server.requestCount
        gateway.timeSource += GatewayCatalog.REFRESH_INTERVAL * 10
        gateway.clock.advance(7200)
        Thread.sleep(200)
        assertEquals(requests, gateway.server.requestCount)
    }

    @Test
    fun closingEndsAVerificationInProgressAndItsRequest() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example", "b.example")))
        val gate = gateway.hold()
        gateway.attestation = {
            gate.await()
            MockResponse().setBody(it)
        }
        val client = gateway.client()
        val pending = async(Dispatchers.IO) { runCatching { client.execute(client.post(chat())) } }
        val verifying = async(Dispatchers.IO) { runCatching { client.ensureVerified("m") } }
        awaitUntil { gateway.attestationFetches.isNotEmpty() }
        Thread.sleep(200)
        client.close()
        for (result in listOf(pending.await(), verifying.await())) {
            val error = assertIs<ConfigurationException>(result.exceptionOrNull())
            assertEquals("the client is closed", error.detail)
        }
        assertEquals(0, gateway.received.size)
    }

    @Test
    fun closingDuringTheFirstFetchOfTheCatalogEndsTheWait() = test {
        val gate = gateway.hold()
        gateway.catalog = {
            gate.await()
            MockResponse().setBody("{}")
        }
        val client = gateway.unverified()
        val waiting = async(Dispatchers.IO) { runCatching { client.models() } }
        awaitUntil { gateway.catalogFetches.get() == 1 }
        client.close()
        assertIs<ConfigurationException>(waiting.await().exceptionOrNull())
    }

    @Test
    fun aCallerThatCancelsWhileAReplicaIsVerifiedSendsNothing() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        gateway.attestation = { MockResponse().setBody(it).setHeadersDelay(500, TimeUnit.MILLISECONDS) }
        val client = gateway.client()
        val job = launch(Dispatchers.IO) { client.execute(client.post(chat())) }
        awaitUntil { gateway.attestationFetches.size == 1 }
        job.cancelAndJoin()
        // The verification, which no caller owns, still finishes.
        awaitUntil { client.replicas().size == 1 }
        Thread.sleep(100)
        assertEquals(0, gateway.received.size)
    }

    @Test
    fun aCallsTimeoutSpansTheVerificationThatItWaitsFor() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val gate = gateway.hold()
        gateway.attestation = {
            gate.await()
            MockResponse().setBody(it)
        }
        val client = gateway.client()
        val call = client.newCall(client.post(chat()))
        call.timeout().timeout(300, TimeUnit.MILLISECONDS)
        val error = assertFailsWith<InterruptedIOException> { call.execute() }
        assertEquals("timeout", error.message)
        assertEquals(0, gateway.received.size)

        val cancelled = client.newCall(client.post(chat()))
        launch(Dispatchers.IO) {
            Thread.sleep(200)
            cancelled.cancel()
        }
        val canceled = assertFailsWith<IOException> { cancelled.execute() }
        assertEquals("Canceled", canceled.message)
        assertEquals(0, gateway.received.size)
    }

    @Test
    fun anEnqueuedCallIsAnsweredThroughItsCallback() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val client = gateway.client()
        val answers = CopyOnWriteArrayList<String>()
        val callback = object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: IOException) {
                answers += e.toString()
            }

            override fun onResponse(call: okhttp3.Call, response: Response) {
                answers += response.text()
            }
        }
        client.newCall(client.post(chat())).enqueue(callback)
        awaitUntil { answers.size == 1 }
        client.newCall(client.post(chat(model = "unknown"))).enqueue(callback)
        awaitUntil { answers.size == 2 }
        assertEquals("ok", answers[0])
        assertTrue(answers[1].contains("configuration error"), answers[1])
    }

    @Test
    fun nothingThatIsSecretIsInAMessageOrADescription() = test {
        gateway.serve("m" to ("tinfoilsh/m" to listOf("a.example")))
        val secret = "a-secret-that-must-stay-on-the-device"
        gateway.endorse = { _, _ -> gateway.refuse() }
        val client = gateway.client(userCacheSecret = secret)
        val body = """{"model":"m","user_cache_secret":"the-end-users-own-secret","messages":["a-private-prompt-0123456789"]}"""
        val errors = listOf(
            assertFailsWith<TinfoilException> { client.execute(client.post(body)) },
            assertFailsWith<TinfoilException> { client.execute(client.post(body.replace("\"m\"", "\"unknown\""))) },
            assertFailsWith<TinfoilException> { client.execute(client.post("""{"model":"m","model":"n","user_cache_secret":"the-end-users-own-secret"}""")) },
        )
        val text = errors.joinToString("\n") { e -> generateSequence<Throwable>(e) { it.cause }.take(8).joinToString { it.toString() } } +
            client.toString() + client.replicas().toString()
        for (hidden in listOf(secret, "the-end-users-own-secret", "a-private-prompt-0123456789", API_KEY)) {
            assertFalse(text.contains(hidden), hidden)
        }
    }

    private companion object {
        const val API_KEY = "test-api-key"
        const val PROMPT = "a-prompt-that-must-not-be-seen-on-the-wire"
        const val SPEC_BODY = """{"model":"test-model","messages":[{"role":"user","content":"hello"}]}"""
        const val SPEC_SALT = "DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8"
        const val SPEC_PREFIX = "ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6"
        val JSON = "application/json".toMediaType()
    }
}
