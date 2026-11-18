package sh.tinfoil.internal.gateway

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer
import okio.BufferedSink
import sh.tinfoil.ConfigurationException
import sh.tinfoil.internal.transport.JsonObjectText
import sh.tinfoil.internal.transport.UserCacheSecret
import sh.tinfoil.testing.containsText
import java.net.ProtocolException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** How a request is prepared for the gateway: the model that it names, and its cache scope. */
class GatewayRequestTest {
    private fun request(
        body: RequestBody?,
        path: String = "/v1/chat/completions",
        authorization: String? = "Bearer test-api-key",
        method: String = "POST",
        headers: List<Pair<String, String>> = emptyList(),
    ): Request = Request.Builder().url("https://gateway.example$path").method(method, body).apply {
        authorization?.let { header("Authorization", it) }
        headers.forEach { (name, value) -> addHeader(name, value) }
    }.build()

    private fun prepare(
        body: String,
        path: String = "/v1/chat/completions",
        secret: String = SECRET,
        authorization: String? = "Bearer test-api-key",
        contentType: String = "application/json",
        headers: List<Pair<String, String>> = emptyList(),
    ): PreparedRequest = prepare(request(body.toByteArray().toRequestBody(contentType.toMediaType()), path, authorization, headers = headers), secret)

    private fun prepare(request: Request, secret: String = SECRET): PreparedRequest =
        runBlocking { GatewayRequest.prepare(request, secret) }

    private fun RequestBody.bytes(): ByteArray = Buffer().also { writeTo(it) }.readByteArray()

    private fun PreparedRequest.text(): String = request.body!!.bytes().toString(Charsets.UTF_8)

    private fun PreparedRequest.salt(): String? =
        (Json.parseToJsonElement(text()).jsonObject[GatewayRequest.CACHE_SALT_FIELD] as? JsonPrimitive)?.content

    private fun PreparedRequest.prefixHeader(): String? = request.header(GatewayRequest.CACHE_PREFIX_HEADER)

    private fun assertRefused(message: String, block: () -> Unit) {
        val error = assertFailsWith<ConfigurationException>(message) { block() }
        assertEquals(message, error.detail)
    }

    // The cache scope.

    @Test
    fun theSaltAndThePrefixAreThoseOfTheSharedVector() {
        val prepared = prepare(SPEC_BODY)
        assertEquals(SPEC_SALT, prepared.salt())
        assertEquals(SPEC_PREFIX, prepared.prefixHeader())
        assertEquals(SPEC_PREFIX, prepared.cachePrefix)
        assertEquals(
            """{"model":"test-model","messages":[{"role":"user","content":"hello"}],"cache_salt":"$SPEC_SALT"}""",
            prepared.text(),
        )
        assertEquals("test-model", prepared.model)
        assertEquals("test-model", prepared.request.header(GatewayRequest.MODEL_HEADER))
        assertEquals("application/json", prepared.request.body!!.contentType().toString())
        assertEquals(prepared.text().length.toLong(), prepared.request.body!!.contentLength())
    }

    @Test
    fun theContentTypeMayCarryParameters() {
        for (contentType in listOf("application/json", "application/json; charset=utf-8", "Application/JSON;charset=UTF-8")) {
            val prepared = prepare(SPEC_BODY, contentType = contentType)
            assertEquals(SPEC_SALT, prepared.salt(), contentType)
            assertEquals(SPEC_PREFIX, prepared.prefixHeader(), contentType)
        }
    }

    @Test
    fun eachApiKeyScopesItsOwnCacheAndRoutesOnItsOwnPrefix() {
        val none = prepare(SPEC_BODY, authorization = null)
        assertEquals("F2pNViQ1aUPagy4IE_5pVQqz2FJKADsdYuTEsV0tFes", none.salt())
        assertEquals("6d350194f059c1bdffcd19f2e358da3271778924fbb6f94e382bec628e956bb1", none.prefixHeader())
        val other = prepare(SPEC_BODY, authorization = "Bearer other-api-key")
        assertEquals("zlArt19s_3JHN2HOFliwIKR0zrkQ7nQzPUZlMTXzmdI", other.salt())
        assertEquals("738f56b1436674255f225aef43bcbd9689615fd94582f93b39f4445b167d5f2f", other.prefixHeader())
        // Only the credential of a bearer token counts, whatever the case of
        // the scheme and the space around it.
        for (authorization in listOf("bearer test-api-key", "BEARER  test-api-key")) {
            assertEquals(SPEC_SALT, prepare(SPEC_BODY, authorization = authorization).salt(), authorization)
            assertEquals(SPEC_PREFIX, prepare(SPEC_BODY, authorization = authorization).prefixHeader(), authorization)
        }
        for (authorization in listOf("Basic test-api-key", "Bearertest-api-key", "Bearer")) {
            assertEquals(none.salt(), prepare(SPEC_BODY, authorization = authorization).salt(), authorization)
            assertEquals(none.prefixHeader(), prepare(SPEC_BODY, authorization = authorization).prefixHeader(), authorization)
        }
        // The first Authorization header is the one that is read.
        val two = prepare(SPEC_BODY, authorization = null, headers = listOf("Authorization" to "Bearer test-api-key", "Authorization" to "Bearer other-api-key"))
        assertEquals(SPEC_SALT, two.salt())
    }

    @Test
    fun theBearerCredentialIsReadAsTheSchemeAllows() {
        val credential = GatewayRequest.CacheScope::bearerCredential
        assertEquals("test-api-key", credential("Bearer test-api-key"))
        assertEquals("test-api-key", credential("bearer test-api-key"))
        assertEquals("test-api-key", credential(" BEARER  test-api-key "))
        assertEquals("a b", credential("Bearer a b"))
        for (authorization in listOf("", "Basic test-api-key", "Bearertest-api-key", "Bearer", " Bearer ", "Token x")) {
            assertEquals("", credential(authorization), authorization)
        }
    }

    @Test
    fun aSecretInTheBodyIsUsedInPlaceOfTheClients() {
        val own = prepare("""{"model":"test-model","user_cache_secret":"end-user"}""", secret = "client-secret")
        assertEquals("ok_acKhkRMWJQTyOkqE_pywND0Nl8Ha1DU8lDakAV3c", own.salt())
        assertEquals("""{"model":"test-model","cache_salt":"ok_acKhkRMWJQTyOkqE_pywND0Nl8Ha1DU8lDakAV3c"}""", own.text())
        assertNull(own.prefixHeader(), "a request without a prompt has no prefix")
        assertEquals("", own.cachePrefix)
        assertEquals(own.salt(), prepare("""{"model":"test-model"}""", secret = "end-user").salt())
        assertNotEquals(own.salt(), prepare("""{"model":"test-model"}""", secret = "client-secret").salt())
    }

    @Test
    fun aSecretInTheBodyThatIsEmptyOrNotAStringLeavesTheClientsAndIsRemoved() {
        for (value in listOf("\"\"", "null", "7", "true", "[\"s\"]", "{\"s\":1}")) {
            val prepared = prepare("""{"model":"m","user_cache_secret":$value,"messages":["a"]}""")
            assertEquals(SPEC_SALT, prepared.salt(), value)
            assertEquals("""{"model":"m","messages":["a"],"cache_salt":"$SPEC_SALT"}""", prepared.text(), value)
            assertEquals("83f42d3ecd29806af05a44714b16d9fa00ad01c87d7edacab9ddd7c13e7cf782", prepared.prefixHeader(), value)
        }
    }

    @Test
    fun theSecretIsDecodedAsJsonBeforeItIsUsed() {
        val escaped = prepare("""{"model":"m","user_cache_secret":"s\u00e9cr\ud83d\ude00et \"q\"","messages":[{"n":12345678901234567890}]}""")
        assertEquals("BZqxEVliBjlwolbN3TQ8F56iSRu-nqe1us2BC7aLGjI", escaped.salt())
        assertEquals("1159731e7c8af5241ed551c3152951f8cb724679f6ab47c845e4f4c5678d6b4a", escaped.prefixHeader())
        assertEquals("""{"model":"m","messages":[{"n":12345678901234567890}],"cache_salt":"BZqxEVliBjlwolbN3TQ8F56iSRu-nqe1us2BC7aLGjI"}""", escaped.text())
        // The same secret, written without escapes.
        val literal = prepare("{\"model\":\"m\",\"user_cache_secret\":\"s\u00e9cr\ud83d\ude00et \\\"q\\\"\",\"messages\":[{\"n\":12345678901234567890}]}")
        assertEquals(escaped.salt(), literal.salt())
        // Half of a surrogate pair decodes to the replacement character.
        val lone = prepare("""{"model":"m","user_cache_secret":"\ud800x","messages":["a"]}""")
        assertEquals("Nc6FhbixNoj6_fAiw4jaBnYGPQI0UDbvuKZOBpbp_34", lone.salt())
        assertEquals("7bb30c92e7144dbf73069a4cf3c69aeb93827b4414087500e7ca698044770913", lone.prefixHeader())
        assertEquals(lone.salt(), prepare("""{"model":"m","user_cache_secret":"\ufffdx"}""").salt())
        // The client's own secret is used as UTF-8.
        val client = prepare("""{"model":"m","inst\u0072uctions":"esc\u0061ped","messages":["a"]}""", secret = "s\u00e9cret-\u00fc", authorization = "Bearer k")
        assertEquals("hcadFQxoT8ptw2l0i7UnzviSO9XismSdTAaNP84lK1Q", client.salt())
        assertEquals("152dd363873d93be977a041dae23e8cce7a3aa6b249ab61f2eda02892328e10f", client.prefixHeader())
    }

    @Test
    fun thePrefixIsKeyedOnTheStartOfThePromptAsItIsWritten() {
        val prefixes = mapOf(
            """{ "model" : "m", "messages" : [ { "role" : "user",  "content" : "hi" } , {"role":"assistant","content":"x"} ] }""" to
                "271f023a775e57519eab1900580f02d9c14a83a96ece16c9f8941aea4809c4d1",
            """{"model":"m","instructions":"be brief","input":"hello"}""" to "2c8e4cb6c395b82c4f360fefd2c37f75e3ada6f53fb5786e55365230b66edfbb",
            """{"model":"m","instructions":"","input":"hello"}""" to "c41b7b094a1efbc22bafbaff5c1b848a74d9165a5a56900436ff31a67275910b",
            """{"model":"m","instructions":null,"input":[{"role":"user","content":"a"}]}""" to
                "a00e8943e22f390f35889ba11b702c2e2c1780523b6052117115afbdbd40dd4a",
            """{"model":"m","messages":[],"prompt":"once upon a time"}""" to "d1161ed8521cea30012ac19609809237be04c32b8babc4afac17d00cccd3f21d",
            """{"model":"m","messages":null,"input":null,"prompt":["a","b"]}""" to "83f42d3ecd29806af05a44714b16d9fa00ad01c87d7edacab9ddd7c13e7cf782",
            """{"model":"m","messages":[1],"messages":[ "last" ]}""" to "bc36f4a3839a6ce7a3b6a5d253860136a8c7cb8fffd8f9dd031fbcaeddbc944a",
            """{"model":"m","user_cache_secret":7,"messages":{"not":"an array"}}""" to "76f4704bbae620fd7867308b72841c201305640eb221df32c496c65f05d9b702",
            """{"model":"m","user_cache_secret":null,"input":"x"}""" to "2a12b7a9e0565c8ea00062aa1c4904265464aa24213a11d2422b78e99645d2d6",
            """{"model":"m","prompt":{"a":[1,2]},"input":[]}""" to "0db35870c167f76fbf99234c980392e39790136eaf51cbb52a4638098e9157af",
            """{"model":"m","messages":[[1,[2]],3]}""" to "92163c7f6a53e949b5f7538d21fe525837d91c8282d4e65f2d03d25686108d41",
            """{"model":"m","instructions":7,"messages":[ null ]}""" to "95d83385315d109a83525fdad878ffcb03c508550f5ce25f017ad61471b4963d",
        )
        for ((body, prefix) in prefixes) {
            val prepared = prepare(body)
            assertEquals(prefix, prepared.prefixHeader(), body)
            assertEquals(SPEC_SALT, prepared.salt(), body)
        }
        for (body in listOf("""{"model":"m"}""", """{"model":"m","messages":[],"input":null}""", """{"model":"m","instructions":""}""")) {
            assertNull(prepare(body).prefixHeader(), body)
        }
    }

    @Test
    fun aPrefixThatTheCallerSetIsReplacedWhenTheCacheIsScopedAndKeptOtherwise() {
        val caller = listOf(GatewayRequest.CACHE_PREFIX_HEADER to "the-callers-prefix")
        assertEquals(SPEC_PREFIX, prepare(SPEC_BODY, headers = caller).prefixHeader())
        val none = prepare("""{"model":"m"}""", headers = caller)
        assertNull(none.prefixHeader())
        assertEquals("", none.cachePrefix)
        val elsewhere = prepare(SPEC_BODY, path = "/v1/embeddings", headers = caller)
        assertEquals("the-callers-prefix", elsewhere.prefixHeader())
        assertEquals("the-callers-prefix", elsewhere.cachePrefix)
        assertRefused("requests must not set the X-Tinfoil-Cache-Prefix header more than once") {
            prepare(SPEC_BODY, headers = caller + caller)
        }
    }

    // The rewrite.

    @Test
    fun onlyTheTwoMembersAreRewrittenAndEveryOtherByteIsKept() {
        // SALT stands for the salt, as a JSON string.
        val rewrites = mapOf(
            "{}" to "{\"cache_salt\":SALT}",
            " {\n} " to " {\n\"cache_salt\":SALT} ",
            """{"user_cache_secret":"s"}""" to "{\"cache_salt\":SALT}",
            """{"user_cache_secret":"s","model":"m"}""" to "{\"model\":\"m\",\"cache_salt\":SALT}",
            """{"model":"m","user_cache_secret":"s"}""" to "{\"model\":\"m\",\"cache_salt\":SALT}",
            """{"a":1,"user_cache_secret":"s","b":2}""" to "{\"a\":1,\"b\":2,\"cache_salt\":SALT}",
            """{ "a" : 12345678901234567890 , "user_cache_secret" : "s" , "model":"m" }""" to
                "{ \"a\" : 12345678901234567890  , \"model\":\"m\" ,\"cache_salt\":SALT}",
            "{\n  \"user_cache_secret\": \"s\",\n  \"n\": 1.0e+400\n}" to "{\n  \n  \"n\": 1.0e+400\n,\"cache_salt\":SALT}",
            """{"cache_salt":"the caller's","model":"m"}""" to "{\"cache_salt\":SALT,\"model\":\"m\"}",
            """{"model":"m", "cache_salt" : {"x":[1]} ,"user_cache_secret":"s"}""" to "{\"model\":\"m\", \"cache_salt\" : SALT }",
            """{"user_cache_secret":"s","cache_salt":null}""" to "{\"cache_salt\":SALT}",
            """{"us\u0065r_cache_secret":"s","n":{"user_cache_secret":"kept","cache_salt":"kept"}}""" to
                "{\"n\":{\"user_cache_secret\":\"kept\",\"cache_salt\":\"kept\"},\"cache_salt\":SALT}",
            """{"model":"m","c\u0061che_salt":0}""" to "{\"model\":\"m\",\"c\\u0061che_salt\":SALT}",
        )
        val ofTheClients = prepare("{}", authorization = null).salt()
        val ofTheBodys = prepare("{}", secret = "s", authorization = null).salt()
        assertNotEquals(ofTheClients, ofTheBodys)
        for ((body, expected) in rewrites) {
            val salt = if (body.contains("\"s\"")) ofTheBodys else ofTheClients
            assertEquals(expected.replace("SALT", "\"$salt\""), prepare(body, authorization = null).text(), body)
        }
    }

    @Test
    fun aRewrittenBodyMeansWhatTheOriginalDidWithoutTheSecretAndWithTheSalt() {
        val random = Random(20261118)
        val values = listOf("1", "-0.5e10", "12345678901234567890123", "\"x\"", "null", "true", "[1,[2,{\"a\":[]}]]", "{\"model\":\"n\",\"cache_salt\":1}", "\"\"")
        val spaces = listOf("", " ", "\n", "\t ", "\r\n")
        repeat(3_000) {
            val names = listOf("model", "user_cache_secret", "cache_salt", "messages", "a", "b", "instructions").shuffled(random)
                .take(random.nextInt(0, 6))
            fun space() = spaces.random(random)
            val body = names.joinToString(",", "${space()}{${space()}", "${space()}}${space()}") { name ->
                val value = if (name == "model") "\"m\"" else values.random(random)
                "${space()}\"$name\"${space()}:${space()}$value${space()}"
            }
            val sent = prepare(body).text()
            val before = Json.parseToJsonElement(body).jsonObject
            val after = Json.parseToJsonElement(sent).jsonObject
            assertFalse(after.containsKey(UserCacheSecret.FIELD), body)
            val salt = (after[GatewayRequest.CACHE_SALT_FIELD] as JsonPrimitive).content
            assertTrue(Regex("[A-Za-z0-9_-]{43}").matches(salt), sent)
            assertEquals(JsonObject(before - UserCacheSecret.FIELD - GatewayRequest.CACHE_SALT_FIELD), JsonObject(after - GatewayRequest.CACHE_SALT_FIELD), body)
            // The members that stay keep their order, and the scanner still reads one object.
            assertEquals((before.keys - UserCacheSecret.FIELD - GatewayRequest.CACHE_SALT_FIELD).toList(), (after.keys - GatewayRequest.CACHE_SALT_FIELD).toList(), body)
            assertTrue(JsonObjectText.members(sent.toByteArray()) { _, _, _, _ -> } >= 0, sent)
        }
    }

    @Test
    fun theSecretIsNowhereInWhatIsSent() {
        val secret = "a-secret-that-must-stay-on-the-device"
        val own = "the-end-users-own-secret-0123456789"
        for (body in listOf(SPEC_BODY, """{"model":"m","user_cache_secret":"$own","messages":["a"]}""")) {
            val prepared = prepare(body, secret = secret)
            val everything = prepared.request.body!!.bytes() + prepared.request.headers.toString().toByteArray()
            assertFalse(everything.containsText(secret), body)
            assertFalse(everything.containsText(own), body)
            assertFalse(everything.containsText(UserCacheSecret.FIELD), body)
        }
    }

    @Test
    fun aBodyOnAPathWithoutAPromptCacheIsSentAsItIs() {
        val body = """{ "model":"m", "user_cache_secret":"s", "input":[1.0e+400, 12345678901234567890] }"""
        for (path in listOf("/v1/embeddings", "/v1/audio/speech", "/v1/chat/completions/x", "/v1/files")) {
            val prepared = prepare(body, path = path)
            assertEquals(body, prepared.text(), path)
            assertEquals("m", prepared.model)
            assertNull(prepared.prefixHeader())
        }
        for (path in listOf("/v1/chat/completions", "/v1/completions", "/v1/responses", "/chat/completions", "/proxy/v2/responses")) {
            assertFalse(prepare(body, path = path).text().contains("user_cache_secret"), path)
        }
    }

    // Repeated members.

    @Test
    fun aBodyThatRepeatsAMemberThatTheClientReadsIsRefused() {
        val refused = mapOf(
            """{"model":"test-model","model":"other-model"}""" to """request body repeats the "model" member""",
            """{"model":"test-model","user_cache_secret":"a","user_cache_secret":"b"}""" to
                """request body repeats the "user_cache_secret" member""",
            """{"model":"test-model","cache_salt":"a","cache_salt":"b"}""" to """request body repeats the "cache_salt" member""",
            """{"model":"test-model","mod\u0065l":"other-model"}""" to """request body repeats the "model" member""",
            """{"cache_salt":"a","model":"x","cache_salt":"b","model":"y","messages":[]}""" to
                """request body repeats the "model", "cache_salt" members""",
            """{"model":"m","user_cache_secret":"a","model":"m","user_cache_secret":"a","x":1}""" to
                """request body repeats the "model", "user_cache_secret" members""",
            """{"\u006d\u006f\u0064\u0065\u006c":"a", "m\u006Fdel" : "b"}""" to """request body repeats the "model" member""",
            """{"model":"a","user_cache_secret":"s","us\u0065r_cache_secret":"t","cache_salt":1,"cache\u005fsalt":2,"model":"a"}""" to
                """request body repeats the "model", "user_cache_secret", "cache_salt" members""",
            " {\n\"model\"\t:\"a\" ,\r\n\"model\": null } \n" to """request body repeats the "model" member""",
        )
        for ((body, message) in refused) {
            for (path in listOf("/v1/chat/completions", "/v1/embeddings")) {
                // Whether the request names its model in a header or not.
                assertRefused(message) { prepare(body, path = path) }
                assertRefused(message) { prepare(body, path = path, headers = listOf(GatewayRequest.MODEL_HEADER to "test-model")) }
            }
        }
    }

    @Test
    fun otherRepeatsAndJsonThatIsNotAnObjectAreSentAsTheyAre() {
        val forwarded = listOf(
            """{"model":"test-model","temperature":0,"temperature":1}""",
            """{"model":"test-model","n":{"model":"a","model":"b","Model":"c"}}""",
            """{"model":"test-model","n":[{"cache_salt":1,"cache_salt":2}],"model ":"z","models":1,"xmodel":2}""",
            """[{"model":"a"},{"model":"b"}]""",
            "\"model\"",
            "null",
            " 7 ",
        )
        for (body in forwarded) {
            val prepared = prepare(body, path = "/v1/embeddings", headers = listOf(GatewayRequest.MODEL_HEADER to "test-model"))
            assertEquals(body, prepared.text())
            assertEquals("test-model", prepared.model)
        }
        // Without the header, a body that is not an object names no model.
        assertEquals("", prepare("""[{"model":"a"}]""").model)
    }

    @Test
    fun aJsonBodyThatIsNotOneJsonValueIsRefused() {
        val refused = listOf(
            """{"model":"a","model":"b"""",
            """{"model":"a","model":"b"} {}""",
            """{"model":"a","model":"b",}""",
            "not json at all",
            """{"model":"a","x":NaN,"model":"b"}""",
            """{"model":"a","x":Infinity}""",
            """{'model':'a'}""",
            "\ufeff{\"model\":\"a\",\"model\":\"b\"}",
            "[1,]",
        ).map { it.toByteArray() } + listOf(
            // Not UTF-8, and other encodings that hold only ASCII.
            "{\"model\":\"a\",\"x\":\"".toByteArray() + byteArrayOf(0xff.toByte()) + "\",\"model\":\"b\"}".toByteArray(),
            """{"model":"a","user_cache_secret":"s","model":"b"}""".toByteArray(Charsets.UTF_16LE),
            """{"model":"a","model":"b"}""".toByteArray(Charsets.UTF_16BE),
            """{"model":"a","model":"b"}""".toByteArray(Charsets.UTF_32LE),
        )
        for (bytes in refused) {
            for (headers in listOf(emptyList(), listOf(GatewayRequest.MODEL_HEADER to "a"))) {
                for (path in listOf("/v1/chat/completions", "/v1/embeddings")) {
                    assertRefused("the JSON request body is not valid JSON") {
                        prepare(request(bytes.toRequestBody(JSON), path = path, headers = headers))
                    }
                }
            }
        }
    }

    @Test
    fun aMemberThatAServerCouldTakeForOneThatTheClientReadsIsRefused() {
        val refused = mapOf(
            """{"model":"A","Model":"B"}""" to "model",
            """{"Model":"m"}""" to "model",
            """{"MODEL":"m","messages":[]}""" to "model",
            """{"m\u004fdel":"m"}""" to "model",
            """{"model":"m","USER_CACHE_SECRET":"x"}""" to "user_cache_secret",
            """{"model":"m","User_Cache_Secret":"x","user_cache_secret":"y"}""" to "user_cache_secret",
            "{\"model\":\"m\",\"user_cache_\u017fecret\":\"x\"}" to "user_cache_secret",
            """{"model":"m","u\u017fer_cache_secret":"x"}""" to "user_cache_secret",
            """{"model":"m","Cache_Salt":"x"}""" to "cache_salt",
            "{\"model\":\"m\",\"cache_\u017falt\":1}" to "cache_salt",
        )
        for ((body, name) in refused) {
            for (path in listOf("/v1/chat/completions", "/v1/embeddings")) {
                for (headers in listOf(emptyList(), listOf(GatewayRequest.MODEL_HEADER to "m"))) {
                    assertRefused("request body has a member whose name differs from \"$name\" only by case") {
                        prepare(body, path = path, headers = headers)
                    }
                }
            }
        }
        // Names that no folding makes the same, and members that are not at the top.
        val body = """{"model":"m","models":1,"mode":2,"model_":3,"n":{"Model":"x","CACHE_SALT":1},"Instructions":"kept"}"""
        assertEquals(body, prepare(body, path = "/v1/embeddings").text())
    }

    // The model.

    @Test
    fun theModelIsTheBodysUnlessAHeaderNamesOne() {
        assertEquals("gpt-oss-120b", prepare("""{"model":"gpt-oss-120b"}""").model)
        assertEquals("a b", prepare("""{"m\u006fdel":"a\u0020b"}""").model)
        for (body in listOf("""{"model":""}""", """{"model":null}""", """{"model":7}""", """{"model":["m"]}""", """{"n":{"model":"m"}}""", "{}")) {
            val prepared = prepare(body)
            assertEquals("", prepared.model, body)
            assertNull(prepared.request.header(GatewayRequest.MODEL_HEADER), body)
        }
        val named = prepare("""{"model":"in-the-body"}""", headers = listOf(GatewayRequest.MODEL_HEADER to "in-the-header"))
        assertEquals("in-the-header", named.model)
        assertEquals(listOf("in-the-header"), named.request.headers(GatewayRequest.MODEL_HEADER))
        assertRefused("requests must not set the X-Tinfoil-Model header more than once") {
            prepare("""{"model":"m"}""", headers = listOf(GatewayRequest.MODEL_HEADER to "a", GatewayRequest.MODEL_HEADER to "b"))
        }
    }

    @Test
    fun aModelNameThatAHeaderCannotCarryIsRefused() {
        for (model in listOf("m\u00e9", "a\\nb", "a\\u0000b", " m", "m ", "\\tm", "m\ud83d\ude00")) {
            assertRefused("the request names a model whose name cannot be sent in a header") {
                prepare("{\"model\":\"$model\"}")
            }
        }
    }

    @Test
    fun requestsWithoutAJsonBodyAreLeftAlone() {
        val get = request(null, method = "GET", path = "/v1/models")
        assertSame(get, prepare(get).request)
        assertEquals("", prepare(get).model)
        val empty = request(ByteArray(0).toRequestBody(JSON))
        assertSame(empty, prepare(empty).request)
        val text = request("""{"model":"m","model":"n"}""".toRequestBody("text/plain".toMediaType()))
        assertSame(text, prepare(text).request)
        assertEquals("", prepare(text).model)
        val put = request("""{"model":"m"}""".toRequestBody(JSON), method = "PUT")
        assertSame(put, prepare(put).request)
        val untyped = request(Fixed("""{"model":"m"}""".toByteArray(), type = null))
        assertSame(untyped, prepare(untyped).request)
        // A header names the content type of a body that has none of its own.
        val byHeader = request(Fixed("""{"model":"m"}""".toByteArray(), type = null), headers = listOf("Content-Type" to "application/json"))
        assertEquals("m", prepare(byHeader).model)
        // A body's own content type is the one that is sent, whatever a header says.
        val both = request("""{"model":"m","model":"n"}""".toByteArray().toRequestBody(JSON), headers = listOf("Content-Type" to "text/plain"))
        assertRefused("""request body repeats the "model" member""") { prepare(both) }
        val plain = request(Fixed("""{"model":"m","model":"n"}""".toByteArray(), type = "text/plain".toMediaType()), headers = listOf("Content-Type" to "application/json"))
        assertSame(plain, prepare(plain).request)
        // A body without a content type of its own is named by one header, not by two.
        val twice = request(
            Fixed("""{"model":"m","model":"n"}""".toByteArray(), type = null),
            headers = listOf("Content-Type" to "text/plain", "Content-Type" to "application/json"),
        )
        assertRefused("requests must not set the Content-Type header more than once") { prepare(twice) }
    }

    /** A body with a fixed content that says what a test wants of itself. */
    private class Fixed(
        private val content: ByteArray,
        private val type: MediaType? = JSON,
        private val declared: Long = content.size.toLong(),
        private val oneShot: Boolean = false,
        private val duplex: Boolean = false,
    ) : RequestBody() {
        var writes = 0

        override fun contentType(): MediaType? = type

        override fun contentLength(): Long = declared

        override fun isOneShot(): Boolean = oneShot

        override fun isDuplex(): Boolean = duplex

        override fun writeTo(sink: BufferedSink) {
            writes++
            sink.write(content)
        }
    }

    @Test
    fun aBodyIsReadOnceAndCanThenBeSentAgain() {
        val body = Fixed(SPEC_BODY.toByteArray(), oneShot = true, declared = -1)
        val prepared = prepare(request(body))
        assertEquals(1, body.writes)
        assertFalse(prepared.request.body!!.isOneShot())
        assertContentEquals(prepared.request.body!!.bytes(), prepared.request.body!!.bytes())
        assertEquals(1, body.writes)
    }

    @Test
    fun aJsonBodyThatCannotBeReadIsRefused() {
        val large = GatewayRequest.MAX_BODY_BYTES + 1
        val declared = Fixed(ByteArray(0), declared = large)
        val error = assertFailsWith<ConfigurationException> { prepare(request(declared)) }
        assertTrue(error.detail.contains("larger than"), error.detail)
        assertEquals(0, declared.writes, "a body that declares too much is not read")
        assertFailsWith<ConfigurationException> { prepare(request(Fixed(SPEC_BODY.toByteArray(), duplex = true))) }
        // A body that does not write what it declares.
        assertFailsWith<ProtocolException> { prepare(request(Fixed(SPEC_BODY.toByteArray(), declared = 5))) }
        assertFailsWith<ProtocolException> { prepare(request(Fixed(SPEC_BODY.toByteArray(), declared = 500))) }
    }

    // Uploads.

    private fun upload(vararg parts: MultipartBody.Part, boundary: String = "the-boundary-0123456789"): MultipartBody =
        MultipartBody.Builder(boundary).setType(MultipartBody.FORM).apply { parts.forEach(::addPart) }.build()

    private fun field(name: String, value: String) = MultipartBody.Part.createFormData(name, value)

    private fun file(name: String = "file", content: String = "audio bytes") =
        MultipartBody.Part.createFormData(name, "a.wav", content.toRequestBody("audio/wav".toMediaType()))

    private fun raw(text: String, boundary: String = "b", headers: List<Pair<String, String>> = emptyList()): Request = request(
        text.toByteArray(Charsets.ISO_8859_1).toRequestBody("multipart/form-data; boundary=$boundary".toMediaType()),
        path = "/v1/audio/transcriptions",
        headers = headers,
    )

    @Test
    fun anUploadNamesItsModelInItsOneModelField() {
        val body = upload(file(), field("model", "whisper-large-v3"), field("language", "en"))
        val prepared = prepare(request(body, path = "/v1/audio/transcriptions"))
        assertEquals("whisper-large-v3", prepared.model)
        assertEquals("whisper-large-v3", prepared.request.header(GatewayRequest.MODEL_HEADER))
        assertContentEquals(body.bytes(), prepared.request.body!!.bytes())
        assertEquals(body.contentType(), prepared.request.body!!.contentType())
        assertFalse(prepared.request.body!!.isOneShot())
    }

    @Test
    fun anUploadWithTheModelHeaderIsStreamedAsItIs() {
        val body = Fixed("--b\r\nnot even a form".toByteArray(), type = "multipart/form-data; boundary=b".toMediaType(), oneShot = true)
        val request = request(body, path = "/v1/audio/transcriptions", headers = listOf(GatewayRequest.MODEL_HEADER to "whisper"))
        val prepared = prepare(request)
        assertSame(request, prepared.request)
        assertEquals("whisper", prepared.model)
        assertEquals(0, body.writes)
    }

    @Test
    fun anUploadMustNameExactlyOneModel() {
        val refused = listOf(
            upload(file()),
            upload(file(), field("model", "a"), field("model", "b")),
            upload(file(), field("model", "a"), field("model", "a")),
            upload(file(), field("model", "")),
            upload(file(), field("model", "  \t ")),
            upload(file(), field("Model", "a")),
        )
        for (body in refused) {
            assertRefused("multipart upload must contain exactly one non-empty model field") {
                prepare(request(body, path = "/v1/audio/transcriptions"))
            }
        }
        // A file is not a model, with a name or without one.
        val named = MultipartBody.Part.createFormData("model", "a.wav", "a".toRequestBody())
        assertRefused("multipart upload must contain exactly one non-empty model field") {
            prepare(request(upload(file(), named), path = "/v1/audio/transcriptions"))
        }
        for (body in listOf(upload(file(), file(name = "model", content = "a")), upload(field("model", "a"), file(name = "model", content = "b")))) {
            assertRefused("invalid multipart upload") { prepare(request(body, path = "/v1/audio/transcriptions")) }
        }
        assertRefused("multipart upload is missing its boundary, or names it ambiguously") {
            prepare(request(Fixed("x".toByteArray(), type = "multipart/form-data".toMediaType()), path = "/v1/audio/transcriptions"))
        }
        assertRefused("the request names a model whose name cannot be sent in a header") {
            prepare(request(upload(field("model", "a\nb")), path = "/v1/audio/transcriptions"))
        }
    }

    @Test
    fun anUploadIsReadWithNoPreambleProblemsAndPlainFields() {
        val part = "Content-Disposition: form-data; name=\"model\"\r\n\r\nwhisper"
        val accepted = listOf(
            "--b\r\n$part\r\n--b--\r\n",
            "--b\r\n$part\r\n--b--",
            "preamble\r\n--b\r\n$part\r\n--b--\r\nepilogue",
            "--b \t\r\n$part\r\n--b--\r\n",
            "--b\r\ncontent-disposition:form-data;name=model\r\nContent-Type: text/plain\r\n\r\nwhisper\r\n--b--\r\n",
            "--b\r\n$part\r\n--b\r\n\r\nno headers\r\n--b\r\nX-Other: 1\r\n\r\nno disposition\r\n--b--\r\n",
            "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\n\r\n--b\r\n$part\r\n--b--\r\n",
        )
        for (text in accepted) {
            assertEquals("whisper", prepare(raw(text)).model, text)
        }
    }

    @Test
    fun anUploadThatTwoParsersCouldReadDifferentlyIsRefused() {
        val model = "Content-Disposition: form-data; name=\"model\"\r\n\r\nwhisper"
        val other = "Content-Disposition: form-data; name=\"model\"\r\n\r\nother"
        val refused = listOf(
            // Nothing that closes the form, or nothing at all.
            "--b", "--b\r\n$model", "--b\r\n$model\r\n", "--b\r\n$model\r\n--b\r\n", "no delimiter",
            // A second model behind a line that ends in a bare line feed.
            "--b\r\n$model\n--b\n$other\r\n--b--\r\n",
            "--b\r\n$model\r\n--b--\r\n--b\r\n$other\r\n--b--\r\n",
            "--b\n$model\n--b--\n",
            // The delimiter where no line starts, and a longer line that starts like it.
            "--b\r\n${model}x--b\r\n--b--\r\n",
            "--b\r\n$model\r\n--bx\r\n$other\r\n--b--\r\n",
            "x--b\r\n$model\r\n--b--\r\n",
            // Headers that are folded, repeated, or not headers.
            "--b\r\nContent-Disposition: form-data;\r\n name=\"model\"\r\n\r\nwhisper\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nother\r\n--b--\r\n",
            "--b\r\nno colon\r\n\r\nwhisper\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\"x\"\nContent-Disposition: form-data; name=\"model\"\r\n\r\nother\r\n--b--\r\n",
            "--b\r\nContent-Disposition: form-data; name=\"model\"\r\nwhisper\r\n--b--\r\n",
            // Names that are encoded, escaped, repeated or not closed.
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name*=UTF-8''model\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\"mo\\del\"\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\"x\"; name=\"model\"\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\"model\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data name=\"model\"\r\n\r\nother\r\n--b--\r\n",
            // A disposition of another kind.
            "--b\r\n$model\r\n--b\r\nContent-Disposition: attachment; name=\"model\"\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: ; name=\"model\"\r\n\r\nother\r\n--b--\r\n",
        )
        for (text in refused) {
            val error = assertFailsWith<ConfigurationException>(text) { prepare(raw(text)) }
            assertEquals("invalid multipart upload", error.detail, text)
        }
        // A value that is not UTF-8 names no model.
        assertRefused("multipart upload must contain exactly one non-empty model field") {
            prepare(raw("--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n\u00ff\r\n--b--\r\n"))
        }
        for (boundary in listOf("b\u00e9", "x".repeat(71))) {
            val error = assertFailsWith<ConfigurationException> {
                prepare(request(Fixed("--b\r\n$model\r\n--b--".toByteArray(), type = "multipart/form-data; boundary=\"$boundary\"".toMediaType()), path = "/v1/audio/transcriptions"))
            }
            assertEquals("multipart upload is missing its boundary, or names it ambiguously", error.detail)
        }
    }

    @Test
    fun theBoundaryIsReadStrictlyFromTheContentType() {
        val form = "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper\r\n--b--\r\n"
        fun typed(contentType: String) =
            request(Fixed(form.toByteArray(), type = null), path = "/v1/audio/transcriptions", headers = listOf("Content-Type" to contentType))
        for (contentType in listOf("multipart/form-data; boundary=b", "multipart/form-data;boundary=\"b\"", "Multipart/Form-Data ; charset=utf-8; Boundary=b")) {
            assertEquals("whisper", prepare(typed(contentType)).model, contentType)
        }
        val refused = listOf(
            "multipart/form-data; boundary='b'",
            "multipart/form-data; boundary=b; boundary=x",
            "multipart/form-data; boundary=x; boundary=b",
            "multipart/form-data; boundary=b; BOUNDARY=x",
            "multipart/form-data; boundary*=utf-8''b",
            "multipart/form-data; boundary=\"b\\\"\"",
            "multipart/form-data; boundary=b x",
            "multipart/form-data; boundary=b;",
            "multipart/form-data; boundary=\"b \"",
            "multipart/form-data; boundary=\"b<\"",
            "multipart/form-data; boundary=",
            "multipart/form-data; boundary",
            "multipart/form-data",
        )
        for (contentType in refused) {
            val error = assertFailsWith<ConfigurationException>(contentType) { prepare(typed(contentType)) }
            assertTrue(error.detail.startsWith("multipart upload") || error.detail.startsWith("invalid multipart upload"), error.detail)
        }
        // The same through a body's own content type, as the HTTP client parsed it.
        val quoted = Fixed(form.toByteArray(), type = "multipart/form-data; boundary='b'".toMediaType())
        assertFailsWith<ConfigurationException> { prepare(request(quoted, path = "/v1/audio/transcriptions")) }
    }

    @Test
    fun aModelFieldCarriesNoHeaderThatCouldChangeHowItIsRead() {
        fun form(headers: String, value: String = "whisper") =
            raw("--b\r\nContent-Disposition: form-data; name=\"model\"\r\n$headers\r\n$value\r\n--b--\r\n")
        for (headers in listOf("", "Content-Type: text/plain\r\n", "content-type: Text/Plain; charset=UTF-8\r\n", "Content-Type: text/plain;charset=us-ascii\r\n", "Content-Length: 7\r\n")) {
            assertEquals("whisper", prepare(form(headers)).model, headers)
        }
        val refused = listOf(
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-Transfer-Encoding: 8bit\r\n",
            "Content-Type: text/plain; charset=utf-16\r\n",
            "Content-Type: application/json\r\n",
            "Content-Type: text/plain; charset=utf-8; x=y\r\n",
            "Content-Type: text/plain\r\nContent-Type: text/plain\r\n",
            "Content-Length: 3\r\n",
            "Content-Length: 07\r\n",
            "Content-Encoding: gzip\r\n",
            "X-Anything: 1\r\n",
        )
        for (headers in refused) {
            val error = assertFailsWith<ConfigurationException>(headers) { prepare(form(headers, value = if (headers.contains("quoted")) "=41" else "whisper")) }
            assertEquals("invalid multipart upload", error.detail, headers)
        }
        // The fields that scope the cache are held to the same rule; any other field is not.
        assertFailsWith<ConfigurationException> {
            prepare(raw("--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper\r\n--b\r\nContent-Disposition: form-data; name=\"cache_salt\"\r\nContent-Transfer-Encoding: base64\r\n\r\nx\r\n--b--\r\n"))
        }
        assertEquals(
            "whisper",
            prepare(raw("--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper\r\n--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\nContent-Transfer-Encoding: binary\r\nX-Other: 1\r\n\r\nx\r\n--b--\r\n")).model,
        )
    }

    @Test
    fun aNameWithAControlCharacterAndAnEndThatIsNotAnEndAreRefused() {
        val model = "Content-Disposition: form-data; name=\"model\"\r\n\r\nwhisper"
        val refused = listOf(
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\"model\u0000\"\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\"mo\tdel\"\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b\r\nContent-Disposition: form-data; name=\"x\"; filename=\"a\u007f\"\r\n\r\nother\r\n--b--\r\n",
            "--b\r\n$model\r\n--b--junk",
            "--b\r\n$model\r\n--b--junk\r\n",
            "--b\r\n$model\r\n--b---\r\n",
            "--b\r\n$model\r\n--b-- x\r\n",
            "--b\r\n$model\r\n--b--\n",
        )
        for (text in refused) {
            val error = assertFailsWith<ConfigurationException>(text) { prepare(raw(text)) }
            assertEquals("invalid multipart upload", error.detail, text)
        }
        for (end in listOf("--b--", "--b--\r\n", "--b-- \t\r\n", "--b--\r\nan epilogue\r\n")) {
            assertEquals("whisper", prepare(raw("--b\r\n$model\r\n$end")).model, end)
        }
    }

    @Test
    fun anUploadThatIsTooLargeToReadIsRefused() {
        val body = Fixed(ByteArray(0), type = "multipart/form-data; boundary=b".toMediaType(), declared = GatewayRequest.MAX_BODY_BYTES + 1)
        val error = assertFailsWith<ConfigurationException> { prepare(request(body, path = "/v1/audio/transcriptions")) }
        assertTrue(error.detail.contains("larger than"), error.detail)
        assertEquals(0, body.writes)
    }

    private companion object {
        const val SECRET = "test-secret"
        const val SPEC_BODY = """{"model":"test-model","messages":[{"role":"user","content":"hello"}]}"""
        const val SPEC_SALT = "DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8"
        const val SPEC_PREFIX = "ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6"
        val JSON = "application/json".toMediaType()
    }
}
