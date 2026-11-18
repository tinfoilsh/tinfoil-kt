package sh.tinfoil.internal.transport

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer
import okio.BufferedSink
import sh.tinfoil.ConfigurationException
import java.io.IOException
import java.net.ProtocolException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class UserCacheSecretTest {
    private val secret = UserCacheSecret.of("s3cret")!!

    private fun spliced(text: ByteArray, secret: UserCacheSecret = this.secret): String? =
        secret.splice(text)?.applyTo(text)?.toString(Charsets.UTF_8)

    private fun spliced(text: String): String? = spliced(text.toByteArray())

    // Where the secret goes.

    @Test
    fun theSecretIsAddedAsTheLastMemberOfAnObject() {
        val cases = mapOf(
            """{}""" to """{"user_cache_secret":"s3cret"}""",
            " { } " to """ { "user_cache_secret":"s3cret"} """,
            "\t\r\n{\n}\n" to "\t\r\n{\n\"user_cache_secret\":\"s3cret\"}\n",
            """{"a":1}""" to """{"a":1,"user_cache_secret":"s3cret"}""",
            "{\"a\":1 \n}\n" to "{\"a\":1 \n,\"user_cache_secret\":\"s3cret\"}\n",
            """{"a":"}","b":"\\","c":"\"}{"}""" to """{"a":"}","b":"\\","c":"\"}{","user_cache_secret":"s3cret"}""",
            """{"a":[{"b":[]},{}],"c":{"d":{}}}""" to """{"a":[{"b":[]},{}],"c":{"d":{}},"user_cache_secret":"s3cret"}""",
            """{"a":null,"b":true,"c":false,"d":-0.5e+10,"e":0,"f":1E-2}""" to
                """{"a":null,"b":true,"c":false,"d":-0.5e+10,"e":0,"f":1E-2,"user_cache_secret":"s3cret"}""",
            """{"é":"☃ \ud83d\ude00 😀 \u0000 \/"}""" to """{"é":"☃ \ud83d\ude00 😀 \u0000 \/","user_cache_secret":"s3cret"}""",
            """{"":1}""" to """{"":1,"user_cache_secret":"s3cret"}""",
            """{"a":"\ud800"}""" to """{"a":"\ud800","user_cache_secret":"s3cret"}""",
        )
        for ((text, expected) in cases) {
            assertEquals(expected, spliced(text), text)
        }
    }

    @Test
    fun anEmptySecretInTheBodyIsReplacedInPlace() {
        val cases = mapOf(
            """{"user_cache_secret":""}""" to """{"user_cache_secret":"s3cret"}""",
            """{"user_cache_secret" : "" ,"a":1}""" to """{"user_cache_secret" : "s3cret" ,"a":1}""",
            """{"a":1,"user_cache_secret":"","b":2}""" to """{"a":1,"user_cache_secret":"s3cret","b":2}""",
            // The name in another spelling is the same name.
            """{"\u0075ser_cache_secret":""}""" to """{"\u0075ser_cache_secret":"s3cret"}""",
            """{"user\u005Fcache_secret":"", "a":""}""" to """{"user\u005Fcache_secret":"s3cret", "a":""}""",
        )
        for ((text, expected) in cases) {
            assertEquals(expected, spliced(text), text)
        }
    }

    @Test
    fun aSecretOrAnyOtherValueInTheBodyIsLeftAlone() {
        val kept = listOf(
            """{"user_cache_secret":"mine"}""",
            """{"user_cache_secret":" "}""",
            """{"user_cache_secret":"\u0000"}""",
            """{"\u0075ser_cache_secret":"mine"}""",
            """{"user_cache_secret":null}""",
            """{"user_cache_secret":0}""",
            """{"user_cache_secret":false}""",
            """{"user_cache_secret":{}}""",
            """{"user_cache_secret":[]}""",
            """{"user_cache_secret":[""]}""",
        )
        for (text in kept) {
            assertNull(spliced(text), text)
        }
    }

    @Test
    fun aBodyThatNamesTheSecretTwiceIsLeftAlone() {
        val repeated = listOf(
            """{"user_cache_secret":"","user_cache_secret":""}""",
            """{"user_cache_secret":"","user_cache_secret":"mine"}""",
            """{"user_cache_secret":"mine","user_cache_secret":""}""",
            """{"user_cache_secret":"","a":1,"\u0075ser_cache_secret":""}""",
            """{"user_cache_\u0073ecret":"","user_cache_secret":""}""",
            """{"user_cache_secret":null,"user_cache_secret":""}""",
            """{"user_cache_secret":"","user_cache_secret":"","user_cache_secret":""}""",
        )
        for (text in repeated) {
            assertNull(spliced(text), text)
        }
    }

    @Test
    fun onlyTopLevelMembersWithExactlyTheNameCount() {
        val cases = mapOf(
            """{"a":{"user_cache_secret":"x","user_cache_secret":"y"}}""" to
                """{"a":{"user_cache_secret":"x","user_cache_secret":"y"},"user_cache_secret":"s3cret"}""",
            """{"a":[{"user_cache_secret":""}],"user_cache_secret":""}""" to
                """{"a":[{"user_cache_secret":""}],"user_cache_secret":"s3cret"}""",
            """{"a":"\"user_cache_secret\":\"\""}""" to
                """{"a":"\"user_cache_secret\":\"\"","user_cache_secret":"s3cret"}""",
            """{"User_cache_secret":"","user_cache_secret ":"","user_cache_secre":"","user_cache_secrets":""}""" to
                """{"User_cache_secret":"","user_cache_secret ":"","user_cache_secre":"","user_cache_secrets":"","user_cache_secret":"s3cret"}""",
            """{"user_cache_secret\u0000":""}""" to """{"user_cache_secret\u0000":"","user_cache_secret":"s3cret"}""",
            """{"user_cache_secre\ud83d\ude00":""}""" to """{"user_cache_secre\ud83d\ude00":"","user_cache_secret":"s3cret"}""",
            """{"\uff55ser_cache_secret":""}""" to """{"\uff55ser_cache_secret":"","user_cache_secret":"s3cret"}""",
        )
        for ((text, expected) in cases) {
            assertEquals(expected, spliced(text), text)
        }
    }

    @Test
    fun numbersKeepEveryDigit() {
        val text = """{"seed":18446744073709551617,"n":9007199254740993,"f":1.000000000000000000001e400,"z":-0}"""

        val result = spliced(text)!!

        assertEquals(text.dropLast(1) + ""","user_cache_secret":"s3cret"}""", result)
        assertTrue(result.contains("18446744073709551617") && result.contains("9007199254740993"))
    }

    // What is not touched.

    @Test
    fun textThatIsNotOneJsonObjectIsLeftAlone() {
        val texts = listOf(
            "", " ", "[]", "[{}]", "\"x\"", "1", "null", "true", "{", "}", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "{,}",
            "{\"a\":1}}", "{\"a\":1} x", "{\"a\":1}{}", "{\"a\":1},", "{}{}", "{} {}", "\uFEFF{}", "{/*c*/}", "{\"a\":1}//c",
            "{\"a\":1}#c", "{'a':1}", "{a:1}", "{\"a\":01}", "{\"a\":+1}", "{\"a\":.5}", "{\"a\":1.}", "{\"a\":1e}",
            "{\"a\":-}", "{\"a\":NaN}", "{\"a\":Infinity}", "{\"a\":0x10}", "{\"a\":\"\\x\"}", "{\"a\":\"\\u12\"}",
            "{\"a\":\"\\u12g4\"}", "{\"a\":\"line\nbreak\"}", "{\"a\":\"tab\there\"}", "{\"a\":tru}", "{\"a\":True}",
            "{\"a\":nul}", "{\"a\":\"unterminated", "{\"a\":\"x\\\"}", "{\"a\":[1,]}", "{\"a\":[1 2]}", "{\"a\":{\"b\":1,}}",
            "{\"a\":{\"b\"}}", "{\"a\":[}", "{\"a\":{]}", "{\"a\":1 \"b\":2}", "{\"a\"::1}", "{\"a\":1,,\"b\":2}",
            "{\"a\":1}\u0000", "\u0000{}", "{\u000C}", "{\u00A0}", "{\"a\":1}\u2028", "{1:2}", "{null:1}", "{\"a\":1;}",
            "{\"a\":'x'}", "{\"a\":1}\n\n]", "{\"a\":[[[[1]]]}", "{\"a\":\"\\",
        )
        for (text in texts) {
            assertNull(spliced(text), text)
        }
    }

    @Test
    fun textThatIsNotUtf8IsLeftAlone() {
        val malformed = mapOf(
            "a byte that is never valid" to byteArrayOf(0xff.toByte()),
            "a stray continuation byte" to byteArrayOf(0x80.toByte()),
            "an overlong form" to byteArrayOf(0xc0.toByte(), 0x80.toByte()),
            "another overlong form" to byteArrayOf(0xe0.toByte(), 0x80.toByte(), 0x80.toByte()),
            "an encoded surrogate" to byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
            "a value past the last code point" to byteArrayOf(0xf4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()),
            "a character that is cut short" to byteArrayOf(0xe2.toByte(), 0x98.toByte()),
            "a lead byte before the quote" to byteArrayOf(0xf0.toByte()),
        )
        for ((name, bytes) in malformed) {
            val inValue = "{\"a\":\"".toByteArray() + bytes + "\"}".toByteArray()
            val inName = "{\"".toByteArray() + bytes + "\":1}".toByteArray()
            assertNull(spliced(inValue), "$name in a value")
            assertNull(spliced(inName), "$name in a name")
            assertNull(spliced("{}".toByteArray() + bytes), "$name after the object")
        }
        assertNotNull(spliced("{\"a\":\"\u00e9\u2603\ud83d\ude00\"}"), "well-formed text is read")
    }

    @Test
    fun nestingIsReadToAFixedDepthWithoutUsingTheStack() {
        fun nested(arrays: Int) = "{\"a\":" + "[".repeat(arrays) + "]".repeat(arrays) + "}"

        assertNotNull(spliced(nested(JsonObjectText.MAX_DEPTH - 1)), "the deepest text that is read")
        assertNull(spliced(nested(JsonObjectText.MAX_DEPTH)), "one level deeper")
        assertNull(spliced("{\"a\":" + "[".repeat(1 shl 20)), "a megabyte of brackets")
        assertNull(spliced("{\"a\":" + "{\"a\":".repeat(1 shl 18)), "objects that never close")
        val objects = "{\"a\":".repeat(5_000) + "1" + "}".repeat(5_000)
        assertEquals(objects.dropLast(1) + ",\"user_cache_secret\":\"s3cret\"}", spliced(objects))
    }

    @Test
    fun largeStringsAndNumbersAreRead() {
        val text = "{\"a\":\"" + "x".repeat(4 shl 20) + "\",\"n\":" + "9".repeat(1 shl 20) + "}"

        val result = spliced(text)!!

        assertEquals(text.length + ",\"user_cache_secret\":\"s3cret\"".length, result.length)
        assertTrue(result.endsWith("9,\"user_cache_secret\":\"s3cret\"}"))
    }

    @Test
    fun generatedObjectsKeepTheirMeaningAndGainTheSecret() {
        val random = Random(20261118)
        repeat(500) {
            val text = Generator(random).document()
            val result = assertNotNull(spliced(text), text)

            val before = Json.parseToJsonElement(text).jsonObject
            val after = Json.parseToJsonElement(result).jsonObject
            assertEquals(JsonObject(before + ("user_cache_secret" to JsonPrimitive("s3cret"))), after, text)
            // Only the secret was added: removing it gives the text back.
            assertEquals(text, result.replaceFirst(Regex(",?\"user_cache_secret\":\"s3cret\"(?=[ \\n\\t\\r]*}[ \\n\\t\\r]*$)"), ""))
        }
    }

    @Test
    fun damagedTextNeverFailsAndNeverChangesMoreThanTheSecret() {
        val random = Random(42)
        repeat(3_000) {
            val bytes = Generator(random).document().toByteArray()
            repeat(1 + random.nextInt(3)) {
                when (random.nextInt(3)) {
                    0 -> bytes[random.nextInt(bytes.size)] = random.nextInt(256).toByte()
                    1 -> bytes[random.nextInt(bytes.size)] = "{}[]\",:\\ ".random(random).code.toByte()
                    else -> bytes[random.nextInt(bytes.size)] = bytes[random.nextInt(bytes.size)]
                }
            }
            val splice = secret.splice(bytes) ?: return@repeat
            // Whatever was accepted is still JSON to an independent parser,
            // and holds the secret exactly once.
            val text = bytes.toString(Charsets.UTF_8)
            val result = splice.applyTo(bytes).toString(Charsets.UTF_8)
            val after = Json.parseToJsonElement(result).jsonObject
            assertEquals(JsonPrimitive("s3cret"), after["user_cache_secret"], text)
            assertEquals(1, Regex("\"user_cache_secret\"\\s*:").findAll(topLevel(result)).count(), text)
        }
    }

    /** [text] with the contents of every nested container and string removed. */
    private fun topLevel(text: String): String {
        val out = StringBuilder()
        var depth = 0
        var inString = false
        var escaped = false
        var name = StringBuilder()
        for (c in text) {
            if (inString) {
                if (depth == 1) name.append(c)
                when {
                    escaped -> escaped = false
                    c == '\\' -> escaped = true
                    c == '"' -> {
                        inString = false
                        if (depth == 1) {
                            // Decode the name, so that every spelling counts.
                            out.append(Json.parseToJsonElement(name.toString()).toString())
                        }
                    }
                }
                continue
            }
            when (c) {
                '"' -> {
                    inString = true
                    name = StringBuilder("\"")
                }
                '{', '[' -> depth++
                '}', ']' -> depth--
                else -> if (depth == 1) out.append(c)
            }
        }
        return out.toString()
    }

    /** Writes random JSON objects, with whitespace and escapes that a caller might produce. */
    private class Generator(private val random: Random) {
        fun document(): String = space() + objectText(0) + space()

        private fun space(): String = " \n\t\r".filter { random.nextInt(4) == 0 }

        private fun objectText(depth: Int): String {
            val members = List(random.nextInt(4)) { string() + space() + ":" + space() + value(depth + 1) }
            return "{" + space() + members.joinToString(space() + "," + space()) + space() + "}"
        }

        private fun value(depth: Int): String = when (random.nextInt(if (depth > 4) 5 else 7)) {
            0 -> string()
            1 -> listOf("0", "-1", "12.5", "1e9", "-0.0E-3", "18446744073709551617", "9007199254740993").random(random)
            2 -> "true"
            3 -> "false"
            4 -> "null"
            5 -> objectText(depth)
            else -> "[" + space() + List(random.nextInt(3)) { value(depth + 1) }.joinToString(space() + ",") + space() + "]"
        }

        private fun string(): String {
            val parts = listOf(
                "a", "b", "user_cache_secre", "}", "{", "[", "]", ",", ":", " ", "\\\"", "\\\\", "\\/", "\\n", "\\u00e9",
                "\\ud83d\\ude00", "\u00e9", "\u2603", "\ud83d\ude00", "x_y",
            )
            return "\"" + List(random.nextInt(4)) { parts.random(random) }.joinToString("") + "\""
        }
    }

    // The secret itself.

    @Test
    fun theSecretIsWrittenAsAJsonString() {
        val awkward = "a\"b\\c\n\u0001\u007f \u00e9\u2603\ud83d\ude00</script>"
        val result = spliced("{}".toByteArray(), UserCacheSecret.of(awkward)!!)!!

        assertEquals("{\"user_cache_secret\":\"a\\\"b\\\\c\\u000a\\u0001\u007f \u00e9\u2603\ud83d\ude00</script>\"}", result)
        assertEquals(JsonPrimitive(awkward), Json.parseToJsonElement(result).jsonObject["user_cache_secret"])
    }

    @Test
    fun noSecretMeansNone() {
        assertNull(UserCacheSecret.of(null))
        assertNull(UserCacheSecret.of(""))
    }

    @Test
    fun aSecretThatIsNotWellFormedTextIsRefusedWithoutBeingEchoed() {
        for (text in listOf("hunter2\ud800", "\udc00hunter2", "hunter2\ud800x", "hunter2\udc00\ud800")) {
            val error = assertFailsWith<ConfigurationException> { UserCacheSecret.of(text) }
            assertFalse(error.message!!.contains("hunter2"), error.message)
            assertFailsWith<ConfigurationException> { UserCacheSecret.orProcessDefault(text) }
        }
    }

    @Test
    fun theProcessSecretIsRandomStableAndNeverPrinted() {
        val first = spliced("{}".toByteArray(), UserCacheSecret.orProcessDefault(null))!!
        val second = spliced("{}".toByteArray(), UserCacheSecret.orProcessDefault(""))!!

        assertEquals(first, second, "one secret for the process")
        val value = assertNotNull(Regex("""\{"user_cache_secret":"([0-9a-f]{64})"}""").matchEntire(first)).groupValues[1]
        assertTrue(value.toSet().size > 4, "256 random bits, not a constant")
        assertSame(UserCacheSecret.orProcessDefault(null), UserCacheSecret.orProcessDefault(null))
        assertFalse(UserCacheSecret.orProcessDefault(null).toString().contains(value))
        assertFalse(secret.toString().contains("s3cret"))
        assertEquals("{\"user_cache_secret\":\"mine\"}", spliced("{}".toByteArray(), UserCacheSecret.orProcessDefault("mine")))
    }

    // Which requests are given it.

    private val json = "application/json; charset=utf-8".toMediaType()

    private fun post(path: String, body: RequestBody, method: String = "POST"): Request =
        Request.Builder().url("https://router.example$path").method(method, body).build()

    private fun provision(request: Request, secret: UserCacheSecret = this.secret): Request =
        runBlocking { secret.provision(request) }

    private fun Request.text(): String = Buffer().also { body!!.writeTo(it) }.readUtf8()

    /** A body that counts how often it is written, and can lie about itself. */
    private class CountingBody(
        private val text: String,
        private val declared: Long? = text.toByteArray().size.toLong(),
        private val oneShot: Boolean = false,
        private val duplex: Boolean = false,
        private val type: MediaType? = null,
    ) : RequestBody() {
        val writes = AtomicInteger()

        override fun contentType(): MediaType? = type

        override fun contentLength(): Long = declared ?: -1

        override fun isOneShot(): Boolean = oneShot

        override fun isDuplex(): Boolean = duplex

        override fun writeTo(sink: BufferedSink) {
            writes.incrementAndGet()
            sink.writeUtf8(text)
        }
    }

    @Test
    fun onlyPostsToTheCachingEndpointsAreGivenTheSecret() {
        val eligible = listOf(
            "/v1/chat/completions", "/v1/completions", "/v1/responses", "/chat/completions", "/completions", "/responses",
            "/proxy/prefix/v1/responses", "/v1/chat%2Fcompletions", "/v1/respon%73es", "/v1/responses?x=/v1/embeddings",
            "/v1/embeddings/responses",
        )
        for (path in eligible) {
            val sent = provision(post(path, "{}".toRequestBody(json)))
            assertEquals("""{"user_cache_secret":"s3cret"}""", sent.text(), path)
        }
        val others = listOf(
            "/v1/embeddings", "/v1/chat/completions/", "/v1/responses/resp_1", "/v1/completionsx", "/v1/models",
            "/", "/v1/audio/speech", "/v1/Responses", "/v1/embeddings?x=/v1/responses", "/v1/responses%2F",
        )
        for (path in others) {
            val request = post(path, "{}".toRequestBody(json))
            assertSame(request, provision(request), path)
        }
        for (method in listOf("PUT", "PATCH", "DELETE", "post", "Post")) {
            val request = post("/v1/responses", "{}".toRequestBody(json), method)
            assertSame(request, provision(request), method)
        }
        val get = Request.Builder().url("https://router.example/v1/responses").build()
        assertSame(get, provision(get))
    }

    @Test
    fun theNewBodyKeepsTheTypeAndDeclaresItsOwnLength() {
        val request = post("/v1/responses", """{"a":1}""".toRequestBody(json)).newBuilder()
            .header("Authorization", "Bearer key")
            .tag(String::class.java, "tagged")
            .build()

        val sent = provision(request)

        assertNotSame(request, sent)
        assertEquals(json, sent.body!!.contentType())
        assertEquals("""{"a":1,"user_cache_secret":"s3cret"}""".length.toLong(), sent.body!!.contentLength())
        assertFalse(sent.body!!.isOneShot())
        assertFalse(sent.body!!.isDuplex())
        assertEquals("Bearer key", sent.header("Authorization"))
        assertEquals("tagged", sent.tag(String::class.java))
        assertEquals(request.url, sent.url)
        assertEquals(sent.text(), sent.text(), "it can be written again")
        assertEquals("""{"a":1}""", request.text(), "the caller's request is as it was")
        assertFalse(sent.toString().contains("s3cret"), sent.toString())
    }

    @Test
    fun aBodyThatIsLeftAloneIsTheCallersOwn() {
        for (text in listOf("not json", "[]", """{"user_cache_secret":"mine"}""", """{"user_cache_secret":"","user_cache_secret":""}""", "")) {
            val body = CountingBody(text)
            val request = post("/v1/responses", body)

            assertSame(request, provision(request), text)
            assertEquals(1, body.writes.get(), "read once to decide")
        }
    }

    @Test
    fun aBodyWithoutADeclaredLengthIsReadUpToTheBound() {
        val bounded = UserCacheSecret.of("s3cret", maxBodyBytes = 32)!!
        val fits = CountingBody("""{"a":"${"x".repeat(24)}"}""", declared = null)
        val tooLong = CountingBody("""{"a":"${"x".repeat(25)}"}""", declared = null)
        val huge = CountingBody("""{"a":"${"x".repeat(1 shl 20)}"}""", declared = null)

        val sent = provision(post("/v1/responses", fits), bounded)
        assertEquals("""{"a":"${"x".repeat(24)}","user_cache_secret":"s3cret"}""", sent.text())
        assertEquals(sent.text().length.toLong(), sent.body!!.contentLength(), "the new body knows its length")

        for (body in listOf(tooLong, huge)) {
            val request = post("/v1/responses", body)
            assertSame(request, provision(request, bounded), "over the bound, the body is sent as it is")
            assertEquals(1, body.writes.get())
        }
    }

    @Test
    fun aBodyOfManyBuffersIsHeldWhole() {
        val text = """{"a":"${"x".repeat(300_000)}","n":9007199254740993}"""
        for (declared in listOf<Long?>(null, text.length.toLong())) {
            for (oneShot in listOf(false, true).filter { declared != null || !it }) {
                val body = CountingBody(text, declared = declared, oneShot = oneShot)

                val sent = provision(post("/v1/chat/completions", body))

                assertEquals(text.dropLast(1) + ""","user_cache_secret":"s3cret"}""", sent.text())
                assertEquals(1, body.writes.get())
            }
        }
    }

    @Test
    fun aBodyThatDeclaresMoreThanTheBoundIsNeverRead() {
        val bounded = UserCacheSecret.of("s3cret", maxBodyBytes = 32)!!
        val atTheBound = CountingBody("""{"a":"${"x".repeat(24)}"}""")
        val over = CountingBody("""{"a":"${"x".repeat(25)}"}""")
        val overOnce = CountingBody("""{"a":"${"x".repeat(25)}"}""", oneShot = true)

        assertEquals(32, atTheBound.contentLength())
        assertTrue(provision(post("/v1/responses", atTheBound), bounded).text().contains("s3cret"))
        for (body in listOf(over, overOnce)) {
            val request = post("/v1/responses", body)
            assertSame(request, provision(request, bounded))
            assertEquals(0, body.writes.get())
        }
        assertEquals(64L shl 20, UserCacheSecret.MAX_BODY_BYTES)
    }

    @Test
    fun aBodyThatCanBeWrittenOnlyOnceIsWrittenOnceAndStaysThatWay() {
        val body = CountingBody("""{"a":1}""", oneShot = true, type = json)

        val sent = provision(post("/v1/responses", body))

        assertEquals(1, body.writes.get())
        assertTrue(sent.body!!.isOneShot(), "so that it is still never sent twice")
        assertEquals(json, sent.body!!.contentType())
        assertEquals("""{"a":1,"user_cache_secret":"s3cret"}""", sent.text())
        assertEquals(1, body.writes.get(), "sending does not write the caller's body again")

        val plain = CountingBody("not json", oneShot = true, type = json)
        val forwarded = provision(post("/v1/responses", plain))
        assertEquals("not json", forwarded.text())
        assertEquals(8L, forwarded.body!!.contentLength())
        assertTrue(forwarded.body!!.isOneShot())
        assertEquals(1, plain.writes.get())
    }

    @Test
    fun aStreamIsReadOnceAndSentFromMemory() {
        val bounded = UserCacheSecret.of("s3cret", maxBodyBytes = 32)!!
        val stream = CountingBody("""{"a":"${"x".repeat(24)}"}""", declared = null, oneShot = true, type = json)

        val sent = provision(post("/v1/responses", stream), bounded)

        assertEquals("""{"a":"${"x".repeat(24)}","user_cache_secret":"s3cret"}""", sent.text())
        assertTrue(sent.body!!.isOneShot())
        assertEquals(sent.text().length.toLong(), sent.body!!.contentLength())
        assertEquals(json, sent.body!!.contentType())
        assertEquals(1, stream.writes.get())

        val plain = CountingBody("not json", declared = null, oneShot = true)
        val forwarded = provision(post("/v1/responses", plain), bounded)
        assertEquals("not json", forwarded.text())
        assertTrue(forwarded.body!!.isOneShot())
        assertEquals(1, plain.writes.get())
    }

    @Test
    fun aStreamThatIsTooLongToExamineIsRefused() {
        val bounded = UserCacheSecret.of("s3cret", maxBodyBytes = 32)!!
        for (text in listOf("""{"a":"${"x".repeat(25)}"}""", """{"hunter2":"${"x".repeat(1 shl 20)}"}""")) {
            val stream = CountingBody(text, declared = null, oneShot = true)

            val error = assertFailsWith<ConfigurationException> { provision(post("/v1/responses", stream), bounded) }

            assertTrue(error.detail.contains("larger than"), error.detail)
            assertFalse(error.toString().contains("s3cret") || error.toString().contains("hunter2"), error.toString())
            assertEquals(1, stream.writes.get())
        }
        // On a path that takes no secret, a stream is not read at all.
        val elsewhere = CountingBody("x".repeat(100), declared = null, oneShot = true)
        val request = post("/v1/embeddings", elsewhere)
        assertSame(request, provision(request, bounded))
        assertEquals(0, elsewhere.writes.get())
    }

    @Test
    fun aDuplexBodyIsRefusedWhereTheSecretBelongsAndUntouchedElsewhere() {
        for (declared in listOf<Long?>(2L, null)) {
            val duplex = CountingBody("{}", declared = declared, duplex = true)

            val error = assertFailsWith<ConfigurationException> { provision(post("/v1/chat/completions", duplex)) }

            assertTrue(error.detail.contains("duplex"), error.detail)
            assertFalse(error.toString().contains("s3cret"))
            assertEquals(0, duplex.writes.get())

            val elsewhere = post("/v1/realtime", duplex)
            assertSame(elsewhere, provision(elsewhere))
            val get = post("/v1/chat/completions", duplex, method = "PUT")
            assertSame(get, provision(get))
            assertEquals(0, duplex.writes.get())
        }
    }

    @Test
    fun aBodyThatDoesNotWriteWhatItDeclaresIsNotRewritten() {
        for (declared in listOf(1L, 3L, 100L)) {
            val again = CountingBody("{}{}", declared = declared)
            val request = post("/v1/responses", again)
            assertSame(request, provision(request), "the HTTP client reports a body that can be written again")

            val once = CountingBody("{}{}", declared = declared, oneShot = true)
            val error = assertFailsWith<ProtocolException> { provision(post("/v1/responses", once)) }
            assertFalse(error.message!!.contains("s3cret"))
            assertEquals(1, once.writes.get())
        }
    }

    @Test
    fun aBodyThatFailsToWriteFailsTheRequest() {
        val failing = object : RequestBody() {
            override fun contentType(): MediaType? = null

            override fun writeTo(sink: BufferedSink) {
                sink.writeUtf8("{")
                throw IOException("disk on fire")
            }
        }

        val error = assertFailsWith<IOException> { provision(post("/v1/responses", failing)) }

        assertEquals("disk on fire", error.message)
        assertContentEquals("{}".toByteArray(), Buffer().also { "{}".toRequestBody().writeTo(it) }.readByteArray())
    }
}
