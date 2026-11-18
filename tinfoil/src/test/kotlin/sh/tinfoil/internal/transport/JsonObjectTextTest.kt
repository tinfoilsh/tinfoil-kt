package sh.tinfoil.internal.transport

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The scanner's reading of members, elements and strings, by their place in a text. */
class JsonObjectTextTest {
    private fun members(text: String): List<Pair<String, String>>? {
        val bytes = text.toByteArray()
        val found = ArrayList<Pair<String, String>>()
        val closing = JsonObjectText.members(bytes) { nameStart, nameEnd, valueStart, valueEnd ->
            found += String(bytes, nameStart, nameEnd - nameStart) to String(bytes, valueStart, valueEnd - valueStart)
        }
        return if (closing < 0) null else found.also { assertEquals('}', text.toByteArray()[closing].toInt().toChar()) }
    }

    private fun elements(text: String): List<String>? {
        val bytes = text.toByteArray()
        val found = ArrayList<String>()
        return if (JsonObjectText.elements(bytes, 0, bytes.size) { start, end -> found += String(bytes, start, end - start) }) found else null
    }

    private fun string(text: String): String? = text.toByteArray().let { JsonObjectText.string(it, 0, it.size) }

    @Test
    fun membersAreReportedInOrderWithTheirTextAsWritten() {
        assertEquals(
            listOf("\"a\"" to "1", "\"b\\u0062\"" to "[ 1, {\"a\":2} ]", "\"a\"" to "{\"x\" : null}", "\"\"" to "\"s\""),
            members(" { \"a\" : 1 ,\"b\\u0062\":[ 1, {\"a\":2} ] , \"a\":{\"x\" : null},\"\":\"s\"}\n"),
        )
        assertEquals(emptyList(), members("{}"))
        for (text in listOf("", "[]", "{", "{\"a\":1,}", "{\"a\":1} x", "{\"a\"}", "{a:1}", "{\"a\":01}", "null")) {
            assertNull(members(text), text)
        }
    }

    @Test
    fun aRangeOfATextIsReadAsATextOfItsOwn() {
        val bytes = "{\"outer\":{\"a\":[1,2],\"b\":\"x\"},\"z\":0}".toByteArray()
        var start = -1
        var end = -1
        JsonObjectText.members(bytes) { nameStart, nameEnd, valueStart, valueEnd ->
            if (JsonObjectText.isName(bytes, nameStart, nameEnd, "outer")) {
                start = valueStart
                end = valueEnd
            }
        }
        val inner = ArrayList<String>()
        assertTrue(JsonObjectText.members(bytes, start, end) { _, _, valueStart, valueEnd -> inner += String(bytes, valueStart, valueEnd - valueStart) } >= 0)
        assertEquals(listOf("[1,2]", "\"x\""), inner)
        // A range that ends early, or runs on, is not one object.
        assertEquals(-1, JsonObjectText.members(bytes, start, end - 1) { _, _, _, _ -> })
        assertEquals(-1, JsonObjectText.members(bytes, start, end + 1) { _, _, _, _ -> })
    }

    @Test
    fun elementsAreReportedInOrderWithTheirTextAsWritten() {
        assertEquals(listOf("1", "\"a,b\"", "[2, [3]]", "{\"k\":[]}", "null"), elements(" [1 , \"a,b\",[2, [3]] ,{\"k\":[]},null ] "))
        assertEquals(emptyList(), elements("[]"))
        assertEquals(emptyList(), elements(" [ ] "))
        for (text in listOf("", "{}", "[", "[1,]", "[,1]", "[1 2]", "[1]]", "[1] x", "\"[1]\"")) {
            assertNull(elements(text), text)
        }
        assertEquals(1, elements("[" + "[".repeat(JsonObjectText.MAX_DEPTH - 2) + "]".repeat(JsonObjectText.MAX_DEPTH - 2) + "]")!!.size)
        assertNull(elements("[".repeat(JsonObjectText.MAX_DEPTH + 1) + "]".repeat(JsonObjectText.MAX_DEPTH + 1)))
    }

    @Test
    fun stringsAreDecoded() {
        assertEquals("", string("\"\""))
        assertEquals("a\"b\\c/d\b\u000c\n\r\te", string("\"a\\\"b\\\\c\\/d\\b\\f\\n\\r\\te\""))
        assertEquals("\u00e9\u4e2d\ud83d\ude00", string("\"\\u00e9\\u4E2D\\ud83d\\uDE00\""))
        assertEquals("\u00e9\u4e2d\ud83d\ude00", string("\"\u00e9\u4e2d\ud83d\ude00\""))
        assertEquals("a\\\\u0041", string("\"a\\\\\\\\u0041\""), "an escaped backslash escapes nothing")
        for (text in listOf("", "\"", "\"a", "a", "\"a\" ", " \"a\"", "\"a\"b\"", "\"\\x\"", "\"\\u12\"", "\"\\u12G4\"", "7", "null", "\"a\nb\"")) {
            assertNull(string(text), text)
        }
    }

    @Test
    fun halfOfASurrogatePairDecodesToTheReplacementCharacter() {
        val replacement = "\ufffd"
        assertEquals("${replacement}x", string("\"\\ud800x\""))
        assertEquals(replacement, string("\"\\ud800\""))
        assertEquals(replacement, string("\"\\udc00\""))
        assertEquals("$replacement$replacement", string("\"\\ude00\\ud83d\""))
        assertEquals("${replacement}A", string("\"\\ud83d\\u0041\""))
        assertEquals("${replacement}A", string("\"\\ud83dA\""))
        assertEquals("$replacement\ud83d\ude00", string("\"\\ud83d\\ud83d\\ude00\""))
        assertEquals("$replacement\n", string("\"\\ud83d\\n\""), "an escape that is not a code unit follows")
    }

    @Test
    fun namesAreComparedDecoded() {
        val bytes = "{\"m\\u006fdel\":1,\"model \":2,\"Model\":3,\"mode\":4,\"modell\":5,\"\\u006d\\u006F\\u0064\\u0065\\u006c\":6}".toByteArray()
        val named = ArrayList<Boolean>()
        JsonObjectText.members(bytes) { nameStart, nameEnd, _, _ -> named += JsonObjectText.isName(bytes, nameStart, nameEnd, "model") }
        assertEquals(listOf(true, false, false, false, false, true), named)
        assertFalse(JsonObjectText.isName("\"\"".toByteArray(), 0, 2, "model"))
    }
}
