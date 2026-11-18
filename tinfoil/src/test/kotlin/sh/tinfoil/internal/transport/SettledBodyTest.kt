package sh.tinfoil.internal.transport

import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer
import okio.BufferedSink
import java.net.ProtocolException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SettledBodyTest {
    /** A body whose every answer about itself changes each time it is asked. */
    private class Shifting(private val text: String) : RequestBody() {
        private val types = AtomicInteger()
        private val lengths = AtomicInteger()
        private val shots = AtomicInteger()

        override fun contentType(): MediaType? = (if (types.getAndIncrement() == 0) "text/plain" else "application/json").toMediaType()

        override fun contentLength(): Long = if (lengths.getAndIncrement() == 0) 0L else text.length.toLong()

        override fun isOneShot(): Boolean = shots.getAndIncrement() > 0

        override fun writeTo(sink: BufferedSink) {
            sink.writeUtf8(text)
        }
    }

    private fun post(body: RequestBody?): Request =
        Request.Builder().url("https://enclave.example/v1/echo").method(if (body == null) "GET" else "POST", body).build()

    @Test
    fun whatABodySaysAboutItselfIsAskedOnce() {
        val settled = SettledBody.settle(post(Shifting("unsealed!"))).body!!

        repeat(5) {
            assertEquals("text/plain".toMediaType(), settled.contentType())
            assertEquals(0L, settled.contentLength())
            assertEquals(false, settled.isOneShot())
        }
        assertFailsWith<ProtocolException> { settled.writeTo(Buffer()) }
    }

    @Test
    fun aBodyThatWritesAnotherLengthThanItDeclaredFailsTheWrite() {
        for ((declared, text) in listOf(0L to "x", 3L to "abcd", 3L to "ab", 3L to "")) {
            val lying = object : RequestBody() {
                override fun contentType(): MediaType? = null

                override fun contentLength(): Long = declared

                override fun writeTo(sink: BufferedSink) {
                    sink.writeUtf8(text)
                }
            }
            val sink = Buffer()
            assertFailsWith<ProtocolException>("$declared, $text") { SettledBody.settle(post(lying)).body!!.writeTo(sink) }
            assertTrue(sink.size <= declared, "no more than was declared is passed on")
        }
    }

    @Test
    fun anHonestBodyIsWrittenAsItIs() {
        val text = "x".repeat(100_000)
        for (declared in listOf(text.length.toLong(), -1L)) {
            val body = object : RequestBody() {
                override fun contentType(): MediaType? = null

                override fun contentLength(): Long = declared

                override fun writeTo(sink: BufferedSink) {
                    text.chunked(7_000).forEach(sink::writeUtf8)
                }
            }
            val settled = SettledBody.settle(post(body)).body!!
            assertEquals(declared, settled.contentLength())
            assertEquals(text, Buffer().also(settled::writeTo).readUtf8())
        }
    }

    @Test
    fun aRequestWithoutABodyOrWithOneThatIsSettledIsReturnedAsItIs() {
        val bodyless = post(null)
        assertSame(bodyless, SettledBody.settle(bodyless))
        assertNull(SettledBody.settle(bodyless).body)
        val once = SettledBody.settle(post("{}".toRequestBody()))
        assertSame(once, SettledBody.settle(once))
        val held = post(HeldBody("{}".toByteArray(), emptyList(), null, false))
        assertSame(held, SettledBody.settle(held))
    }
}
