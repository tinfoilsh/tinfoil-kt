package sh.tinfoil.internal.transport

import okhttp3.MediaType
import okhttp3.RequestBody
import okio.Buffer
import okio.BufferedSink
import okio.Sink
import okio.Timeout
import okio.buffer
import java.io.IOException

/** Bytes to put in place of the range from [start] to [end] of a text. */
internal class Splice(val start: Int, val end: Int, val replacement: ByteArray) {
    fun applyTo(text: ByteArray): ByteArray =
        text.copyOfRange(0, start) + replacement + text.copyOfRange(end, text.size)
}

/**
 * A request body that was read into memory, written with [splices] applied.
 * The splices are in the order of the text and do not overlap; the text
 * itself is held once and never copied.
 */
internal class HeldBody(
    private val text: ByteArray,
    private val splices: List<Splice>,
    private val type: MediaType?,
    private val oneShot: Boolean,
) : RequestBody() {
    override fun contentType(): MediaType? = type

    override fun contentLength(): Long =
        text.size.toLong() + splices.sumOf { it.replacement.size - (it.end - it.start) }

    override fun isOneShot(): Boolean = oneShot

    override fun writeTo(sink: BufferedSink) {
        var written = 0
        for (splice in splices) {
            sink.write(text, written, splice.start - written)
            sink.write(splice.replacement)
            written = splice.end
        }
        sink.write(text, written, text.size - written)
    }

    internal companion object {
        private const val INITIAL_ROOM = 8 * 1024
        private const val MAX_CAUSE_DEPTH = 8

        /**
         * What [body] writes, or null if that is more than [limit] bytes or
         * than the [declared] length, which is negative when the body
         * declares none. The body is written once, here.
         *
         * @throws IOException if the body fails to write itself.
         */
        @Throws(IOException::class)
        fun read(body: RequestBody, declared: Long, limit: Long): ByteArray? {
            // A body that says how long it is gets exactly that much room, so
            // that it is held once and not copied.
            val held = if (declared >= 0) Held(declared.toInt(), declared.toInt()) else Held(INITIAL_ROOM, limit.toInt())
            val sink = held.buffer()
            try {
                body.writeTo(sink)
                sink.flush()
                return held.bytes()
            } catch (e: IOException) {
                if (e.isOverLimit()) {
                    return null
                }
                throw e
            }
        }

        private fun IOException.isOverLimit(): Boolean =
            generateSequence<Throwable>(this) { it.cause }.take(MAX_CAUSE_DEPTH).any { it is OverLimit }
    }

    /**
     * Keeps what is written to it, up to [limit] bytes, and fails the write
     * that would pass that and every write after it: a body that goes on
     * writing after a failure that it swallowed must not leave a text that
     * lacks what the failed write carried. Once a write has failed, there
     * is no text to take.
     */
    private class Held(room: Int, private val limit: Int) : Sink {
        private var bytes = ByteArray(minOf(room, limit))
        private var size = 0
        private var failed = false

        override fun write(source: Buffer, byteCount: Long) {
            if (failed || byteCount > limit - size) {
                failed = true
                throw OverLimit()
            }
            val count = byteCount.toInt()
            if (count > bytes.size - size) {
                bytes = bytes.copyOf(minOf(limit.toLong(), maxOf(2L * bytes.size, size.toLong() + count)).toInt())
            }
            var copied = 0
            while (copied < count) {
                val read = source.read(bytes, size + copied, count - copied)
                if (read == -1) {
                    throw java.io.EOFException()
                }
                copied += read
            }
            size += count
        }

        @Throws(IOException::class)
        fun bytes(): ByteArray {
            if (failed) {
                throw OverLimit()
            }
            return if (size == bytes.size) bytes else bytes.copyOf(size)
        }

        override fun flush() = Unit

        override fun timeout(): Timeout = Timeout.NONE

        override fun close() = Unit
    }

    private class OverLimit : IOException("the request body is larger than is read")
}
