package sh.tinfoil.internal.transport

import okhttp3.MediaType
import okhttp3.Request
import okhttp3.RequestBody
import okio.Buffer
import okio.BufferedSink
import okio.ForwardingSink
import okio.buffer
import java.net.ProtocolException

/**
 * A caller's request body, with what it says about itself asked once.
 *
 * A request is judged by what its body declares: whether the body is empty
 * decides whether it is sealed, and its length and type decide whether it is
 * read to be given a cache scope. The HTTP client asks the same questions
 * again when it sends the body. A body may answer differently each time, as
 * one does that is backed by a file that grows, and then what was judged is
 * not what is sent. So each answer is taken once and repeated from then on,
 * and a body that writes another number of bytes than the length that it
 * declared fails the write, before the bytes beyond that length are passed
 * on.
 */
internal class SettledBody private constructor(private val body: RequestBody) : RequestBody() {
    private val type: MediaType? = body.contentType()
    private val oneShot: Boolean = body.isOneShot()
    private val duplex: Boolean = body.isDuplex()

    // Asked when it is first needed, on the thread that needs it: a body
    // may read its length from a file.
    private val length: Long by lazy { body.contentLength() }

    override fun contentType(): MediaType? = type

    override fun contentLength(): Long = length

    override fun isOneShot(): Boolean = oneShot

    override fun isDuplex(): Boolean = duplex

    override fun writeTo(sink: BufferedSink) {
        val declared = length
        // A duplex body goes on writing after this returns, so it cannot
        // be counted here; the clients that judge bodies refuse it.
        if (declared < 0 || duplex) {
            body.writeTo(sink)
            return
        }
        val counted = Counted(sink, declared)
        val buffered = counted.buffer()
        body.writeTo(buffered)
        buffered.emit()
        if (counted.written != declared) {
            throw ProtocolException("the request body declared $declared bytes and wrote ${counted.written}")
        }
    }

    /** Passes on at most [limit] bytes, and fails the write that would pass more. */
    private class Counted(sink: BufferedSink, private val limit: Long) : ForwardingSink(sink) {
        var written = 0L
            private set

        override fun write(source: Buffer, byteCount: Long) {
            if (byteCount > limit - written) {
                throw ProtocolException("the request body wrote more than the $limit bytes that it declared")
            }
            super.write(source, byteCount)
            written += byteCount
        }
    }

    internal companion object {
        /**
         * [request] with a body that answers for itself once. A request
         * without a body, or with one that this SDK made, is returned as it
         * is.
         */
        fun settle(request: Request): Request {
            val body = request.body
            if (body == null || body is SettledBody || body is HeldBody) {
                return request
            }
            return request.newBuilder().method(request.method, SettledBody(body)).build()
        }
    }
}
