package sh.tinfoil.internal.transport

import okhttp3.MediaType
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.buffer
import java.net.ProtocolException

/**
 * This response, which the sealing client has opened, with a body that has
 * to prove that something was sealed, where the sealing client does not ask
 * for that proof itself. A response without a body is returned as it is.
 *
 * The header that marks a response as sealed proves nothing by itself: it
 * is not sealed, any 32 bytes pass for its value, and a body without a
 * sealed piece leaves nothing to check it against.
 *
 * Below a status of 400 the sealing client asks for the proof: it fails a
 * body in which no piece authenticates, and a piece that seals no bytes
 * counts, so an empty response that the enclave sealed is read as empty.
 * Such a response is returned as it is.
 *
 * From 400 on the sealing client accepts a body without any piece, because
 * the protocol lets an error pass that is not sealed at all. But an error
 * that is marked as sealed is presented as the enclave's, and one that is
 * not is presented as nobody's, so the mark has to be proven there too.
 * The sealing client does not say whether a piece authenticated, so the
 * body has to yield at least one byte, which is released only once the
 * piece that carries it has authenticated; a body that ends before that
 * fails the read. A sealed error with an empty body is refused with it.
 *
 * This shows that the response is the enclave's and how it begins. It does
 * not show that the response is whole: a sealed body carries no mark of its
 * end, so one that is cut off between two pieces ends like one that was
 * finished.
 */
internal fun Response.proven(): Response {
    val sealed = body
    if (code < FIRST_ERROR_STATUS || sealed == null) {
        return this
    }
    return newBuilder().body(ProvenBody(sealed)).build()
}

private const val FIRST_ERROR_STATUS = 400

private class ProvenBody(private val sealed: ResponseBody) : ResponseBody() {
    private val source: BufferedSource = object : ForwardingSource(sealed.source()) {
        private var proven = false

        override fun read(sink: Buffer, byteCount: Long): Long {
            val read = super.read(sink, byteCount)
            if (read > 0) {
                proven = true
            } else if (read == -1L && !proven) {
                throw ProtocolException("FRAMING_TRUNCATED: the response ended before any of it authenticated")
            }
            return read
        }
    }.buffer()

    override fun contentType(): MediaType? = sealed.contentType()

    override fun contentLength(): Long = -1L

    override fun source(): BufferedSource = source
}
