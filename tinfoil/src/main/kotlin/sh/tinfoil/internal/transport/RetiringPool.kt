package sh.tinfoil.internal.transport

import okhttp3.ConnectionPool
import okhttp3.MediaType
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.buffer
import sh.tinfoil.internal.Background
import java.util.Collections
import java.util.WeakHashMap

/**
 * The connection pool of one bound transport, which closes its connections
 * once the transport is retired, without cutting off a response that is
 * still being read.
 *
 * The HTTP client takes a connection back as soon as the last byte that a
 * response declares has arrived. Over HTTP/2 the end of the response's
 * stream can arrive later, and closing the connection in between fails the
 * read that waits for it, although the whole body has arrived. So a call is
 * open, here, from when it starts until its response body is read to its
 * end or closed, or the call fails; and the connections of a retired
 * transport are closed only when no call of the transport is open. Once the
 * client is closed, its calls are cancelled, and connections are closed
 * whatever is open.
 */
internal class RetiringPool(private val calls: ActiveCalls) {
    val pool = ConnectionPool()

    private val lock = Any()

    // Held weakly, as ActiveCalls holds them, so that a response that is
    // dropped without being closed does not keep its call here for good.
    // Guarded by lock.
    private val open: MutableSet<Any> = Collections.newSetFromMap(WeakHashMap())

    // Guarded by lock.
    private var retired = false

    /** How many connections are open, in use or kept for later. */
    val connectionCount: Int get() = pool.connectionCount()

    /** Notes that [call] has started. */
    fun opened(call: Any) {
        synchronized(lock) { open.add(call) }
    }

    /**
     * Notes that [call] has ended: its response body was read to its end or
     * closed, or the call failed. It may be called more than once for a
     * call, and from any thread, the caller's included, so connections are
     * closed on a background thread.
     */
    fun ended(call: Any) {
        synchronized(lock) { open.remove(call) }
        if (mayClose()) {
            Background.run {
                // A call may have started since.
                if (mayClose()) {
                    pool.evictAll()
                }
            }
        }
    }

    /**
     * Keeps no connection for later from now on: those that are idle are
     * closed now if no call is open, and otherwise when the last open call
     * ends. It closes sockets, so it is for a background thread.
     */
    fun retire() {
        synchronized(lock) { retired = true }
        if (mayClose()) {
            pool.evictAll()
        }
    }

    /** [response], whose body ends [call] once it has been read to its end or closed. */
    fun endingWithBody(response: Response, call: Any): Response {
        val body = response.body ?: return response.also { ended(call) }
        return response.newBuilder().body(EndingBody(body) { ended(call) }).build()
    }

    private fun mayClose(): Boolean = calls.isClosed || synchronized(lock) { retired && open.isEmpty() }
}

/** [body], which calls [onEnd] when it has been read to its end or closed. */
private class EndingBody(private val body: ResponseBody, onEnd: () -> Unit) : ResponseBody() {
    private val source: BufferedSource = object : ForwardingSource(body.source()) {
        override fun read(sink: Buffer, byteCount: Long): Long {
            val read = super.read(sink, byteCount)
            if (read == -1L) {
                onEnd()
            }
            return read
        }

        override fun close() {
            try {
                super.close()
            } finally {
                onEnd()
            }
        }
    }.buffer()

    override fun contentType(): MediaType? = body.contentType()

    override fun contentLength(): Long = body.contentLength()

    override fun source(): BufferedSource = source
}
