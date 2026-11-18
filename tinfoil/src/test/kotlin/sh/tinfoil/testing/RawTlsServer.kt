package sh.tinfoil.testing

import okhttp3.tls.HeldCertificate
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

/**
 * A TLS server that hands each connection to [serve] once its handshake has
 * completed, so that a test sees exactly what a client wrote to it.
 */
internal class RawTlsServer(
    certificate: HeldCertificate,
    private val serve: RawTlsServer.(SSLSocket) -> Unit,
) : AutoCloseable {
    private val listener = certificate.serverHandshake().sslContext().serverSocketFactory
        .createServerSocket(0, 50, InetAddress.getByName("localhost")) as SSLServerSocket

    val port: Int = listener.localPort

    /** Connections whose TLS handshake completed. */
    val handshakes = AtomicInteger()

    /** Connections that have ended. */
    val finished = AtomicInteger()

    /** Bytes of application data that clients sent. */
    val bytesReceived = AtomicLong()

    /** Bytes of application data that the server managed to write. */
    val bytesSent = AtomicLong()

    init {
        thread(isDaemon = true) {
            while (true) {
                val socket = try {
                    listener.accept() as SSLSocket
                } catch (_: IOException) {
                    return@thread
                }
                thread(isDaemon = true) {
                    try {
                        socket.startHandshake()
                        handshakes.incrementAndGet()
                        serve(socket)
                    } catch (_: IOException) {
                        // The client went away.
                    } finally {
                        try {
                            socket.close()
                        } catch (_: IOException) {
                        }
                        finished.incrementAndGet()
                    }
                }
            }
        }
    }

    /** Reads whatever the client sends until it closes or goes quiet, counting it. */
    fun countWhatArrives(socket: SSLSocket) {
        socket.soTimeout = 2_000
        val buffer = ByteArray(4096)
        while (true) {
            val read = socket.inputStream.read(buffer)
            if (read < 0) {
                return
            }
            bytesReceived.addAndGet(read.toLong())
        }
    }

    override fun close() {
        listener.close()
    }
}

/** Waits until [condition] holds, failing after [timeoutMillis]. */
internal fun awaitUntil(timeoutMillis: Long = 10_000, condition: () -> Boolean) {
    val deadline = System.nanoTime() + timeoutMillis * 1_000_000
    while (!condition()) {
        check(System.nanoTime() < deadline) { "condition not met within $timeoutMillis ms" }
        Thread.sleep(10)
    }
}
