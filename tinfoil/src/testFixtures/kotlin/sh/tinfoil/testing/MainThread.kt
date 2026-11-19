package sh.tinfoil.testing

import android.app.Instrumentation
import android.os.Looper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.Request
import okhttp3.Response
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration.Companion.seconds

/**
 * Android's main thread, for the instrumented tests that use a client from
 * it as an app does.
 */
public class MainThread(private val instrumentation: Instrumentation) {
    /** Runs [block] on the main thread, and throws here what it throws there. */
    public fun onMain(block: () -> Unit) {
        val failure = AtomicReference<Throwable>()
        instrumentation.runOnMainSync {
            check(Looper.getMainLooper().isCurrentThread)
            try {
                block()
            } catch (e: Throwable) {
                failure.set(e)
            }
        }
        failure.get()?.let { throw it }
    }

    /** Runs [block] in a coroutine on `Dispatchers.Main`, as an app's own coroutines run. */
    public fun <T> fromMain(block: suspend () -> T): T = runBlocking {
        withTimeout(180.seconds) {
            withContext(Dispatchers.Main) {
                check(Looper.getMainLooper().isCurrentThread)
                block()
            }
        }
    }

    /** Sends [request] from the main dispatcher, and reads the answer where an app may: off the main thread. */
    public fun answerTo(send: suspend (Request) -> Response, request: Request): Pair<Int, String> = fromMain {
        val response = send(request)
        withContext(Dispatchers.IO) { response.use { it.code to it.body!!.string() } }
    }
}
