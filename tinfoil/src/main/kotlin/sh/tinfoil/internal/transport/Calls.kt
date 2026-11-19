package sh.tinfoil.internal.transport

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Response
import sh.tinfoil.internal.Background
import java.io.IOException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Sends this call and returns its response once the headers arrive, with the
 * body still to be read. Cancelling the coroutine while it waits cancels the
 * call; a response that arrives for a coroutine that is already cancelled is
 * closed. The call is cancelled on a background thread, since cancelling
 * closes its socket and the coroutine may be cancelled from any thread.
 */
internal suspend fun Call.await(): Response = suspendCancellableCoroutine { continuation ->
    continuation.invokeOnCancellation { Background.run { cancel() } }
    enqueue(
        object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                continuation.resume(response) { _, unclaimed, _ -> Background.run { unclaimed.closeQuietly() } }
            }
        },
    )
}

/**
 * Sends this call and returns what [read] makes of its response, which is
 * closed afterwards. [read] runs on the HTTP client's thread and may block
 * on the body; cancelling the coroutine cancels the call, which ends a read
 * in progress.
 */
internal suspend fun <T> Call.awaitAndRead(read: (Response) -> T): T = suspendCancellableCoroutine { continuation ->
    continuation.invokeOnCancellation { Background.run { cancel() } }
    enqueue(
        object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                val result = try {
                    response.use(read)
                } catch (e: Exception) {
                    continuation.resumeWithException(e)
                    return
                }
                continuation.resume(result)
            }
        },
    )
}

internal fun Response.closeQuietly() {
    try {
        close()
    } catch (_: Exception) {
        // Nothing can be done for a response that will not close.
    }
}
