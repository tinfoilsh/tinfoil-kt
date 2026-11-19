package sh.tinfoil.openai

import com.openai.core.http.AsyncStreamResponse
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.channels.trySendBlocking
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flowOn
import sh.tinfoil.internal.Background
import java.util.Optional
import java.util.concurrent.CompletionException

/**
 * This streamed response as a [Flow] of its events, such as the chunks of a
 * chat completion:
 *
 * ```kotlin
 * client.openAIAsync.chat().completions().createStreaming(params).asFlow().collect { chunk ->
 *     chunk.choices().forEach { choice -> choice.delta().content().ifPresent(::print) }
 * }
 * ```
 *
 * Events are delivered as they arrive, and the response is read only as fast
 * as the flow is collected. The flow is safe to collect on the main thread:
 * the events are handed to the collector there, and the response is read
 * and closed on background threads. When the collector stops, because it is
 * cancelled, fails or takes only the first events, the response is closed
 * and its request is cancelled; if the response has not started by then, it
 * is closed as soon as it does. A failure of the stream is thrown to the
 * collector as the OpenAI SDK reports it.
 *
 * The flow can be collected once: a response is one exchange, and
 * collecting again fails with an [IllegalStateException]. A response that is
 * never collected must be [closed][AsyncStreamResponse.close].
 */
public fun <T : Any> AsyncStreamResponse<T>.asFlow(): Flow<T> = callbackFlow {
    subscribe(
        object : AsyncStreamResponse.Handler<T> {
            override fun onNext(value: T) {
                // This is the OpenAI SDK's stream thread, which waits here
                // for the collector; throwing ends its reading.
                if (trySendBlocking(value).isFailure) {
                    throw CancellationException("the stream's collector has stopped")
                }
            }

            override fun onComplete(error: Optional<Throwable>) {
                val failure = error.orElse(null)
                close((failure as? CompletionException)?.cause ?: failure)
            }
        },
    )
    awaitClose { this@asFlow.close() }
    // Closing a response that is still open closes its connection, which
    // the collector's thread may not be allowed to do; so the subscription
    // and the closing run on a background thread, and only the events are
    // handed to the collector.
}.buffer(Channel.RENDEZVOUS).flowOn(Background.dispatcher)
