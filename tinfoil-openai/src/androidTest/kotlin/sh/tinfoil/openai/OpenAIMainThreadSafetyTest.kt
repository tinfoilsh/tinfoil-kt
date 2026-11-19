package sh.tinfoil.openai

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import sh.tinfoil.TransportMode
import sh.tinfoil.testing.MainThread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Uses the OpenAI clients from Android's main thread, as an app does that
 * creates one in a coroutine on `Dispatchers.Main` and closes it in a
 * lifecycle callback. The platform refuses network work on that thread, the
 * closing of a TLS socket included, so nothing that a client does there may
 * reach a socket.
 *
 * The test reaches production, so it runs only when the instrumentation
 * argument `tinfoilIntegration` is `true`.
 */
@RunWith(AndroidJUnit4::class)
class OpenAIMainThreadSafetyTest {
    private val main = MainThread(InstrumentationRegistry.getInstrumentation())

    private fun requireLive() {
        val enabled = InstrumentationRegistry.getArguments().getString("tinfoilIntegration")
        assumeTrue("live tests run only with the instrumentation argument tinfoilIntegration=true", enabled == "true")
    }

    private fun onMain(block: () -> Unit) = main.onMain(block)

    private fun <T> fromMain(block: suspend () -> T): T = main.fromMain(block)

    @Test
    fun theOpenAIClientsAreCreatedAndClosedOnTheMainThread() {
        requireLive()
        val client = fromMain { Client.create("none") }
        val listed = runBlocking { withContext(Dispatchers.IO) { client.openAI.models().list().data().size } }
        assertTrue(listed > 0)
        onMain { client.close() }

        val sealed = fromMain { RouterOpenAIClient.create("none") { transportMode = TransportMode.EHBP } }
        val models = Request.Builder().url(sealed.httpClient.baseUrl.resolve("v1/models")!!).build()
        assertEquals(200, main.answerTo(sealed.httpClient::execute, models).first)
        onMain { sealed.close() }
    }
}
