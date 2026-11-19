package sh.tinfoil

import okhttp3.Request
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The README's examples of this module, kept here so that they compile
 * against the API as it is. They are not run: each would verify a production
 * enclave. Change the README and this file together.
 */
@Suppress("unused")
class DocumentationExamplesTest {
    private suspend fun httpClient(apiKey: String) {
        val client = EnclaveHttpClient.create(
            enclave = "inference.tinfoil.sh",
            pin = Pin(repo = "tinfoilsh/confidential-model-router"),
        )

        val request = Request.Builder()
            .url(client.baseUrl.resolve("v1/models")!!)
            .header("Authorization", "Bearer $apiKey")
            .build()
        client.execute(request).use { response -> println(response.body!!.string()) }

        client.close()
    }

    private suspend fun sealedBodies(): EnclaveHttpClient {
        val client = EnclaveHttpClient.create(
            enclave = "inference.tinfoil.sh",
            pin = Pin(repo = "tinfoilsh/confidential-model-router"),
        ) {
            transportMode = TransportMode.EHBP
            baseUrl = "https://proxy.example.com/"
        }
        return client
    }

    @Test
    fun theExamplesNameTheTransportModeThatTheyAskFor() {
        assertEquals("EHBP", TransportMode.EHBP.name)
    }
}
