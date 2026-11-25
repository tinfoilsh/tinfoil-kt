package sh.tinfoil

import okhttp3.Request
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.days

/**
 * The examples of this module in the README and in `docs/`, kept here so
 * that they compile against the API as it is. They are not run: each would
 * verify a production enclave. Change the documentation and this file
 * together.
 */
@Suppress("unused")
class DocumentationExamplesTest {
    private suspend fun httpClient(apiKey: String) {
        val client = EnclaveHttpClient.create(
            enclave = "inference.tinfoil.sh",
            trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
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
            trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
        ) {
            transport = Transport.Ehbp(proxyUrl = "https://proxy.example.com/")
        }
        return client
    }

    private suspend fun trustAndPolicy(freshnessKeyPem: String): EnclaveHttpClient {
        val client = EnclaveHttpClient.create("enclave.example.com", Trust.ProjectPin("org/project")) {
            policy = Policy(
                freshnessMaxAge = 1.days,
                artifacts = ArtifactTrust.EndorsedArtifacts(freshnessKeys = listOf(freshnessKeyPem)),
            )
        }
        return client
    }

    private suspend fun relays(): RouterHttpClient {
        val client = RouterHttpClient.create {
            transport = Transport.Ehbp(proxyUrl = "https://app.example/tinfoil/proxy")
            fetchAttestation = AttestationRelay("https://app.example/tinfoil")
            fetchRouterList = RouterListRelay("https://app.example/tinfoil")
        }
        return client
    }

    private suspend fun verificationReports(): EnclaveHttpClient {
        val client = EnclaveHttpClient.create("enclave.example.com", Trust.RepoPin("org/repo")) {
            onVerificationAttempt = { host, attempt ->
                when (attempt) {
                    is VerificationAttempt.Passed ->
                        println("$host runs ${attempt.report.verifiedFacts?.codeDigest}")
                    is VerificationAttempt.Failed -> {
                        val report = (attempt.error.cause as? VerificationException)?.report
                        println("$host failed at ${report?.failedStep?.layer}: ${attempt.error.detail}")
                    }
                }
            }
        }
        return client
    }

    private suspend fun reportsAsJson(): EnclaveHttpClient {
        val client = EnclaveHttpClient.create("enclave.example.com", Trust.RepoPin("org/repo")) {
            onVerificationAttempt = { _, attempt ->
                val report = attempt.report ?: (attempt.error?.cause as? VerificationException)?.report
                report?.let { println(it.toJson()) }
            }
        }
        return client
    }

    @Test
    fun theExamplesNameTheTransportThatTheyAskFor() {
        assertEquals(Transport.Ehbp("https://proxy.example.com/"), Transport.Ehbp(proxyUrl = "https://proxy.example.com/"))
    }
}
