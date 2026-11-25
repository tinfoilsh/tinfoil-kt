# Verification

## What is trusted

An enclave that you name is verified under a trust argument, which names
who vouches for the config that it runs. It is one of the variants of
`Trust`:

| Variant | Accepts |
|---|---|
| `Trust.RepoPin(repo)` | v2 collateral for a GitHub repository, `owner/name[@tag][@sha256:digest]` |
| `Trust.ProjectPin(project, registryIds)` | v3 collateral for a config registry project, `org/project[@revision][@sha256:digest]`, endorsed by the public registry (`registryIds = null`) or by exactly the registries listed; an empty list is refused |
| `Trust.SignedBy(keys, project)` | v3 configs whose endorsements your keys sign, optionally only those of one project |
| `Trust.AuthorizedBy(authorize)` | v3 configs that your `ConfigAuthorizer` approves |
| `Trust.EmbeddedConfig(bytes, name)` | v3 collateral for exactly the JSON config bytes that you supply |
| `Trust.EitherPin(repo, project)` | either of the first two, for the migration from v2 to v3 collateral |

The router's trust is fixed to its repository, and the gateway's to the
repository of each model. Every client also takes a `policy`, which is plain
data: register pins, the freshness bound, and who vouches for the runtime
and platform artifacts, Tinfoil's endorsements or your own:

```kotlin
val client = EnclaveHttpClient.create("enclave.example.com", Trust.ProjectPin("org/project")) {
    policy = Policy(
        freshnessMaxAge = 1.days,
        artifacts = ArtifactTrust.EndorsedArtifacts(freshnessKeys = listOf(freshnessKeyPem)),
    )
}
```

A client checks its trust argument and its policy before any network I/O,
and refuses one that no verification could pass with a
`ConfigurationException`.

## Verification reports

Every verification that a client runs is an attempt, and each attempt that
reached the verifier has a `VerificationReport`: one step for each layer of
the verifier (`envelope`, `provenance`, `quote`, `policy`), each `passed`,
`failed`, `skipped` or `not_run`, and the facts that it established. A
report that passed has `verifiedFacts`, which hold the keys that the client
binds its connections to. When the verifier rejects a document, the client
throws an `AttestationException` whose cause is a `VerificationException`,
and its report has the step that failed and `partialFacts`: the expected
and measured values that the steps before the failure established, side by
side. The key fingerprints in partial facts are the document's claim alone,
never verified. A failed fetch is a `NetworkException`, and has no report.

The clients keep the verification that their requests are sent under apart
from the attempts that produced it:

| Call | I/O | Returns |
|---|---|---|
| `ensureVerified()` | Only if needed | The report of a verification that is valid now, verifying first if the last one has expired or been withdrawn |
| `reverify()` | Always | The report of a new verification, or its exception |
| `currentVerification()` | None | The report of the verification that requests are sent under now: fresh and not withdrawn. Null before the first success, after an `AttestationException` withdrew it, and once it has expired |
| `lastVerificationAttempt()` | None | The most recent attempt: its report if it passed, its exception if it failed |
| `onVerificationAttempt` option | Push | Each attempt once its outcome is decided, failed attempts included |

The two functions differ after a `reverify()` that fails for a reason other
than attestation, such as a `NetworkException`: `lastVerificationAttempt()`
returns the failure, while `currentVerification()` still returns the
earlier report, which requests are still sent under until it expires. A
`reverify()` that fails with an `AttestationException` withdraws the
verification, so `currentVerification()` returns null and the next request
verifies again.

- Health and readiness checks call `ensureVerified()`. It returns at once
  while the verification is valid, and verifies when it is not. Clients do
  not verify again in the background, so `currentVerification()` is null
  between the expiry of a verification and the next request; that is not
  a failure.
- Status displays show `currentVerification()` for the verification in
  use, and `lastVerificationAttempt()` for the outcome of the latest
  attempt, which may be a failure.
- Live status and logging use `onVerificationAttempt`, which is told of
  every attempt, with the host that it verified, including the retries
  that `lastVerificationAttempt()` has already moved past:

```kotlin
import sh.tinfoil.VerificationAttempt
import sh.tinfoil.VerificationException

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
```

A report is for showing and logging what happened. Decide what to do from
the exception's category, never from a report; a decision about trust
belongs in `verificationCheck`, which sees only verified facts.

`toJson()` writes a report in the JSON form that every Tinfoil SDK writes,
so that it can be passed on, for example to a browser, a log or another
process, and read in the same way whichever SDK wrote it:

```kotlin
val client = EnclaveHttpClient.create("enclave.example.com", Trust.RepoPin("org/repo")) {
    onVerificationAttempt = { _, attempt ->
        val report = attempt.report ?: (attempt.error?.cause as? VerificationException)?.report
        report?.let { println(it.toJson()) }
    }
}
```

The JSON has a `schema_version`, one step for each layer, and either
`verified_facts` or `partial_facts`; members are snake_case, hex is
lowercase, times are RFC 3339 in UTC, and a fact that was not established
is left out. A measurement names its `platform` and its registers, as in
`{"platform": "tdx", "rtmr1": "…", "rtmr2": "…"}`, and the TLS and HPKE
keys appear only in `verified_facts.crypto_material`. Every report that a
client hands out names the host that the client contacted for the document
in `metadata.host` (for a router client the router, for a gateway client
the replica), so that a proxy that passes a report on need not add it. The
host is what the client connected to, not an attested fact.

The JSON authorizes nothing. This SDK has no API that reads it back into a
report or into verified facts, and whoever holds it cannot tell whether a
verifier wrote it. Never bind a connection to a key that was read from it,
or treat it as proof that a verification took place; the client binds its
connections only to the verified facts of a verification that it ran
itself.

## Errors

Creating a client throws this SDK's exceptions, which are `IOException`s:
an `AttestationException` when the enclave is not to be trusted, a
`NetworkException` when it cannot be reached to be verified, and a
`ConfigurationException` for an invalid argument. A retry loop that retries
any `IOException` should first read `isRetryable`, which is true only for a
`NetworkException`: an attestation failure must not be retried blindly.
When the verifier rejected the attestation document, the cause of the
`AttestationException` is a `VerificationException`, which names the layer
that rejected it and carries the report (see
[Verification reports](#verification-reports)). Any other attestation
failure, such as a rejection by `verificationCheck`, says what failed in
its `detail`; a rejection that the verifier reports without a report leads
its `detail` with the layer, as in `quote: <detail>`.

The OpenAI SDK throws unchecked exceptions, all of them `OpenAIException`s.
An error status from the API is one of its subclasses, such as
`UnauthorizedException`. A failure of this SDK during a request, such as an
enclave that no longer verifies, is the cause of the exception that the
OpenAI SDK's call throws, and `tinfoilException` finds it:

```kotlin
import com.openai.errors.OpenAIException
import com.openai.errors.OpenAIServiceException
import sh.tinfoil.AttestationException
import sh.tinfoil.tinfoilException

try {
    client.openAI.chat().completions().create(params)
} catch (e: OpenAIException) {
    val failure = e.tinfoilException
    when {
        failure is AttestationException -> println("The enclave is not to be trusted: ${failure.detail}")
        failure != null -> println("The request could not be sent: ${failure.detail}")
        e is OpenAIServiceException -> println("The API answered with ${e.statusCode()}")
        else -> println("The request failed: ${e.message}")
    }
}
```

The OpenAI SDK sends a request again after a failure of the network and
after some error statuses, twice by default (`maxRetries`). It does not send
one again after an `AttestationException` or a `ConfigurationException`.
Each of its attempts can itself send the request more than once, when an
enclave has changed its key and is verified again, so how often one call can
send a request depends on the route. With the default options it is up to 6
times over a router or an enclave client: 3 attempts of up to 2 sends. Over
a gateway client it is up to 24 times:
3 attempts of up to 8 sends, because the gateway can also route a request to
another replica up to 3 times. A request whose body the OpenAI SDK can write
only once, such as an upload that it streams, is sent once.
