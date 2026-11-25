# Tinfoil Kotlin Client

A Kotlin client for verifiably private AI inference with [Tinfoil](https://tinfoil.sh).

This SDK is in pre-release: no version is published yet, and the API may still
change before the first release. Until then, build it from source as
[CONTRIBUTING.md](CONTRIBUTING.md#development) describes.

## Install

The SDK is two artifacts, with the same version. They are **not yet
published**, and their coordinates may still change. Once a release is out,
an app depends on them like this:

```kotlin
dependencies {
    // The OpenAI clients. It brings `tinfoil` with it.
    implementation("sh.tinfoil:tinfoil-openai:<version>")

    // Or only the verifier and the attested HTTP clients.
    implementation("sh.tinfoil:tinfoil:<version>")
}
```

- `sh.tinfoil:tinfoil-openai` is for apps that call the inference API
  through the [OpenAI Java SDK](https://github.com/openai/openai-java):
  `Client`, which is built on top of an attested HTTP client of
  `tinfoil`, in the package `sh.tinfoil.openai`. It depends on
  `tinfoil`, and on the OpenAI SDK, which is large; see [App size](docs/app-size.md).
- `sh.tinfoil:tinfoil` is the attestation verifier and the attested HTTP
  clients, `EnclaveHttpClient`, `RouterHttpClient` and `GatewayHttpClient`,
  in the package `sh.tinfoil`. Use it alone when the app makes its own HTTP
  requests, or brings another API client that takes an OkHttp
  `Call.Factory`: it has no dependency on the OpenAI SDK.

Both need Android 8.0 (API level 26) or later.

`tinfoil` depends on the
[EHBP client](https://github.com/tinfoilsh/encrypted-http-body-protocol),
which is published only through JitPack, so the app's build must also name
that repository, and should use it for that one module and nothing else:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        exclusiveContent {
            forRepository { maven("https://jitpack.io") }
            filter { includeModule("com.github.tinfoilsh", "encrypted-http-body-protocol") }
        }
    }
}
```

## Quick start

`Client` is an OpenAI client for inference on Tinfoil's recommended route.
Creating one verifies the service that it will talk to; from then on, every
request that the OpenAI SDK makes, the API key included, goes to that
verified service and nowhere else.

```kotlin
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.future.await
import sh.tinfoil.openai.Client

val client = Client.create(apiKey)

val params = ChatCompletionCreateParams.builder()
    .model("gpt-oss-120b")
    .addUserMessage("Hello!")
    .build()
val completion = client.openAIAsync.chat().completions().create(params).await()
println(completion.choices().first().message().content().orElse(""))

client.close()
```

`client.openAI` and `client.openAIAsync` are the client of the official
[OpenAI Java SDK](https://github.com/openai/openai-java), with blocking calls
and with calls that return a `CompletableFuture`; see
[The OpenAI client](docs/openai-client.md) for streaming, options and what
it reads from the environment.

To name the enclave and who vouches for its config, create an
`EnclaveHttpClient` with a `Trust` and put the OpenAI client over it:

```kotlin
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.Trust

val enclave = EnclaveHttpClient.create(
    enclave = "inference.tinfoil.sh",
    trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
)
val client = Client.create(enclave, apiKey)
println(enclave.currentVerification()?.verifiedFacts?.codeDigest)

client.close()
enclave.close()
```

The OpenAI client does not own the HTTP client: close each.

## Choosing a route

`Client.create(apiKey)` takes Tinfoil's recommended route, and does not say
which, so that the route can change. To choose it, create one of the
attested HTTP clients and pass it to `Client.create`:

| Route | HTTP client | Sends to |
|---|---|---|
| Router | `RouterHttpClient` | One of Tinfoil's routers, which it chooses and verifies when it is created |
| Enclave | `EnclaveHttpClient` | An enclave that you name, verified under the `Trust` that you name for it |
| Gateway (experimental) | `GatewayHttpClient` | A verified replica of each model that you pin, through Tinfoil's gateway, which reads everything but the body |

See [Routes](docs/routes.md) for the options of each route, the gateway's
experimental API, and the HTTP clients without the OpenAI SDK.

## What is verified

- No request leaves before the service that it goes to is verified: an
  enclave under the `Trust` that you name, a router against its repository,
  or, on the gateway route, a replica against its model's pin. Every
  request, the API key included, goes only to a verified service, through
  the gateway on that route. See
  [What is trusted](docs/verification.md#what-is-trusted).
- With `Transport.Tls`, the default, every connection is pinned to the
  attested TLS key. With `Transport.Ehbp`, only bodies are sealed, and
  connections are validated as any HTTPS connection is: a proxy reads, and
  can change, the method, the URL and the headers, the API key among them,
  and can cut a sealed response short without an error. See
  [Transports](docs/transports.md) for everything that this mode does not
  protect.
- The gateway is not trusted with what a request says, but it reads the URL,
  the headers, the API key among them, and the name of the model. See
  [Gateway](docs/routes.md#gateway-experimental).
- An `AttestationException` means that the service is not to be trusted:
  `isRetryable` is true only for a `NetworkException`, and an attestation
  failure must not be retried blindly. See [Errors](docs/verification.md#errors).
- The OpenAI client reaches the network only through this SDK, except
  through the OpenAI SDK's `withOptions`: a client that it returns with
  another HTTP client sends its requests, and the API key, without any of
  this SDK's protection. See [The OpenAI client](docs/openai-client.md).
- A verification report, and its JSON, are for showing and logging what
  happened, and authorize nothing. See
  [Verification reports](docs/verification.md#verification-reports).

## Documentation

- [The OpenAI client](docs/openai-client.md): its options, streaming, and
  what it reads from the environment.
- [Routes](docs/routes.md): choosing the route, the experimental gateway,
  and the HTTP clients without the OpenAI SDK.
- [Verification](docs/verification.md): what is trusted, verification
  reports, and errors.
- [Transports](docs/transports.md): TLS and EHBP, relays, and session
  recovery.
- [App size](docs/app-size.md): what the SDK adds to an app, and how to keep
  it small.
- [Contributing](CONTRIBUTING.md): building, testing, the pinned verifier
  library, and the conformance tests.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
