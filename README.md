# Tinfoil Kotlin Client

A Kotlin client for verifiably private AI inference with [Tinfoil](https://tinfoil.sh).

This SDK is under development and is not yet ready for use.

## Install

The SDK is two artifacts, with the same version. They are **not yet
published**, and their coordinates may still change:

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
  `tinfoil`, and on the OpenAI SDK, which is large; see [App size](#app-size).
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

## Usage

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

`client.openAI` is the client of the official
[OpenAI Java SDK](https://github.com/openai/openai-java), with blocking
calls, and `client.openAIAsync` is the same client with calls that return a
`CompletableFuture`, which a coroutine awaits with `await()`. Use them as
that SDK documents. The API key is passed in: no credential, URL or option
is taken from the environment or from system properties. (The OpenAI SDK
reads the variable `OPENAI_LOG` when its options are made, which this SDK
overrides with logging off, and it describes the platform in its
`X-Stainless-*` request headers, from the system properties `os.name`,
`os.arch`, `os.version` and `java.version`.)

A streamed response becomes a `Flow` with `asFlow()`. Events arrive as the
service sends them, and cancelling the collection cancels the request:

```kotlin
import sh.tinfoil.openai.asFlow

client.openAIAsync.chat().completions().createStreaming(params).asFlow().collect { chunk ->
    chunk.choices().forEach { choice -> choice.delta().content().ifPresent(::print) }
}
```

Other options of the OpenAI client are set on its own options builder, in
`openAI { }`:

```kotlin
val client = Client.create(apiKey) {
    openAI {
        maxRetries(1)
        timeout(Duration.ofMinutes(2))
    }
}
```

An HTTP client or a base URL that is set there is replaced, and so is one
that the OpenAI SDK reads from `OPENAI_BASE_URL`: the OpenAI client reaches
the network only through this SDK. The one way around that is
the OpenAI SDK's `withOptions`, on the client or on one of its services: a
client that it returns with another HTTP client sends its requests, and the
API key, without any of this SDK's protection.

### Choosing the route

`Client.create(apiKey)` says nothing about how requests reach the models, so
that the route can change. To choose the route, create one of the attested
HTTP clients of the `tinfoil` artifact and put an OpenAI client over it:

- `RouterHttpClient` sends to one of Tinfoil's routers, which it chooses and
  verifies when it is created;
- `EnclaveHttpClient` sends to an enclave that you name, verified under the
  trust that you name for it (see [What is trusted](#what-is-trusted));
- `GatewayHttpClient` sends through Tinfoil's gateway (see
  [Gateway](#gateway-experimental)).

```kotlin
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.Transport
import sh.tinfoil.openai.Client
import sh.tinfoil.openai.TinfoilEvent

val router = RouterHttpClient.create {
    transport = Transport.Ehbp(proxyUrl = "https://proxy.example.com/")
    userCacheSecret = cacheSecret
}
val client = Client.create(router, apiKey) {
    tinfoilEvents = setOf(TinfoilEvent.WEB_SEARCH)
}
```

```kotlin
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.Trust

val enclave = EnclaveHttpClient.create(
    enclave = "inference.tinfoil.sh",
    trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
)
val client = Client.create(enclave, apiKey) {
    apiPath = "/v1/"
}
println(enclave.current?.codeDigest)
```

Creating the OpenAI client does no network I/O: the HTTP client verified
its service when it was created, and verifies it again by itself. Requests
go to `apiPath`, `/v1/` by default, under the HTTP client's `baseUrl`: the
enclave's origin, `https://<enclave>/`, or the proxy URL of
`Transport.Ehbp`, whose path is where the proxy is mounted. Over a gateway
client they go to the gateway's URL as it is given, and `apiPath` is
refused. The OpenAI client does not own the HTTP client: close each, and one
HTTP client can serve several OpenAI clients, each with its own API key.
`Client.create(apiKey)` makes its own router client, and closes it with
itself.

### What is trusted

An enclave that you name is verified under a trust argument, which names
who vouches for the config that it runs. It is one of the variants of
`Trust`:

| Variant | Accepts |
|---|---|
| `Trust.RepoPin(repo)` | v2 collateral for a GitHub repository, `owner/name[@tag][@sha256:digest]` |
| `Trust.ProjectPin(project, registryIds)` | v3 collateral for a config registry project, `org/project[@revision][@sha256:digest]`, endorsed by the public registry (`registryIds = null`) or by exactly the registries listed; an empty list is refused |
| `Trust.SignedBy(keys, project)` | v3 configs whose endorsements your keys sign, optionally only those of one project |
| `Trust.AuthorizedBy(authorize)` | v3 configs that your `ConfigAuthorizer` approves |
| `Trust.EmbeddedConfig(bytes, name)` | v3 collateral for exactly the config bytes that you supply |
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

### Gateway (experimental)

The gateway route is new, and its API may change or be removed in a later
release. Its classes are marked `@ExperimentalTinfoilApi`, and using them is
a compile error until the code opts in.

Tinfoil's gateway forwards each request to an enclave that serves the model
that the request names: a replica of that model. The gateway is not trusted
with what a request says. `GatewayHttpClient` picks a replica, verifies its
attestation, and seals the request's body to the key that the attestation
endorses, so the gateway forwards a body that it cannot read. It does read
everything else: the URL, the headers, the API key among them, and the name
of the model.

```kotlin
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.ModelPin
import sh.tinfoil.openai.Client

@OptIn(ExperimentalTinfoilApi::class)
suspend fun gateway(apiKey: String): Client {
    val gateway = GatewayHttpClient.create {
        modelPins = mapOf("deepseek-v4-1-flash" to ModelPin("tinfoilsh/confidential-deepseek-v4-1-flash"))
        pinnedModelsOnly = true
    }
    val client = Client.create(gateway, apiKey)
    println(gateway.models())
    return client
}
```

A model with a pin is verified against the pin's repository, and against one
release of it if the pin has a tag or a digest. A model without a pin is
verified against the repository that the gateway's catalog names for it,
which must be one of Tinfoil's, `tinfoilsh/<name>`: the client is then
assured that the request goes to an enclave that runs a release of one of
Tinfoil's repositories, and trusts Tinfoil for which of them serves the
model. `pinnedModelsOnly` serves no model without a pin.

A request has to name its model, so the calls of the OpenAI SDK that name
none, such as listing models, are refused; `GatewayHttpClient.models()` lists what
the client serves. A JSON body that names `model`, `user_cache_secret` or
`cache_salt` twice, or in another case, such as `Model`, is refused too,
since a server could read another member than the client did.
`userCacheSecret` scopes the prompt cache as it does for the other clients,
but on the chat, completions and responses requests the secret never leaves
the device: the client replaces it in the body with a salt that it derives
from it.
`GatewayHttpClient` is the HTTP client itself, and describes all of this.

### Errors

Creating a client throws this SDK's exceptions, which are `IOException`s:
an `AttestationException` when the enclave is not to be trusted, a
`NetworkException` when it cannot be reached to be verified, and a
`ConfigurationException` for an invalid argument. A retry loop that retries
any `IOException` should first read `isRetryable`, which is true only for a
`NetworkException`: an attestation failure must not be retried blindly.

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

### Without the OpenAI SDK

The HTTP clients of the `tinfoil` artifact are what the OpenAI clients send
through, and work without them. Each is an OkHttp `Call.Factory` that sends
a request only to the service that it verified:

```kotlin
import okhttp3.Request
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.Trust

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
```

### App size

Build release variants with R8 (`isMinifyEnabled = true`). What the SDK then
adds to an app is mostly these three things:

- **The OpenAI SDK, with `tinfoil-openai` only.** It adds about 15 MB of dex
  code to a minified app, about 4.4 MB of the APK, whether or not the app
  uses all of it: the keep rules that the OpenAI SDK ships pin its classes,
  and Jackson and `kotlin-reflect` with them, so R8 cannot remove what is
  not used. An app that depends on `tinfoil` alone carries none of it.
- **The native verifier library, with either artifact.** It is about 20 MB
  for each ABI, about 7 MB compressed, and is built for `arm64-v8a`,
  `armeabi-v7a` and `x86_64`. There is no library for 32-bit `x86`. An app
  bundle delivers one ABI to a device; an APK that is built for all of them
  carries all three.
- **Bouncy Castle's resources, with either artifact.** Bouncy Castle, which
  seals bodies with `Transport.Ehbp`, ships about 1.2 MB of data files for
  an algorithm that this SDK does not use. R8 does not remove resources, but
  the app's build can leave them out:

  ```kotlin
  android {
      packaging {
          resources {
              excludes += "org/bouncycastle/pqc/crypto/picnic/**"
          }
      }
  }
  ```

The SDK's own classes are small, and the artifacts carry the keep rules that
they need.

## Transports

A client protects its requests with the keys that the enclave's attestation
endorses, in one of two ways, which its `transport` option selects.

`Transport.Tls`, the default, pins every connection to the attested TLS
key. It protects the whole request and response, and needs a direct
connection to the enclave, so it takes no URL.

`Transport.Ehbp` seals request and response bodies to the attested HPKE key
with [EHBP](https://docs.tinfoil.sh/resources/ehbp), so that they stay
private through a proxy, its `proxyUrl`, or on a direct connection when that
is null:

```kotlin
val client = EnclaveHttpClient.create(
    enclave = "inference.tinfoil.sh",
    trust = Trust.RepoPin("tinfoilsh/confidential-model-router"),
) {
    transport = Transport.Ehbp(proxyUrl = "https://proxy.example.com/")
}
```

The proxy URL's path is where the proxy is mounted: request paths, and the
OpenAI clients' `v1/`, join under it whether or not it ends with `/`. A proxy
on the enclave's own origin is refused; leave `proxyUrl` null to connect
directly.

What this mode does not protect:

- **Only bodies are sealed.** The method, the URL and the headers of every
  request, an API key among them, are not: the proxy reads them and can
  change them. The proxy must therefore use HTTPS; `http://` is accepted only
  for `localhost` or a loopback IP address. A proxy on this machine is
  reached directly, whatever HTTP proxy the system is configured with.
- **A request without a body is not sealed, and neither is its response.**
  The same goes for a body that is empty: one that declares a length of
  zero, or one of undeclared length that writes nothing.
- Connections are validated as any HTTPS connection is, and are not pinned to
  the enclave's key: whoever holds a valid certificate for the host that you
  named, the proxy's or the enclave's own, reads what is not sealed. The
  router clients are the exception, because you do not name the router's
  host: without a proxy, their connections are pinned to the router's
  attested key in this mode too. With a proxy, which makes the connection to
  the router itself, the router that discovery chose is named to the proxy.
  An attestation document is not tied to the host that serves it, so the
  source of the router list, Tinfoil's or yours, is then trusted not to name
  a host that would pass on another router's attestation: such a host would
  receive the request headers, the API key among them, though not the
  sealed bodies.
- A response with an error status of 400 or above may come from the proxy and
  not from the enclave. A response that the enclave did not seal is
  authenticated by nothing.
- **A sealed response can be cut short without an error.** Every piece of a
  sealed body is authenticated, and a body that ends inside a piece fails the
  read. A body that ends between two pieces does not: the protocol does not
  mark the last piece, so a proxy can end a response early. What you read is
  the enclave's, but only its content shows that it is complete, such as the
  `[DONE]` event at the end of a stream, or JSON that parses.
- Protocol upgrades, such as WebSockets, and `CONNECT` are refused.
- A response that is marked as sealed has to show it: the read of its body
  fails unless a piece of it authenticates. An empty response that the
  enclave sealed is read as empty, except with an error status of 400 or
  above, where it is refused: the sealing library does not tell it there
  from one that only claims to be sealed.

Requests to a proxy carry `X-Tinfoil-Enclave-Url: https://<enclave>`, which
tells the proxy where to forward them. See `EnclaveHttpClient.execute` for
the full rules.

### Relays

By default, a client fetches each attestation document directly from the
enclave, and the router client fetches its list of candidate routers from
`https://atc.tinfoil.sh/routers`. The `fetchAttestation` option of the
enclave and router clients, and the `fetchRouterList` option of the router
client, change how they are obtained, so that, together with a proxy, a
client reaches only your own origin: for a device that should not reveal
its address to enclaves, or a network that allows one destination.

```kotlin
val client = RouterHttpClient.create {
    transport = Transport.Ehbp(proxyUrl = "https://app.example/tinfoil/proxy")
    fetchAttestation = AttestationRelay("https://app.example/tinfoil")
    fetchRouterList = RouterListRelay("https://app.example/tinfoil")
}
```

`AttestationRelay(url)` sends
`GET <url>/.well-known/tinfoil-attestation?nonce=<hex>&enclave=<host>`, which
the relay forwards to `https://<host>/.well-known/tinfoil-attestation?nonce=<hex>`,
returning the body unchanged. `RouterListRelay(url)` sends `GET <url>/routers`,
which the relay forwards to `https://atc.tinfoil.sh/routers`. A relay should
forward only to the enclave hosts that the application expects, so that it
is not an open proxy. A relay URL follows the rules of a proxy URL, and is
checked when the relay is made. Any other function can take either place:
`fetchAttestation = AttestationFetcher { host, nonce -> ... }`.

Neither option changes what is trusted. Every document is verified as a
fetched one is, and the list only proposes routers: discovery always runs,
tries a shuffled copy of the list, verifies each router that it tries, and
falls back to `inference.tinfoil.sh`. A fetcher's failure is a
`NetworkException` that keeps it as its cause, unless it is already one of
this SDK's exceptions, and a router list that cannot be obtained counts as
empty.

### Session recovery

With `Transport.Ehbp`, `executeRecoverable` returns a response together
with its session recovery token, which can open that one response again
later, without the client that sent the request. Use it for a response that
the server keeps and that can be fetched again after an interruption:

```kotlin
client.executeRecoverable(request).use { recoverable ->
    recoverable.recoveryToken?.let { store(it.toJson()) }   // before reading the body
    read(recoverable.response.body!!.source())
}

// Later, with the sealed response fetched again from where it is kept:
val plaintext = SessionRecoveryToken.fromJson(stored).decryptResponse(sealedResponse)
```

A token is secret key material for its response. Keep it in protected
storage, never log it, and delete it once the response has been read.

## Migrating from earlier versions

This release reshapes how clients are configured, as in the other Tinfoil
SDKs. The changes are breaking:

| Before | Now |
|---|---|
| `EnclaveHttpClient.create(enclave, Pin(repo = "org/repo"))` | `EnclaveHttpClient.create(enclave, Trust.RepoPin("org/repo"))` |
| `Pin(project = "org/project")` | `Trust.ProjectPin("org/project")`, with `registryIds` for registries other than the public one (an empty list is refused) |
| `Pin(repo = ..., project = ...)` | `Trust.EitherPin(repo, project)` |
| `Pin.NONE` with `Verifier(configAuthorizer = ...)` | `Trust.AuthorizedBy(authorizer)` |
| `Pin.NONE` with `Verifier(embeddedReferences = EmbeddedReferences(config = EmbeddedConfig.Bytes(bytes)))` | `Trust.EmbeddedConfig(bytes, name)`; a config named by its digest and runtime has no replacement |
| `Verifier(configSigningKeysPem = keys)` | `Trust.SignedBy(keys, project)` |
| `verifier = Verifier(pinnedRegisters = ..., freshnessMaxAge = ...)` | `policy = Policy(pinnedRegisters = ..., freshnessMaxAge = ...)`; a zero age selects the default |
| `Verifier(freshnessSigningKeysPem = keys)` | `Policy(artifacts = ArtifactTrust.EndorsedArtifacts(keys))` |
| `EmbeddedReferences(runtime = ..., platform = ...)` | `Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime, platform))` |
| `ModelPin(repo, verifier)` | `ModelPin(repo, policy)` |
| `GatewayOptions.baseUrl`, `GatewayHttpClient.DEFAULT_BASE_URL` | `GatewayOptions.url`, `GatewayHttpClient.DEFAULT_URL` |
| `Verifier.PUBLIC_REGISTRY_ID` | `Trust.PUBLIC_REGISTRY_ID` |
| `client.pin` | `client.trust` on the enclave client; none on the router client |
| `transportMode = TransportMode.EHBP` | `transport = Transport.Ehbp()` |
| `transportMode = TransportMode.EHBP` and `baseUrl = "https://proxy.example/v1/"` | `transport = Transport.Ehbp(proxyUrl = "https://proxy.example/")`; the OpenAI client adds `/v1/` |
| `baseUrl` as a path on the enclave's own origin | none: requests name their own paths, and the OpenAI client takes `apiPath` |
| `client.transportMode` | `client.transport` |
| `attestationRelay = "relay.example"` | `fetchAttestation = AttestationRelay("https://relay.example")`; discovery now runs with it |
| a proxy or a relay that skipped router discovery | discovery always runs; see [Relays](#relays) |
| `userCacheSecret` on `EnclaveHttpClient` | none: set `user_cache_secret` in each request body that needs one |
| an empty `userCacheSecret`, which was refused | selects the process's random secret |
| `EnclaveOpenAIClient.create(enclave, pin, apiKey) { ... }` | `Client.create(EnclaveHttpClient.create(enclave, trust) { ... }, apiKey) { ... }` |
| `RouterOpenAIClient.create(apiKey) { ... }` | `Client.create(RouterHttpClient.create { ... }, apiKey) { ... }` |
| `GatewayOpenAIClient.create(apiKey) { ... }` | `Client.create(GatewayHttpClient.create { ... }, apiKey) { ... }` |
| `Client.httpClient: Call.Factory` | `Client.httpClient: AttestedHttpClient` |

An OpenAI client that is made over an HTTP client of yours does not close
it: close both. A base URL that is set in `openAI { }` was replaced before,
and still is.

## Development

The SDK is two Android library modules: `tinfoil`, the verifier and the
attested HTTP clients, and `tinfoil-openai`, the OpenAI clients over them.
Building them needs JDK 17, the Android SDK
(`ANDROID_HOME`), and the attestation verifier library, `TinfoilGo.aar`, which
is built from [tinfoil-go](https://github.com/tinfoilsh/tinfoil-go) at the
commit in `tinfoil-go.properties`:

```bash
# in a tinfoil-go checkout at that commit
bash scripts/setup-mobile.sh
bash scripts/build-mobile-android.sh /path/to/TinfoilGo.aar

# in this repository
export TINFOIL_GO_AAR=/path/to/TinfoilGo.aar
./gradlew assembleRelease lintRelease testDebugUnitTest apiCheck
./gradlew connectedDebugAndroidTest   # needs a running emulator or a device
```

A task that is named without a module runs in both. Name the module to run
it in one, as in `./gradlew :tinfoil:testDebugUnitTest` or
`./gradlew :tinfoil-openai:connectedDebugAndroidTest`. `tinfoil` does not
depend on the OpenAI SDK, and its build fails if a dependency ever brings
that in.

The EHBP client, which seals request bodies with `Transport.Ehbp`, is the
released artifact `com.github.tinfoilsh:encrypted-http-body-protocol`, which
JitPack builds from the release tag of
[encrypted-http-body-protocol](https://github.com/tinfoilsh/encrypted-http-body-protocol).
JitPack builds an artifact for any GitHub repository that it is asked for,
so `settings.gradle.kts` uses it for this one module only, and
`gradle/verification-metadata.xml` pins the SHA-256 of the files that it
serves: a build fails if they ever change. To move to another release, change
the version in `gradle/libs.versions.toml` and the checksums together, after
comparing JitPack's jar with a build of the tag. Every other dependency is
trusted as its repository serves it for now.

The verifier library is native code for Android, so the tests that reach it
are instrumented tests; the unit tests run on the JVM without it.

The instrumented tests that verify Tinfoil's production enclaves reach the
network, so they are skipped unless they are asked for:

```bash
./gradlew connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.tinfoilIntegration=true
```

The live tests that complete a chat also need an API key. It is passed on
the command line, from the environment, and those tests are skipped without
it. Never write it into a file:

```bash
./gradlew connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.tinfoilIntegration=true \
  -Pandroid.testInstrumentationRunnerArguments.tinfoilApiKey="$TINFOIL_API_KEY"
```

### Conformance tests

`ConformanceVectorTest` runs the full-verify vectors of the
[conformance suite](https://github.com/tinfoilsh/tinfoil-conformance) through
the verifier library and through this SDK's decoding and error
classification, and compares each verdict, rejection layer and verified fact
with what the vector expects. The vectors are those of the commit in
`tinfoil-conformance.properties`, which also records how many there are.

A vector brings its own trust anchors and its own time, so these tests need a
verifier library with two test-only entry points that accept them. It is
built from the same tinfoil-go commit with `MOBILE_BUILD_TAGS`:

```bash
# in a tinfoil-go checkout at the commit in tinfoil-go.properties
MOBILE_BUILD_TAGS=tinfoil_conformance \
  bash scripts/build-mobile-android.sh /path/to/TinfoilGo-conformance.aar

# the vectors
git clone https://github.com/tinfoilsh/tinfoil-conformance ../tinfoil-conformance
git -C ../tinfoil-conformance checkout "$(sed -n 's/^commit=//p' tinfoil-conformance.properties)"

# in this repository, with a running emulator or a device
TINFOIL_CONFORMANCE=1 \
TINFOIL_GO_AAR=/path/to/TinfoilGo-conformance.aar \
TINFOIL_CONFORMANCE_VECTORS=../tinfoil-conformance/vectors \
./gradlew :tinfoil:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=sh.tinfoil.internal.verification.ConformanceVectorTest
```

The build packages the full-verify vectors into the test APK, and fails when
a JSON file in the vectors directory does not parse or when their number is
not the pinned one. The tests reach no network, and log each vector's outcome
under the tag `TinfoilConformance`.

**A verifier library built with `tinfoil_conformance` must never ship**: its
test-only entry points replace the trust anchors and the clock. The build
enforces this in both directions. Without `TINFOIL_CONFORMANCE=1`, every
build fails when `TINFOIL_GO_AAR` names a library that has those entry
points. With it, the build fails when the library lacks them, and refuses
every task, in either module, that packages the SDK, belongs to the release
variant or publishes; only the instrumented tests run.

The SDK's version is `version` in `gradle.properties`, for both modules, and
`Tinfoil.VERSION` is generated from it.

The public API of each module is pinned, in `tinfoil/api/tinfoil.api` and
`tinfoil-openai/api/tinfoil-openai.api`, and `apiCheck` fails when the code
and those files disagree. After a deliberate change to the API, run
`./gradlew apiDump` and commit the result.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
