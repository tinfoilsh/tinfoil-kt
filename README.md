# Tinfoil Kotlin Client

A Kotlin client for verifiably private AI inference with [Tinfoil](https://tinfoil.sh).

This SDK is under development and is not yet ready for use.

## Usage

`Client` is an OpenAI client for inference on Tinfoil's recommended route.
Creating one verifies the service that it will talk to; from then on, every
request that the OpenAI SDK makes, the API key included, goes to that
verified service and nowhere else.

```kotlin
import com.openai.models.chat.completions.ChatCompletionCreateParams
import kotlinx.coroutines.future.await
import sh.tinfoil.Client

val client = Client.create(apiKey = apiKey)

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

Other options of the OpenAI client are set on its own options builder:

```kotlin
val client = Client.create(apiKey = apiKey) {
    maxRetries(1)
    timeout(Duration.ofMinutes(2))
}
```

An HTTP client or a base URL that is set there is replaced: the OpenAI
client reaches the network only through this SDK. The one way around that is
the OpenAI SDK's `withOptions`, on the client or on one of its services: a
client that it returns with another HTTP client sends its requests, and the
API key, without any of this SDK's protection.

### Choosing the route

`Client` says nothing about how requests reach the models, so that the route
can change. Two clients do, and take the options of the HTTP clients that
they send through.

`RouterOpenAIClient` sends to one of Tinfoil's routers, which it chooses and
verifies when it is created:

```kotlin
import sh.tinfoil.TinfoilEvent
import sh.tinfoil.TransportMode
import sh.tinfoil.openai.RouterOpenAIClient

val client = RouterOpenAIClient.create(
    transportMode = TransportMode.Ehbp,
    baseUrl = "https://proxy.example.com/v1/",
    userCacheSecret = cacheSecret,
    apiKey = apiKey,
    tinfoilEvents = setOf(TinfoilEvent.WebSearch),
)
```

`EnclaveOpenAIClient` sends to an enclave that you name, verified against
what you pin it to:

```kotlin
import sh.tinfoil.Pin
import sh.tinfoil.openai.EnclaveOpenAIClient

val client = EnclaveOpenAIClient.create(
    enclave = "inference.tinfoil.sh",
    pin = Pin(repo = "tinfoilsh/confidential-model-router"),
    apiKey = apiKey,
)
println(client.httpClient.current?.codeDigest)
```

Both send to `https://<enclave>/v1/`, or to `baseUrl` as it is given. Their
`httpClient` is the attested HTTP client itself, for requests that the
OpenAI SDK has no call for.

### Gateway (experimental)

The gateway route is new, and its API may change or be removed in a later
release. Its classes are marked `@ExperimentalTinfoilApi`, and using them is
a compile error until the code opts in.

Tinfoil's gateway forwards each request to an enclave that serves the model
that the request names: a replica of that model. The gateway is not trusted
with what a request says. `GatewayOpenAIClient` picks a replica, verifies its
attestation, and seals the request's body to the key that the attestation
endorses, so the gateway forwards a body that it cannot read. It does read
everything else: the URL, the headers, the API key among them, and the name
of the model.

```kotlin
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.ModelPin
import sh.tinfoil.openai.GatewayOpenAIClient

@OptIn(ExperimentalTinfoilApi::class)
suspend fun gateway(apiKey: String): GatewayOpenAIClient {
    val client = GatewayOpenAIClient.create(
        modelPins = mapOf("deepseek-v4-1-flash" to ModelPin("tinfoilsh/confidential-deepseek-v4-1-flash")),
        pinnedModelsOnly = true,
        apiKey = apiKey,
    )
    println(client.httpClient.models())
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
none, such as listing models, are refused; `httpClient.models()` lists what
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
`ConfigurationException` for an invalid argument.

The OpenAI SDK throws unchecked exceptions, all of them `OpenAIException`s.
An error status from the API is one of its subclasses, such as
`UnauthorizedException`. A failure of this SDK during a request, such as an
enclave that no longer verifies, is the cause of the exception that the
OpenAI SDK's call throws, and `tinfoilException` finds it:

```kotlin
import com.openai.errors.OpenAIException
import com.openai.errors.OpenAIServiceException
import sh.tinfoil.AttestationException
import sh.tinfoil.openai.tinfoilException

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
times with `Client`, `RouterOpenAIClient` and `EnclaveOpenAIClient`: 3
attempts of up to 2 sends. With `GatewayOpenAIClient` it is up to 24 times:
3 attempts of up to 8 sends, because the gateway can also route a request to
another replica up to 3 times. A request whose body the OpenAI SDK can write
only once, such as an upload that it streams, is sent once.

### App size

The OpenAI SDK is large: its classes add tens of megabytes to an app that is
not shrunk. Build release variants with R8 (`isMinifyEnabled = true`). The
OpenAI SDK and this SDK each carry the keep rules that they need.

## Transport modes

A client protects its requests with the keys that the enclave's attestation
endorses, in one of two ways.

`TransportMode.Tls`, the default, pins every connection to the attested TLS
key. It protects the whole request and response, and needs a direct
connection to the enclave.

`TransportMode.Ehbp` seals request and response bodies to the attested HPKE
key with [EHBP](https://docs.tinfoil.sh/resources/ehbp), so that they stay
private through a proxy that you pass as `baseUrl`:

```kotlin
val client = EnclaveHttpClient.create(
    enclave = "inference.tinfoil.sh",
    pin = Pin(repo = "tinfoilsh/confidential-model-router"),
    transportMode = TransportMode.Ehbp,
    baseUrl = "https://proxy.example.com/",
)
```

What this mode does not protect:

- **Only bodies are sealed.** The method, the URL and the headers of every
  request, an API key among them, are not: the proxy reads them and can
  change them. The proxy must therefore use HTTPS; `http://` is accepted only
  for `localhost` or a loopback IP address. A base URL on this machine is
  reached directly, whatever HTTP proxy the system is configured with.
- **A request without a body is not sealed, and neither is its response.**
- Connections are validated as any HTTPS connection is, and are not pinned to
  the enclave's key: whoever holds a valid certificate for the host that you
  named, the proxy's or the enclave's own, reads what is not sealed. The
  router clients are the exception, because you do not name the router's
  host. Without a proxy, their connections are pinned to the router's
  attested key in this mode too. With a proxy, which makes the connection to
  the router itself, they always use `inference.tinfoil.sh` and do not
  consult Tinfoil's router list, which is not trusted.
- A response with an error status of 400 or above may come from the proxy and
  not from the enclave. A response that the enclave did not seal is
  authenticated by nothing.
- **A sealed response can be cut short without an error.** Every piece of a
  sealed body is authenticated, and a body that ends inside a piece fails the
  read. A body that ends between two pieces does not: the protocol does not
  mark the last piece, so a proxy can end a response early. What you read is
  the enclave's, but only its content shows that it is complete, such as the
  `[DONE]` event at the end of a stream, or JSON that parses.
- Protocol upgrades, such as WebSockets, and `CONNECT` are refused. So is a
  response that is marked as sealed and has an empty body, whatever its
  status: nothing in it shows that the enclave sent it.

Requests to a proxy carry `X-Tinfoil-Enclave-Url: https://<enclave>`, which
tells the proxy where to forward them. See `EnclaveHttpClient.execute` for
the full rules.

### Session recovery

With `TransportMode.Ehbp`, `executeRecoverable` returns a response together
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

## Development

The SDK is an Android library. Building it needs JDK 17, the Android SDK
(`ANDROID_HOME`), and the attestation verifier library, `TinfoilGo.aar`, which
is built from [tinfoil-go](https://github.com/tinfoilsh/tinfoil-go) at the
commit in `tinfoil-go.properties`:

```bash
# in a tinfoil-go checkout at that commit
bash scripts/setup-mobile.sh
bash scripts/build-mobile-android.sh /path/to/TinfoilGo.aar

# in this repository
export TINFOIL_GO_AAR=/path/to/TinfoilGo.aar
./gradlew :tinfoil:assembleRelease :tinfoil:lintRelease :tinfoil:testDebugUnitTest :tinfoil:apiCheck
./gradlew :tinfoil:connectedDebugAndroidTest   # needs a running emulator or a device
```

The EHBP client, which seals request bodies in `TransportMode.Ehbp`, is not
released yet. It is built from source, as a Gradle included build, out of the
`kotlin/` directory of a checkout of
[encrypted-http-body-protocol](https://github.com/tinfoilsh/encrypted-http-body-protocol)
at the commit in `ehbp.properties`. The build looks for the checkout next to
this repository, in `../encrypted-http-body-protocol`; set `EHBP_KOTLIN_DIR`
to the `kotlin/` directory of a checkout that is somewhere else:

```bash
git clone https://github.com/tinfoilsh/encrypted-http-body-protocol ../encrypted-http-body-protocol
git -C ../encrypted-http-body-protocol checkout "$(sed -n 's/^commit=//p' ehbp.properties)"
```

The verifier library is native code for Android, so the tests that reach it
are instrumented tests; the unit tests run on the JVM without it.

The instrumented tests that verify Tinfoil's production enclaves reach the
network, so they are skipped unless they are asked for:

```bash
./gradlew :tinfoil:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.tinfoilIntegration=true
```

The live tests that complete a chat also need an API key. It is passed on
the command line, from the environment, and those tests are skipped without
it. Never write it into a file:

```bash
./gradlew :tinfoil:connectedDebugAndroidTest \
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
every task that packages the SDK, belongs to the release variant or
publishes; only the instrumented tests run.

The SDK's version is `version` in `gradle.properties`, and `Tinfoil.VERSION`
is generated from it.

The public API is pinned in `tinfoil/api/tinfoil.api`, and `apiCheck` fails
when the code and that file disagree. After a deliberate change to the API,
run `./gradlew :tinfoil:apiDump` and commit the result.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
