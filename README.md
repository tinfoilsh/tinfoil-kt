# Tinfoil Kotlin Client

A Kotlin client for verifiably private AI inference with [Tinfoil](https://tinfoil.sh).

This SDK is under development and is not yet ready for use.

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
  for `localhost` or a loopback IP address.
- **A request without a body is not sealed, and neither is its response.**
- Connections are validated as any HTTPS connection is, and are not pinned to
  the enclave's key.
- A response with an error status of 400 or above may come from the proxy and
  not from the enclave. A response that the enclave did not seal is
  authenticated by nothing.
- Protocol upgrades, such as WebSockets, and `CONNECT` are refused. So is a
  response to a sealed request that reports success with an empty body:
  nothing in it shows that the enclave sent it.

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

The public API is pinned in `tinfoil/api/tinfoil.api`, and `apiCheck` fails
when the code and that file disagree. After a deliberate change to the API,
run `./gradlew :tinfoil:apiDump` and commit the result.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
