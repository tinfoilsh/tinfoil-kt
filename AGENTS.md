# AGENTS.md

Guidance for AI agents working in this repository.

## Layout

The SDK is two Android library modules, which become two artifacts with one
version. A class's package names its artifact.

- `tinfoil/`: the artifact `tinfoil`, in the package `sh.tinfoil`: the
  bundled verifier library, the attested HTTP clients, their options and
  exceptions. Everything under `sh.tinfoil.internal` is implementation
  detail; `sh.tinfoil.internal.gateway` is the experimental gateway route.
  It does not depend on the OpenAI SDK, on Jackson or on `kotlin-reflect`,
  directly or through another dependency, and its build fails if it does
  (`checkRuntimeDependencies`): apps use it alone to stay small.
- `tinfoil-openai/`: the artifact `tinfoil-openai`, in the package
  `sh.tinfoil.openai` and nowhere else: `Client`, the OpenAI client that is
  built on top of an attested HTTP client, its options and `TinfoilEvent`. Its
  implementation detail is under `sh.tinfoil.openai.internal`. It depends on
  `tinfoil` and on the OpenAI SDK, and has no native library of its own.
- `tinfoil/src/testFixtures`: the fakes and test servers that the tests of
  both modules share, in `sh.tinfoil.testing`. They are sources of `tinfoil`
  so that they can use its internals. What is public in them is what the
  tests of `tinfoil-openai` use. They are not part of an artifact and are
  never published.
- `build-logic/`: the convention plugin `tinfoil.android-library`, which
  holds what the two modules' builds have in common.
- `tinfoil-go.properties`: the tinfoil-go commit that the attestation verifier
  library is built from.
- `gradle/verification-metadata.xml`: the SHA-256 of the released EHBP
  client, which JitPack serves. `settings.gradle.kts` lets JitPack serve
  that one module and nothing else. Never widen that filter, and change the
  checksums only together with the version in `gradle/libs.versions.toml`,
  after comparing the jar with a build of the release tag; see the README.
- `tinfoil-conformance.properties`: the tinfoil-conformance commit whose
  full-verify vectors the conformance tests run, and their number.
- `tinfoil/src/androidTestConformance`: the conformance tests, compiled only
  with `TINFOIL_CONFORMANCE=1`; see the README.

## The verifier is not written here

Attestation documents are verified by a native library built from
[tinfoil-go](https://github.com/tinfoilsh/tinfoil-go) and bundled into this
SDK's AAR. Never reimplement or relax a verification check in Kotlin; a change
to what is verified belongs in tinfoil-go.

## Building and testing

`TINFOIL_GO_AAR` must name a `TinfoilGo.aar`; see the README.

A task that is named without a module runs in both modules; `:tinfoil:` or
`:tinfoil-openai:` before it runs it in one.

- `./gradlew testDebugUnitTest` runs the unit tests on the JVM. The
  verifier library cannot load there, so these tests use fakes for it.
- `./gradlew connectedDebugAndroidTest` runs the tests that reach the
  verifier library, on a running emulator or a device.
- Instrumented tests that reach production enclaves are skipped unless the
  instrumentation argument `tinfoilIntegration` is `true`:
  `-Pandroid.testInstrumentationRunnerArguments.tinfoilIntegration=true`.
  Run them after a change to verification, the TLS pin or the transports.
- `./gradlew lintRelease` must pass; warnings are errors.
- `./gradlew apiCheck` compares the public API of each module with its
  dump, `tinfoil/api/tinfoil.api` and
  `tinfoil-openai/api/tinfoil-openai.api`. Change those files only with
  `./gradlew apiDump`, and only for a deliberate API change.

## Rules

- Fail closed: no request leaves before its enclave is verified, and option
  errors are raised before any network I/O.
- With `Transport.Tls`, a request is written only to a connection whose
  leaf certificate carries the attested key, checked after the platform's
  own TLS validation. Nothing
  that can weaken that check, such as trusted roots, a proxy or a stand-in
  verifier, is part of the public API. Tests reach them through `internal`
  members, and those on a public class are also `@JvmSynthetic`, because
  Kotlin's `internal` is public to Java; a public class has no ordinary
  member that takes one. Classes under `sh.tinfoil.internal` stay visible to
  Java as such, and are not an API.
- `tinfoil-openai` uses `tinfoil` through its public API and through what is
  marked `@InternalTinfoilApi`, and nothing else: Kotlin's `internal` ends at
  the module. Everything that is marked is in or named by
  `sh.tinfoil.internal.CrossArtifact`. Keep that set as small as it is. It
  is left out of the API dumps (`nonPublicMarkers` in the root build file)
  and has no compatibility promise, which is sound only because the two
  artifacts are released together and `tinfoil-openai` depends on exactly
  its own version of `tinfoil`; keep that so when publishing is set up. A
  marked function is `@JvmSynthetic`.
- Nothing that is marked `@InternalTinfoilApi` may take or reveal a verifier,
  a trust anchor, a clock or a proxy: an app that opts in must gain nothing
  that weakens verification. The seams for those stay `internal` to
  `tinfoil`. The tests of `tinfoil-openai` reach them only through the test
  fixtures, which wrap them in public functions, such as
  `TestEnclave.connections()`; the drop-in `Client.create(apiKey)` has a
  seam for tests that takes a function that returns a `RouterHttpClient`,
  and nothing less.
- With `Transport.Ehbp`, a request body is sealed to the HPKE key of the
  verification that the request was sent under, and to no other key: the key
  comes only from the verification, never from the network. The sealing
  itself belongs to the EHBP client library; write no EHBP cryptography or
  framing here. A request with a body leaves sealed or not at all, cleartext
  HTTP is for a loopback proxy URL only, and a response that was not sealed
  is never presented as the enclave's.
- The router list is untrusted: it only proposes hosts, and each is verified
  against the router's pin like any enclave. Nothing read from it may relax
  a check, choose a pin, or be parsed with code that recurses on its input.
  An attestation document is not tied to the host that served it, so a
  listed host is reached directly only over connections that are pinned to
  its attested TLS key, in both transport modes. Discovery always runs, a
  proxy and the fetchers included; through an EHBP proxy a chosen router is
  named to the proxy, so the list's source is trusted with the request
  headers there, a risk that the spec accepts and the docs state.
- Attestation documents and router lists that `fetchAttestation` and
  `fetchRouterList` obtain are untrusted, as fetched ones are: a document is
  verified against its nonce, the trust and the policy, and a list only
  proposes hosts. A fetcher's error is classified where it is called: an
  SDK exception keeps its category, anything else is a `NetworkException`
  that keeps it as its cause, and a `CancellationException` is the caller's
  only when the caller's coroutine is cancelled. A timeout of the SDK's own
  is never left to pass for the caller's cancellation. Relay URLs follow
  the rules for proxy URLs and are checked when the relay is made.
- A request body is changed only to add the user cache secret, on the
  router route, or to replace it with the cache salt, on the gateway route, by rewriting those
  members in the text of a body that a strict JSON scanner accepts as one
  object; every other byte is the caller's. The enclave client never
  changes a body. On the router route, a body that the scanner does not
  accept is sent unchanged; on the
  gateway route, a JSON body that is not strictly one JSON value is refused.
- The gateway and its catalog are untrusted: they only propose replicas.
  Each replica is verified against its model's pin, or for a model without
  one against the catalog's repository, which must be a bare `tinfoilsh/`
  name, before a body is sealed to it, and a body is sealed only to the key
  of that verification. Nothing read from the gateway may relax a check or
  choose a tag or a digest, and none of it is parsed with code that recurses
  on its input. The client routes on the same model that the server will
  read: a body or an upload in which two parsers could find different
  models is refused, not interpreted, and a request that names no model is
  refused before the catalog is read. The client's cache secret never
  leaves the device on this route; only the salt that is derived from it
  does.
- Every export of the gateway route carries `@ExperimentalTinfoilApi`, its
  KDoc says that it may change or be removed, and `ExperimentalApiTest`
  of its module lists it. Experimental classes stay in the API dumps.
- The OpenAI SDK reaches the network only through this SDK's attested
  clients. Depend on `openai-java-core` alone: the artifacts `openai-java`
  and `openai-java-client-okhttp` bring an HTTP client of their own and must
  stay off the classpath. `Client` takes only an `AttestedHttpClient`, which
  is sealed to this SDK's three clients. It sets the OpenAI SDK's HTTP
  client and base URL after the caller's options, so that a base URL from
  the caller, `OPENAI_BASE_URL` or a data residency option has no effect;
  the caller chooses only the API path, which is checked against RFC 3986's
  `path-absolute` without dot segments, `%2F` or `%5C`. It takes no
  credential, URL or option from
  the environment or from system properties; `OpenAIHttpAdapter` opens no
  connection. What the OpenAI SDK reads there by itself is known and
  harmless: `OPENAI_LOG` when its options builder is made, which is then
  overridden with logging off, and `os.*` and `java.version` for its
  `X-Stainless-*` headers.
- A failure that must not be retried, an `AttestationException` or a
  `ConfigurationException`, leaves the adapter wrapped in a plain
  `OpenAIException`, never as an `IOException` or an `OpenAIIoException`:
  the OpenAI SDK sends a request again after those.
- The OpenAI SDK's client is exposed as it is. Do not wrap its services or
  re-declare its calls.
- The process's cache secret, which the router and gateway clients use when
  they are given none, comes from a secure random number generator and
  nowhere else: no environment variable, file or other source is read, and
  it is never written. If the generator fails, its exception reaches the
  caller unchanged and nothing is kept; no predictable value is ever used.
- Never put an API key, a cache secret, a session recovery token or key
  material in a log, an exception message or a `toString()`.
- A `create` function takes what it requires as parameters and everything
  else as a property of its options type, in its module's `Options.kt`, set
  in the one block that it takes. A new option is a new property with a
  default, never a new parameter or an overload. The block runs once, on the
  caller's thread, and a client is made only from the copies that are taken
  when it returns (`sh.tinfoil.internal.Settings.kt`). The options types are
  marked `@TinfoilOptionsDsl`, and only the two `Options.kt` files make one:
  their constructors are `internal`. An option of a route is declared once,
  in `tinfoil`; `tinfoil-openai` has the options of the OpenAI client alone.
  Do not copy an option into `tinfoil-openai`.
- The suspending functions and `close()` of every client are safe to call
  from Android's main thread, where the platform refuses network work, the
  closing of a TLS socket included. Nothing that they do on the caller's
  thread may reach a socket, read a request body, or call into the verifier
  library, whose first use loads it: such work runs through
  `sh.tinfoil.internal.Background`. `MainThreadSafetyTest` and
  `OpenAIMainThreadSafetyTest` run the clients from the main thread of a
  device; `CallerThreadTest` and `OpenAICallerThreadTest` check the same on
  the JVM.
- The verifier library's test-only entry points, whose names contain
  `DangerousTestOnly`, replace the trust anchors and the clock. Only the
  conformance tests in `tinfoil/src/androidTestConformance` call them; code
  under `src/main` never names them, and a library that has them is never
  packaged or published. Do not weaken or bypass the build's checks for
  this (`checkVerifierLibraryEntryPoints` and the refusal of release tasks
  under `TINFOIL_CONFORMANCE=1`, which the convention plugin applies to both
  modules: `tinfoil-openai` would otherwise package the library as a
  dependency).
- A conformance vector that fails is a finding to investigate. Do not add it
  to the known divergences in `ConformanceVectorTest`, and do not change the
  decoding or the error classification to make it pass, without a decision
  from a maintainer.
- Comments and test names describe this code; they do not cite other SDKs.
- Live tests take credentials from the environment and skip without them.
  An instrumented test receives the API key as the instrumentation argument
  `tinfoilApiKey`, passed on the command line as
  `-Pandroid.testInstrumentationRunnerArguments.tinfoilApiKey="$TINFOIL_API_KEY"`.
  Never write a credential into a file, and never log one.
- The examples in the README are compiled, in the `DocumentationExamplesTest`
  of the module whose API they use. Change both together.
