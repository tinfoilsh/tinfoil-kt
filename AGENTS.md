# AGENTS.md

Guidance for AI agents working in this repository.

## Layout

- `tinfoil/`: the SDK, an Android library in the package `sh.tinfoil`.
  Everything under `sh.tinfoil.internal` is implementation detail.
- `tinfoil-go.properties`: the tinfoil-go commit that the attestation verifier
  library is built from.

## The verifier is not written here

Attestation documents are verified by a native library built from
[tinfoil-go](https://github.com/tinfoilsh/tinfoil-go) and bundled into this
SDK's AAR. Never reimplement or relax a verification check in Kotlin; a change
to what is verified belongs in tinfoil-go.

## Building and testing

`TINFOIL_GO_AAR` must name a `TinfoilGo.aar`; see the README.

- `./gradlew :tinfoil:testDebugUnitTest` runs the unit tests on the JVM. The
  verifier library cannot load there, so these tests use fakes for it.
- `./gradlew :tinfoil:connectedDebugAndroidTest` runs the tests that reach the
  verifier library, on a running emulator or a device.
- Instrumented tests that reach production enclaves are skipped unless the
  instrumentation argument `tinfoilIntegration` is `true`:
  `-Pandroid.testInstrumentationRunnerArguments.tinfoilIntegration=true`.
  Run them after a change to verification, the TLS pin or the transports.
- `./gradlew :tinfoil:lintRelease` must pass; warnings are errors.
- `./gradlew :tinfoil:apiCheck` compares the public API with
  `tinfoil/api/tinfoil.api`. Change that file only with
  `./gradlew :tinfoil:apiDump`, and only for a deliberate API change.

## Rules

- Fail closed: no request leaves before its enclave is verified, and option
  errors are raised before any network I/O.
- A request is written only to a connection whose leaf certificate carries
  the attested key, checked after the platform's own TLS validation. Nothing
  that can weaken that check, such as trusted roots, a proxy or a stand-in
  verifier, is part of the public API. Tests reach them through `internal`
  members, and those on a public class are also `@JvmSynthetic`, because
  Kotlin's `internal` is public to Java; a public class has no ordinary
  member that takes one. Classes under `sh.tinfoil.internal` stay visible to
  Java as such, and are not an API.
- The router list is untrusted: it only proposes hosts, and each is verified
  against the router's pin like any enclave. Nothing read from it may relax
  a check, choose a pin, or be parsed with code that recurses on its input.
- A request body is changed only to add the user cache secret, by splicing
  it into the text of a body that a strict JSON scanner accepts as one
  object; every other byte is the caller's. A body that the scanner does not
  accept is sent unchanged.
- Never put an API key, a cache secret or key material in a log, an exception
  message or a `toString()`.
- Comments and test names describe this code; they do not cite other SDKs.
- Live tests take credentials from the environment and skip without them.
  Never write a credential into a file.
