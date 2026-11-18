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
- `./gradlew :tinfoil:lintRelease` must pass; warnings are errors.

## Rules

- Fail closed: no request leaves before its enclave is verified, and option
  errors are raised before any network I/O.
- Never put an API key, a cache secret or key material in a log, an exception
  message or a `toString()`.
- Comments and test names describe this code; they do not cite other SDKs.
- Live tests take credentials from the environment and skip without them.
  Never write a credential into a file.
