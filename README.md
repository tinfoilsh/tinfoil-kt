# Tinfoil Kotlin Client

A Kotlin client for verifiably private AI inference with [Tinfoil](https://tinfoil.sh).

This SDK is under development and is not yet ready for use.

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

The verifier library is native code for Android, so the tests that reach it
are instrumented tests; the unit tests run on the JVM without it.

The public API is pinned in `tinfoil/api/tinfoil.api`, and `apiCheck` fails
when the code and that file disagree. After a deliberate change to the API,
run `./gradlew :tinfoil:apiDump` and commit the result.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
