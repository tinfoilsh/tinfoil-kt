# Contributing

## Development

The SDK is two Android library modules: `tinfoil`, the verifier and the
attested HTTP clients, and `tinfoil-openai`, the OpenAI clients over them.
Building them needs JDK 17 and the Android SDK (`ANDROID_HOME`):

```bash
./gradlew assembleRelease lintRelease testDebugUnitTest apiCheck
./gradlew connectedDebugAndroidTest   # needs a running emulator or a device
```

The attestation verifier library, `TinfoilGo.aar`, is the one that a
[tinfoil-go](https://github.com/tinfoilsh/tinfoil-go) release publishes.
`tinfoil-go.properties` pins the release by its tag (`version`) and the
library by its SHA-256 (`sha256`). The build downloads the library from the
release and refuses it unless its SHA-256 is the pinned one; it never builds
the library, and never reads the checksum from the release. To move to
another release, run

```bash
./update_verifier.sh v0.17.0
```

which downloads that release's library, checks it against the checksum that
the release publishes, and writes the tag and the library's SHA-256 together.
Build and test against it, and commit `tinfoil-go.properties` in a change of
its own.

To work against a tinfoil-go that is not released, build the library from a
tinfoil-go checkout and name it with `TINFOIL_GO_AAR` (or the Gradle property
`tinfoilGoAar`); a relative path is resolved against this repository's root.
That library replaces the pinned release, is not checked against the pin, and
the build says so:

```bash
# in a tinfoil-go checkout
bash scripts/setup-mobile.sh
bash scripts/build-mobile-android.sh /path/to/TinfoilGo.aar

# in this repository
TINFOIL_GO_AAR=/path/to/TinfoilGo.aar ./gradlew testDebugUnitTest
```

A task that is named without a module runs in both. Name the module to run
it in one, as in `./gradlew :tinfoil:testDebugUnitTest` or
`./gradlew :tinfoil-openai:connectedDebugAndroidTest`. `tinfoil` does not
depend on the OpenAI SDK, and its build fails if a dependency ever brings
that in.

### The EHBP client

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

### Tests

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
verifier library with two test-only entry points that accept them. No release
publishes that library: it is built from the tag of the pinned release with
`MOBILE_BUILD_TAGS`, and named with `TINFOIL_GO_AAR`, without which the
conformance build fails:

```bash
# in a tinfoil-go checkout at the tag in tinfoil-go.properties
git checkout "$(sed -n 's/^version=//p' /path/to/tinfoil-kt/tinfoil-go.properties)"
bash scripts/setup-mobile.sh
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
build fails when its library, the pinned release's or the one that
`TINFOIL_GO_AAR` names, has those entry points. With it, the build fails
when the library lacks them, and refuses every task, in either module, that
packages the SDK, belongs to the release variant or publishes; only the
instrumented tests run.

### Version and API

The SDK's version is `version` in `gradle.properties`, for both modules, and
`Tinfoil.VERSION` is generated from it.

The public API of each module is pinned, in `tinfoil/api/tinfoil.api` and
`tinfoil-openai/api/tinfoil-openai.api`, and `apiCheck` fails when the code
and those files disagree. After a deliberate change to the API, run
`./gradlew apiDump` and commit the result.
