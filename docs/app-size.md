# App size

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
