package sh.tinfoil.internal

/** How this SDK identifies itself in the metadata of a verification. */
internal object SdkIdentity {
    const val NAME: String = "tinfoil-kt"

    /** The Gradle project's version, written into the build by its `generateSdkVersion` task. */
    const val VERSION: String = GeneratedSdkVersion.VERSION
}
