package sh.tinfoil.internal

/** How this SDK identifies itself in the metadata of a verification. */
internal object SdkIdentity {
    const val NAME: String = "tinfoil-kt"

    // There is no release yet; the release tooling will derive this from the
    // published version.
    const val VERSION: String = "0.0.0-dev"
}
