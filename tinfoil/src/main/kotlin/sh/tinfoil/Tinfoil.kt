package sh.tinfoil

import sh.tinfoil.internal.SdkIdentity

/** Facts about this SDK. */
public object Tinfoil {
    /**
     * This SDK's version, as it also appears in a verification's metadata.
     * A version that ends in `-dev` is a build from source, not a release.
     */
    // Not a `const`: the compiler would copy a constant's value into the
    // code that reads it, which would then keep reporting the version that
    // it was compiled against.
    public val VERSION: String = SdkIdentity.VERSION
}
