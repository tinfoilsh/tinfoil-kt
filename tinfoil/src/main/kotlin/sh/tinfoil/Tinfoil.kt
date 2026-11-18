package sh.tinfoil

import sh.tinfoil.internal.SdkIdentity

/** Facts about this SDK. */
public object Tinfoil {
    /**
     * This SDK's version, as it also appears in a verification's metadata.
     * A version that ends in `-dev` is a build from source, not a release.
     */
    public const val VERSION: String = SdkIdentity.VERSION
}
