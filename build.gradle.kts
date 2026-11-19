plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.binary.compatibility.validator)
}

apiValidation {
    // What one artifact of this SDK offers only to the others is not part
    // of the public API: they are released together, and each depends on
    // exactly its own version of the others.
    nonPublicMarkers.add("sh.tinfoil.InternalTinfoilApi")
}
