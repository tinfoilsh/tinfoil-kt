plugins {
    // Loaded here, and applied by the modules, so that every project of the
    // build, and the API validator below, sees one copy of the Android and
    // Kotlin plugins that come with it.
    id("tinfoil.android-library") apply false
    alias(libs.plugins.binary.compatibility.validator)
}

apiValidation {
    // What one artifact of this SDK offers only to the others is not part
    // of the public API: they are released together, and each depends on
    // exactly its own version of the others.
    nonPublicMarkers.add("sh.tinfoil.InternalTinfoilApi")
}
