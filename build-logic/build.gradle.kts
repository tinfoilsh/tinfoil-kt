plugins {
    `kotlin-dsl`
}

// The plugins that the convention plugin applies, at the versions of the
// version catalog. The modules get them from here, so they name no version.
dependencies {
    implementation(libs.android.gradle.plugin)
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.kotlin.serialization.plugin)
}
