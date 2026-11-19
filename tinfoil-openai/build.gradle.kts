import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("tinfoil.android-library")
}

// The OpenAI clients, over the attested HTTP clients of the tinfoil
// artifact. This module has no native library and no verifier of its own:
// both come with tinfoil, at this module's own version.
android {
    namespace = "sh.tinfoil.openai"
}

// The tests read the snapshots of options that this module takes, which are
// marked as internal to the SDK's artifacts. The module's own sources opt in
// file by file, where they use one.
tasks.withType<KotlinCompile>().matching { it.name.contains("Test") }.configureEach {
    compilerOptions.optIn.add("sh.tinfoil.InternalTinfoilApi")
}

// ExperimentalApiTest reads the committed API.
tasks.withType<Test>().configureEach {
    inputs.files("api/tinfoil-openai.api", "../tinfoil/api/tinfoil.api").withPathSensitivity(PathSensitivity.RELATIVE)
}

dependencies {
    // The attested HTTP clients, their options and their exceptions are
    // part of the public API.
    api(project(":tinfoil"))
    // The OpenAI SDK's client and model types are part of the public API.
    // Only its core is used: the SDK's own HTTP client, the artifact
    // openai-java-client-okhttp, must stay off the classpath, so that
    // nothing but this SDK's attested clients can carry its requests. A
    // test checks that.
    api(libs.openai.java.core)
    // The OpenAI SDK reflects on its models with kotlin-reflect at run time.
    implementation(libs.kotlin.reflect)

    testImplementation(testFixtures(project(":tinfoil")))
    testImplementation(libs.junit)
    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.okhttp.mockwebserver)

    androidTestImplementation(testFixtures(project(":tinfoil")))
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlin.test.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
