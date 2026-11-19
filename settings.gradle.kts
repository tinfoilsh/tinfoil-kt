pluginManagement {
    // The convention plugin that the modules share.
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "tinfoil-kt"
// tinfoil is the verifier and the attested HTTP clients; tinfoil-openai puts
// the OpenAI SDK over them, and is the only module that depends on it.
include(":tinfoil")
include(":tinfoil-openai")

// The EHBP client is not released yet, so it is built from source, as an
// included build of a checkout of
// https://github.com/tinfoilsh/encrypted-http-body-protocol at the commit in
// ehbp.properties. EHBP_KOTLIN_DIR, or the ehbpKotlinDir Gradle property,
// names the checkout's kotlin/ directory; a relative path is resolved against
// this directory. The default is a checkout next to this repository.
val ehbpKotlinDir: File = providers.environmentVariable("EHBP_KOTLIN_DIR")
    .orElse(providers.gradleProperty("ehbpKotlinDir"))
    .orElse("../encrypted-http-body-protocol/kotlin")
    .map { rootDir.resolve(it).normalize() }
    .get()
if (!ehbpKotlinDir.resolve("settings.gradle.kts").isFile) {
    throw GradleException(
        "No EHBP Kotlin client at $ehbpKotlinDir. Check out " +
            "https://github.com/tinfoilsh/encrypted-http-body-protocol at the commit in ehbp.properties, " +
            "and set EHBP_KOTLIN_DIR to its kotlin/ directory.",
    )
}
// That build adds an Android subproject of its own when it finds an Android
// SDK, and loads a second copy of the Android Gradle plugin for it. Only its
// root project, a JVM library, is wanted here, so it is told to leave the
// subproject out: an included build reads the invocation's project
// properties.
gradle.startParameter.projectProperties = gradle.startParameter.projectProperties + ("noAndroid" to "true")
includeBuild(ehbpKotlinDir) {
    dependencySubstitution {
        substitute(module("sh.tinfoil:ehbp")).using(project(":"))
    }
}
