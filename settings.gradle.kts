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
        // JitPack builds an artifact on demand for any GitHub repository, so
        // it is asked for one module only, the released EHBP client, and that
        // module is taken from nowhere else. Its bytes are pinned in
        // gradle/verification-metadata.xml.
        exclusiveContent {
            forRepository { maven("https://jitpack.io") }
            filter { includeModule("com.github.tinfoilsh", "encrypted-http-body-protocol") }
        }
    }
}

rootProject.name = "tinfoil-kt"
// tinfoil is the verifier and the attested HTTP clients; tinfoil-openai puts
// the OpenAI SDK over them, and is the only module that depends on it.
include(":tinfoil")
include(":tinfoil-openai")
