import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// What every module of this SDK that becomes an artifact has in common: an
// Android library in Kotlin, with an explicit API and no warnings, that is
// never packaged in the conformance build.

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

// TINFOIL_CONFORMANCE=1, or the tinfoilConformance Gradle property, selects
// the conformance build: TINFOIL_GO_AAR then names a verifier library built
// with MOBILE_BUILD_TAGS=tinfoil_conformance, and the conformance tests are
// compiled against it. That library has two test-only entry points, which
// replace the trust anchors and set the clock, so nothing built in this mode
// may be packaged or published.
val isConformanceBuild: Boolean = providers.environmentVariable("TINFOIL_CONFORMANCE")
    .orElse(providers.gradleProperty("tinfoilConformance"))
    .orNull
    .let { setting ->
        when (setting) {
            null, "", "0" -> false
            "1" -> true
            else -> throw GradleException("TINFOIL_CONFORMANCE must be 1 or 0, not \"$setting\"")
        }
    }
// For the module's own build file.
extra["tinfoilConformanceBuild"] = isConformanceBuild

// The conformance build exists to run instrumented tests. A task that
// packages a library, belongs to the release variant or publishes anything
// is refused before any task runs, in every module, so that the test-only
// verifier library cannot reach an artifact of this SDK: not its own, and
// not, as a dependency, another's.
if (isConformanceBuild) {
    val projectPrefix = "${project.path}:"
    val refusedNames = Regex("(?i).*release.*|publish.*|bundle.*Aar")
    gradle.taskGraph.whenReady {
        val refused = allTasks.map { it.path }
            .filter { it.startsWith(projectPrefix) && refusedNames.matches(it.removePrefix(projectPrefix)) }
        if (refused.isNotEmpty()) {
            throw GradleException(
                "TINFOIL_CONFORMANCE=1 builds against the test-only verifier library, which must never ship, " +
                    "so it only runs the instrumented tests. Refused: ${refused.take(5).joinToString()}" +
                    if (refused.size > 5) " and ${refused.size - 5} more" else "",
            )
        }
    }
}

android {
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        // Versions are pinned and bumped deliberately, in their own changes.
        disable += setOf("GradleDependency", "AndroidGradlePluginVersion", "NewerVersionAvailable")
    }
}

// A failing test prints its whole stack trace, causes included, so that a
// failure that does not happen again can still be diagnosed from the log.
tasks.withType<Test>().configureEach {
    testLogging {
        events(TestLogEvent.FAILED)
        exceptionFormat = TestExceptionFormat.FULL
        showCauses = true
        showStackTraces = true
    }
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}
