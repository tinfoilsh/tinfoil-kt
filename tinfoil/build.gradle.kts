import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

// The Go verifier library, TinfoilGo.aar, is built from tinfoil-go with its
// scripts/build-mobile-android.sh. TINFOIL_GO_AAR, or the tinfoilGoAar Gradle
// property, names it; a relative path is resolved against the repository root.
val tinfoilGoAar: Provider<RegularFile> = providers.environmentVariable("TINFOIL_GO_AAR")
    .orElse(providers.gradleProperty("tinfoilGoAar"))
    .map { rootProject.layout.projectDirectory.file(it) }

// An Android library cannot depend on a local AAR and still be packaged as
// one, so the Go library is unpacked and its parts are bundled into this
// library's own AAR: the classes as a jar, the native libraries as JNI
// libraries, and its keep rules as consumer rules. Consumers then depend on
// one artifact.
val unpackTinfoilGo by tasks.registering(Sync::class) {
    val aar = tinfoilGoAar.orNull?.asFile
    doFirst {
        if (aar == null) {
            throw GradleException(
                "Set TINFOIL_GO_AAR to a TinfoilGo.aar built with tinfoil-go's scripts/build-mobile-android.sh",
            )
        }
        if (!aar.isFile) {
            throw GradleException("TINFOIL_GO_AAR names no file: $aar")
        }
    }
    if (aar != null) {
        from(zipTree(aar)) {
            include("classes.jar", "jni/**", "proguard.txt")
        }
    }
    into(layout.buildDirectory.dir("tinfoil-go"))
}
val tinfoilGoDir = layout.buildDirectory.dir("tinfoil-go").get().asFile

// Every variant's native-library, keep-rule and compile tasks read the
// unpacked library, and each depends on preBuild.
tasks.named("preBuild") { dependsOn(unpackTinfoilGo) }

android {
    namespace = "sh.tinfoil"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles(tinfoilGoDir.resolve("proguard.txt"))
    }

    sourceSets["main"].jniLibs.srcDir(tinfoilGoDir.resolve("jni"))

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

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    implementation(files(tinfoilGoDir.resolve("classes.jar")).builtBy(unpackTinfoilGo))
    implementation(libs.kotlinx.serialization.json)
    // OkHttp's types are part of the public API: requests, responses and
    // Call.Factory.
    api(libs.okhttp)
    // Suspend functions are part of the public API.
    api(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    // The EHBP client and, through it, Bouncy Castle. No EHBP type is part of
    // the public API.
    implementation(libs.ehbp)
    // The OpenAI SDK's client and model types are part of the public API.
    // Only its core is used: the SDK's own HTTP client, the artifact
    // openai-java-client-okhttp, must stay off the classpath, so that
    // nothing but this SDK's attested clients can carry its requests. A
    // test checks that.
    api(libs.openai.java.core)
    // The OpenAI SDK reflects on its models with kotlin-reflect at run time.
    implementation(libs.kotlin.reflect)

    testImplementation(libs.junit)
    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.okhttp.mockwebserver)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlin.test.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
