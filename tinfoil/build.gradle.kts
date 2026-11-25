import groovy.json.JsonException
import groovy.json.JsonSlurper
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Duration
import java.util.Properties
import java.util.zip.ZipFile

plugins {
    id("tinfoil.android-library")
}
// It comes with the convention plugin's own dependencies, at the Kotlin
// version of the version catalog, so it is applied by name.
apply(plugin = "org.jetbrains.kotlin.plugin.serialization")

// The Go verifier library, TinfoilGo.aar, is the one that a tinfoil-go release
// publishes. tinfoil-go.properties pins the release by its tag and the
// library's SHA-256, and the build downloads the library and refuses it unless
// its SHA-256 is the pinned one. The checksum is never read from the release.
abstract class DownloadTinfoilGo : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val pin: RegularFileProperty

    @get:OutputFile
    abstract val aar: RegularFileProperty

    @TaskAction
    fun download() {
        val pinFile = pin.get().asFile
        val pinned = Properties().apply { pinFile.inputStream().use(::load) }
        val version = pinned.getProperty("version")?.takeIf { VERSION.matches(it) }
            ?: throw GradleException("${pinFile.name} names no tinfoil-go release version, such as v0.17.0")
        val expected = pinned.getProperty("sha256")?.takeIf { SHA256.matches(it) }
            ?: throw GradleException("${pinFile.name} names no SHA-256 of TinfoilGo.aar, as 64 lowercase hex digits")
        val url = URI("https://github.com/tinfoilsh/tinfoil-go/releases/download/$version/TinfoilGo.aar")

        val target = aar.get().asFile
        target.delete()
        target.parentFile.mkdirs()
        val partial = File(target.parentFile, "${target.name}.partial")
        partial.delete()
        // Redirect.NORMAL follows GitHub's redirect to its download host and
        // never follows one from HTTPS to HTTP. GitHub's download host can
        // refuse a stream of an HTTP/2 connection, so HTTP/1.1 is used.
        val client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(30))
            .build()
        val request = HttpRequest.newBuilder(url).timeout(Duration.ofMinutes(5)).GET().build()
        val response = try {
            client.send(request, HttpResponse.BodyHandlers.ofInputStream())
        } catch (e: IOException) {
            throw GradleException("Could not download the verifier library from $url: ${e.message}", e)
        }
        val digest = MessageDigest.getInstance("SHA-256")
        response.body().use { body ->
            if (response.statusCode() != 200) {
                throw GradleException("Could not download the verifier library from $url: HTTP ${response.statusCode()}")
            }
            partial.outputStream().use { out ->
                val buffer = ByteArray(1 shl 16)
                var total = 0L
                while (true) {
                    val read = body.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_SIZE) {
                        partial.delete()
                        throw GradleException("The verifier library at $url is larger than $MAX_SIZE bytes")
                    }
                    digest.update(buffer, 0, read)
                    out.write(buffer, 0, read)
                }
            }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        if (actual != expected) {
            partial.delete()
            throw GradleException(
                "The verifier library at $url has SHA-256 $actual, and ${pinFile.name} pins $expected. " +
                    "It is refused. Re-pin only with update_verifier.sh, after checking the release.",
            )
        }
        Files.move(partial.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
    }

    private companion object {
        val VERSION = Regex("v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?")
        val SHA256 = Regex("[0-9a-f]{64}")
        const val MAX_SIZE = 256L * 1024 * 1024
    }
}

val downloadTinfoilGo by tasks.registering(DownloadTinfoilGo::class) {
    pin.set(rootProject.layout.projectDirectory.file("tinfoil-go.properties"))
    aar.set(layout.buildDirectory.file("tinfoil-go-release/TinfoilGo.aar"))
}

// TINFOIL_GO_AAR, or the tinfoilGoAar Gradle property, replaces the pinned
// release with a local TinfoilGo.aar, such as one that is built from an
// unreleased tinfoil-go with its scripts/build-mobile-android.sh, or the
// conformance build's library. A relative path is resolved against the
// repository root. That library is not checked against the pin.
val tinfoilGoOverride: File? = providers.environmentVariable("TINFOIL_GO_AAR")
    .orElse(providers.gradleProperty("tinfoilGoAar"))
    .orNull
    ?.takeIf { it.isNotEmpty() }
    ?.let { rootProject.layout.projectDirectory.file(it).asFile }

// Whether this is the conformance build, which the convention plugin reads
// from TINFOIL_CONFORMANCE and refuses to package.
val isConformanceBuild: Boolean = extra["tinfoilConformanceBuild"] as Boolean
if (isConformanceBuild && tinfoilGoOverride == null) {
    throw GradleException(
        "TINFOIL_CONFORMANCE=1 needs TINFOIL_GO_AAR to name a verifier library built with " +
            "MOBILE_BUILD_TAGS=tinfoil_conformance, which no release publishes; see the README",
    )
}

// An Android library cannot depend on a local AAR and still be packaged as
// one, so the Go library is unpacked and its parts are bundled into this
// library's own AAR: the classes as a jar, the native libraries as JNI
// libraries, and its keep rules as consumer rules. Consumers then depend on
// one artifact.
val unpackTinfoilGo by tasks.registering(Sync::class) {
    val override = tinfoilGoOverride
    if (override != null) {
        from(zipTree(override)) {
            include("classes.jar", "jni/**", "proguard.txt")
        }
    } else {
        dependsOn(downloadTinfoilGo)
        from(zipTree(downloadTinfoilGo.flatMap { it.aar })) {
            include("classes.jar", "jni/**", "proguard.txt")
        }
    }
    into(layout.buildDirectory.dir("tinfoil-go"))
}
if (tinfoilGoOverride != null) {
    logger.warn("Using the verifier library that TINFOIL_GO_AAR names, $tinfoilGoOverride, instead of the pinned release")
}
val tinfoilGoDir = layout.buildDirectory.dir("tinfoil-go").get().asFile

// Fails the build when the unpacked verifier library is not the kind that
// this build is for: a test-only entry point outside the conformance build,
// or none in it.
abstract class CheckVerifierLibraryEntryPoints : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val library: DirectoryProperty

    @get:Input
    abstract val conformanceBuild: Property<Boolean>

    @TaskAction
    fun check() {
        val directory = library.get().asFile
        val jar = directory.resolve("classes.jar")
        val nativeLibraries = directory.resolve("jni").walk().filter { it.isFile }.toList()
        if (!jar.isFile || nativeLibraries.isEmpty()) {
            throw GradleException("The verifier library in $directory has no classes or no native libraries")
        }
        // Names survive as plain text in a class file and in a native
        // library, so each is searched as bytes.
        val parts = mutableMapOf<String, String>()
        ZipFile(jar).use { zip ->
            for (entry in zip.entries()) {
                if (!entry.isDirectory) {
                    parts["classes.jar!/${entry.name}"] = zip.getInputStream(entry).use { it.readBytes() }.toString(Charsets.ISO_8859_1)
                }
            }
        }
        for (file in nativeLibraries) {
            parts[file.relativeTo(directory).path] = file.readBytes().toString(Charsets.ISO_8859_1)
        }
        val carriers = parts.filterValues { it.contains(MARKER, ignoreCase = true) }.keys
        if (!conformanceBuild.get()) {
            if (carriers.isNotEmpty()) {
                throw GradleException(
                    "The verifier library has test-only entry points, which replace the trust anchors and " +
                        "must never ship (found in ${carriers.joinToString()}). If TINFOIL_GO_AAR names it, build " +
                        "it without MOBILE_BUILD_TAGS; only the conformance tests, with TINFOIL_CONFORMANCE=1, use " +
                        "one that has them.",
                )
            }
            return
        }
        val classes = parts.filterKeys { it.startsWith("classes.jar!/") }.values
        val missing = ENTRY_POINTS.filter { entryPoint -> classes.none { it.contains(entryPoint) } } +
            nativeLibraries.map { it.relativeTo(directory).path }.filter { it !in carriers }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "TINFOIL_CONFORMANCE=1 needs a verifier library built with MOBILE_BUILD_TAGS=tinfoil_conformance, " +
                    "and TINFOIL_GO_AAR names one without its test-only entry points (missing: " +
                    "${missing.joinToString()})",
            )
        }
    }

    private companion object {
        const val MARKER = "DangerousTestOnly"
        val ENTRY_POINTS = listOf("newDangerousTestOnlyVerifier", "dangerousTestOnlyVerifyAt")
    }
}

// The check has no outputs, so it runs in every build.
val checkVerifierLibraryEntryPoints by tasks.registering(CheckVerifierLibraryEntryPoints::class) {
    library.set(layout.dir(unpackTinfoilGo.map { it.destinationDir }))
    conformanceBuild.set(isConformanceBuild)
}

// Every variant's native-library, keep-rule and compile tasks read the
// unpacked library, and each depends on preBuild.
tasks.named("preBuild") { dependsOn(unpackTinfoilGo, checkVerifierLibraryEntryPoints) }

// The conformance tests run the full-verify vectors of the conformance suite
// at the commit in tinfoil-conformance.properties. TINFOIL_CONFORMANCE_VECTORS,
// or the tinfoilConformanceVectors Gradle property, names the suite's vectors
// directory. Only the full-verify vectors are packaged, as assets of the test
// APK; every JSON file in the directory must parse, so that a vector broken
// by an edit fails the build rather than drops out.
abstract class PackageConformanceVectors : DefaultTask() {
    @get:Input
    abstract val vectorsDirectory: Property<String>

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val vectorFiles: ConfigurableFileCollection

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val pin: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun pack() {
        val source = vectorsDirectory.get().takeIf { it.isNotEmpty() }?.let(::File)
            ?: throw GradleException(
                "TINFOIL_CONFORMANCE=1 needs TINFOIL_CONFORMANCE_VECTORS, the conformance suite's vectors directory",
            )
        if (!source.isDirectory) {
            throw GradleException("TINFOIL_CONFORMANCE_VECTORS names no directory: $source")
        }
        val pinned = Properties().apply { pin.get().asFile.inputStream().use(::load) }
        val expected = pinned.getProperty(COUNT)?.toIntOrNull()
            ?: throw GradleException("${pin.get().asFile.name} names no $COUNT")

        val output = outputDir.get().asFile
        output.deleteRecursively()
        val vectors = output.resolve("conformance/vectors")
        var packaged = 0
        for (file in source.walk().filter { it.isFile && it.extension == "json" }.sortedBy { it.path }) {
            val parsed = try {
                JsonSlurper().parse(file)
            } catch (e: JsonException) {
                throw GradleException("Conformance vector $file is not JSON: ${e.message}", e)
            }
            if ((parsed as? Map<*, *>)?.get("stage") != FULL_VERIFY_STAGE) {
                continue
            }
            file.copyTo(vectors.resolve(file.relativeTo(source).path))
            packaged++
        }
        if (packaged != expected) {
            throw GradleException(
                "Found $packaged full-verify vectors under $source, and ${pin.get().asFile.name} pins $expected. " +
                    "Check out the suite at the pinned commit, ${pinned.getProperty("commit")}.",
            )
        }
        pin.get().asFile.copyTo(output.resolve("conformance/pin.properties"))
    }

    private companion object {
        const val FULL_VERIFY_STAGE = "verify-attestation-v3"
        const val COUNT = "fullVerifyVectors"
    }
}

val packageConformanceVectors by tasks.registering(PackageConformanceVectors::class) {
    val directory = providers.environmentVariable("TINFOIL_CONFORMANCE_VECTORS")
        .orElse(providers.gradleProperty("tinfoilConformanceVectors"))
        .map { rootProject.layout.projectDirectory.asFile.resolve(it).normalize().path }
        .orElse("")
    vectorsDirectory.set(directory)
    vectorFiles.from(directory.map { path -> if (path.isEmpty()) files() else fileTree(path) { include("**/*.json") } })
    pin.set(rootProject.layout.projectDirectory.file("tinfoil-conformance.properties"))
}

// The SDK's version is the Gradle project's, set in gradle.properties. It is
// compiled in as a constant, from a source file that is written here.
abstract class GenerateSdkVersion : DefaultTask() {
    @get:Input
    abstract val sdkVersion: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val version = sdkVersion.get()
        // The version becomes a string literal, so it must not be able to end one.
        if (!Regex("[0-9A-Za-z][0-9A-Za-z.+-]*").matches(version)) {
            throw GradleException("The project version is not a version: $version")
        }
        val file = outputDir.get().file("sh/tinfoil/internal/GeneratedSdkVersion.kt").asFile
        file.parentFile.mkdirs()
        file.writeText(
            """
            |package sh.tinfoil.internal
            |
            |/** Generated by the build from the Gradle project's version. */
            |internal object GeneratedSdkVersion {
            |    const val VERSION: String = "$version"
            |}
            |
            """.trimMargin(),
        )
    }
}

val generateSdkVersion by tasks.registering(GenerateSdkVersion::class) {
    sdkVersion.set(providers.provider { project.version.toString() })
}

// This artifact is for apps that want the verifier and the attested HTTP
// clients without the OpenAI SDK, which, with Jackson and kotlin-reflect,
// adds megabytes that shrinking does not remove. So none of them may be
// among what this artifact brings to an app, directly or through another
// dependency: they belong to tinfoil-openai.
abstract class CheckRuntimeDependencies : DefaultTask() {
    /** The modules of the runtime classpath, as `group:name`. */
    @get:Input
    abstract val modules: SetProperty<String>

    @TaskAction
    fun check() {
        val unwanted = modules.get().filter { module -> UNWANTED.any { module.startsWith(it) } }.sorted()
        if (unwanted.isNotEmpty()) {
            throw GradleException(
                "The tinfoil artifact must not depend on the OpenAI SDK, Jackson or kotlin-reflect, and its release " +
                    "runtime classpath has ${unwanted.joinToString()}. Such a dependency belongs to tinfoil-openai.",
            )
        }
    }

    private companion object {
        val UNWANTED = listOf("com.openai:", "com.fasterxml.jackson", "org.jetbrains.kotlin:kotlin-reflect")
    }
}

// The check has no outputs, so it runs in every build.
val checkRuntimeDependencies by tasks.registering(CheckRuntimeDependencies::class) {
    modules.set(
        providers.provider {
            configurations.getByName("releaseRuntimeClasspath").incoming.resolutionResult.allComponents
                .mapNotNull { (it.id as? ModuleComponentIdentifier)?.let { id -> "${id.group}:${id.module}" } }
                .toSet()
        },
    )
}
tasks.named("preBuild") { dependsOn(checkRuntimeDependencies) }

androidComponents {
    onVariants { variant ->
        variant.sources.java?.addGeneratedSourceDirectory(generateSdkVersion, GenerateSdkVersion::outputDir)
        if (isConformanceBuild) {
            // Assets of the test APK only; a library's own assets would be
            // part of its AAR.
            variant.androidTest?.sources?.assets
                ?.addGeneratedSourceDirectory(packageConformanceVectors, PackageConformanceVectors::outputDir)
        }
    }
}

android {
    namespace = "sh.tinfoil"

    defaultConfig {
        consumerProguardFiles(tinfoilGoDir.resolve("proguard.txt"))
    }

    sourceSets["main"].jniLibs.srcDir(tinfoilGoDir.resolve("jni"))
    if (isConformanceBuild) {
        // These tests call the test-only entry points, which only the
        // conformance build of the verifier library has, so they are not
        // sources of an ordinary build.
        sourceSets["androidTest"].kotlin.srcDir("src/androidTestConformance/kotlin")
        // The golden files of the report's JSON form, which they check
        // against the vectors that the files name.
        sourceSets["androidTest"].assets.srcDir("testdata")
    }

    // The fakes and test servers that the tests of every module share. They
    // are sources of this module so that they can use its internals, and
    // are never published: they replace the trust anchors and the verifier.
    testFixtures {
        enable = true
    }
}

kotlin {
    compilerOptions {
        // This module owns what is marked for the SDK's other artifacts.
        optIn.add("sh.tinfoil.InternalTinfoilApi")
    }
}

// ExperimentalApiTest reads the committed API, and ReportJsonTest the golden
// files of the report's JSON form.
tasks.withType<Test>().configureEach {
    inputs.files("api/tinfoil.api").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir("testdata").withPathSensitivity(PathSensitivity.RELATIVE)
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

    testFixturesApi(libs.okhttp.tls)
    testFixturesApi(libs.okhttp.mockwebserver)
    testFixturesImplementation(libs.ehbp)

    testImplementation(libs.junit)
    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.okhttp.mockwebserver)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlin.test.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.okhttp.tls)
    androidTestImplementation(libs.okhttp.mockwebserver)
}
