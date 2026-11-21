package sh.tinfoil

import sh.tinfoil.internal.verification.VerifierInputs
import sh.tinfoil.internal.verification.VerifierOptions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.nanoseconds

class TrustTest {
    @Test
    fun thePublicRegistryIdIsReadableWithoutTheNativeLibrary() {
        assertEquals("https://registry.tinfoil.sh/scopes/public", Trust.PUBLIC_REGISTRY_ID)
    }

    @Test
    fun aRepoPinTrustsThePublicRegistryForItsRepository() {
        val inputs = VerifierInputs.of(Trust.RepoPin("org/repo@v1"))
        assertNull(inputs.config)
        assertEquals(Pin(repo = "org/repo@v1"), inputs.pin)
    }

    @Test
    fun aProjectPinTrustsThePublicRegistryOrExactlyTheRegistriesThatItLists() {
        val public = VerifierInputs.of(Trust.ProjectPin("org/project"))
        assertNull(public.config)
        assertEquals(Pin(project = "org/project"), public.pin)

        val listed = VerifierInputs.of(Trust.ProjectPin("org/project", listOf("a", Trust.PUBLIC_REGISTRY_ID)))
        assertEquals(listOf("a", Trust.PUBLIC_REGISTRY_ID), assertIs<VerifierOptions.ConfigTrust.Registries>(listed.config).ids)
        assertEquals(Pin(project = "org/project"), listed.pin)
    }

    /** An empty list that an application computed must not widen trust to the public registry. */
    @Test
    fun anEmptyListOfRegistriesIsRefused() {
        val error = assertFailsWith<ConfigurationException> { VerifierInputs.of(Trust.ProjectPin("org/project", emptyList())) }
        assertTrue(error.detail.contains("registryIds must not be empty"), error.detail)
    }

    @Test
    fun signedByTrustsTheKeysAndPinsItsProjectIfAny() {
        val restricted = VerifierInputs.of(Trust.SignedBy(listOf("key"), "org/project"))
        assertEquals(listOf("key"), assertIs<VerifierOptions.ConfigTrust.SigningKeys>(restricted.config).keysPem)
        assertEquals(Pin(project = "org/project"), restricted.pin)
        assertEquals(Pin.NONE, VerifierInputs.of(Trust.SignedBy(listOf("key"))).pin)
        assertEquals(Pin.NONE, VerifierInputs.of(Trust.SignedBy(listOf("key"), "")).pin)
        // The library refuses an empty list of keys.
        assertEquals(
            emptyList(),
            assertIs<VerifierOptions.ConfigTrust.SigningKeys>(VerifierInputs.of(Trust.SignedBy(emptyList())).config).keysPem,
        )
    }

    @Test
    fun aConfigThatTheCallerSuppliesOrApprovesHasNoPin() {
        val authorize = ConfigAuthorizer { }
        val authorized = VerifierInputs.of(Trust.AuthorizedBy(authorize))
        assertSame(authorize, assertIs<VerifierOptions.ConfigTrust.Authorizer>(authorized.config).authorizer)
        assertEquals(Pin.NONE, authorized.pin)

        val embedded = VerifierInputs.of(Trust.EmbeddedConfig(byteArrayOf(1, 2), "/org/project/v1"))
        val config = assertIs<VerifierOptions.ConfigTrust.EmbeddedConfig>(embedded.config)
        assertContentEquals(byteArrayOf(1, 2), config.bytes)
        assertEquals("/org/project/v1", config.name)
        assertEquals(Pin.NONE, embedded.pin)
        assertNull(assertIs<VerifierOptions.ConfigTrust.EmbeddedConfig>(VerifierInputs.of(Trust.EmbeddedConfig(byteArrayOf(1), "")).config).name)
    }

    @Test
    fun anEitherPinPinsBoth() {
        val inputs = VerifierInputs.of(Trust.EitherPin("org/repo", "org/project"))
        assertNull(inputs.config)
        assertEquals(Pin(repo = "org/repo", project = "org/project"), inputs.pin)
    }

    @Test
    fun aVariantWithoutWhatItRequiresIsRefused() {
        val refused = mapOf(
            "RepoPin requires a repo" to Trust.RepoPin(""),
            "ProjectPin requires a project" to Trust.ProjectPin(""),
            "EitherPin requires both" to Trust.EitherPin("", "org/project"),
            "EitherPin requires both " to Trust.EitherPin("org/repo", ""),
        )
        for ((message, trust) in refused) {
            val error = assertFailsWith<ConfigurationException>(trust.toString()) { VerifierInputs.of(trust) }
            assertTrue(error.detail.contains(message.trim()), error.detail)
        }
    }

    @Test
    fun variantsCopyWhatTheyAreGivenAndCompareByValue() {
        val ids = mutableListOf("a")
        val project = Trust.ProjectPin("org/project", ids)
        ids[0] = "b"
        assertEquals(listOf("a"), project.registryIds)

        val keys = mutableListOf("key")
        val signed = Trust.SignedBy(keys)
        keys[0] = "other"
        assertEquals(listOf("key"), signed.keys)

        val bytes = byteArrayOf(1, 2)
        val embedded = Trust.EmbeddedConfig(bytes)
        bytes[0] = 9
        embedded.bytes[1] = 9
        assertContentEquals(byteArrayOf(1, 2), embedded.bytes)

        assertEquals(Trust.RepoPin("org/repo"), Trust.RepoPin("org/repo"))
        assertEquals(Trust.ProjectPin("org/p", listOf("a")), Trust.ProjectPin("org/p", listOf("a")))
        assertNotEquals(Trust.ProjectPin("org/p"), Trust.ProjectPin("org/p", emptyList()))
        assertEquals(Trust.EmbeddedConfig(byteArrayOf(1), "n"), Trust.EmbeddedConfig(byteArrayOf(1), "n"))
        assertEquals(Trust.EmbeddedConfig(byteArrayOf(1)).hashCode(), Trust.EmbeddedConfig(byteArrayOf(1)).hashCode())
        assertNotEquals<Trust>(Trust.RepoPin("org/repo"), Trust.EitherPin("org/repo", "org/repo"))
    }

    @Test
    fun aPolicyCrossesToTheLibrary() {
        assertNull(VerifierInputs.policy(Policy()).freshnessMaxAgeNs)
        assertNull(VerifierInputs.policy(Policy()).artifacts)
        assertEquals(3_600_000_000_000, VerifierInputs.policy(Policy(freshnessMaxAge = 1.hours)).freshnessMaxAgeNs)
        val keys = VerifierInputs.policy(Policy(artifacts = ArtifactTrust.EndorsedArtifacts(listOf("key")))).artifacts
        assertEquals(listOf("key"), assertIs<VerifierOptions.Artifacts.Endorsed>(keys).freshnessKeysPem)
        val embedded = VerifierInputs.policy(Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = byteArrayOf(1)))).artifacts
        assertContentEquals(byteArrayOf(1), assertIs<VerifierOptions.Artifacts.Embedded>(embedded).runtime)
    }

    @Test
    fun aNegativeFreshnessBoundIsRefused() {
        for (age in listOf((-1).nanoseconds, -Duration.INFINITE, Duration.INFINITE)) {
            val error = assertFailsWith<ConfigurationException>(age.toString()) {
                VerifierInputs.policy(Policy(freshnessMaxAge = age))
            }
            assertTrue(error.detail.contains("freshness maximum age"), error.detail)
        }
    }
}
