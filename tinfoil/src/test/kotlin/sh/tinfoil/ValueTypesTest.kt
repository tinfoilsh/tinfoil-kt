package sh.tinfoil

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

class ValueTypesTest {
    @Test
    fun aConfigEndorsementCopiesItsArraysInAndOut() {
        val config = byteArrayOf(1, 2, 3)
        val bundle = byteArrayOf(4, 5)
        val issuer = byteArrayOf(6)
        val endorsement = ConfigEndorsement(config, "sha256:ab", bundle, issuer)

        config[0] = 9
        bundle[0] = 9
        issuer[0] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), endorsement.config)
        assertContentEquals(byteArrayOf(4, 5), endorsement.sigstoreBundle)
        assertContentEquals(byteArrayOf(6), endorsement.issuerCertificate)

        endorsement.config[0] = 9
        endorsement.sigstoreBundle!![0] = 9
        endorsement.issuerCertificate!![0] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), endorsement.config)
        assertContentEquals(byteArrayOf(4, 5), endorsement.sigstoreBundle)
        assertContentEquals(byteArrayOf(6), endorsement.issuerCertificate)
    }

    @Test
    fun configEndorsementsCompareByContent() {
        val one = ConfigEndorsement(byteArrayOf(1), "sha256:ab", byteArrayOf(2), byteArrayOf(3))
        val same = ConfigEndorsement(byteArrayOf(1), "sha256:ab", byteArrayOf(2), byteArrayOf(3))
        assertEquals(one, same)
        assertEquals(one.hashCode(), same.hashCode())
        assertNotEquals(one, ConfigEndorsement(byteArrayOf(9), "sha256:ab", byteArrayOf(2), byteArrayOf(3)))
        assertNotEquals(one, ConfigEndorsement(byteArrayOf(1), "sha256:cd", byteArrayOf(2), byteArrayOf(3)))
        assertNotEquals(one, ConfigEndorsement(byteArrayOf(1), "sha256:ab", byteArrayOf(9), byteArrayOf(3)))
        assertNotEquals(one, ConfigEndorsement(byteArrayOf(1), "sha256:ab", byteArrayOf(2), null))
        assertEquals(ConfigEndorsement(byteArrayOf(1)), ConfigEndorsement(byteArrayOf(1), reference = ""))
        assertNull(ConfigEndorsement(byteArrayOf(1), reference = "").reference)
    }

    @Test
    fun embeddedArtifactsCopyTheirArraysInAndOut() {
        val runtime = byteArrayOf(1, 2)
        val platform = byteArrayOf(3, 4)
        val keys = mutableListOf("key")
        val artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = runtime, platform = platform, freshnessKeys = keys)

        runtime[0] = 9
        platform[0] = 9
        keys[0] = "other"
        artifacts.runtime!![1] = 9
        artifacts.platform!![1] = 9
        assertContentEquals(byteArrayOf(1, 2), artifacts.runtime)
        assertContentEquals(byteArrayOf(3, 4), artifacts.platform)
        assertEquals(listOf("key"), artifacts.freshnessKeys)
    }

    @Test
    fun artifactTrustComparesByContent() {
        val one = ArtifactTrust.EmbeddedArtifacts(byteArrayOf(1), byteArrayOf(2))
        val same = ArtifactTrust.EmbeddedArtifacts(byteArrayOf(1), byteArrayOf(2))
        assertEquals(one, same)
        assertEquals(one.hashCode(), same.hashCode())
        assertNotEquals(one, ArtifactTrust.EmbeddedArtifacts(byteArrayOf(9), byteArrayOf(2)))
        assertNotEquals(one, ArtifactTrust.EmbeddedArtifacts(byteArrayOf(1), null))
        assertNotEquals(one, ArtifactTrust.EmbeddedArtifacts(byteArrayOf(1), byteArrayOf(2), listOf("key")))
        assertEquals(ArtifactTrust.EndorsedArtifacts(), ArtifactTrust.EndorsedArtifacts(null))
        assertNotEquals(ArtifactTrust.EndorsedArtifacts(), ArtifactTrust.EndorsedArtifacts(emptyList()))
        assertNotEquals<ArtifactTrust>(ArtifactTrust.EndorsedArtifacts(), ArtifactTrust.EmbeddedArtifacts())
    }

    @Test
    fun aPolicyIsPlainData() {
        assertEquals(Policy(), Policy(null, Duration.ZERO, ArtifactTrust.EndorsedArtifacts()))
        assertEquals(Policy(freshnessMaxAge = 1.hours), Policy(freshnessMaxAge = 60.minutes))
        assertNotEquals(Policy(), Policy(freshnessMaxAge = 1.hours))
        assertEquals(
            Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = byteArrayOf(1))),
            Policy(artifacts = ArtifactTrust.EmbeddedArtifacts(runtime = byteArrayOf(1))),
        )
    }

    @OptIn(ExperimentalTinfoilApi::class)
    @Test
    fun modelPinsCompareByRepositoryAndPolicy() {
        val policy = Policy(freshnessMaxAge = 1.hours)
        assertEquals(ModelPin("tinfoilsh/m"), ModelPin("tinfoilsh/m"))
        assertEquals(ModelPin("tinfoilsh/m").hashCode(), ModelPin("tinfoilsh/m").hashCode())
        assertEquals(ModelPin("tinfoilsh/m", policy), ModelPin("tinfoilsh/m", Policy(freshnessMaxAge = 1.hours)))
        assertEquals(ModelPin("tinfoilsh/m", policy).hashCode(), ModelPin("tinfoilsh/m", policy.copy()).hashCode())
        assertNotEquals(ModelPin("tinfoilsh/m"), ModelPin("tinfoilsh/other"))
        assertNotEquals(ModelPin("tinfoilsh/m", policy), ModelPin("tinfoilsh/m", Policy()))
        assertNotEquals(ModelPin("tinfoilsh/m", policy), ModelPin("tinfoilsh/m"))
        assertEquals("ModelPin(repo=tinfoilsh/m, policy=the client's)", ModelPin("tinfoilsh/m").toString())
    }

    @Test
    fun descriptionsGiveSizesNotBytes() {
        val secretLooking = "do-not-print".toByteArray()
        val descriptions = listOf(
            ConfigEndorsement(secretLooking, "sha256:ab", secretLooking, secretLooking).toString(),
            ArtifactTrust.EmbeddedArtifacts(secretLooking, secretLooking).toString(),
            Trust.EmbeddedConfig(secretLooking).toString(),
        )
        for (description in descriptions) {
            assertFalse(description.contains("do-not-print"), description)
            assertFalse(description.contains(secretLooking.toString()), description)
            assertEquals(true, description.contains("12 bytes"), description)
        }
    }

    @Test
    fun aMeasurementCopiesItsRegisters() {
        val registers = mutableListOf("aa", "")
        val measurement = Measurement("https://tinfoil.sh/predicate/tdx-guest/v2", registers)
        registers[0] = "ff"
        assertEquals(listOf("aa", ""), measurement.registers)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (measurement.registers as MutableList<String>).add("bb")
        }
        assertEquals(measurement, Measurement("https://tinfoil.sh/predicate/tdx-guest/v2", listOf("aa", "")))
        assertEquals(
            measurement.hashCode(),
            Measurement("https://tinfoil.sh/predicate/tdx-guest/v2", listOf("aa", "")).hashCode(),
        )
        assertNotEquals(measurement, Measurement("https://tinfoil.sh/predicate/tdx-guest/v2", listOf("aa")))
        assertNotEquals(measurement, Measurement("https://tinfoil.sh/predicate/sev-snp-guest/v2", listOf("aa", "")))
    }

    @Test
    fun referenceSourcesAreAnOpenSet() {
        assertEquals("endorsement", ReferenceSource.ENDORSEMENT.value)
        assertEquals("embedded", ReferenceSource.EMBEDDED.value)
        assertEquals("policy", ReferenceSource.POLICY.value)
        assertEquals(ReferenceSource.POLICY, ReferenceSource("policy"))
        assertEquals("witness", ReferenceSource("witness").toString())
    }
}
