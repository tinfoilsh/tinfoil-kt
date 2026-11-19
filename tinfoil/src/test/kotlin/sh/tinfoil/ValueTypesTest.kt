package sh.tinfoil

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
    fun embeddedReferencesCopyTheirArraysInAndOut() {
        val runtime = byteArrayOf(1, 2)
        val platform = byteArrayOf(3, 4)
        val references = EmbeddedReferences(runtime = runtime, platform = platform)

        runtime[0] = 9
        platform[0] = 9
        references.runtime!![1] = 9
        references.platform!![1] = 9
        assertContentEquals(byteArrayOf(1, 2), references.runtime)
        assertContentEquals(byteArrayOf(3, 4), references.platform)
    }

    @Test
    fun embeddedReferencesCompareByContent() {
        val config = EmbeddedConfig.Bytes(byteArrayOf(7), name = "/org/project/v1")
        val one = EmbeddedReferences(config, byteArrayOf(1), byteArrayOf(2))
        val same = EmbeddedReferences(EmbeddedConfig.Bytes(byteArrayOf(7), "/org/project/v1"), byteArrayOf(1), byteArrayOf(2))
        assertEquals(one, same)
        assertEquals(one.hashCode(), same.hashCode())
        assertNotEquals(one, EmbeddedReferences(config, byteArrayOf(9), byteArrayOf(2)))
        assertNotEquals(one, EmbeddedReferences(config, byteArrayOf(1), null))
        assertNotEquals(one, EmbeddedReferences(null, byteArrayOf(1), byteArrayOf(2)))
        assertEquals(EmbeddedReferences(), EmbeddedReferences())
    }

    @Test
    fun anEmptyNameOfAnEmbeddedConfigIsRefusedAndNotReadAsNotSet() {
        val runtime = RuntimeReference("tinfoilsh/cvmimage", "v0.15.0", "ab")
        val errors = listOf(
            assertFailsWith<ConfigurationException> { EmbeddedConfig.Bytes(byteArrayOf(1), name = "") },
            assertFailsWith<ConfigurationException> { EmbeddedConfig.Reference("cd", runtime, name = "") },
        )
        for (error in errors) {
            assertTrue(error.detail.contains("embedded config's name must not be empty"), error.detail)
        }
    }

    @Test
    fun anEmbeddedConfigCopiesItsBytesAndHasNoNameByDefault() {
        val bytes = byteArrayOf(1, 2)
        val config = EmbeddedConfig.Bytes(bytes, name = null)
        bytes[0] = 9
        config.bytes[1] = 9
        assertContentEquals(byteArrayOf(1, 2), config.bytes)
        assertNull(config.name)

        val runtime = RuntimeReference("tinfoilsh/cvmimage", "v0.15.0", "ab")
        val reference = EmbeddedConfig.Reference("cd", runtime, name = null)
        assertNull(reference.name)
        assertEquals(reference, EmbeddedConfig.Reference("cd", RuntimeReference("tinfoilsh/cvmimage", "v0.15.0", "ab")))
        assertEquals(reference.hashCode(), EmbeddedConfig.Reference("cd", runtime).hashCode())
        assertNotEquals<EmbeddedConfig>(reference, EmbeddedConfig.Bytes(byteArrayOf(1)))
        assertNotEquals(reference, EmbeddedConfig.Reference("cd", RuntimeReference("tinfoilsh/cvmimage", "v0.15.1", "ab")))
        assertNotEquals(EmbeddedConfig.Bytes(byteArrayOf(1)), EmbeddedConfig.Bytes(byteArrayOf(1), "/org/project/v1"))
    }

    @Test
    fun descriptionsGiveSizesNotBytes() {
        val secretLooking = "do-not-print".toByteArray()
        val descriptions = listOf(
            ConfigEndorsement(secretLooking, "sha256:ab", secretLooking, secretLooking).toString(),
            EmbeddedReferences(EmbeddedConfig.Bytes(secretLooking), secretLooking, secretLooking).toString(),
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
