package sh.tinfoil

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PinTest {
    @Test
    fun aPinNamesNothingByDefault() {
        val pin = Pin()
        assertNull(pin.repo)
        assertNull(pin.project)
    }

    @Test
    fun anEmptyOrBlankPartIsRefusedAndNotReadAsNotSet() {
        for (text in listOf("", " ", "\t\n")) {
            val repo = assertFailsWith<ConfigurationException> { Pin(repo = text) }
            assertTrue(repo.detail.contains("Pin.repo"), repo.detail)
            val project = assertFailsWith<ConfigurationException> { Pin(repo = "org/repo", project = text) }
            assertTrue(project.detail.contains("Pin.project"), project.detail)
        }
    }

    @Test
    fun onlyNullMeansNotSet() {
        assertEquals(Pin(), Pin(repo = null, project = null))
        assertEquals(Pin().hashCode(), Pin(repo = null, project = null).hashCode())
        assertNull(Pin(project = "org/project").repo)
    }

    @Test
    fun partsAreKeptAsGiven() {
        val pin = Pin(repo = "org/repo@v1", project = "org/project@sha256:ab")
        assertEquals("org/repo@v1", pin.repo)
        assertEquals("org/project@sha256:ab", pin.project)
        // Nothing is trimmed.
        assertEquals(" org/repo ", Pin(repo = " org/repo ").repo)
    }

    @Test
    fun pinsCompareByValue() {
        assertEquals(Pin("org/repo", "org/project"), Pin("org/repo", "org/project"))
        assertEquals(Pin("org/repo", "org/project").hashCode(), Pin("org/repo", "org/project").hashCode())
        assertNotEquals(Pin(repo = "org/name"), Pin(project = "org/name"))
        assertNotEquals(Pin(repo = "org/repo"), Pin(repo = "org/other"))
        assertEquals("Pin(repo=org/repo, project=null)", Pin(repo = "org/repo").toString())
    }
}
