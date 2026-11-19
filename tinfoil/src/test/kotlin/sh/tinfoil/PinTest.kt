package sh.tinfoil

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PinTest {
    @Test
    fun aPinMustNameSomething() {
        for (make in listOf({ Pin() }, { Pin(repo = null, project = null) })) {
            val error = assertFailsWith<ConfigurationException> { make() }
            assertTrue(error.detail.contains("Pin.NONE"), error.detail)
        }
    }

    @Test
    fun thePinThatNamesNothingIsAskedForByName() {
        assertNull(Pin.NONE.repo)
        assertNull(Pin.NONE.project)
        assertEquals(Pin.NONE, Pin.NONE)
        assertNotEquals(Pin.NONE, Pin(repo = "org/repo"))
        assertNotEquals(Pin(project = "org/project"), Pin.NONE)
        assertEquals("Pin(repo=null, project=null)", Pin.NONE.toString())
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
        assertNull(Pin(project = "org/project").repo)
        assertNull(Pin(repo = "org/repo", project = null).project)
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
