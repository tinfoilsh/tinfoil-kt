package sh.tinfoil

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

class PinTest {
    @Test
    fun aPinNamesNothingByDefault() {
        val pin = Pin()
        assertNull(pin.repo)
        assertNull(pin.project)
    }

    @Test
    fun anEmptyStringIsStoredAsNull() {
        val pin = Pin(repo = "", project = "")
        assertNull(pin.repo)
        assertNull(pin.project)
        assertEquals(Pin(), pin)
        assertEquals(Pin().hashCode(), pin.hashCode())
    }

    @Test
    fun partsAreKeptAsGiven() {
        val pin = Pin(repo = "org/repo@v1", project = "org/project@sha256:ab")
        assertEquals("org/repo@v1", pin.repo)
        assertEquals("org/project@sha256:ab", pin.project)
        // Only the empty string means "not set"; nothing is trimmed.
        assertEquals(" ", Pin(repo = " ").repo)
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
