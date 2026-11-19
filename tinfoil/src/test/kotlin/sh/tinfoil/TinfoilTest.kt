package sh.tinfoil

import sh.tinfoil.internal.SdkIdentity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The SDK's identity. */
class TinfoilTest {
    @Test
    fun theVersionIsTheBuildsAndIsNotARelease() {
        assertEquals(SdkIdentity.VERSION, Tinfoil.VERSION)
        assertTrue(Regex("[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?").matches(Tinfoil.VERSION), Tinfoil.VERSION)
    }
}
