package sh.tinfoil.internal.verification

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith
import sh.tinfoil.go.mobile.Mobile
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@RunWith(AndroidJUnit4::class)
class GoVerifierLibraryTest {
    @Test
    fun noncesAreFreshAndFullLength() {
        val first = GoVerifierLibrary.newNonce()
        val second = GoVerifierLibrary.newNonce()

        assertEquals(GoVerifierLibrary.NONCE_SIZE, first.size)
        assertFalse(first.contentEquals(second))
        assertFalse(first.all { it == 0.toByte() })
    }

    @Test
    fun theDefaultVerifierRejectsAnEmptyDocumentAsAVerificationError() {
        val verifier = Mobile.newVerifier("")
        val nonce = GoVerifierLibrary.newNonce()

        val error = assertFailsWith<Exception> {
            verifier.verify(ByteArray(0), nonce, "tinfoilsh/confidential-model-router", "")
        }

        assertTrue(error.message.orEmpty().startsWith(Mobile.VerificationErrorPrefix), error.message)
    }

    @Test
    fun unknownOptionsAreAUsageError() {
        val error = assertFailsWith<Exception> { Mobile.newVerifier("""{"no_such_option": true}""") }

        assertTrue(error.message.orEmpty().startsWith(Mobile.UsageErrorPrefix), error.message)
    }

    @Test
    fun verifyDoesNotModifyTheNonce() {
        val verifier = Mobile.newVerifier("")
        val nonce = GoVerifierLibrary.newNonce()
        val copy = nonce.copyOf()

        runCatching { verifier.verify(ByteArray(0), nonce, "tinfoilsh/confidential-model-router", "") }

        assertContentEquals(copy, nonce)
    }
}
