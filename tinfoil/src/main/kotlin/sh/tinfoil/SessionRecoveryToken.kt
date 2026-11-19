package sh.tinfoil

import okhttp3.Response
import sh.tinfoil.ehbp.identity.decryptResponseWithToken
import sh.tinfoil.internal.transport.proven
import java.io.IOException
import sh.tinfoil.ehbp.identity.SessionRecoveryToken as SealedSessionToken

/**
 * The key material that opens one sealed response, and only that one,
 * without the client that sent its request.
 *
 * A request that is sent with [TransportMode.EHBP] and has a body gets a
 * response that only the sending client can open. The token lets the response
 * be opened elsewhere or later: store it, with [toJson], before reading the
 * body, and if the read fails, or the response ends before its content is
 * complete, fetch the sealed response again from where it is kept and open
 * it with [decryptResponse]. A sealed response can be opened only from its
 * first byte.
 *
 * **A token is secret key material.** Whoever holds it can read the response
 * that it belongs to. Keep it in protected storage, for no longer than the
 * response may need to be recovered, and delete every copy once the response
 * has been read in full or is given up. Never log it: [toString] reveals
 * nothing, but the text that [toJson] returns is the secret itself.
 */
public class SessionRecoveryToken private constructor(private val token: SealedSessionToken) {
    /**
     * The token as JSON, in the form that every implementation of the
     * sealing protocol reads. The text is the secret: store it protected, and
     * keep it out of logs and error messages.
     */
    public fun toJson(): String = token.toJson()

    /**
     * Opens a sealed response with this token. [response] is the stored
     * response as it was sent: its `Ehbp-Response-Nonce` header and its
     * sealed body, from the first byte. Any HTTP client may have fetched it,
     * from wherever it is kept; nothing here checks who sent it, and nothing
     * needs to, because only the enclave that answered the token's request
     * can have sealed a body that this token opens.
     *
     * The returned response has the same status and headers, and a body
     * that yields the plaintext as it is read. Every piece is authenticated
     * before it is yielded; a body that was altered, or that ends inside a
     * piece, fails the read with an [IOException], and yields nothing after
     * that. What was yielded before is a true beginning of the response.
     *
     * A body that ends between two pieces is read to that end without an
     * error: the sealing marks no last piece, so a stored copy that lost
     * its last pieces opens like a whole one. Whether the response is whole
     * shows only in its content, such as the `[DONE]` event that ends a
     * stream of events, or JSON that parses.
     *
     * The status and the headers are not sealed, and so are not
     * authenticated. Closing the returned response closes [response].
     *
     * This call reads nothing and does not block. Reading the returned
     * body reads [response]'s body, and blocks as that does.
     *
     * A response whose body yields nothing fails the read as well, whatever
     * its status: the header is not sealed, so a response with nothing
     * sealed behind it shows nothing of where it came from.
     *
     * @throws IOException if [response] has no usable `Ehbp-Response-Nonce`
     *   header or no body.
     */
    @Throws(IOException::class)
    public fun decryptResponse(response: Response): Response = decryptResponseWithToken(response, token).proven()

    /** Says only that this is a token. The key material is never part of it. */
    override fun toString(): String = "SessionRecoveryToken(redacted)"

    public companion object {
        /**
         * Reads a token that [toJson] wrote, here or in another
         * implementation of the sealing protocol.
         *
         * @throws ConfigurationException if [json] is not a token. The error
         *   does not repeat any of [json].
         */
        @JvmStatic
        @Throws(ConfigurationException::class)
        public fun fromJson(json: String): SessionRecoveryToken {
            val token = try {
                SealedSessionToken.fromJson(json)
            } catch (_: IOException) {
                // The parser's own error can quote its input, which is a
                // secret, so it is not kept as the cause.
                throw ConfigurationException("invalid session recovery token")
            }
            return SessionRecoveryToken(token)
        }

        @JvmSynthetic
        internal fun of(token: SealedSessionToken): SessionRecoveryToken = SessionRecoveryToken(token)
    }
}
