package sh.tinfoil

import okhttp3.Response
import java.io.Closeable

/**
 * A response whose body is still to be read, together with the token that
 * can open it again later. `executeRecoverable` on a client returns one.
 *
 * It is for a response that the server keeps, so that it can be fetched
 * again after an interruption: store [recoveryToken] before reading the
 * body, and if the read is cut off, fetch the sealed response again and open
 * it with [SessionRecoveryToken.decryptResponse].
 *
 * Close it, or its [response], when done.
 */
public class RecoverableResponse internal constructor(
    /**
     * The response, as `execute` returns it: its body streams as it is read,
     * as plaintext.
     */
    public val response: Response,
    /**
     * The token that opens this response's sealed form, or null when the
     * response is not sealed: the request had no body, or something on the
     * way answered with an error of its own before the request reached the
     * enclave. A response without a token is authenticated by nothing. A
     * token does not show by itself that the enclave answered: the body
     * does, by being read without a failure, because every piece of it is
     * authenticated as it is read.
     *
     * It is secret key material for this one response; see
     * [SessionRecoveryToken].
     */
    public val recoveryToken: SessionRecoveryToken?,
) : Closeable {
    /** Closes [response]. */
    override fun close() {
        response.close()
    }

    /** The response's status and whether there is a token; never the token. */
    override fun toString(): String =
        "RecoverableResponse(code=${response.code}, recoveryToken=${if (recoveryToken == null) "none" else "redacted"})"
}
