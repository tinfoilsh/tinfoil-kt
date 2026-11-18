package sh.tinfoil.internal.transport

import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.Request
import sh.tinfoil.AttestationException
import sh.tinfoil.ConfigurationException
import sh.tinfoil.TransportMode
import sh.tinfoil.Verification
import java.io.IOException

/**
 * One way of protecting requests with the keys that a verification endorses.
 * A client has one, chosen by its [TransportMode], and asks it for a
 * [BoundTransport] for each verification.
 */
internal interface TransportProtocol {
    val mode: TransportMode

    /**
     * Throws for a request that this protocol cannot protect. It runs before
     * any network I/O, including the verification that a request may need.
     */
    @Throws(ConfigurationException::class)
    fun checkRequest(request: Request)

    /**
     * A transport whose requests are protected with the keys of
     * [verification], and with no other. A verification without the key
     * that this protocol needs is an [AttestationException].
     */
    @Throws(AttestationException::class)
    fun bind(verification: Verification): BoundTransport

    /**
     * Ends everything that this protocol's transports are doing, whichever
     * verification they were bound to: new requests are refused, and
     * requests in flight are cancelled, a response body that is still being
     * read included.
     */
    fun close()
}

/**
 * Sends requests under the keys of one verification. A request that it
 * accepts either reaches a peer that holds those keys or fails.
 */
internal interface BoundTransport {
    /**
     * A call that sends [request] under this transport's keys.
     *
     * @throws ConfigurationException once the transport is closed.
     */
    @Throws(ConfigurationException::class)
    fun newCall(request: Request): Call

    /**
     * Why [failure] means that the peer does not hold this transport's keys,
     * found out before the peer could read any of the request that the keys
     * protect, so that sending the request again under new keys delivers it
     * once; or null for any other failure.
     */
    fun keyRejection(failure: IOException): String?

    /**
     * Opens a connection to [url]'s host as a request would, and closes it
     * without writing any of a request to it. A transport that pins its
     * connections to an attested key thereby finds out whether the host
     * presents that key; one that pins nothing does nothing here.
     *
     * @throws IOException if no connection that would carry a request can
     *   be opened; [keyRejection] says whether the key is why.
     */
    @Throws(IOException::class)
    suspend fun probe(url: HttpUrl)

    /**
     * Stops keeping connections for later requests, because a newer
     * verification has replaced this one or the client has closed. Requests
     * in flight finish, unless the protocol's close cancels them.
     */
    fun retire()
}
