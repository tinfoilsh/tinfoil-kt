package sh.tinfoil.internal.transport

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import okhttp3.HttpUrl
import okhttp3.Request
import sh.tinfoil.ConfigurationException
import java.io.IOException
import java.net.ProtocolException
import java.security.SecureRandom

/**
 * A client's prompt-cache secret, and the rule that adds it to requests.
 *
 * Tinfoil's router keeps a separate prompt cache for each value of the
 * `user_cache_secret` member of a request's JSON body: requests with the
 * same secret, under the same API key, share cached prompt prefixes, and
 * requests with different secrets cannot observe each other's cache timing.
 * [provision] adds the client's secret to the requests that take one and
 * that do not already carry their own.
 *
 * The secret is added below the rule that keeps requests on the enclave's
 * origin and above the transport, so it is written only to a connection that
 * holds the attested key. It is never part of a message or of [toString].
 */
internal class UserCacheSecret private constructor(
    /** The secret itself, for a client that derives from it what it sends. */
    val value: String,
    /** The largest body that [provision] reads. */
    private val maxBodyBytes: Long,
) {
    /** The secret as a JSON string, quotes included. */
    private val json: ByteArray = quote(value)

    /** The member to add to an object that has none. */
    private val member: ByteArray = "\"$FIELD\":".toByteArray(Charsets.US_ASCII) + json

    override fun toString(): String = "UserCacheSecret(hidden)"

    /**
     * [request], with this secret in its body if it takes one; otherwise
     * [request] itself, or a request with the same body bytes.
     *
     * A request takes the secret when it is a `POST` to a path that ends in
     * one of [ELIGIBLE_PATHS], and its body is the text of one JSON object
     * in which `user_cache_secret` is absent or is the empty string. The
     * secret is spliced into that text: every other byte stays as the caller
     * wrote it, so a number keeps all its digits. The body's content type
     * and whether it can be sent only once stay the same; its length is the
     * new text's.
     *
     * Everything else is sent as it is: a body that is not such an object,
     * including one with data after the object or with text that is not
     * UTF-8; one that names `user_cache_secret` more than once at its top
     * level, in any spelling; and one whose `user_cache_secret` is a
     * non-empty string, which is the caller's own scope for the request, or
     * is not a string.
     *
     * To decide, the body is read into memory here, before the request is
     * sent and before anything is verified for it, and at most once. A body
     * that can be written only once is sent from what was read. No more
     * than [maxBodyBytes] are held, which is the largest body that the
     * router accepts. So a body that declares more than that, or that can
     * be written again and turns out to be longer, is sent as it is: the
     * router refuses it for its size, and nothing of it is cached.
     *
     * A request to one of those paths whose body cannot be examined is
     * refused, because sending it would put it in the cache that every
     * client of the API key shares, which is what the secret is there to
     * prevent:
     * - a duplex body, which is written while the response is read; and
     * - a body that declares no length, can be written only once and turns
     *   out to be longer than [maxBodyBytes]: it is spent by then, and
     *   cannot be sent whole.
     *
     * @throws ConfigurationException for a body that cannot be examined.
     * @throws IOException if the body fails to write itself, or can be
     *   written only once and does not write the length that it declares.
     */
    @Throws(IOException::class)
    suspend fun provision(request: Request): Request {
        val body = request.body ?: return request
        if (request.method != "POST" || !isEligible(request.url)) {
            return request
        }
        if (body.isDuplex()) {
            throw ConfigurationException(
                "a duplex request body cannot be given the user cache secret, so it is not sent to this endpoint",
            )
        }
        val declared = body.contentLength()
        val oneShot = body.isOneShot()
        if (declared > maxBodyBytes) {
            return request
        }
        val text = runInterruptible(Dispatchers.IO) { HeldBody.read(body, declared, maxBodyBytes) }
        if (text == null || (declared >= 0 && text.size.toLong() != declared)) {
            if (oneShot && declared < 0) {
                throw ConfigurationException(
                    "the request body is larger than the $maxBodyBytes bytes that the client can give " +
                        "the user cache secret, and it can be written only once, so it is not sent",
                )
            }
            if (oneShot) {
                // It is spent, and what it wrote is not what it declared.
                throw ProtocolException("the request body did not write the length that it declared")
            }
            // The body can be written again, so the HTTP client deals with it.
            return request
        }
        val splice = splice(text)
        if (splice == null && !oneShot) {
            return request
        }
        // A body that could be read only once is sent from what was read.
        val held = HeldBody(text, listOfNotNull(splice), body.contentType(), oneShot)
        return request.newBuilder().method(request.method, held).build()
    }

    /**
     * Where this secret goes in [text], or null if [text] is to be sent as
     * it is.
     */
    internal fun splice(text: ByteArray): Splice? {
        val layout = JsonObjectText.scan(text, FIELD) ?: return null
        return when (layout.occurrences) {
            0 -> Splice(
                layout.closingBrace,
                layout.closingBrace,
                if (layout.memberCount == 0) member else COMMA + member,
            )
            // Only the empty string asks for the client's secret; `""` is
            // its one spelling.
            1 -> if (layout.valueEnd - layout.valueStart == 2 && text[layout.valueStart] == QUOTE) {
                Splice(layout.valueStart, layout.valueEnd, json)
            } else {
                null
            }
            // A parser may keep the first or the last of repeated members,
            // so no edit here would mean the same to all of them.
            else -> null
        }
    }

    internal companion object {
        /** The member of a request's body that scopes the prompt cache. */
        const val FIELD: String = "user_cache_secret"

        /**
         * The ends of the paths whose bodies take the member: the endpoints
         * that cache prompt prefixes. They are matched as endings, so that
         * a base URL with a path of its own still qualifies.
         */
        val ELIGIBLE_PATHS: List<String> = listOf("/chat/completions", "/completions", "/responses")

        /**
         * The largest body that is read to add the secret: the largest that
         * the router accepts, so nothing that it would answer is left out.
         */
        const val MAX_BODY_BYTES: Long = 64L shl 20

        private const val SECRET_BYTES = 32
        private const val QUOTE = '"'.code.toByte()
        private val COMMA = byteArrayOf(','.code.toByte())

        /**
         * A secret that is generated once in each process and shared by
         * every client in it that is given none: 256 random bits, in hex. It
         * is kept in memory only and lasts as long as the process.
         */
        private val processSecret: UserCacheSecret by lazy {
            val bytes = ByteArray(SECRET_BYTES).also { SecureRandom().nextBytes(it) }
            UserCacheSecret(bytes.joinToString("") { "%02x".format(it) }, MAX_BODY_BYTES)
        }

        /**
         * The secret that a client was given, or null if it was given none:
         * null and the empty string both mean that.
         *
         * @throws ConfigurationException for text that is not well-formed
         *   Unicode, which could not reach the server as it was given.
         */
        @Throws(ConfigurationException::class)
        fun of(explicit: String?, maxBodyBytes: Long = MAX_BODY_BYTES): UserCacheSecret? {
            if (explicit.isNullOrEmpty()) {
                return null
            }
            if (!isWellFormed(explicit)) {
                // Two such secrets could arrive as one, and share a cache.
                throw ConfigurationException("the user cache secret is not well-formed Unicode text")
            }
            return UserCacheSecret(explicit, maxBodyBytes)
        }

        /** The secret that a client was given, or else the process's own. */
        @Throws(ConfigurationException::class)
        fun orProcessDefault(explicit: String?): UserCacheSecret = of(explicit) ?: processSecret

        /** Whether [url]'s path is one whose bodies take the member. */
        fun isEligible(url: HttpUrl): Boolean {
            // The path as the server reads it, with its escapes decoded.
            val path = url.pathSegments.joinToString("/", prefix = "/")
            return ELIGIBLE_PATHS.any(path::endsWith)
        }

        private fun isWellFormed(text: String): Boolean {
            var i = 0
            while (i < text.length) {
                val c = text[i]
                if (c.isHighSurrogate()) {
                    if (i + 1 >= text.length || !text[i + 1].isLowSurrogate()) {
                        return false
                    }
                    i++
                } else if (c.isLowSurrogate()) {
                    return false
                }
                i++
            }
            return true
        }

        /** [text] as a JSON string in UTF-8. */
        private fun quote(text: String): ByteArray {
            val quoted = StringBuilder(text.length + 2).append('"')
            for (c in text) {
                when {
                    c == '"' || c == '\\' -> quoted.append('\\').append(c)
                    c.code < 0x20 -> quoted.append("\\u%04x".format(c.code))
                    else -> quoted.append(c)
                }
            }
            return quoted.append('"').toString().toByteArray(Charsets.UTF_8)
        }
    }
}
