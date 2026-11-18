package sh.tinfoil.internal.gateway

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import okhttp3.Request
import okhttp3.RequestBody
import sh.tinfoil.ConfigurationException
import sh.tinfoil.internal.transport.HeldBody
import sh.tinfoil.internal.transport.JsonObjectText
import sh.tinfoil.internal.transport.Splice
import sh.tinfoil.internal.transport.UserCacheSecret
import java.io.IOException
import java.net.ProtocolException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** A request that is ready to route: what the gateway is sent, and what the client routes it on. */
internal class PreparedRequest(
    val request: Request,
    /** The model that the request names, or the empty string if it names none. */
    val model: String,
    /** What keeps a conversation on one replica, or the empty string. */
    val cachePrefix: String,
)

/**
 * How the gateway client prepares a request before it routes it.
 *
 * The gateway reads headers, never bodies, so the model that a request names
 * is copied from its body into a header; the client chooses and verifies the
 * replica by that same name. And no router sits between a gateway client and
 * the model, so the client does here what a router would: it scopes the
 * prompt cache, by replacing the body's cache secret with a salt that is
 * derived from it.
 *
 * A body is changed only by rewriting those members in its text; every
 * other byte of it stays as the caller wrote it.
 */
internal object GatewayRequest {
    /** Names the model of a request, for the gateway. */
    const val MODEL_HEADER: String = "X-Tinfoil-Model"

    /** Keeps the requests of one conversation on one replica. It is keyed, so it says nothing of the prompt. */
    const val CACHE_PREFIX_HEADER: String = "X-Tinfoil-Cache-Prefix"

    /** Names the replica that a request's body is sealed to and, in an answer, the one that the gateway chose instead. */
    const val SEAL_HEADER: String = "X-Tinfoil-Seal"

    /** The member that scopes the prompt cache for the model. */
    const val CACHE_SALT_FIELD: String = "cache_salt"

    /** The largest body that is read to find the model that it names. */
    const val MAX_BODY_BYTES: Long = UserCacheSecret.MAX_BODY_BYTES

    private const val CACHE_SALT_DOMAIN = "tinfoil/client-cache-salt/v2"
    private const val CACHE_ROUTE_DOMAIN = "tinfoil/client-cache-route/v2"
    private const val HMAC = "HmacSHA256"
    private const val HASH_BYTES = 32

    // The members that are read, by their place in the arrays of a scan.
    private const val MODEL = 0
    private const val SECRET = 1
    private const val SALT = 2
    private const val INSTRUCTIONS = 3
    private val NAMES = arrayOf("model", UserCacheSecret.FIELD, CACHE_SALT_FIELD, "instructions", "messages", "input", "prompt")
    private val PROMPTS = 4..6

    /**
     * [request], ready to route. [secret] is the client's cache secret.
     *
     * A `POST` whose body is JSON is read into memory. A body that is not
     * exactly one JSON value, by the strict grammar and in UTF-8, is
     * refused: a more lenient parser could read an object in it whose
     * members were not examined here. If the body is one JSON object:
     * - it is refused if it names `model`, `user_cache_secret` or
     *   `cache_salt` more than once at its top level, in any spelling, or
     *   has a top-level member whose name differs from one of them only by
     *   case: a server may read another member than the client did, and so
     *   serve another model than the one whose replica was verified, or
     *   scope the cache by another value;
     * - its `model`, if that is a non-empty string, names the model, unless
     *   the request already carries [MODEL_HEADER];
     * - on a path whose prompts are cached, its `user_cache_secret` member
     *   is removed and `cache_salt` is set to a salt that is derived from
     *   that secret, or from [secret] when the body has none, and from the
     *   request's bearer token; and [CACHE_PREFIX_HEADER] is set from the
     *   start of the prompt, under a key that is derived the same way. So
     *   on such a request the secret itself is not sent, to anyone.
     *
     * A JSON value that is not an object is sent as it is, and names no
     * model. A multipart upload without [MODEL_HEADER] is read to find its
     * one `model` field. Every other request is returned as it is: [secret]
     * is never added to one, and a `user_cache_secret` member that its
     * caller wrote stays in its body.
     *
     * @throws ConfigurationException for a request that is refused: one
     *   with a JSON body that cannot be read here or is not valid JSON,
     *   with repeated or look-alike members, with an upload that does not
     *   name exactly one model, or with more than one [MODEL_HEADER],
     *   [CACHE_PREFIX_HEADER] or content type.
     * @throws IOException if the body fails to write itself.
     */
    @Throws(IOException::class)
    suspend fun prepare(request: Request, secret: String): PreparedRequest {
        val named = single(request, MODEL_HEADER)
        val prefix = single(request, CACHE_PREFIX_HEADER)
        val unchanged = PreparedRequest(request, named, prefix)
        val body = request.body
        if (request.method != "POST" || body == null || body.contentLength() == 0L) {
            return unchanged
        }
        // The body's own content type is the one that is sent; a header
        // names it only for a body that has none.
        val contentType = body.contentType()?.toString() ?: single(request, "Content-Type").ifEmpty { return unchanged }
        return when (contentType.substringBefore(';').trim().lowercase()) {
            "multipart/form-data" -> if (named.isEmpty()) upload(request, body, contentType, prefix) else unchanged
            "application/json" -> json(request, body, secret, named, prefix)
            else -> unchanged
        }
    }

    /** The one value of the header [name], or the empty string if there is none. */
    private fun single(request: Request, name: String): String {
        val values = request.headers(name)
        if (values.size > 1) {
            throw ConfigurationException("requests must not set the $name header more than once")
        }
        return values.firstOrNull().orEmpty()
    }

    private suspend fun json(request: Request, body: RequestBody, secret: String, named: String, prefix: String): PreparedRequest {
        val text = read(body, "the JSON request body")
        val scan = Scan(text)
        val builder = request.newBuilder()
        if (!scan.isObject) {
            if (!JsonObjectText.isValue(text)) {
                // A parser that is more lenient than this one, about a byte
                // order mark, the encoding or the grammar, could still read
                // an object here, with members that were not examined.
                throw ConfigurationException("the JSON request body is not valid JSON")
            }
            return PreparedRequest(builder.post(HeldBody(text, emptyList(), body.contentType(), false)).build(), named, prefix)
        }
        refuseRepeatedMembers(scan)
        var model = named
        if (model.isEmpty()) {
            model = scan.string(MODEL).orEmpty()
            if (model.isNotEmpty()) {
                builder.header(MODEL_HEADER, headerValue(model))
            }
        }
        var cachePrefix = prefix
        var splices = emptyList<Splice>()
        if (UserCacheSecret.isEligible(request.url)) {
            val bodySecret = scan.string(SECRET).orEmpty()
            val scope = CacheScope.derive(
                secret = bodySecret.ifEmpty { secret },
                authorization = request.headers("Authorization").firstOrNull().orEmpty(),
                promptHead = scan.promptHead(),
            )
            splices = scan.scoped(scope.salt)
            cachePrefix = scope.prefix
            builder.removeHeader(CACHE_PREFIX_HEADER)
            if (cachePrefix.isNotEmpty()) {
                builder.header(CACHE_PREFIX_HEADER, cachePrefix)
            }
        }
        // The body is in memory now, so it can be sent again.
        return PreparedRequest(builder.post(HeldBody(text, splices, body.contentType(), false)).build(), model, cachePrefix)
    }

    private suspend fun upload(request: Request, body: RequestBody, contentType: String, prefix: String): PreparedRequest {
        // Read here, strictly, and not by the HTTP client's parser, which
        // accepts what a server's may read differently.
        val boundary = Multipart.boundary(contentType)
        val bytes = read(body, "a multipart upload without the $MODEL_HEADER header")
        val model = Multipart.model(bytes, boundary)
        val prepared = request.newBuilder()
            .header(MODEL_HEADER, headerValue(model))
            .post(HeldBody(bytes, emptyList(), body.contentType(), false))
            .build()
        return PreparedRequest(prepared, model, prefix)
    }

    /** What [body] writes, read once and whole. */
    private suspend fun read(body: RequestBody, what: String): ByteArray {
        if (body.isDuplex()) {
            throw ConfigurationException("$what cannot be read before it is sent, because it is duplex")
        }
        val declared = body.contentLength()
        val tooLarge = { ConfigurationException("$what is larger than the $MAX_BODY_BYTES bytes that the client reads") }
        if (declared > MAX_BODY_BYTES) {
            throw tooLarge()
        }
        val bytes = runInterruptible(Dispatchers.IO) { HeldBody.read(body, declared, MAX_BODY_BYTES) }
        if (bytes == null && declared < 0) {
            throw tooLarge()
        }
        if (bytes == null || (declared >= 0 && bytes.size.toLong() != declared)) {
            throw ProtocolException("the request body did not write the length that it declared")
        }
        return bytes
    }

    private fun refuseRepeatedMembers(scan: Scan) {
        // A server that matches member names without regard to case reads
        // such a member as the one that the client reads, or does not: the
        // client cannot know which, so it does not guess.
        scan.lookalike?.let { name ->
            throw ConfigurationException("request body has a member whose name differs from \"${NAMES[name]}\" only by case")
        }
        val repeated = (MODEL..SALT).filter { scan.count[it] > 1 }.map { "\"${NAMES[it]}\"" }
        if (repeated.isNotEmpty()) {
            throw ConfigurationException(
                "request body repeats the ${repeated.joinToString(", ")} member${if (repeated.size > 1) "s" else ""}",
            )
        }
    }

    /** [model] as a header's value, which carries only printable ASCII, and that only as it is written. */
    private fun headerValue(model: String): String {
        if (model.any { it !in ' '..'~' } || model.first() == ' ' || model.last() == ' ') {
            throw ConfigurationException("the request names a model whose name cannot be sent in a header")
        }
        return model
    }

    /**
     * [name] as a parser that ignores case reads it: ASCII letters in lower
     * case, and the two other characters that fold to one, the long s and
     * the Kelvin sign.
     */
    private fun folded(name: String): String = buildString(name.length) {
        for (c in name) {
            append(
                when (c) {
                    in 'A'..'Z' -> c + ('a' - 'A')
                    LONG_S -> 's'
                    KELVIN -> 'k'
                    else -> c
                },
            )
        }
    }

    /** Where the members that the client reads are in the text of a JSON object. */
    private class Scan(private val text: ByteArray) {
        /** How many top-level members have each of [NAMES], in any spelling. */
        val count = IntArray(NAMES.size)

        // Of the last member with each name.
        private val nameStart = IntArray(NAMES.size)
        private val valueStart = IntArray(NAMES.size)
        private val valueEnd = IntArray(NAMES.size)
        private var members = 0

        /** The first of the names that a member has in another case, or null. */
        var lookalike: Int? = null
            private set
        private val closingBrace: Int = JsonObjectText.members(text) { name, nameEnd, value, end ->
            members++
            if (lookalike == null && nameEnd - name > 2 && mayFold(text[name + 1])) {
                val spelled = JsonObjectText.string(text, name, nameEnd).orEmpty()
                val read = folded(spelled)
                lookalike = (MODEL..SALT).firstOrNull { NAMES[it] == read && NAMES[it] != spelled }
            }
            for (i in NAMES.indices) {
                if (JsonObjectText.isName(text, name, nameEnd, NAMES[i])) {
                    count[i]++
                    nameStart[i] = name
                    valueStart[i] = value
                    valueEnd[i] = end
                    break
                }
            }
        }

        val isObject: Boolean get() = closingBrace >= 0

        /**
         * Whether a name that starts with [first] could be one of the three
         * in another case: each starts with `m`, `u` or `c`, however that
         * letter is written.
         */
        private fun mayFold(first: Byte): Boolean = when (first.toInt().toChar()) {
            'm', 'M', 'u', 'U', 'c', 'C', '\\' -> true
            else -> false
        }

        /** The value of the member [name], if there is one and it is a string. */
        fun string(name: Int): String? =
            if (count[name] == 0) null else JsonObjectText.string(text, valueStart[name], valueEnd[name])

        /**
         * The part of the prompt that the later turns of a conversation
         * share, as the caller wrote it: the instructions, if they are a
         * non-empty string; else, of the first of `messages`, `input` and
         * `prompt` that has one, the first element of an array or the whole
         * of any other value but null.
         */
        fun promptHead(): ByteArray? {
            if (!string(INSTRUCTIONS).isNullOrEmpty()) {
                return text.copyOfRange(valueStart[INSTRUCTIONS], valueEnd[INSTRUCTIONS])
            }
            for (name in PROMPTS) {
                if (count[name] == 0) {
                    continue
                }
                val start = valueStart[name]
                val end = valueEnd[name]
                if (end - start == NULL.size && NULL.indices.all { text[start + it] == NULL[it] }) {
                    continue
                }
                if (text[start] != '['.code.toByte()) {
                    return text.copyOfRange(start, end)
                }
                var first: ByteArray? = null
                JsonObjectText.elements(text, start, end) { elementStart, elementEnd ->
                    if (first == null) {
                        first = text.copyOfRange(elementStart, elementEnd)
                    }
                }
                first?.let { return it }
            }
            return null
        }

        /**
         * The changes that take the cache secret out of the text and put
         * [salt], a JSON string, in as `cache_salt`, in the order of the
         * text. Neither member is in the text more than once.
         */
        fun scoped(salt: ByteArray): List<Splice> {
            val splices = ArrayList<Splice>(2)
            if (count[SECRET] == 1) {
                splices += removal(nameStart[SECRET], valueEnd[SECRET])
            }
            if (count[SALT] == 1) {
                splices += Splice(valueStart[SALT], valueEnd[SALT], salt)
            } else {
                val others = members - count[SECRET]
                val member = (if (others > 0) "," else "") + "\"$CACHE_SALT_FIELD\":"
                splices += Splice(closingBrace, closingBrace, member.toByteArray(Charsets.US_ASCII) + salt)
            }
            return splices.sortedBy { it.start }
        }

        /**
         * Takes out the member from [start] to [end], with the comma that
         * separated it from its neighbour: the one before it, or, for the
         * first member, the one after it.
         */
        private fun removal(start: Int, end: Int): Splice {
            var before = start - 1
            while (isWhitespace(text[before])) {
                before--
            }
            if (text[before] == COMMA) {
                return Splice(before, end, EMPTY)
            }
            var after = end
            while (isWhitespace(text[after])) {
                after++
            }
            return if (text[after] == COMMA) Splice(start, after + 1, EMPTY) else Splice(start, end, EMPTY)
        }

        private fun isWhitespace(b: Byte): Boolean = b == SPACE || b == TAB || b == LINE_FEED || b == CARRIAGE_RETURN
    }

    /** What scopes the prompt cache for one request. */
    internal class CacheScope(
        /** The `cache_salt` member's value, as a JSON string. */
        val salt: ByteArray,
        /** The value of [CACHE_PREFIX_HEADER], or the empty string for a request without a prompt. */
        val prefix: String,
    ) {
        internal companion object {
            /**
             * The scope for [secret], the API key in [authorization] and
             * the start of the prompt.
             *
             * The salt is HKDF-SHA-256 of the secret, salted with the API
             * key, so that neither can be worked out from it and each API
             * key has caches of its own. The prefix is an HMAC-SHA-256 of
             * the start of the prompt under a second key that is derived
             * the same way, so that the gateway, which sees it, learns
             * only whether two requests of one user start alike.
             */
            fun derive(secret: String, authorization: String, promptHead: ByteArray?): CacheScope {
                val key = secret.toByteArray(Charsets.UTF_8)
                val apiKey = bearerCredential(authorization).toByteArray(Charsets.UTF_8)
                val salt = Base64.getUrlEncoder().withoutPadding().encodeToString(hkdf(key, apiKey, CACHE_SALT_DOMAIN))
                val prefix = promptHead?.let { head ->
                    hmac(hkdf(key, apiKey, CACHE_ROUTE_DOMAIN), head).joinToString("") { "%02x".format(it) }
                }
                return CacheScope("\"$salt\"".toByteArray(Charsets.US_ASCII), prefix.orEmpty())
            }

            /**
             * The credential of a `Bearer` authorization, whose scheme is
             * matched without regard to case; the empty string for any
             * other.
             */
            fun bearerCredential(authorization: String): String {
                val trimmed = authorization.trim()
                val space = trimmed.indexOf(' ')
                if (space < 0 || !trimmed.substring(0, space).equals("Bearer", ignoreCase = true)) {
                    return ""
                }
                return trimmed.substring(space + 1).trim()
            }

            /** HKDF with SHA-256 (RFC 5869), for one block of output. */
            private fun hkdf(secret: ByteArray, salt: ByteArray, info: String): ByteArray {
                // An empty salt is a block of zeros, by the RFC.
                val pseudorandomKey = hmac(if (salt.isEmpty()) ByteArray(HASH_BYTES) else salt, secret)
                return hmac(pseudorandomKey, info.toByteArray(Charsets.US_ASCII) + 1.toByte())
            }

            private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
                Mac.getInstance(HMAC).apply { init(SecretKeySpec(key, HMAC)) }.doFinal(data)
        }
    }

    private const val LONG_S = '\u017f'
    private const val KELVIN = '\u212a'
    private val NULL = "null".toByteArray(Charsets.US_ASCII)
    private val EMPTY = ByteArray(0)
    private const val COMMA = ','.code.toByte()
    private const val SPACE = ' '.code.toByte()
    private const val TAB = '\t'.code.toByte()
    private const val LINE_FEED = '\n'.code.toByte()
    private const val CARRIAGE_RETURN = '\r'.code.toByte()
}

/**
 * Reads a `multipart/form-data` upload far enough to find the model that it
 * names.
 *
 * The client routes an upload by its `model` field, and the server reads
 * that field for itself, with a parser of its own. So the upload is read
 * strictly, and anything that two parsers could read differently is refused
 * rather than interpreted: text that looks like a boundary where none
 * belongs, a line that does not end in CRLF, a part's header that is folded
 * or repeated, a field name that is escaped or encoded, and a header on the
 * model's field that says how its value is encoded.
 */
internal object Multipart {
    /**
     * The value of the one `model` field of [body], whose parts are
     * separated by [boundary].
     *
     * @throws ConfigurationException if [body] is not such an upload, or
     *   does not have exactly one `model` field with a value that is not
     *   blank.
     */
    @Throws(ConfigurationException::class)
    fun model(body: ByteArray, boundary: String): String {
        val parts = parts(body, boundary) ?: throw ConfigurationException("invalid multipart upload")
        val models = parts.filter { it.name == "model" }
        val model = models.singleOrNull()?.takeIf { !it.isFile }?.let { utf8(body, it.start, it.end) }
        if (model.isNullOrBlank()) {
            throw ConfigurationException("multipart upload must contain exactly one non-empty model field")
        }
        return model
    }

    /**
     * The boundary that [contentType], a `multipart/form-data` content type
     * as it is written, names: its one `boundary` parameter, a token or a
     * quoted string without escapes, of 1 to 70 of the characters that a
     * boundary may have.
     *
     * @throws ConfigurationException if there is no such parameter, or the
     *   content type is written in a way that parsers read differently.
     */
    @Throws(ConfigurationException::class)
    fun boundary(contentType: String): String {
        val boundary = parameters(contentType)?.second?.get("boundary")
        if (boundary == null || !isBoundary(boundary)) {
            throw ConfigurationException("multipart upload is missing its boundary, or names it ambiguously")
        }
        return boundary
    }

    private fun isBoundary(boundary: String): Boolean =
        boundary.length in 1..MAX_BOUNDARY && !boundary.endsWith(' ') &&
            boundary.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it in BOUNDARY_PUNCTUATION }

    /** A part with a `form-data` disposition: its name, and where its content is. */
    private class Part(val name: String?, val isFile: Boolean, val start: Int, val end: Int)

    private fun parts(body: ByteArray, boundary: String): List<Part>? {
        if (!isBoundary(boundary)) {
            return null
        }
        val delimiter = "--$boundary".toByteArray(Charsets.US_ASCII)
        val parts = ArrayList<Part>()
        // Where the content of the part that is being read starts.
        var content = -1
        var at = indexOf(body, delimiter, 0)
        while (at >= 0) {
            // A delimiter starts a line, and nothing else may spell one.
            if (at != 0 && !(at >= 2 && body[at - 2] == CR && body[at - 1] == LF)) {
                return null
            }
            if (content >= 0) {
                parts += part(body, content, at - 2) ?: return null
            }
            var next = at + delimiter.size
            if (startsWith(body, next, CLOSE)) {
                // The last delimiter ends its line, and what follows that
                // line is not part of the form.
                next += CLOSE.size
                while (next < body.size && (body[next] == SP || body[next] == HT)) {
                    next++
                }
                val endsLine = next == body.size || startsWith(body, next, CRLF)
                return if (endsLine && indexOf(body, delimiter, next) < 0) parts else null
            }
            while (next < body.size && (body[next] == SP || body[next] == HT)) {
                next++
            }
            if (!startsWith(body, next, CRLF)) {
                return null
            }
            content = next + 2
            at = indexOf(body, delimiter, content)
        }
        // No delimiter closed the form.
        return null
    }

    /** The part whose headers and content are the bytes from [start] to [end]. */
    private fun part(body: ByteArray, start: Int, end: Int): Part? {
        if (end < start) {
            return null
        }
        // Headers end at an empty line; a part may have none.
        val contentStart: Int
        val headersEnd: Int
        if (startsWith(body, start, CRLF) && start + 2 <= end) {
            headersEnd = start
            contentStart = start + 2
        } else {
            headersEnd = indexOf(body, BLANK_LINE, start).takeIf { it in start until end } ?: return null
            contentStart = headersEnd + BLANK_LINE.size
            if (contentStart > end) {
                return null
            }
        }
        var disposition: String? = null
        val others = ArrayList<Pair<String, String>>()
        var lineStart = start
        while (lineStart < headersEnd) {
            val lineEnd = indexOf(body, CRLF, lineStart).takeIf { it in lineStart..headersEnd } ?: headersEnd
            val line = String(body, lineStart, lineEnd - lineStart, Charsets.ISO_8859_1)
            val colon = line.indexOf(':')
            if (colon <= 0 || line.any { it == '\r' || it == '\n' } || !line.substring(0, colon).all(::isTokenCharacter)) {
                return null
            }
            if (line.substring(0, colon).equals("Content-Disposition", ignoreCase = true)) {
                if (disposition != null) {
                    return null
                }
                disposition = line.substring(colon + 1)
            } else {
                others += line.substring(0, colon).lowercase() to line.substring(colon + 1)
            }
            lineStart = lineEnd + 2
        }
        val (type, parameters) = parameters(disposition ?: return Part(null, false, contentStart, end)) ?: return null
        if (type != "form-data") {
            return null
        }
        val name = parameters["name"]
        // A field that the client or the server acts on is its bytes, as
        // they are: no header may say that they are encoded.
        val plain = others.all { (header, value) -> isPlain(header, value, end - contentStart) } &&
            others.map { it.first }.toSet().size == others.size
        if (name in WATCHED && !plain) {
            return null
        }
        return Part(name, parameters.containsKey("filename"), contentStart, end)
    }

    /**
     * Whether a part's header leaves its content to be read as the bytes
     * that it is: a length that is the content's, or a content type of
     * plain text in UTF-8 or ASCII. Each may be given once.
     */
    private fun isPlain(header: String, value: String, length: Int): Boolean = when (header) {
        "content-length" -> value.trim(' ', '\t') == length.toString()
        "content-type" -> parameters(value)?.let { (type, parameters) ->
            type == "text/plain" && parameters.all { (name, charset) ->
                name == "charset" && (charset.equals("utf-8", ignoreCase = true) || charset.equals("us-ascii", ignoreCase = true))
            }
        } ?: false
        else -> false
    }

    /**
     * The value of a header that has parameters, such as a disposition or a
     * content type: what leads it, in lower case, and its parameters by
     * their names in lower case. Null for one that is not written plainly:
     * each parameter once, as a token or as a quoted string without escapes
     * or control characters, and none in the extended notation that encodes
     * its value.
     */
    private fun parameters(header: String): Pair<String, Map<String, String>>? {
        val text = header.trim { it == ' ' || it == '\t' }
        var at = text.indexOf(';').let { if (it < 0) text.length else it }
        val type = text.substring(0, at).trimEnd(' ', '\t').lowercase()
        if (type.isEmpty() || !type.all { isTokenCharacter(it) || it == '/' }) {
            return null
        }
        val parameters = HashMap<String, String>()
        while (at < text.length) {
            // At a semicolon.
            at++
            while (at < text.length && (text[at] == ' ' || text[at] == '\t')) {
                at++
            }
            val nameStart = at
            while (at < text.length && isTokenCharacter(text[at])) {
                at++
            }
            val name = text.substring(nameStart, at).lowercase()
            if (name.isEmpty() || name.endsWith('*') || at >= text.length || text[at] != '=') {
                return null
            }
            at++
            val value: String
            if (at < text.length && text[at] == '"') {
                val close = text.indexOf('"', at + 1)
                if (close < 0) {
                    return null
                }
                value = text.substring(at + 1, close)
                if (value.any { it == '\\' || it.isISOControl() }) {
                    return null
                }
                at = close + 1
            } else {
                val valueStart = at
                while (at < text.length && isTokenCharacter(text[at])) {
                    at++
                }
                value = text.substring(valueStart, at)
                if (value.isEmpty()) {
                    return null
                }
            }
            while (at < text.length && (text[at] == ' ' || text[at] == '\t')) {
                at++
            }
            if ((at < text.length && text[at] != ';') || parameters.put(name, value) != null) {
                return null
            }
        }
        return Pair(type, parameters)
    }

    private fun isTokenCharacter(c: Char): Boolean = c in '!'..'~' && c !in "()<>@,;:\\\"/[]?={}"

    private fun utf8(body: ByteArray, from: Int, to: Int): String? =
        try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(body, from, to - from))
                .toString()
        } catch (_: CharacterCodingException) {
            null
        }

    private fun startsWith(body: ByteArray, at: Int, prefix: ByteArray): Boolean =
        at + prefix.size <= body.size && prefix.indices.all { body[at + it] == prefix[it] }

    /** The index of the first [wanted] at or after [from], or -1. */
    private fun indexOf(body: ByteArray, wanted: ByteArray, from: Int): Int {
        val first = wanted[0]
        var at = from
        val last = body.size - wanted.size
        while (at <= last) {
            if (body[at] == first && startsWith(body, at, wanted)) {
                return at
            }
            at++
        }
        return -1
    }

    private const val MAX_BOUNDARY = 70
    private const val BOUNDARY_PUNCTUATION = "'()+_,-./:=? "

    /** The fields that the client or the model acts on. */
    private val WATCHED = setOf("model", UserCacheSecret.FIELD, GatewayRequest.CACHE_SALT_FIELD)
    private const val CR = '\r'.code.toByte()
    private const val LF = '\n'.code.toByte()
    private const val SP = ' '.code.toByte()
    private const val HT = '\t'.code.toByte()
    private val CRLF = byteArrayOf(CR, LF)
    private val BLANK_LINE = byteArrayOf(CR, LF, CR, LF)
    private val CLOSE = "--".toByteArray(Charsets.US_ASCII)
}
