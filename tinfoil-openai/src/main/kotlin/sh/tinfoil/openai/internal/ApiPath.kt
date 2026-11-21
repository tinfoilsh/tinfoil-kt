package sh.tinfoil.openai.internal

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.AttestedHttpClient
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.InternalTinfoilApi
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.internal.CrossArtifact

/**
 * Where an OpenAI client sends its requests: the API path joined under an
 * attested client's base URL.
 */
@OptIn(InternalTinfoilApi::class, ExperimentalTinfoilApi::class)
internal object ApiPath {
    /** The API path when none is set. */
    const val DEFAULT: String = "/v1/"

    /**
     * The OpenAI base URL for [httpClient] and [apiPath]: [apiPath], or
     * [DEFAULT] when it is null, joined under the client's base URL, the
     * proxy URL or `https://<enclave>/`, whether or not that ends with `/`,
     * and ending with `/`. For a gateway client it is the gateway's URL as
     * it is given, ending with `/`, and an API path is refused, since the
     * gateway's URL already carries its path.
     *
     * @throws ConfigurationException for an [apiPath] that is not a valid
     *   API path, and for any API path with a gateway client.
     */
    fun baseUrl(httpClient: AttestedHttpClient, apiPath: String?): HttpUrl {
        val base = when (httpClient) {
            is EnclaveHttpClient, is RouterHttpClient -> httpClient.baseUrl
            is GatewayHttpClient -> {
                if (apiPath != null) {
                    throw CrossArtifact.configurationException(
                        "apiPath must not be set with a gateway client: the gateway's URL already carries its path",
                    )
                }
                return withSlash(httpClient.baseUrl)
            }
        }
        val path = check(apiPath ?: DEFAULT)
        val joined = base.toString().trimEnd('/') + path + if (path.endsWith("/")) "" else "/"
        return joined.toHttpUrlOrNull()
            ?: throw CrossArtifact.configurationException("apiPath does not make a URL under ${base.scheme}://${base.host}")
    }

    /**
     * [path] if it is a valid API path: an RFC 3986 `path-absolute`, which
     * starts with `/` but not `//` and holds nothing but `pchar`s and `/`,
     * without a `.` or `..` segment, plain or percent-encoded, and without
     * an encoded `/` or `\`.
     */
    fun check(path: String): String {
        fun invalid(why: String): Nothing = throw CrossArtifact.configurationException("invalid apiPath: $why")
        if (!path.startsWith("/")) {
            invalid("it must be an absolute path, which starts with /")
        }
        if (path.startsWith("//")) {
            invalid("it must not start with //")
        }
        var i = 0
        while (i < path.length) {
            val c = path[i]
            when {
                c == '%' -> {
                    if (i + 2 >= path.length || !isHex(path[i + 1]) || !isHex(path[i + 2])) {
                        invalid("a % must start an escape of two hexadecimal digits")
                    }
                    val escaped = path.substring(i + 1, i + 3).uppercase()
                    if (escaped == "2F" || escaped == "5C") {
                        invalid("it must not encode a / or a \\")
                    }
                    i += 3
                    continue
                }
                c == '/' || c in PCHAR_OTHERS || c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' -> Unit
                else -> invalid("it may hold only RFC 3986 path characters and escapes")
            }
            i++
        }
        for (segment in path.split('/')) {
            val decoded = segment.replace("%2e", ".", ignoreCase = true)
            if (decoded == "." || decoded == "..") {
                invalid("it must not have a . or .. segment")
            }
        }
        return path
    }

    private fun withSlash(url: HttpUrl): HttpUrl =
        if (url.encodedPath.endsWith("/")) url else url.newBuilder().encodedPath(url.encodedPath + "/").build()

    private fun isHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

    /** What `pchar` allows besides letters, digits and escapes. */
    private const val PCHAR_OTHERS = "-._~!$&'()*+,;=:@"
}
