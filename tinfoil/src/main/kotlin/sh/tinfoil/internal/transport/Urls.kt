package sh.tinfoil.internal.transport

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import sh.tinfoil.ConfigurationException

/**
 * A scheme, host and port: what a client's requests are confined to. The
 * values are those of an [HttpUrl], so the host is lowercase, an
 * internationalized name is in its ASCII form, an IPv6 address is canonical
 * and a missing port is the scheme's default.
 */
internal class Origin private constructor(
    val scheme: String,
    val host: String,
    val port: Int,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is Origin && scheme == other.scheme && host == other.host && port == other.port)

    override fun hashCode(): Int = 31 * (31 * scheme.hashCode() + host.hashCode()) + port

    /** The origin as text, without the scheme's default port. It never carries credentials. */
    override fun toString(): String {
        val authority = if (host.contains(':')) "[$host]" else host
        return if (port == HttpUrl.defaultPort(scheme)) "$scheme://$authority" else "$scheme://$authority:$port"
    }

    companion object {
        fun of(url: HttpUrl): Origin = Origin(url.scheme, url.host, url.port)
    }
}

/**
 * Reads the URLs that a client is configured with. Nothing here echoes a URL
 * that it refuses, because such a URL may carry credentials.
 */
internal object Urls {
    /**
     * The HTTPS URL of [enclave]'s own origin. [enclave] is a host with an
     * optional port, not a URL.
     */
    @Throws(ConfigurationException::class)
    fun enclaveUrl(enclave: String): HttpUrl {
        if (enclave.isEmpty()) {
            throw ConfigurationException("enclave host is required")
        }
        val url = if (enclave.any { it in AUTHORITY_DELIMITERS || isUnsafe(it) }) {
            null
        } else {
            "https://$enclave/".toHttpUrlOrNull()
        }
        // A parser that drops or rewrites part of the text would make the
        // client talk to another host than the one that is verified.
        if (url == null || url.encodedPath != "/" || !namesAuthority(enclave, url)) {
            throw ConfigurationException("invalid enclave: want a host with an optional port, not a URL")
        }
        return url
    }

    /**
     * A base URL: an absolute `https` or `http` URL without user information,
     * a query or a fragment, even an empty one, since request paths join
     * under it.
     */
    @Throws(ConfigurationException::class)
    fun baseUrl(text: String): HttpUrl {
        val schemeLength = SCHEMES.firstOrNull { text.startsWith(it, ignoreCase = true) }?.length
            ?: throw ConfigurationException("invalid base URL: it must be an absolute https:// URL")
        if (text.any { it == '?' || it == '#' }) {
            throw ConfigurationException("invalid base URL: a base URL must not carry a query or a fragment")
        }
        if (text.any(::isUnsafe)) {
            throw ConfigurationException("invalid base URL: it contains a space, a control character or a backslash")
        }
        val authority = text.substring(schemeLength).substringBefore('/')
        if (authority.contains('@')) {
            throw ConfigurationException("invalid base URL: a base URL must not contain user information")
        }
        val url = text.toHttpUrlOrNull()
        if (url == null || url.username.isNotEmpty() || url.password.isNotEmpty() ||
            url.querySize != 0 || url.fragment != null || !namesAuthority(authority, url)
        ) {
            throw ConfigurationException("invalid base URL: it does not parse as an absolute URL with a host")
        }
        return url
    }

    /**
     * Whether [url] is exactly what [authority] spelled: its host in the
     * form that the URL holds it, and its port or none. The URL parser is
     * lenient, and the verifier reads the enclave's host for itself, so a
     * text that could be read in more than one way is refused. An
     * internationalized name is therefore written in its ASCII form.
     */
    private fun namesAuthority(authority: String, url: HttpUrl): Boolean {
        val host = if (url.host.contains(':')) "[${url.host}]" else url.host
        val written = authority.lowercase()
        return written == host || written == "$host:${url.port}"
    }

    private fun isUnsafe(c: Char): Boolean = c.isWhitespace() || c.isISOControl() || c == '\\'

    private const val AUTHORITY_DELIMITERS = "/@?#"
    private val SCHEMES = listOf("https://", "http://")
}
