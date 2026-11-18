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
     * Whether [url]'s host, as it is written, is this machine: `localhost`
     * or a loopback IP address, which is to say `127.0.0.0/8` or `::1`. No
     * name is resolved, so DNS cannot make a remote host pass.
     */
    fun isLoopback(url: HttpUrl): Boolean {
        val host = url.host
        return host == "localhost" || host == "::1" || (isDottedIpv4(host) && host.startsWith("127."))
    }

    /**
     * A relay: a host with an optional port, held to the rules for an
     * enclave.
     */
    @Throws(ConfigurationException::class)
    fun requireRelay(relay: String) {
        try {
            enclaveUrl(relay)
        } catch (_: ConfigurationException) {
            throw ConfigurationException("invalid attestation relay: want a host with an optional port, not a URL")
        }
    }

    /**
     * Whether [url] is exactly what [authority] spelled: its host in the
     * form that the URL holds it, and its port or none. The URL parser is
     * lenient, the verifier reads the enclave's host for itself, and the
     * resolver reads it a third time, so a text that any of them could read
     * differently from how it is written is refused:
     * - anything but printable ASCII, so an internationalized name is
     *   written in its ASCII form, and no character can fold into another;
     * - a name that ends in a number without being a plain dotted IPv4
     *   address, such as `127.1` or `0x7f.1`, which a resolver may read as
     *   an address that the text does not show.
     *
     * A name that ends in a dot is the same name, fully qualified, and is
     * dialled as written; it is a different origin from the name without
     * the dot.
     */
    private fun namesAuthority(authority: String, url: HttpUrl): Boolean {
        if (!authority.all { it.code in PRINTABLE_ASCII }) {
            return false
        }
        val host = if (url.host.contains(':')) "[${url.host}]" else url.host
        val written = authority.lowercase()
        if (written != host && written != "$host:${url.port}") {
            return false
        }
        return host.startsWith("[") || !endsInNumber(host) || isDottedIpv4(host)
    }

    private fun endsInNumber(host: String): Boolean {
        val last = host.removeSuffix(".").substringAfterLast('.')
        return last.isNotEmpty() && (last.all(Char::isDigit) || last.startsWith("0x"))
    }

    /** Four decimal octets without leading zeros, and nothing else. */
    private fun isDottedIpv4(host: String): Boolean {
        val parts = host.split('.')
        return parts.size == 4 && parts.all { part ->
            part.length in 1..3 && part.all(Char::isDigit) && (part.length == 1 || part[0] != '0') && part.toInt() <= 255
        }
    }

    private fun isUnsafe(c: Char): Boolean = c.isWhitespace() || c.isISOControl() || c == '\\'

    private const val AUTHORITY_DELIMITERS = "/@?#"
    private val PRINTABLE_ASCII = 0x21..0x7e
    private val SCHEMES = listOf("https://", "http://")
}
