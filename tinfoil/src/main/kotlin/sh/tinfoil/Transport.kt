package sh.tinfoil

/**
 * How a client protects its traffic to an enclave: [Tls], the default, or
 * [Ehbp]. A proxy exists only inside [Ehbp], so that it cannot be combined
 * with a pinned TLS connection.
 */
public sealed interface Transport {
    /**
     * Pins every connection to the TLS key that the enclave's attestation
     * endorses. It protects the whole request and response, and needs a
     * direct connection to the enclave, so it takes no URL: requests go to
     * the enclave's own HTTPS origin.
     */
    public data object Tls : Transport

    /**
     * Seals request and response bodies to the HPKE key that the enclave's
     * attestation endorses, so that they stay private through a proxy.
     *
     * Only bodies are sealed. The method, the URL and the headers of every
     * request, an API key among them, are not, and neither is a request
     * without a body or the response to it: a proxy, or anything else on
     * the way that ends the TLS connection, reads them and can change them.
     * Connections are validated as the platform validates any HTTPS
     * connection, and are not pinned to the enclave's key, so the host that
     * requests are sent to is trusted with all of that. A router client's
     * direct connections, to a host that the client chose by itself, are
     * pinned to the attested key in this mode too. Protocol upgrades, such
     * as WebSockets, and `CONNECT` tunnels are refused, because nothing
     * after the handshake would be sealed.
     */
    public data class Ehbp(
        /**
         * A proxy that forwards requests to the enclave, and that requests
         * are sent to; null sends them directly to the enclave. Each request
         * carries `X-Tinfoil-Enclave-Url: https://<enclave>` so that the
         * proxy can forward it.
         *
         * Its path, if any, is where the proxy is mounted, not the API
         * path: request paths join under it, whether or not it ends with
         * `/`. The proxy reads everything that is not sealed, so it must use
         * HTTPS; `http://` is accepted only when its host is `localhost` or
         * a loopback IP address, for a proxy on the same machine, and such a
         * proxy is reached directly, whatever HTTP proxy the system is
         * configured with. On Android, cleartext HTTP also has to be
         * permitted by the app's network security configuration. A URL that
         * is empty, or that has user information, a query or a fragment,
         * even an empty one, is refused with a [ConfigurationException], and
         * so is a proxy on the enclave's own origin, which is no proxy:
         * leave it null to connect directly.
         */
        public val proxyUrl: String? = null,
    ) : Transport
}
