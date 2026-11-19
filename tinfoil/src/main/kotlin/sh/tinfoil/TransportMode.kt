package sh.tinfoil

/** How a client protects its traffic to an enclave. */
public enum class TransportMode {
    /**
     * Pins every connection to the TLS key that the enclave's attestation
     * endorses. It protects the whole request and response, and needs a
     * direct connection to the enclave.
     */
    TLS,

    /**
     * Seals request and response bodies to the HPKE key that the enclave's
     * attestation endorses, so that they stay private through a proxy.
     *
     * Only bodies are sealed. The method, the URL and the headers of every
     * request, an API key among them, are not, and neither is a request
     * without a body or the response to it: a proxy, or anything else on the
     * way that ends the TLS connection, reads them and can change them.
     * Connections are validated as the platform validates any HTTPS
     * connection, and are not pinned to the enclave's key, so the host
     * that the client was created with is trusted with all of that. A
     * client that chooses its enclave's host by itself, [RouterHttpClient],
     * pins its direct connections to the attested key in this mode too.
     * Protocol upgrades, such as WebSockets, and `CONNECT` tunnels are
     * refused, because nothing after the handshake would be sealed.
     */
    EHBP,
}
