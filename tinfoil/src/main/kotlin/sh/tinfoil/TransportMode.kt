package sh.tinfoil

/** How a client protects its traffic to an enclave. */
public enum class TransportMode {
    /**
     * Pins every connection to the TLS key that the enclave's attestation
     * endorses. It protects the whole request and response, and needs a
     * direct connection to the enclave.
     */
    Tls,

    /**
     * Seals request and response bodies to the HPKE key that the enclave's
     * attestation endorses, so that they stay private through a proxy.
     *
     * This version of the SDK does not implement it yet: a client created
     * with it fails with a [ConfigurationException] before any network I/O.
     */
    Ehbp,
}
