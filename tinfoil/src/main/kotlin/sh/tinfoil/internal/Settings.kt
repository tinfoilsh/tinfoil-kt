@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.internal

import sh.tinfoil.AttestationFetcher
import sh.tinfoil.Catalog
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.ModelPin
import sh.tinfoil.Policy
import sh.tinfoil.RouterListFetcher
import sh.tinfoil.Transport
import sh.tinfoil.VerificationCheck

// What a caller's options block set, copied when the block returned. A
// client is made from these copies alone, so nothing that happens to the
// options object afterwards reaches it. None of them is a data class: they
// hold secrets, and must not print them.
//

/** The options of a client for one enclave, or for a router that is chosen. */
internal class RouteSettings(
    val transport: Transport = Transport.Tls,
    val fetchAttestation: AttestationFetcher? = null,
    val fetchRouterList: RouterListFetcher? = null,
    val policy: Policy = Policy(),
    val userCacheSecret: String? = null,
    val verificationCheck: VerificationCheck? = null,
    val onVerification: VerificationObserver? = null,
)

/** The options of a client for the gateway. */
internal class GatewaySettings(
    val modelPins: Map<String, ModelPin> = emptyMap(),
    val pinnedModelsOnly: Boolean = false,
    val url: String? = null,
    val policy: Policy = Policy(),
    val userCacheSecret: String? = null,
    val verificationCheck: VerificationCheck? = null,
    val onVerification: VerificationObserver? = null,
    val catalog: (() -> Catalog)? = null,
)
