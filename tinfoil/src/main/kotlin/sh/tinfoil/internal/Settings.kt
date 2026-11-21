@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.internal

import sh.tinfoil.Catalog
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.InternalTinfoilApi
import sh.tinfoil.ModelPin
import sh.tinfoil.Policy
import sh.tinfoil.Transport
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck

// What a caller's options block set, copied when the block returned. A
// client is made from these copies alone, so nothing that happens to the
// options object afterwards reaches it. None of them is a data class: they
// hold secrets, and must not print them.
//
// They are public, and marked, because the OpenAI clients, which are another
// artifact, take a snapshot of their caller's block and hand it back when
// the client is made. Only this artifact makes one, and only from an
// options object: a snapshot holds what a caller's block set, and nothing
// else.

/** The options of a client for one enclave, or for a router that is chosen. */
@InternalTinfoilApi
public class RouteSettings internal constructor(
    @get:JvmSynthetic public val transport: Transport = Transport.Tls,
    @get:JvmSynthetic public val attestationRelay: String? = null,
    @get:JvmSynthetic public val policy: Policy = Policy(),
    @get:JvmSynthetic public val userCacheSecret: String? = null,
    @get:JvmSynthetic public val verificationCheck: VerificationCheck? = null,
    @get:JvmSynthetic public val onVerificationResult: ((Result<Verification>) -> Unit)? = null,
)

/** The options of a client for the gateway. */
@InternalTinfoilApi
public class GatewaySettings internal constructor(
    @get:JvmSynthetic public val modelPins: Map<String, ModelPin> = emptyMap(),
    @get:JvmSynthetic public val pinnedModelsOnly: Boolean = false,
    @get:JvmSynthetic public val baseUrl: String? = null,
    @get:JvmSynthetic public val policy: Policy = Policy(),
    @get:JvmSynthetic public val userCacheSecret: String? = null,
    @get:JvmSynthetic public val verificationCheck: VerificationCheck? = null,
    @get:JvmSynthetic public val onVerificationResult: ((Result<Verification>) -> Unit)? = null,
    @get:JvmSynthetic public val catalog: (() -> Catalog)? = null,
)
