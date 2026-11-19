@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.internal

import com.openai.core.ClientOptions
import sh.tinfoil.Catalog
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.ModelPin
import sh.tinfoil.TinfoilEvent
import sh.tinfoil.TransportMode
import sh.tinfoil.Verification
import sh.tinfoil.VerificationCheck
import sh.tinfoil.Verifier

// What a caller's options block set, copied when the block returned. A
// client is made from these copies alone, so nothing that happens to the
// options object afterwards reaches it. None of them is a data class: they
// hold secrets, and must not print them.

/** The options of a client for one enclave, or for a router that is chosen. */
internal class RouteSettings(
    val transportMode: TransportMode = TransportMode.Tls,
    val baseUrl: String? = null,
    val attestationRelay: String? = null,
    val verifier: Verifier? = null,
    val userCacheSecret: String? = null,
    val verificationCheck: VerificationCheck? = null,
    val onVerificationResult: ((Result<Verification>) -> Unit)? = null,
)

/** The options of a client for the gateway. */
internal class GatewaySettings(
    val modelPins: Map<String, ModelPin> = emptyMap(),
    val pinnedModelsOnly: Boolean = false,
    val baseUrl: String? = null,
    val verifier: Verifier? = null,
    val userCacheSecret: String? = null,
    val verificationCheck: VerificationCheck? = null,
    val onVerificationResult: ((Result<Verification>) -> Unit)? = null,
    val catalog: (() -> Catalog)? = null,
)

/** The options of the OpenAI client that is put over an attested client. */
internal class OpenAISettings(
    val tinfoilEvents: Set<TinfoilEvent> = emptySet(),
    /** What the caller does to the OpenAI SDK's options builder, in the order in which it was given. */
    val configure: List<ClientOptions.Builder.() -> Unit> = emptyList(),
)
