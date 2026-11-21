@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.internal

import kotlinx.coroutines.CoroutineDispatcher
import sh.tinfoil.ConfigurationException
import sh.tinfoil.EnclaveHttpClient
import sh.tinfoil.EnclaveOptions
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.GatewayOptions
import sh.tinfoil.InternalTinfoilApi
import sh.tinfoil.RouterHttpClient
import sh.tinfoil.RouterOptions
import sh.tinfoil.Trust

/**
 * Everything that another artifact of this SDK uses of this one beyond its
 * public API, in one place. Besides this object, only the constructors of
 * the options types and the classes [RouteSettings] and [GatewaySettings],
 * which carry a snapshot from here back to here, are marked
 * [InternalTinfoilApi].
 *
 * Nothing here takes a verifier, a trust anchor, a clock or a proxy: a
 * client that is made here is made exactly as the public `create` of its
 * class makes it, from options that a caller's block set.
 */
@InternalTinfoilApi
public object CrossArtifact {
    /** [Background.dispatcher]. */
    @get:JvmSynthetic
    public val dispatcher: CoroutineDispatcher get() = Background.dispatcher

    /** [Background.creating]. */
    @JvmSynthetic
    public suspend fun <T : AutoCloseable> creating(block: suspend () -> T): T = Background.creating(block)

    /** A [ConfigurationException], whose constructor is this artifact's. */
    @JvmSynthetic
    public fun configurationException(detail: String, cause: Throwable? = null): ConfigurationException =
        ConfigurationException(detail, cause)

    /** [options] as they are now, copied. */
    @JvmSynthetic
    public fun snapshot(options: EnclaveOptions): RouteSettings = options.snapshot()

    /** [options] as they are now, copied. */
    @JvmSynthetic
    public fun snapshot(options: RouterOptions): RouteSettings = options.snapshot()

    /** [options] as they are now, copied. */
    @JvmSynthetic
    public fun snapshot(options: GatewayOptions): GatewaySettings = options.snapshot()

    /** [EnclaveHttpClient.create], with options that were read already. */
    @JvmSynthetic
    public suspend fun enclaveHttpClient(enclave: String, trust: Trust, settings: RouteSettings): EnclaveHttpClient =
        EnclaveHttpClient.create(enclave, trust, settings, Internals())

    /** [RouterHttpClient.create], with options that were read already. */
    @JvmSynthetic
    public suspend fun routerHttpClient(settings: RouteSettings): RouterHttpClient =
        RouterHttpClient.create(settings, Internals())

    /** [GatewayHttpClient.create], with options that were read already. */
    @JvmSynthetic
    public suspend fun gatewayHttpClient(settings: GatewaySettings): GatewayHttpClient =
        GatewayHttpClient.create(settings, Internals())
}
