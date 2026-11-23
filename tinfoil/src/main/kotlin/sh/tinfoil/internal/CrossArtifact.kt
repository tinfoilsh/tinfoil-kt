package sh.tinfoil.internal

import kotlinx.coroutines.CoroutineDispatcher
import sh.tinfoil.ConfigurationException
import sh.tinfoil.InternalTinfoilApi

/**
 * Everything that another artifact of this SDK uses of this one beyond its
 * public API, in one place; nothing else is marked [InternalTinfoilApi].
 *
 * Nothing here takes or reveals a verifier, a trust anchor, a clock or a
 * proxy.
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
}
