package sh.tinfoil.internal.verification

import sh.tinfoil.ConfigAuthorizer
import sh.tinfoil.go.mobile.ConfigAuthorizer as GoConfigAuthorizer

/**
 * Hands each config that the verifier library asks about to a
 * [ConfigAuthorizer]. The library calls it synchronously during a
 * verification, possibly on several threads at once; it holds no state of
 * its own.
 */
internal class ConfigAuthorizerBridge(private val authorizer: ConfigAuthorizer) : GoConfigAuthorizer {
    /** Returns to approve the config, and throws to reject it. */
    override fun authorizeConfig(endorsementJson: String?) {
        ConfigAuthorization.authorize(authorizer, endorsementJson)
    }
}
