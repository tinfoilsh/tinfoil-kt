package sh.tinfoil.openai

import sh.tinfoil.TinfoilException

/**
 * The [TinfoilException] behind this failure: the failure itself, or the
 * nearest of its causes that is one, or null if there is none.
 *
 * The OpenAI SDK reports every failure as an unchecked
 * [com.openai.errors.OpenAIException], so a failure of this SDK's own, such
 * as an enclave that does not verify, reaches the caller of an OpenAI client
 * wrapped in one, as its cause. This finds it, whichever exception the
 * OpenAI SDK or a `CompletableFuture` wrapped it in:
 *
 * ```kotlin
 * try {
 *     client.openAI.chat().completions().create(params)
 * } catch (e: OpenAIException) {
 *     when (val failure = e.tinfoilException) {
 *         is AttestationException -> TODO("the enclave is not to be trusted")
 *         is ConfigurationException -> TODO("the request or the client is invalid")
 *         is NetworkException -> TODO("the enclave could not be verified again: try later")
 *         null -> TODO("the API's own error, or a failure of the network")
 *     }
 * }
 * ```
 */
public val Throwable.tinfoilException: TinfoilException?
    get() = generateSequence(this) { it.cause }.take(MAX_CAUSES).firstNotNullOfOrNull { it as? TinfoilException }

private const val MAX_CAUSES = 32
