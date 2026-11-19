@file:JvmName("TinfoilErrors")

package sh.tinfoil

/**
 * The [TinfoilException] behind this failure: the failure itself, or the
 * nearest of its causes that is one, or null if there is none.
 *
 * A library that sends its requests through one of this SDK's clients
 * reports a failure in its own way, and a failure of this SDK's own, such
 * as an enclave that does not verify, then reaches the caller wrapped, as a
 * cause. The OpenAI SDK, for one, reports every failure as an unchecked
 * `OpenAIException`. This finds the failure, whichever exception such a
 * library or a `CompletableFuture` wrapped it in:
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
