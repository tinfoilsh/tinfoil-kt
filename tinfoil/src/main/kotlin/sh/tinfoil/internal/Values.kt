package sh.tinfoil.internal

import sh.tinfoil.ConfigurationException
import java.util.Collections

/** A copy of this list that no one can change, whatever the caller does with the original. */
internal fun <T> List<T>.immutableCopy(): List<T> = Collections.unmodifiableList(ArrayList(this))

/**
 * Null for a string that is null or empty, which both mean "absent" in what
 * the verifier library reports. It is for decoding only: a caller's own
 * empty string is refused, with [requireNotEmpty].
 */
internal fun String?.nullIfEmpty(): String? = if (isNullOrEmpty()) null else this

/**
 * [value], which a caller gave as [option]. Only null means that the option
 * is not set: an empty string is a mistake, and is refused, not read as null.
 */
@Throws(ConfigurationException::class)
internal fun requireNotEmpty(value: String?, option: String): String? {
    if (value != null && value.isEmpty()) {
        throw ConfigurationException("$option must not be empty: leave it null to not set it")
    }
    return value
}
