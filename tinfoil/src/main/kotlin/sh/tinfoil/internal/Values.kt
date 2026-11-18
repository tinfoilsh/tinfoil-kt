package sh.tinfoil.internal

import java.util.Collections

/** A copy of this list that no one can change, whatever the caller does with the original. */
internal fun <T> List<T>.immutableCopy(): List<T> = Collections.unmodifiableList(ArrayList(this))

/** Null for a string that is null or empty, which both mean "absent". */
internal fun String?.nullIfEmpty(): String? = if (isNullOrEmpty()) null else this
