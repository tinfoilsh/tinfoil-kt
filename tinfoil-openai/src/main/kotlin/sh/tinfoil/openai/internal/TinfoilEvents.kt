package sh.tinfoil.openai.internal

import sh.tinfoil.openai.TinfoilEvent

/** How a set of [TinfoilEvent]s is asked for. */
internal object TinfoilEvents {
    /** The header that asks the router for events. */
    const val HEADER: String = "X-Tinfoil-Events"

    /** The header's value for [events], or null when there are none and the header is left out. */
    fun headerValue(events: Set<TinfoilEvent>): String? =
        events.map { it.value }.sorted().joinToString(",").ifEmpty { null }
}
