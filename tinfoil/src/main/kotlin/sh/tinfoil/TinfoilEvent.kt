package sh.tinfoil

/**
 * A kind of progress event that Tinfoil's router can report while it works
 * on a request, on top of what the OpenAI API defines.
 *
 * The OpenAI clients of this SDK take a set of these as `tinfoilEvents`, and
 * ask for them with the `X-Tinfoil-Events` header of every request. The
 * router then writes each event into the assistant's text as it happens, as
 * a `<tinfoil-event>...</tinfoil-event>` marker. The OpenAI SDK knows nothing
 * of these markers and delivers them as text, so a caller that asks for
 * events has to find the markers in the text and take them out before
 * showing it.
 */
public enum class TinfoilEvent(
    /** The event's name in the `X-Tinfoil-Events` header. */
    public val value: String,
) {
    /**
     * Progress of the web searches and URL fetches that the router runs for
     * the model. A marker carries what the `web_search_call` output item of
     * a finished response carries, and may also report the status `blocked`
     * and an `error` object.
     */
    WEB_SEARCH("web_search"),
}
