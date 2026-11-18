package sh.tinfoil.internal

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import sh.tinfoil.ConfigurationException
import sh.tinfoil.Pin
import sh.tinfoil.TinfoilException
import sh.tinfoil.internal.transport.Urls
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Chooses one of Tinfoil's routers: the first on Tinfoil's router list that
 * verifies.
 *
 * The list is not trusted. It only proposes hosts, and each is verified
 * against the router's pin like any enclave before anything is sent to it,
 * so a forged list can at worst waste the time that discovery is allowed.
 * That time is bounded as a whole: the fetch of the list and every
 * verification share one budget, however long the list is.
 */
internal class RouterDiscovery(
    private val settings: Settings,
    /** Fetches the list; any failure of it leaves no candidates. */
    private val fetchList: suspend (HttpUrl) -> ByteArray,
) {
    /** Where discovery looks, and for how long. */
    internal class Settings(
        val listUrl: HttpUrl = LIST_URL.toHttpUrl(),
        val fallback: String = FALLBACK_ROUTER,
        val budget: Duration = BUDGET,
        val timeSource: TimeSource = TimeSource.Monotonic,
    )

    /**
     * The connection that [open] makes for the first router on the list
     * that verifies within the budget, already verified; or null if there
     * is none, which leaves the caller its fallback.
     *
     * Routers are tried one at a time, in the order of the list, each with
     * a single attempt. A router that fails is passed over, whatever the
     * reason: its attestation cannot be fetched, it does not verify, or the
     * caller's check rejects it. So is a list that cannot be fetched or
     * read. No router is tried once the budget is spent.
     *
     * Every connection that [open] made and that is not returned is closed,
     * which ends whatever it was doing: one that failed, one that the
     * budget cut off, and one that was in progress when the caller's
     * coroutine was cancelled.
     */
    suspend fun discover(open: (host: String) -> EnclaveConnection): EnclaveConnection? {
        val start = settings.timeSource.markNow()
        var candidate: EnclaveConnection? = null
        try {
            val chosen = withTimeoutOrNull(settings.budget) {
                for (host in routers()) {
                    // The budget's timer can fire late, as when a
                    // verification's own timeout ends at the same instant.
                    if (start.elapsedNow() >= settings.budget) {
                        break
                    }
                    val connection = try {
                        open(host)
                    } catch (_: TinfoilException) {
                        // A host that no connection can be made for.
                        continue
                    }
                    candidate = connection
                    try {
                        connection.verifyOnce()
                        return@withTimeoutOrNull connection
                    } catch (_: TinfoilException) {
                        candidate = null
                        connection.close()
                    }
                }
                null
            }
            // A router that verified just as the budget ran out is verified
            // all the same.
            val verified = chosen ?: candidate?.takeIf { it.current != null }
            if (verified != null) {
                candidate = null
            }
            return verified
        } finally {
            candidate?.close()
        }
    }

    private suspend fun routers(): List<String> {
        val body = try {
            fetchList(settings.listUrl)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return emptyList()
        }
        return candidates(body)
    }

    internal companion object {
        /** Tinfoil's list of routers: a JSON array of hosts. */
        const val LIST_URL: String = "https://atc.tinfoil.sh/routers"

        /** The router that is used when none on the list verifies. */
        const val FALLBACK_ROUTER: String = "inference.tinfoil.sh"

        private const val ROUTER_NAME = "tinfoilsh/confidential-model-router"

        /**
         * What every router is verified against. Tinfoil owns the router's
         * name both as a source repository and as a registry project.
         */
        val ROUTER_PIN: Pin = Pin(repo = ROUTER_NAME, project = ROUTER_NAME)

        /** The time for the fetch of the list and every verification together. */
        val BUDGET: Duration = 30.seconds

        /** The time for the fetch of the list alone. */
        val LIST_TIMEOUT: Duration = 30.seconds

        /** The largest list that is read. */
        const val MAX_LIST_BYTES: Long = 1L shl 20

        /** How many routers of a list are tried at most. */
        const val MAX_CANDIDATES: Int = 64

        /**
         * The hosts that [list] proposes, in its order: the strings of a
         * JSON array that are a host with an optional port, as an enclave is
         * named, each once, and no more than [MAX_CANDIDATES] of them.
         * Numbers, booleans and nulls in the array are skipped. A text that
         * is anything but one flat JSON array in UTF-8 proposes nothing.
         */
        fun candidates(list: ByteArray): List<String> {
            val strings = try {
                val text = Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(list))
                    .toString()
                flatArrayStrings(text) ?: return emptyList()
            } catch (_: Exception) {
                return emptyList()
            }
            val hosts = LinkedHashMap<String, String>()
            for (host in strings) {
                if (hosts.size >= MAX_CANDIDATES) {
                    break
                }
                try {
                    Urls.enclaveUrl(host)
                } catch (_: ConfigurationException) {
                    continue
                }
                // Host names do not depend on case.
                hosts.putIfAbsent(host.lowercase(), host)
            }
            return hosts.values.toList()
        }

        /**
         * The strings in [text] if it is a JSON array whose elements are all
         * strings, numbers, booleans or nulls; otherwise null. The array is
         * read in one pass without recursion, so that no text, however it
         * nests, costs more than its length.
         */
        private fun flatArrayStrings(text: String): List<String>? {
            fun skipWhitespace(from: Int): Int {
                var i = from
                while (i < text.length && text[i] in JSON_WHITESPACE) {
                    i++
                }
                return i
            }
            var i = skipWhitespace(0)
            if (i >= text.length || text[i] != '[') {
                return null
            }
            val strings = ArrayList<String>()
            i = skipWhitespace(i + 1)
            if (i < text.length && text[i] == ']') {
                i++
            } else {
                while (true) {
                    if (i >= text.length) {
                        return null
                    }
                    val start = i
                    if (text[i] == '"') {
                        i++
                        while (i < text.length && text[i] != '"') {
                            i += if (text[i] == '\\') 2 else 1
                        }
                        if (i >= text.length) {
                            return null
                        }
                        i++
                        strings += Json.decodeFromString<String>(text.substring(start, i))
                    } else {
                        while (i < text.length && text[i] != ',' && text[i] != ']' && text[i] !in JSON_WHITESPACE) {
                            i++
                        }
                        if (!SCALAR.matches(text.substring(start, i))) {
                            return null
                        }
                    }
                    i = skipWhitespace(i)
                    if (i >= text.length) {
                        return null
                    }
                    if (text[i] == ']') {
                        i++
                        break
                    }
                    if (text[i] != ',') {
                        return null
                    }
                    i = skipWhitespace(i + 1)
                }
            }
            return if (skipWhitespace(i) == text.length) strings else null
        }

        private const val JSON_WHITESPACE = " \t\n\r"
        private val SCALAR = Regex("true|false|null|-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")
    }
}
