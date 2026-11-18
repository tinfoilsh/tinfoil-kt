@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.internal.gateway

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import okhttp3.HttpUrl
import sh.tinfoil.Catalog
import sh.tinfoil.CatalogEntry
import sh.tinfoil.ConfigurationException
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.NetworkException
import sh.tinfoil.TinfoilException
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.internal.transport.JsonObjectText
import sh.tinfoil.internal.transport.Urls
import sh.tinfoil.internal.verification.AttestationFetcher
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * Reads a gateway's catalog: which models the gateway routes, the repository
 * that each model's replicas run, and where the replicas are.
 *
 * A catalog is not trusted. It only proposes replicas, and each is verified
 * against its model's repository before anything is sealed to it; the
 * repository itself is accepted only if it is one of Tinfoil's, named
 * without a tag or a digest. So a forged catalog can waste a client's time
 * or leave it without replicas, and can do nothing else. Reading one costs a
 * bounded wait and a bounded amount of memory, and no part of it is parsed
 * with code that recurses on its input.
 */
internal object GatewayCatalog {
    /** The owner of every repository that a catalog may name: Tinfoil. */
    const val TRUSTED_OWNER: String = "tinfoilsh/"

    /** How often a catalog is fetched again while it is used: as often as a gateway reloads its own. */
    val REFRESH_INTERVAL: Duration = 10.seconds

    /** The time for one fetch of a catalog, redirects included. */
    val FETCH_TIMEOUT: Duration = 10.seconds

    /** The largest catalog that is read. */
    const val MAX_BYTES: Long = 2L shl 20

    /** How many models a catalog may list. */
    const val MAX_MODELS: Int = 4096

    /** How many replicas a catalog may list for one model. */
    const val MAX_HOSTS: Int = 1024

    private const val PATH = "/catalog"
    private const val OK = 200

    /**
     * Whether [entry] can be routed to: its repository is one of Tinfoil's,
     * `tinfoilsh/name` with nothing after the name, and it has a replica.
     * A catalog's repository is what a model that the caller did not pin is
     * verified against, so only a repository of the one trusted owner is
     * taken from it, and never a tag or a digest, which would choose a
     * release.
     */
    fun isTrusted(entry: CatalogEntry?): Boolean {
        if (entry == null || entry.hosts.isEmpty() || !entry.repo.startsWith(TRUSTED_OWNER)) {
            return false
        }
        val name = entry.repo.substring(TRUSTED_OWNER.length)
        return name.isNotEmpty() && name.all(::isNameCharacter)
    }

    private fun isNameCharacter(c: Char): Boolean =
        c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '_' || c == '.' || c == '-'

    /** Where the catalog of the gateway at [host] is: [host] is a host with an optional port, not a URL. */
    @Throws(ConfigurationException::class)
    fun url(host: String): HttpUrl {
        val origin = try {
            Urls.enclaveUrl(host)
        } catch (_: ConfigurationException) {
            throw ConfigurationException("invalid gateway host: want a host with an optional port, not a URL")
        }
        return origin.newBuilder().encodedPath(PATH).build()
    }

    /**
     * What fetches catalogs: as attestation documents are fetched, over
     * HTTPS only, every redirect included, within a time and a size, on
     * connections of its own. Only a `200` carries a catalog.
     */
    fun fetcher(settings: HttpSettings): AttestationFetcher =
        AttestationFetcher(settings, timeout = FETCH_TIMEOUT, maxBodyBytes = MAX_BYTES, accepted = OK..OK)

    /**
     * The catalog of the gateway at [host], with only the entries that can
     * be routed to.
     *
     * @throws ConfigurationException if [host] is not a host.
     * @throws NetworkException if the catalog cannot be fetched or read.
     */
    @Throws(TinfoilException::class)
    suspend fun fetch(host: String, fetcher: AttestationFetcher): Catalog = parse(fetcher.fetch(url(host)))

    /**
     * The catalog that [body] spells, with only the entries that can be
     * routed to.
     *
     * [body] is one JSON object in UTF-8 whose members are the models. A
     * model's value is an object with a string `repo` and an array of
     * strings `hosts`, and any other members, which are ignored; or null,
     * which lists nothing for the model. An entry for a model whose name is
     * empty or blank is left out. Anything else is refused whole,
     * rather than read in part: a text that is not such an object, a model
     * or one of those two members that is named twice, a value of another
     * type, and more models or replicas than [MAX_MODELS] and [MAX_HOSTS].
     *
     * @throws NetworkException for a catalog that is refused.
     */
    @Throws(NetworkException::class)
    fun parse(body: ByteArray): Catalog {
        // Each model's name and value, by where they are in the text.
        val members = ArrayList<IntArray>()
        val closingBrace = JsonObjectText.members(body) { nameStart, nameEnd, valueStart, valueEnd ->
            if (members.size <= MAX_MODELS) {
                members += intArrayOf(nameStart, nameEnd, valueStart, valueEnd)
            }
        }
        if (closingBrace < 0) {
            throw unreadable("it is not one JSON object")
        }
        if (members.size > MAX_MODELS) {
            throw unreadable("it lists more than $MAX_MODELS models")
        }
        val entries = LinkedHashMap<String, CatalogEntry?>()
        for ((nameStart, nameEnd, valueStart, valueEnd) in members) {
            val model = JsonObjectText.string(body, nameStart, nameEnd) ?: throw unreadable("a model's name is not a string")
            if (entries.containsKey(model)) {
                throw unreadable("it lists a model twice")
            }
            entries[model] = entry(body, valueStart, valueEnd)
        }
        val trusted = LinkedHashMap<String, CatalogEntry>()
        for ((model, entry) in entries) {
            // A request always names its model, so no model is without a name.
            if (entry != null && model.isNotBlank() && isTrusted(entry)) {
                trusted[model] = entry
            }
        }
        return Catalog(trusted)
    }

    /** The entry that the text from [from] to [to] spells, or null for a JSON null. */
    private fun entry(body: ByteArray, from: Int, to: Int): CatalogEntry? {
        if (isNull(body, from, to)) {
            return null
        }
        var repos = 0
        var repoStart = -1
        var repoEnd = -1
        var lists = 0
        var hostsStart = -1
        var hostsEnd = -1
        val closingBrace = JsonObjectText.members(body, from, to) { nameStart, nameEnd, valueStart, valueEnd ->
            if (JsonObjectText.isName(body, nameStart, nameEnd, "repo")) {
                repos++
                repoStart = valueStart
                repoEnd = valueEnd
            } else if (JsonObjectText.isName(body, nameStart, nameEnd, "hosts")) {
                lists++
                hostsStart = valueStart
                hostsEnd = valueEnd
            }
        }
        if (closingBrace < 0) {
            throw unreadable("a model's entry is not an object")
        }
        if (repos > 1 || lists > 1) {
            throw unreadable("a model's entry names its repository or its replicas twice")
        }
        val repo = when {
            repos == 0 || isNull(body, repoStart, repoEnd) -> ""
            else -> JsonObjectText.string(body, repoStart, repoEnd) ?: throw unreadable("a model's repository is not a string")
        }
        val hosts = ArrayList<String>()
        if (lists == 1 && !isNull(body, hostsStart, hostsEnd)) {
            var strings = true
            val isArray = JsonObjectText.elements(body, hostsStart, hostsEnd) { start, end ->
                val host = if (hosts.size <= MAX_HOSTS) JsonObjectText.string(body, start, end) else ""
                if (host == null) {
                    strings = false
                } else {
                    hosts += host
                }
            }
            if (!isArray || !strings) {
                throw unreadable("a model's replicas are not an array of strings")
            }
            if (hosts.size > MAX_HOSTS) {
                throw unreadable("it lists more than $MAX_HOSTS replicas for a model")
            }
        }
        return CatalogEntry(repo, hosts)
    }

    private fun isNull(body: ByteArray, from: Int, to: Int): Boolean =
        to - from == NULL.size && NULL.indices.all { body[from + it] == NULL[it] }

    private fun unreadable(why: String) = NetworkException("decoding gateway catalog: $why")

    private val NULL = "null".toByteArray(Charsets.US_ASCII)
}

/**
 * A gateway's catalog, fetched on first use and again, on use, once
 * [GatewayCatalog.REFRESH_INTERVAL] has passed since the last fetch ended.
 *
 * Until a fetch has succeeded, callers wait for one, share it, and get its
 * failure; the next use tries again. After that no caller waits: the last
 * catalog is returned while a fetch runs behind it, and a fetch that fails
 * keeps that catalog for another interval. Nothing runs between uses, so a
 * client that is idle fetches nothing.
 */
internal class CatalogCache(
    private val fetch: suspend () -> Catalog,
    /** Runs the fetches, which no single caller owns. Cancelling it ends them. */
    private val scope: CoroutineScope,
    private val timeSource: TimeSource = TimeSource.Monotonic,
) {
    private val lock = Any()

    // Guarded by lock.
    private var catalog: Catalog? = null
    private var refreshAt: TimeMark? = null
    private var loading: CompletableDeferred<Result<Catalog>>? = null

    /**
     * The catalog. Cancelling a caller that waits ends only its own wait.
     *
     * @throws TinfoilException if no catalog has been fetched yet and the
     *   fetch fails.
     */
    @Throws(TinfoilException::class, CancellationException::class)
    suspend fun get(): Catalog {
        val first = synchronized(lock) {
            val current = catalog
            if (current != null) {
                if (refreshAt?.hasPassedNow() != false && loading == null) {
                    // Moved ahead now, so that later callers start no fetch
                    // of their own; the fetch sets it again when it ends.
                    refreshAt = timeSource.markNow() + GatewayCatalog.REFRESH_INTERVAL
                    load()
                }
                return current
            }
            loading ?: load()
        }
        return first.await().getOrThrow()
    }

    /** Starts a fetch. Called with the lock held. */
    private fun load(): CompletableDeferred<Result<Catalog>> {
        val outcome = CompletableDeferred<Result<Catalog>>()
        loading = outcome
        val job = scope.launch {
            val result = try {
                Result.success(fetch())
            } catch (e: CancellationException) {
                throw e
            } catch (e: TinfoilException) {
                Result.failure(e)
            } catch (e: Exception) {
                Result.failure(NetworkException("fetching gateway catalog: ${e.message ?: e.javaClass.simpleName}", cause = e))
            }
            finish(outcome, result)
        }
        // A fetch that was cancelled, or never ran, leaves no one waiting.
        job.invokeOnCompletion { finish(outcome, Result.failure(ConfigurationException("the client is closed"))) }
        return outcome
    }

    private fun finish(outcome: CompletableDeferred<Result<Catalog>>, result: Result<Catalog>) {
        synchronized(lock) {
            if (loading !== outcome) {
                return
            }
            loading = null
            result.onSuccess { catalog = it }
            if (catalog != null) {
                refreshAt = timeSource.markNow() + GatewayCatalog.REFRESH_INTERVAL
            }
        }
        outcome.complete(result)
    }
}
