@file:OptIn(ExperimentalTinfoilApi::class)

package sh.tinfoil.internal.gateway

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import sh.tinfoil.Catalog
import sh.tinfoil.CatalogEntry
import sh.tinfoil.ConfigurationException
import sh.tinfoil.ExperimentalTinfoilApi
import sh.tinfoil.GatewayHttpClient
import sh.tinfoil.NetworkException
import sh.tinfoil.internal.Internals
import sh.tinfoil.internal.transport.HttpSettings
import sh.tinfoil.testing.TestAuthority
import sh.tinfoil.testing.awaitUntil
import sh.tinfoil.testing.httpsServer
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/** A gateway's catalog: what is read from it, what is kept, and when it is fetched. */
class GatewayCatalogTest {
    private val authority = TestAuthority()
    private val servers = ArrayList<MockWebServer>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @AfterTest
    fun shutDown() {
        scope.cancel()
        servers.forEach { it.shutdown() }
    }

    private fun parse(text: String): Catalog = GatewayCatalog.parse(text.toByteArray())

    private fun entry(repo: String, vararg hosts: String) = CatalogEntry(repo, hosts.toList())

    private fun assertRefused(text: String, why: String? = null) {
        val error = assertFailsWith<NetworkException>(text.take(80)) { parse(text) }
        assertTrue(error.detail.startsWith("decoding gateway catalog: "), error.detail)
        if (why != null) {
            assertTrue(error.detail.contains(why), error.detail)
        }
    }

    // Reading.

    @Test
    fun onlyEntriesWithABareRepositoryOfTinfoilsAndAReplicaAreKept() {
        val catalog = parse(
            """{
                "ok": {"repo": "tinfoilsh/ok", "hosts": ["a.example"]},
                "tagged": {"repo": "tinfoilsh/ok@v1", "hosts": ["a.example"]},
                "other": {"repo": "acme/ok", "hosts": ["a.example"]},
                "empty": {"repo": "tinfoilsh/empty", "hosts": []}
            }""",
        )
        assertEquals(Catalog(mapOf("ok" to entry("tinfoilsh/ok", "a.example"))), catalog)
    }

    @Test
    fun aRepositoryIsTrustedOnlyAsOneNameUnderTinfoilsOwner() {
        val digest = "ab".repeat(32)
        val refused = listOf(
            "", "tinfoilsh", "tinfoilsh/", "tinfoilsh//", "tinfoilsh/a/b", "tinfoilsh/a@v1", "tinfoilsh/a@sha256:$digest",
            "tinfoilsh/a@v1@sha256:$digest", "tinfoilsh/a@", "Tinfoilsh/a", "TINFOILSH/a", " tinfoilsh/a", "tinfoilsh/a ",
            "tinfoilsh/a\n", "tinfoilsh/a b", "tinfoilsh/a?b", "tinfoilsh/a#b", "tinfoilsh/a:b", "tinfoilsh/\u00e9",
            "tinfoilsh/\uff41", "tinfoil\u017fh/a", "acme/a", "acme/tinfoilsh/a", "github.com/tinfoilsh/a", "tinfoilsh/a\u0000",
        )
        for (repo in refused) {
            assertFalse(GatewayCatalog.isTrusted(entry(repo, "a.example")), repo)
        }
        for (repo in listOf("tinfoilsh/a", "tinfoilsh/confidential-model_1.5", "tinfoilsh/A-Z_09.x", "tinfoilsh/.", "tinfoilsh/-")) {
            assertTrue(GatewayCatalog.isTrusted(entry(repo, "a.example")), repo)
        }
        assertFalse(GatewayCatalog.isTrusted(entry("tinfoilsh/a")), "an entry without replicas")
        assertFalse(GatewayCatalog.isTrusted(null))
    }

    @Test
    fun otherMembersOfAnEntryAreIgnoredWhateverTheyHold() {
        val catalog = parse(
            """{"m":{"context":1048576,"vision":true,"x":{"repo":"acme/x","hosts":["evil.example"]},"repo":"tinfoilsh/m",""" +
                """"y":[{"hosts":[]}],"hosts":["a.example","b.example:8443"],"Repo":"acme/y","HOSTS":["evil.example"]}}""",
        )
        assertEquals(Catalog(mapOf("m" to entry("tinfoilsh/m", "a.example", "b.example:8443"))), catalog)
    }

    @Test
    fun namesAndValuesAreDecoded() {
        val catalog = parse("""{"m\u006fdel \"q\"":{"rep\u006f":"tinfoilsh\/m","hosts":["a\u002eexample"]}}""")
        assertEquals(Catalog(mapOf("model \"q\"" to entry("tinfoilsh/m", "a.example"))), catalog)
    }

    @Test
    fun anEntryThatListsNothingIsLeftOut() {
        val catalog = parse(
            """{"a":null,"b":{},"c":{"repo":null,"hosts":null},"d":{"repo":"tinfoilsh/d"},"e":{"hosts":["a.example"]},""" +
                """"ok":{"repo":"tinfoilsh/ok","hosts":["a.example"]}}""",
        )
        assertEquals(setOf("ok"), catalog.entries.keys)
        assertEquals(Catalog(emptyMap()), parse(" { } \n"))
    }

    @Test
    fun aCatalogThatIsNotWhatItShouldBeIsRefusedWhole() {
        val ok = """"ok":{"repo":"tinfoilsh/ok","hosts":["a.example"]}"""
        val refused = listOf(
            "", " ", "null", "[]", "\"catalog\"", "7", "{", "{$ok", "{$ok}}", "{$ok} {}", "{$ok,}", "{$ok}x", "\ufeff{$ok}",
            "{$ok,\"m\":7}", "{$ok,\"m\":\"tinfoilsh/m\"}", "{$ok,\"m\":[]}", "{$ok,\"m\":true}",
            "{$ok,\"m\":{\"repo\":7,\"hosts\":[\"a.example\"]}}",
            "{$ok,\"m\":{\"repo\":[\"tinfoilsh/m\"],\"hosts\":[\"a.example\"]}}",
            "{$ok,\"m\":{\"repo\":\"tinfoilsh/m\",\"hosts\":\"a.example\"}}",
            "{$ok,\"m\":{\"repo\":\"tinfoilsh/m\",\"hosts\":{\"0\":\"a.example\"}}}",
            "{$ok,\"m\":{\"repo\":\"tinfoilsh/m\",\"hosts\":[\"a.example\",7]}}",
            "{$ok,\"m\":{\"repo\":\"tinfoilsh/m\",\"hosts\":[\"a.example\",null]}}",
            "{$ok,\"m\":{\"repo\":\"tinfoilsh/m\",\"hosts\":[[\"a.example\"]]}}",
            "{$ok,\"m\":{\"repo\":\"tinfoilsh/m\",\"hosts\":[\"a.example\",]}}",
            "{'ok':{}}", "{ok:{}}", "{$ok,/* */\"m\":null}",
        )
        for (text in refused) {
            assertRefused(text)
        }
        // Text that is not UTF-8, in a name and in a value.
        for (bytes in listOf("{\"\u00e9\":null}".toByteArray(Charsets.ISO_8859_1), "{\"m\":{\"x\":\"\u00ff\"}}".toByteArray(Charsets.ISO_8859_1))) {
            assertFailsWith<NetworkException> { GatewayCatalog.parse(bytes) }
        }
    }

    @Test
    fun aModelOrAMemberThatIsNamedTwiceIsRefused() {
        val a = """{"repo":"tinfoilsh/a","hosts":["a.example"]}"""
        val b = """{"repo":"tinfoilsh/b","hosts":["evil.example"]}"""
        assertRefused("""{"m":$a,"m":$b}""", "twice")
        assertRefused("""{"m":$a,"\u006d":$b}""", "twice")
        assertRefused("""{"m":$a,"m":null}""", "twice")
        assertRefused("""{"m":{"repo":"tinfoilsh/a","repo":"tinfoilsh/b","hosts":["a.example"]}}""", "twice")
        assertRefused("""{"m":{"repo":"tinfoilsh/a","rep\u006f":null,"hosts":["a.example"]}}""", "twice")
        assertRefused("""{"m":{"repo":"tinfoilsh/a","hosts":["a.example"],"hosts":["evil.example"]}}""", "twice")
        // The same name in two entries, or deeper, is not a repeat.
        assertEquals(2, parse("""{"m":$a,"n":{"repo":"tinfoilsh/b","hosts":["b.example"],"x":{"repo":1,"repo":2}}}""").entries.size)
    }

    @Test
    fun deepNestingCostsNoStackAndIsRefusedPastTheLimit() {
        fun nested(depth: Int, open: String, close: String) =
            """{"ok":{"repo":"tinfoilsh/ok","hosts":["a.example"],"x":${open.repeat(depth)}${close.repeat(depth)}}}"""
        assertEquals(setOf("ok"), parse(nested(5_000, "[", "]")).entries.keys)
        assertEquals(setOf("ok"), parse(nested(5_000, "{\"a\":", "}").replace("{\"a\":}", "{}")).entries.keys)
        assertRefused(nested(200_000, "[", "]"))
        assertRefused("[".repeat(500_000))
        assertRefused("{\"a\":".repeat(300_000))
        assertRefused("""{"m":{"repo":"tinfoilsh/m","hosts":${"[".repeat(100_000)}${"]".repeat(100_000)}}}""")
    }

    @Test
    fun aCatalogListsNoMoreModelsAndReplicasThanTheLimits() {
        fun models(count: Int) = (1..count).joinToString(",", "{", "}") { """"m$it":{"repo":"tinfoilsh/m","hosts":["a.example"]}""" }
        assertEquals(GatewayCatalog.MAX_MODELS, parse(models(GatewayCatalog.MAX_MODELS)).entries.size)
        assertRefused(models(GatewayCatalog.MAX_MODELS + 1), "more than ${GatewayCatalog.MAX_MODELS} models")
        // Entries that list nothing count too.
        assertRefused((0..GatewayCatalog.MAX_MODELS).joinToString(",", "{", "}") { "\"m$it\":null" }, "models")

        fun hosts(count: Int) = """{"m":{"repo":"tinfoilsh/m","hosts":[${(1..count).joinToString(",") { "\"h$it.example\"" }}]}}"""
        assertEquals(GatewayCatalog.MAX_HOSTS, parse(hosts(GatewayCatalog.MAX_HOSTS))["m"]!!.hosts.size)
        assertRefused(hosts(GatewayCatalog.MAX_HOSTS + 1), "more than ${GatewayCatalog.MAX_HOSTS} replicas")
    }

    @Test
    fun hostsAreKeptAsTheyAreWrittenForTheClientToJudge() {
        val catalog = parse("{\"m\":{\"repo\":\"tinfoilsh/m\",\"hosts\":[\"\u00e9xample.com\",\"a.example/path\",\"\",\"a.example\"]}}")
        assertEquals(listOf("\u00e9xample.com", "a.example/path", "", "a.example"), catalog["m"]!!.hosts)
    }

    @Test
    fun theTypesAreImmutableAndCompareByContent() {
        val hosts = mutableListOf("a.example")
        val entry = CatalogEntry("tinfoilsh/m", hosts)
        val entries = mutableMapOf("m" to entry)
        val catalog = Catalog(entries)
        hosts += "evil.example"
        entries["n"] = entry("acme/n", "evil.example")
        assertEquals(listOf("a.example"), entry.hosts)
        assertEquals(setOf("m"), catalog.entries.keys)
        assertFailsWith<UnsupportedOperationException> { (catalog.entries as MutableMap<String, CatalogEntry>).clear() }
        assertFailsWith<UnsupportedOperationException> { (entry.hosts as MutableList<String>).clear() }
        assertEquals(Catalog(mapOf("m" to entry("tinfoilsh/m", "a.example"))), catalog)
        assertEquals(Catalog(mapOf("m" to entry("tinfoilsh/m", "a.example"))).hashCode(), catalog.hashCode())
        assertNull(catalog["n"])
        assertEquals("Catalog({m=CatalogEntry(repo=tinfoilsh/m, hosts=[a.example])})", catalog.toString())
    }

    // Fetching.

    private fun gateway(): MockWebServer = httpsServer(authority.issue()).also { servers += it }

    private fun internals() = Internals(http = HttpSettings(trust = authority.trust))

    private fun fetch(server: MockWebServer): Catalog =
        runBlocking { withTimeout(30.seconds) { GatewayHttpClient.fetchCatalog("localhost:${server.port}", internals()) } }

    @Test
    fun theCatalogIsFetchedFromTheGatewaysHost() {
        val server = gateway()
        server.enqueue(MockResponse().setBody("""{"m":{"repo":"tinfoilsh/m","hosts":["a.example"]},"x":{"repo":"acme/x","hosts":["b.example"]}}"""))
        assertEquals(Catalog(mapOf("m" to entry("tinfoilsh/m", "a.example"))), fetch(server))
        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/catalog", request.path)
        assertNull(request.getHeader("Authorization"))
    }

    @Test
    fun aHostThatIsNotAHostIsRefusedBeforeAnythingIsFetched() {
        val server = gateway()
        val refused = listOf(
            "", "https://localhost:${server.port}", "localhost:${server.port}/catalog", "user@localhost:${server.port}",
            "localhost:${server.port}?x", "localhost:${server.port}#x", "local host", "localhost:${server.port}\n", "127.1",
            "\u00e9xample.com", "localhost:99999",
        )
        for (host in refused) {
            val error = assertFailsWith<ConfigurationException>(host) {
                runBlocking { GatewayHttpClient.fetchCatalog(host, internals()) }
            }
            assertTrue(error.detail.startsWith("invalid gateway host"), error.detail)
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun onlyA200CarriesACatalog() {
        val server = gateway()
        val body = """{"m":{"repo":"tinfoilsh/m","hosts":["a.example"]}}"""
        for (status in listOf(201, 203, 204, 206, 400, 401, 404, 429, 500, 503)) {
            server.enqueue(MockResponse().setResponseCode(status).setBody(if (status == 204) "" else body))
            val error = assertFailsWith<NetworkException>("$status") { fetch(server) }
            assertEquals(status, error.status)
        }
    }

    @Test
    fun aCatalogOfExactlyTheLargestSizeIsReadAndALargerOneIsNot() {
        val server = gateway()
        val entry = """{"m":{"repo":"tinfoilsh/m","hosts":["a.example"]}}"""
        val maximal = entry + " ".repeat(GatewayCatalog.MAX_BYTES.toInt() - entry.length)
        server.enqueue(MockResponse().setBody(maximal))
        assertEquals(setOf("m"), fetch(server).entries.keys)

        server.enqueue(MockResponse().setBody("$maximal "))
        val error = assertFailsWith<NetworkException> { fetch(server) }
        assertTrue(error.detail.contains("exceeds"), error.detail)

        // Whatever length the gateway declares, or none.
        server.enqueue(MockResponse().setChunkedBody("$maximal ", 64 * 1024))
        assertFailsWith<NetworkException> { fetch(server) }
    }

    @Test
    fun aRedirectIsFollowedOnlyToHttps() {
        val server = gateway()
        val mirror = gateway()
        val body = """{"m":{"repo":"tinfoilsh/m","hosts":["a.example"]}}"""
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "https://localhost:${mirror.port}/catalog"))
        mirror.enqueue(MockResponse().setBody(body))
        assertEquals(setOf("m"), fetch(server).entries.keys)

        val cleartext = MockWebServer().also { servers += it }
        cleartext.enqueue(MockResponse().setBody(body))
        cleartext.start()
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "http://localhost:${cleartext.port}/catalog"))
        val error = assertFailsWith<NetworkException> { fetch(server) }
        assertTrue(error.detail.contains("not HTTPS"), error.detail)
        assertEquals(0, cleartext.requestCount)
    }

    @Test
    fun aGatewayWithACertificateThatIsNotTrustedGivesNoCatalog() {
        val stranger = httpsServer(TestAuthority().issue()).also { servers += it }
        stranger.enqueue(MockResponse().setBody("{}"))
        assertFailsWith<NetworkException> { fetch(stranger) }
        assertEquals(0, stranger.requestCount)
    }

    // The cache.

    private val old = Catalog(mapOf("old" to entry("tinfoilsh/old", "a.example")))
    private val new = Catalog(mapOf("new" to entry("tinfoilsh/new", "b.example")))

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(30.seconds) { block() } }

    @Test
    fun concurrentFirstUsesShareOneFetchAndAFailureIsTriedAgainAtTheNextUse() = test {
        val failure = NetworkException("gateway unavailable")
        val release = CompletableDeferred<Unit>()
        val fetches = AtomicInteger()
        val cache = CatalogCache(
            fetch = {
                val n = fetches.incrementAndGet()
                release.await()
                if (n == 1) throw failure else old
            },
            scope = scope,
        )
        val waiters = (1..3).map { async(Dispatchers.IO) { runCatching { cache.get() } } }
        val cancelled = launch(Dispatchers.IO) { cache.get() }
        awaitUntil { fetches.get() == 1 }
        // A waiter that is cancelled leaves without ending the shared fetch.
        cancelled.cancelAndJoin()
        release.complete(Unit)
        for (waiter in waiters) {
            assertSame(failure, waiter.await().exceptionOrNull())
        }
        assertEquals(1, fetches.get())

        assertSame(old, cache.get())
        assertSame(old, cache.get())
        assertEquals(2, fetches.get(), "a catalog that was fetched is kept")
    }

    @Test
    fun aCatalogIsRefreshedOnUseAfterTheIntervalWithoutMakingAnyoneWait() = test {
        val time = TestTimeSource()
        val fetches = AtomicInteger()
        val gates = List(4) { CompletableDeferred<Catalog?>() }
        val cache = CatalogCache(
            fetch = {
                val n = fetches.incrementAndGet()
                gates[n - 1].await() ?: throw NetworkException("gateway unavailable")
            },
            scope = scope,
            timeSource = time,
        )
        gates[0].complete(old)
        assertSame(old, cache.get())

        time += GatewayCatalog.REFRESH_INTERVAL - 1.nanoseconds
        assertSame(old, cache.get())
        assertEquals(1, fetches.get(), "a catalog is kept for the interval")

        time += 1.nanoseconds
        assertSame(old, cache.get(), "the last catalog is returned while a new one is fetched")
        awaitUntil { fetches.get() == 2 }
        assertSame(old, cache.get())
        time += GatewayCatalog.REFRESH_INTERVAL * 3
        assertSame(old, cache.get())
        assertEquals(2, fetches.get(), "a use during a fetch starts no second one, however long the fetch takes")

        // The fetch fails: the last catalog is kept for another interval,
        // which starts when the fetch ends.
        gates[1].complete(null)
        awaitUntil { runBlocking { cache.get() }; true }
        Thread.sleep(50)
        time += GatewayCatalog.REFRESH_INTERVAL - 1.nanoseconds
        assertSame(old, cache.get())
        Thread.sleep(50)
        assertEquals(2, fetches.get(), "a failed fetch is not tried again before the interval has passed")

        time += 1.nanoseconds
        assertSame(old, cache.get())
        awaitUntil { fetches.get() == 3 }
        gates[2].complete(new)
        awaitUntil { runBlocking { cache.get() } === new }
        assertEquals(3, fetches.get())
    }

    @Test
    fun nothingIsFetchedWhileTheCatalogIsNotUsed() = test {
        val time = TestTimeSource()
        val fetches = AtomicInteger()
        val cache = CatalogCache(fetch = { fetches.incrementAndGet(); old }, scope = scope, timeSource = time)
        cache.get()
        time += GatewayCatalog.REFRESH_INTERVAL * 100
        Thread.sleep(100)
        assertEquals(1, fetches.get())
    }

    @Test
    fun aFetchThatFailsWithSomethingElseIsANetworkError() = test {
        val cache = CatalogCache(fetch = { throw IllegalStateException("boom") }, scope = scope)
        val error = assertFailsWith<NetworkException> { cache.get() }
        assertIs<IllegalStateException>(error.cause)
    }

    @Test
    fun closingEndsAFetchAndItsWaiters() = test {
        val own = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val started = CompletableDeferred<Unit>()
        val cache = CatalogCache(
            fetch = {
                started.complete(Unit)
                CompletableDeferred<Catalog>().await()
            },
            scope = own,
        )
        val waiter = async(Dispatchers.IO) { runCatching { cache.get() } }
        started.await()
        own.cancel()
        assertIs<ConfigurationException>(waiter.await().exceptionOrNull())
        // And a use after that does not wait for a fetch that cannot run.
        assertFailsWith<ConfigurationException> { cache.get() }
    }
}
