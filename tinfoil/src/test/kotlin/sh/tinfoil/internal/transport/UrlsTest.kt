package sh.tinfoil.internal.transport

import okhttp3.HttpUrl.Companion.toHttpUrl
import sh.tinfoil.ConfigurationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class UrlsTest {
    @Test
    fun anEnclaveIsAHostWithAnOptionalPort() {
        assertEquals("https://inference.tinfoil.sh/", Urls.enclaveUrl("inference.tinfoil.sh").toString())
        assertEquals("https://inference.tinfoil.sh/", Urls.enclaveUrl("Inference.Tinfoil.SH").toString())
        assertEquals("https://inference.tinfoil.sh/", Urls.enclaveUrl("inference.tinfoil.sh:443").toString())
        assertEquals("https://localhost:8443/", Urls.enclaveUrl("localhost:8443").toString())
        assertEquals("https://127.0.0.1:8443/", Urls.enclaveUrl("127.0.0.1:8443").toString())
        assertEquals("https://[::1]:8443/", Urls.enclaveUrl("[::1]:8443").toString())
    }

    @Test
    fun anEnclaveThatCouldBeReadInTwoWaysIsRefused() {
        val refused = listOf(
            "", "https://host", "host/path", "user@host", "user:pw@host", "host?x", "host#x", "ho st", "host\t",
            "host\\evil", "host:", "host:port", "host:99999", ":443", "[::1", "host:443:443",
            // Each of these names a host that the parser would rewrite.
            "%65xample.com", "exämple.com", "[0:0:0:0:0:0:0:1]", "host..",
        )
        for (enclave in refused) {
            assertFailsWith<ConfigurationException>("\"$enclave\"") { Urls.enclaveUrl(enclave) }
        }
    }

    @Test
    fun aHostThatIsDialledDifferentlyFromHowItIsWrittenIsRefused() {
        val refused = listOf(
            // Characters that fold into ASCII when a name is lowercased or normalized.
            "\u212Aexample.com", "ex\u0131mple.com", "\uFF45xample.com", "example\u3002com", "exa\u00ADmple.com",
            "example.com\u0000", "example.com\u007f",
            // Names that a resolver may read as an address.
            "127.1", "0x7f.1", "0x7f000001", "2130706433", "127.0.0.1.", "1.2.3.04", "010.0.0.1", "example.com.1",
            "1.2.3.4.5", "256.1.1.1",
        )
        for (host in refused) {
            assertFailsWith<ConfigurationException>("enclave \"$host\"") { Urls.enclaveUrl(host) }
            assertFailsWith<ConfigurationException>("enclave \"$host:8443\"") { Urls.enclaveUrl("$host:8443") }
            assertFailsWith<ConfigurationException>("relay \"$host\"") { Urls.requireRelay(host) }
            assertFailsWith<ConfigurationException>("base URL \"$host\"") { Urls.baseUrl("https://$host/v1") }
        }
    }

    @Test
    fun aFullyQualifiedNameIsDialledAsWrittenAndIsAnOriginOfItsOwn() {
        val qualified = Urls.enclaveUrl("example.com.")

        assertEquals("example.com.", qualified.host)
        assertNotEquals(Origin.of(qualified), Origin.of(Urls.enclaveUrl("example.com")))
        assertEquals("example.com.", Urls.baseUrl("https://example.com./v1").host)
        // A label that only contains digits is still a name.
        assertEquals("host123.example", Urls.enclaveUrl("host123.example").host)
        assertEquals("123.example", Urls.enclaveUrl("123.example").host)
        Urls.requireRelay("relay.example:8443")
        assertFailsWith<ConfigurationException> { Urls.requireRelay("https://relay.example/") }
    }

    @Test
    fun aBaseUrlKeepsItsPath() {
        assertEquals("https://host.example/v1/", Urls.baseUrl("https://host.example/v1/").toString())
        assertEquals("https://host.example/", Urls.baseUrl("HTTPS://HOST.example").toString())
        assertEquals("https://host.example:8443/a/b", Urls.baseUrl("https://host.example:8443/a/b").toString())
        assertEquals("http://localhost:8080/", Urls.baseUrl("http://localhost:8080").toString())
    }

    @Test
    fun aBaseUrlWithMoreThanAnOriginAndAPathIsRefusedWithoutEchoingIt() {
        val refused = listOf(
            "", "host.example", "//host.example/", "https:/host.example/", "https:host.example", "ftp://host.example/",
            "https://user@host.example/", "https://user:hunter2@host.example/", "https://@host.example/",
            "https://:hunter2@host.example/", "https://host.example/?", "https://host.example/?k=hunter2",
            "https://host.example/#", "https://host.example/#hunter2", "https://host.example?hunter2",
            "https://host.example\\@evil.example/", "https://host.example /", " https://host.example/",
            "https://host.example/\n", "https:///host.example/", "https://", "https://host.example:x/",
            "https://%68ost.example/", "https://host.example:/",
        )
        for (url in refused) {
            val error = assertFailsWith<ConfigurationException>("\"$url\"") { Urls.baseUrl(url) }
            assertFalse(error.message!!.contains("hunter2"), error.message)
            assertFalse(error.message!!.contains("host.example"), error.message)
        }
    }

    @Test
    fun anOriginIsASchemeAHostAndAPort() {
        fun origin(url: String) = Origin.of(url.toHttpUrl())

        assertEquals(origin("https://host.example/a?b#c"), origin("https://HOST.example:443/"))
        assertEquals(origin("https://user:pw@host.example/"), origin("https://host.example/"))
        assertNotEquals(origin("https://host.example/"), origin("http://host.example/"))
        assertNotEquals(origin("https://host.example/"), origin("https://host.example:8443/"))
        assertNotEquals(origin("https://host.example/"), origin("https://host.example./"))
        assertNotEquals(origin("https://host.example/"), origin("https://sub.host.example/"))
        assertEquals("https://host.example", origin("https://user:pw@host.example:443/path").toString())
        assertEquals("https://host.example:8443", origin("https://host.example:8443/").toString())
        assertEquals("http://[::1]:8080", origin("http://[::1]:8080/").toString())
    }

    @Test
    fun onlyAHostThatIsWrittenAsThisMachineIsLoopback() {
        val loopback = listOf(
            "http://localhost/", "http://LOCALHOST:8080/", "http://127.0.0.1/", "http://127.255.255.254:1/",
            "http://[::1]/", "http://[::1]:8080/x", "https://localhost/",
        )
        for (url in loopback) {
            assertTrue(Urls.isLoopback(Urls.baseUrl(url)), url)
        }
        val remote = listOf(
            "http://localhost.example/", "http://localhost./", "http://example.localhost/", "http://127.0.0.1.example/",
            "http://126.0.0.1/", "http://128.0.0.1/", "http://0.0.0.0/", "http://10.0.0.1/", "http://192.168.0.1/",
            "http://[::2]/", "http://[::]/", "http://[fe80::1]/", "http://proxy.example/",
        )
        for (url in remote) {
            assertFalse(Urls.isLoopback(Urls.baseUrl(url)), url)
        }
        // An address that is written in another form than the one that is dialled is no base URL at all.
        for (url in listOf("http://[::ffff:127.0.0.1]/", "http://[0:0:0:0:0:0:0:1]/", "http://127.1/", "http://0x7f.0.0.1/")) {
            assertFailsWith<ConfigurationException>(url) { Urls.baseUrl(url) }
        }
    }
}
