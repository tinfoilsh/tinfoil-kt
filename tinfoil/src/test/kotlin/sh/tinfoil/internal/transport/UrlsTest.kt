package sh.tinfoil.internal.transport

import okhttp3.HttpUrl.Companion.toHttpUrl
import sh.tinfoil.ConfigurationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

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
}
