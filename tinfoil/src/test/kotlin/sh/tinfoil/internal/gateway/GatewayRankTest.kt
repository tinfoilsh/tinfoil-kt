package sh.tinfoil.internal.gateway

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The order in which a request tries a model's replicas. */
class GatewayRankTest {
    private val hosts = listOf("a.example", "b.example", "c.example", "d.example:8443", "e.example")

    private fun rank(prefix: String, first: String? = null) = GatewayRouter.rank(hosts, prefix, first)

    @Test
    fun aPrefixRanksTheReplicasByTheirScoreForIt() {
        assertEquals(
            listOf("d.example:8443", "c.example", "b.example", "a.example", "e.example"),
            rank("ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6"),
        )
        assertEquals(listOf("c.example", "b.example", "e.example", "a.example", "d.example:8443"), rank("test-model"))
        assertEquals(listOf("d.example:8443", "b.example", "e.example", "a.example", "c.example"), rank("gpt-oss-120b"))
        assertEquals(listOf("e.example", "b.example", "c.example", "a.example", "d.example:8443"), rank("x"))
    }

    @Test
    fun theReplicaThatTheGatewayLastChoseGoesFirstAndTheRestKeepTheirOrder() {
        assertEquals(
            listOf("c.example", "d.example:8443", "b.example", "a.example", "e.example"),
            rank("ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6", first = "c.example"),
        )
        assertEquals(listOf("c.example", "b.example", "e.example", "a.example", "d.example:8443"), rank("test-model", first = "c.example"))
        assertEquals(listOf("c.example", "d.example:8443", "b.example", "e.example", "a.example"), rank("gpt-oss-120b", first = "c.example"))
        assertEquals(listOf("c.example", "e.example", "b.example", "a.example", "d.example:8443"), rank("x", first = "c.example"))
        // One that is not a replica of the model changes nothing.
        assertEquals(rank("x"), rank("x", first = "z.example"))
    }

    @Test
    fun theOrderForAPrefixDoesNotDependOnTheOrderOfTheCatalog() {
        val prefix = "ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6"
        repeat(20) {
            assertEquals(rank(prefix), GatewayRouter.rank(hosts.shuffled(), prefix, null))
        }
        // A replica that goes away leaves the others in their order.
        assertEquals(rank(prefix) - "c.example", GatewayRouter.rank(hosts - "c.example", prefix, null))
    }

    @Test
    fun withoutAPrefixTheOrderIsRandom() {
        val many = (1..50).map { "h$it.example" }
        val orders = (1..20).map { GatewayRouter.rank(many, "", null) }
        assertTrue(orders.all { it.sorted() == many.sorted() })
        assertNotEquals(1, orders.toSet().size)
        assertEquals(emptyList(), GatewayRouter.rank(emptyList(), "", null))
        assertEquals(emptyList(), GatewayRouter.rank(emptyList(), "x", "a.example"))
    }
}
