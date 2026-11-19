package sh.tinfoil

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The experimental API is exactly what is listed here. Every other public
 * class is stable: adding one that is experimental, or that uses one that
 * is, fails here until it is marked and listed.
 */
class ExperimentalApiTest {
    /** The public classes that carry [ExperimentalTinfoilApi]: the gateway route. */
    private val experimental = setOf(
        "sh/tinfoil/Catalog",
        "sh/tinfoil/CatalogEntry",
        "sh/tinfoil/GatewayHttpClient",
        "sh/tinfoil/GatewayOpenAIOptions",
        "sh/tinfoil/GatewayOptions",
        "sh/tinfoil/ModelPin",
        "sh/tinfoil/ReplicaVerification",
        "sh/tinfoil/openai/GatewayOpenAIClient",
    )

    private val marker = "Lsh/tinfoil/ExperimentalTinfoilApi;"

    /** The public API as it is committed: each class with the lines of its members. */
    private val api: Map<String, List<String>> = run {
        val classes = LinkedHashMap<String, MutableList<String>>()
        var current: MutableList<String>? = null
        for (line in File("api/tinfoil.api").readLines()) {
            val declared = Regex("""^public .*?class ([\w/$]+)""").find(line)
            when {
                declared != null -> current = ArrayList<String>().also { classes[declared.groupValues[1]] = it }
                line.startsWith("}") -> current = null
                else -> current?.add(line)
            }
        }
        classes
    }

    /** The class that [name] is declared in, at the top of its file. */
    private fun outer(name: String): String = name.substringBefore('$')

    /** Whether the compiled class [name] is annotated with the marker, on itself or on a member. */
    private fun isMarked(name: String): Boolean {
        val bytes = checkNotNull(javaClass.getResourceAsStream("/$name.class")) { "no class file for $name" }.use { it.readBytes() }
        return String(bytes, Charsets.ISO_8859_1).contains(marker)
    }

    @Test
    fun theCommittedApiIsRead() {
        assertTrue(api.size > 30, "the API dump was not found or not understood")
        assertTrue("sh/tinfoil/EnclaveHttpClient" in api && "sh/tinfoil/ExperimentalTinfoilApi" in api)
    }

    @Test
    fun exactlyTheListedClassesAreMarkedExperimental() {
        // The marker's own class file names itself.
        val classes = api.keys.map(::outer).toSet() - "sh/tinfoil/ExperimentalTinfoilApi"
        assertEquals(experimental, classes.filter(::isMarked).toSet())
    }

    @Test
    fun experimentalClassesStayInTheCommittedApi() {
        assertEquals(emptySet(), experimental - api.keys, "an experimental class is missing from the API dump")
    }

    @Test
    fun noStableClassExposesAnExperimentalOne() {
        val exposing = api.filter { (name, members) ->
            outer(name) !in experimental && members.any { line -> experimental.any { line.contains("L$it;") || line.contains("L$it$") } }
        }
        assertEquals(emptySet(), exposing.keys)
    }

    @Test
    fun everyClassOfTheGatewayRouteIsExperimental() {
        val named = api.keys.map(::outer).filter { name ->
            listOf("Gateway", "Catalog", "ModelPin", "Replica").any { name.substringAfterLast('/').contains(it) }
        }.toSet()
        assertEquals(experimental, named)
    }
}
