package sh.tinfoil.openai

import sh.tinfoil.ExperimentalTinfoilApi
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The experimental API of this module is exactly what is listed here. Every
 * other public class is stable: adding one that is experimental, or that
 * uses one that is, of this module or of the `tinfoil` module that it is
 * built on, fails here until it is marked and listed.
 */
class ExperimentalApiTest {
    /** The public classes that carry [ExperimentalTinfoilApi]: the gateway route. */
    private val experimental = setOf(
        "sh/tinfoil/openai/GatewayOpenAIClient",
        "sh/tinfoil/openai/GatewayOpenAIOptions",
    )

    private val marker = "Lsh/tinfoil/ExperimentalTinfoilApi;"

    /** The public API of this module as it is committed: each class with the lines of its members. */
    private val api: Map<String, List<String>> = read("api/tinfoil-openai.api")

    /**
     * The experimental classes of the `tinfoil` module, which a stable class
     * here must not expose either: those of its committed API that carry the
     * marker.
     */
    private val experimentalBelow: Set<String> =
        read("../tinfoil/api/tinfoil.api").keys.map(::outer).filter(::isMarked).toSet() - "sh/tinfoil/ExperimentalTinfoilApi"

    private fun read(dump: String): Map<String, List<String>> = run {
        val classes = LinkedHashMap<String, MutableList<String>>()
        var current: MutableList<String>? = null
        for (line in File(dump).readLines()) {
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
        assertTrue(api.size > 10, "the API dump was not found or not understood")
        assertTrue("sh/tinfoil/openai/EnclaveOpenAIClient" in api && "sh/tinfoil/openai/Client" in api)
        assertTrue("sh/tinfoil/GatewayHttpClient" in experimentalBelow && "sh/tinfoil/ModelPin" in experimentalBelow)
    }

    @Test
    fun exactlyTheListedClassesAreMarkedExperimental() {
        val classes = api.keys.map(::outer).toSet()
        assertEquals(experimental, classes.filter(::isMarked).toSet())
    }

    @Test
    fun experimentalClassesStayInTheCommittedApi() {
        assertEquals(emptySet(), experimental - api.keys, "an experimental class is missing from the API dump")
    }

    @Test
    fun noStableClassExposesAnExperimentalOne() {
        val all = experimental + experimentalBelow
        val exposing = api.filter { (name, members) ->
            outer(name) !in experimental && members.any { line -> all.any { line.contains("L$it;") || line.contains("L$it$") } }
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
