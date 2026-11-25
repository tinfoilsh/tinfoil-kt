package sh.tinfoil

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The host that [report] names in its JSON form, `metadata.host`, or null
 * if it names none. It also checks that the report's own metadata names
 * the same host.
 */
internal fun jsonHost(report: VerificationReport?): String? {
    checkNotNull(report) { "no report" }
    val written = Json.parseToJsonElement(report.toJson()).jsonObject.getValue("metadata").jsonObject["host"]?.jsonPrimitive?.content
    check(written == report.metadata.host) { "the JSON names $written, the report ${report.metadata.host}" }
    return written
}

/** The report of the verifier's rejection that caused [error]. */
internal fun rejectedReport(error: Throwable?): VerificationReport =
    (checkNotNull(error) { "no error" }.cause as? VerificationException)?.report
        ?: error("$error was not caused by the verifier's rejection")
