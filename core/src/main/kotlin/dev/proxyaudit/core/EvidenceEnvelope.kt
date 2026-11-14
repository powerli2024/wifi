package dev.proxyaudit.core

/** Shared provenance only; does not upgrade observations into attribution or correlation. */
object EvidenceEnvelope {
    fun toMap(reportKind: String, appVersion: String, runId: String, origin: String,
              scope: String, sources: List<String>, stopped: Boolean): Map<String, Any?> = linkedMapOf(
        "namespace" to "dev.proxyaudit.evidence", "version" to 1,
        "reportKind" to reportKind, "appVersion" to appVersion, "runId" to runId,
        "origin" to origin, "scope" to scope, "sources" to sources.distinct(),
        "stopped" to stopped,
        "completeness" to if (stopped) "PARTIAL_OR_INTERRUPTED" else "SEE_SOURCE_EXECUTION_STATUS",
        "crossSourceCorrelation" to "NOT_ESTABLISHED",
        "interpretationPolicy" to "OBSERVATIONS_AND_DERIVED_ANALYSIS_REMAIN_SEPARATE"
    )

    fun toJson(reportKind: String, appVersion: String, runId: String, origin: String,
               scope: String, sources: List<String>, stopped: Boolean): String =
        Json.write(toMap(reportKind, appVersion, runId, origin, scope, sources, stopped))
}
