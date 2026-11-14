package dev.proxyaudit.core

object ReportExporter {
    /** No raw body, request URL, exception message, headers, or persistent device identifier is serialized. */
    fun toJson(report: RunReport, includeNetworkIdentifiers: Boolean = false): String {
        fun identifier(value: String?): String? = if (value == null) null else if (includeNetworkIdentifiers) value else "[REDACTED]"
        fun identifiers(values: Collection<String>): List<String> = if (includeNetworkIdentifiers) values.toList() else values.map { "[REDACTED]" }
        fun network(n: NetworkSnapshot): Map<String, Any?> = linkedMapOf(
            "observationAvailable" to n.observationAvailable, "networkId" to identifier(n.networkId),
            "transports" to n.transports, "vpnCapability" to n.vpnCapability,
            "internetCapability" to n.internetCapability, "validatedCapability" to n.validatedCapability,
            "localAddresses" to identifiers(n.localAddresses), "configuredDnsServers" to identifiers(n.configuredDnsServers),
            "privateDnsActive" to n.privateDnsActive, "privateDnsServerName" to identifier(n.privateDnsServerName)
        )
        fun assessment(a: Assessment) = linkedMapOf("verdict" to a.verdict.name, "label" to a.verdict.label, "reason" to a.reason)
        fun dns(result: DnsObservation): Map<String, Any?> = linkedMapOf(
            "execution" to result.execution.name,
            "api" to "android.net.DnsResolver.query", "requestedFamilies" to "SYSTEM_MANAGED_A_AAAA_SELECTION",
            "cacheStatus" to "UNKNOWN", "wireResolverAndTransport" to "UNKNOWN",
            "addresses" to identifiers(result.addresses), "durationMillis" to result.durationMillis,
            "errorCode" to result.failure?.name, "diagnosticStage" to result.diagnosticStage?.name,
            "responseCode" to result.responseCode, "resolverErrorCode" to result.resolverErrorCode,
            "systemErrno" to result.systemErrno, "exceptionKind" to result.exceptionKind?.name)
        fun raw(result: RawDnsObservation): Map<String, Any?> = linkedMapOf(
            "transport" to result.transport.name, "execution" to result.execution.name,
            "transactionId" to result.transactionId, "durationMillis" to result.durationMillis,
            "responseCode" to result.responseCode, "truncated" to result.truncated,
            "addresses" to identifiers(result.addresses), "errorCode" to result.failure?.name,
            "wireResolverAndPath" to "UNKNOWN", "privacyVerdict" to if (result.execution == Execution.NOT_STARTED) "NOT_RUN" else "INSUFFICIENT")
        fun https(result: HttpsObservation): Map<String, Any?> = linkedMapOf(
            "execution" to result.execution.name, "statusCode" to result.statusCode,
            "durationMillis" to result.durationMillis, "platformTlsValidated" to result.tlsValidated,
            "redirectsFollowed" to false, "parser" to "STRICT_FLAT_ECHO_V1",
            "echoedRequestId" to result.echoedRequestId,
            "serverReportedSourceIp" to identifier(result.serverReportedSourceIp),
            "selectedPhoneTransportFamily" to "UNKNOWN", "errorCode" to result.failure?.name)
        val policy = report.config.policy
        val data = linkedMapOf<String, Any?>(
            "evidenceEnvelope" to EvidenceEnvelope.toMap("PROXY_AUDIT", report.appVersion, report.runId,
                report.evidenceOrigin.name, RunReport.SCOPE, buildList {
                    add("NETWORK_SNAPSHOT")
                    if (report.dns.execution != Execution.NOT_STARTED) add("SYSTEM_DNS")
                    if (report.https.execution != Execution.NOT_STARTED) add("HTTPS_ECHO")
                    if (report.rawDns.any { it.execution != Execution.NOT_STARTED }) add("RAW_DNS")
                }, report.stopReason != null),
            "schemaVersion" to 2, "evidenceOrigin" to report.evidenceOrigin.name, "runId" to report.runId, "scope" to RunReport.SCOPE,
            "startedAtUtc" to report.startedAtUtc, "finishedAtUtc" to report.finishedAtUtc,
            "durationMillis" to report.durationMillis, "androidApi" to report.androidApi, "appVersion" to report.appVersion,
            "networkIdentifiersIncluded" to includeNetworkIdentifiers,
            "policy" to linkedMapOf("httpsEnabled" to policy.runHttps, "dnsEnabled" to policy.runDns,
                "expectedSourceIps" to identifiers(policy.expectedSourceIps), "ipv6InScope" to policy.ipv6InScope,
                "endpointTrustedByUser" to policy.endpointTrustedByUser),
            "endpointOrigin" to identifier(report.config.endpoint?.origin), "endpointPath" to "/v1/echo",
            "dnsHost" to identifier(report.config.dnsHost), "timeoutMillisPerProbe" to report.config.timeoutMillis,
            "evidenceBudgetMillis" to report.config.evidenceBudgetMillis,
            "maxAttemptsPerProbe" to report.config.maxAttempts,
            "retryBackoffPolicy" to "FIXED_500_MS_WITHIN_ORIGINAL_RUN_BUDGET",
            "aggregatePolicy" to "FIRST_RESULT_PRESERVED_ADDITIONAL_ATTEMPTS_NEVER_HIDE_FAILURE",
            "stopReason" to report.stopReason?.name,
            "rawDnsConfig" to report.config.rawDns?.let { linkedMapOf(
                "serverIp" to identifier(it.serverIp), "port" to it.port, "host" to identifier(it.host),
                "recordType" to it.recordType.name, "udp" to it.udp, "tcp" to it.tcp,
                "requestedSocketTargetFamily" to if (':' in it.serverIp) "IPv6" else "IPv4"
            ) },
            "requestBinding" to "ANDROID_DEFAULT_NETWORK_NO_EXPLICIT_BYPASS",
            "networkBefore" to network(report.networkBefore), "networkAfter" to network(report.networkAfter),
            "networkChangeObserved" to report.networkChanged,
            "dns" to (dns(report.dns) + ("privacyAssessment" to assessment(report.dnsPrivacy))),
            "rawDns" to report.rawDns.map(::raw),
            "https" to (https(report.https) + ("egressAssessment" to assessment(report.egress))),
            "attempts" to report.attempts.map { linkedMapOf(
                "attemptId" to it.attemptId, "probe" to it.probe.name, "attemptNumber" to it.attemptNumber,
                "startedAfterMillis" to it.startedAfterMillis, "finishedAfterMillis" to it.finishedAfterMillis,
                "timeoutMillis" to it.timeoutMillis, "retryTrigger" to it.retryTrigger?.name,
                "retryScheduled" to it.retryScheduled, "retryDelayMillis" to it.retryDelayMillis,
                "dns" to it.dns?.let(::dns), "https" to it.https?.let(::https), "rawDns" to it.rawDns?.let(::raw)
            ) },
            "ipv6Assessment" to assessment(report.ipv6), "limitations" to RunReport.LIMITATIONS
        )
        return Json.write(data) + "\n"
    }
}

internal object Json {
    fun write(value: Any?): String = when (value) {
        null -> "null"
        is String -> quote(value)
        is Boolean, is Int, is Long -> value.toString()
        is Map<*, *> -> value.entries.joinToString(",", "{", "}") { quote(it.key as String) + ":" + write(it.value) }
        is Iterable<*> -> value.joinToString(",", "[", "]") { write(it) }
        else -> error("Unsupported JSON type")
    }
    private fun quote(value: String): String = buildString {
        append('"')
        for (c in value) when (c) {
            '"' -> append("\\\""); '\\' -> append("\\\\")
            '\n' -> append("\\n"); '\r' -> append("\\r"); '\t' -> append("\\t")
            else -> if (c.code < 32 || c.code in 0xd800..0xdfff) append("\\u%04x".format(c.code)) else append(c)
        }
        append('"')
    }
}
