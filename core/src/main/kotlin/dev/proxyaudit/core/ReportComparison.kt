package dev.proxyaudit.core

import java.util.Locale

data class ComparisonSummary(val comparable: Boolean, val summary: String, val details: List<String>)

/** Compares availability observations, never scores privacy or attributes improvement to a repair. */
object ReportComparison {
    fun compare(before: RunReport, after: RunReport): ComparisonSummary {
        fun incomparable(reason: String) = ComparisonSummary(false, "不可比：$reason",
            listOf("保留两次原始观察；不把未执行、取消或条件变化当作改善或退化。",
                "比较不证明已修复，也不证明全机 DNS 无泄露。"))
        if (before.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME || after.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME)
            return incomparable("包含演示数据")
        if (before.runId == after.runId) return incomparable("两项引用同一次运行")
        if (before.appVersion != after.appVersion || before.androidApi != after.androidApi)
            return incomparable("应用版本或 Android 版本不同")
        if (!samePlan(before.config, after.config)) return incomparable("探测目标、查询、策略或超时配置不同")
        if (before.stopReason != null || after.stopReason != null)
            return incomparable("至少一次运行被取消、超出总预算或提前停止")
        if (!validAttempts(before) || !validAttempts(after))
            return incomparable("尝试记录缺失、未完成或不一致")
        if (DiagnosticAttemptEvidence.mixed(before) || DiagnosticAttemptEvidence.mixed(after))
            return incomparable("至少一次运行中同一探针的尝试结果不一致，观察不足")
        if (!DiagnosticEvidence.stable(before) || !DiagnosticEvidence.stable(after))
            return incomparable("至少一次运行的网络不稳定或观察不可用")
        if (!sameEnvironment(before.networkAfter, after.networkBefore))
            return incomparable("网络、传输、VPN 或链路条件改变")

        val details = mutableListOf<String>()
        if (before.attempts.any { it.attemptNumber > 1 } || after.attempts.any { it.attemptNumber > 1 })
            details += "至少一次运行包含附加尝试；以下按首个结果比较，全部失败与附加结果保留，不挑选成功覆盖失败。"
        if (before.networkAfter.configuredDnsServers != after.networkBefore.configuredDnsServers ||
            before.networkAfter.privateDnsActive != after.networkBefore.privateDnsActive ||
            before.networkAfter.privateDnsServerName != after.networkBefore.privateDnsServerName) {
            details += "两次之间的 DNS 配置发生变化；可以对照相同探针取得地址的情况，不能据此归因于某项修复。"
        }
        var improved = 0
        var regressed = 0
        var examined = 0
        fun compareOne(label: String, previous: Boolean, current: Boolean) {
            examined++
            when {
                !previous && current -> { improved++; details += "$label：前次未取得可用结果，本次取得。" }
                previous && !current -> { regressed++; details += "$label：前次取得可用结果，本次未取得。" }
                previous -> details += "$label：两次均取得可用结果；地址或延迟差异不作为安全评分。"
                else -> details += "$label：两次均未取得可用结果；具体响应码和错误请对照各自报告。"
            }
        }
        if (before.config.policy.runDns) {
            if (!DiagnosticEvidence.finished(before.dns.execution, before.dns.failure) ||
                !DiagnosticEvidence.finished(after.dns.execution, after.dns.failure))
                return incomparable("系统解析未完成或已取消")
            compareOne("系统解析", DiagnosticEvidence.systemUsable(before.dns), DiagnosticEvidence.systemUsable(after.dns))
        }
        for (transport in DiagnosticEvidence.enabledTransports(before.config.rawDns)) {
            val previous = before.rawDns.singleOrNull { it.transport == transport }
            val current = after.rawDns.singleOrNull { it.transport == transport }
            if (previous == null || current == null ||
                !DiagnosticEvidence.finished(previous.execution, previous.failure) ||
                !DiagnosticEvidence.finished(current.execution, current.failure))
                return incomparable("${transport.name} DNS 记录缺失、未完成或已取消")
            compareOne("${transport.name} DNS", DiagnosticEvidence.rawUsable(previous), DiagnosticEvidence.rawUsable(current))
        }
        if (before.config.policy.runHttps) {
            if (!DiagnosticEvidence.finished(before.https.execution, before.https.failure) ||
                !DiagnosticEvidence.finished(after.https.execution, after.https.failure))
                return incomparable("HTTPS 探测未完成或已取消")
            compareOne("HTTPS 回显", httpsUsable(before), httpsUsable(after))
            if (before.egress.verdict != after.egress.verdict)
                details += "HTTPS 出口策略结论发生变化；需查看两份报告，不能将回显可用性当作出口策略符合。"
        }
        if (examined == 0) return incomparable("没有共同启用的探针")
        details += "取得 DNS 地址不保证该地址可连接或网站可用；这些是两次单次观察，不能证明已修复、不能归因于某项操作，也不能证明全机无泄露。"
        return ComparisonSummary(true, when {
            improved > 0 && regressed > 0 -> "观察有改善也有退化：请逐项对照"
            improved > 0 -> "可用性观察改善：不等于已修复或无泄露"
            regressed > 0 -> "可用性观察退化：原因尚未确定"
            else -> "可用性观察未变：不表示已通过隐私验证"
        }, details)
    }

    fun toJson(before: RunReport, after: RunReport, includeNetworkIdentifiers: Boolean = false): String {
        val comparison = compare(before, after)
        // Embed the complete existing exporter objects directly; never parse/reconstruct or quote them as strings.
        return "{\"schemaVersion\":1,\"artifactType\":\"REPORT_COMPARISON\"," +
            "\"networkIdentifiersIncluded\":$includeNetworkIdentifiers," +
            "\"comparison\":" + Json.write(linkedMapOf(
                "comparable" to comparison.comparable, "summary" to comparison.summary, "details" to comparison.details
            )) + ",\"before\":" + ReportExporter.toJson(before, includeNetworkIdentifiers).trimEnd() +
            ",\"after\":" + ReportExporter.toJson(after, includeNetworkIdentifiers).trimEnd() + "}\n"
    }

    private fun samePlan(a: RunConfig, b: RunConfig): Boolean =
        a.endpoint?.origin == b.endpoint?.origin &&
            normalizedHost(a.dnsHost) == normalizedHost(b.dnsHost) &&
            a.policy == b.policy && a.timeoutMillis == b.timeoutMillis &&
            a.evidenceBudgetMillis == b.evidenceBudgetMillis && a.maxAttempts == b.maxAttempts && sameRawPlan(a.rawDns, b.rawDns)

    private fun validAttempts(report: RunReport): Boolean {
        // Older schema-2 reports contain no attempt records and keep their original semantics.
        if (report.attempts.isEmpty()) return report.config.maxAttempts == 1
        if (report.attempts.map { it.attemptId }.distinct().size != report.attempts.size) return false
        val expected = buildSet {
            if (report.config.policy.runDns) add(ProbeKind.SYSTEM_DNS)
            if (report.config.policy.runHttps) add(ProbeKind.HTTPS)
            if (report.config.rawDns?.udp == true) add(ProbeKind.RAW_UDP)
            if (report.config.rawDns?.tcp == true) add(ProbeKind.RAW_TCP)
        }
        if (report.attempts.map { it.probe }.toSet() != expected) return false
        return report.attempts.groupBy { it.probe }.all { (kind, attempts) ->
            attempts.size <= report.config.maxAttempts && attempts.map { it.attemptNumber } == (1..attempts.size).toList() &&
                attempts.all { attempt ->
                    val execution = attempt.dns?.execution ?: attempt.https?.execution ?: attempt.rawDns?.execution
                    val failure = attempt.dns?.failure ?: attempt.https?.failure ?: attempt.rawDns?.failure
                    attempt.attemptId.isNotBlank() && attempt.timeoutMillis in 1..report.config.timeoutMillis &&
                        attempt.finishedAfterMillis?.let { it >= attempt.startedAfterMillis } == true &&
                        listOfNotNull(attempt.dns, attempt.https, attempt.rawDns).size == 1 &&
                        execution != null && DiagnosticEvidence.finished(execution, failure) && when (kind) {
                            ProbeKind.SYSTEM_DNS -> attempt.dns != null
                            ProbeKind.HTTPS -> attempt.https != null
                            ProbeKind.RAW_UDP -> attempt.rawDns?.transport == DnsTransport.UDP
                            ProbeKind.RAW_TCP -> attempt.rawDns?.transport == DnsTransport.TCP
                        }
                } && when (kind) {
                    ProbeKind.SYSTEM_DNS -> attempts.first().dns == report.dns
                    ProbeKind.HTTPS -> attempts.first().https == report.https
                    ProbeKind.RAW_UDP -> attempts.first().rawDns == report.rawDns.singleOrNull { it.transport == DnsTransport.UDP }
                    ProbeKind.RAW_TCP -> attempts.first().rawDns == report.rawDns.singleOrNull { it.transport == DnsTransport.TCP }
                }
        }
    }

    private fun sameRawPlan(a: RawDnsConfig?, b: RawDnsConfig?): Boolean {
        if (a == null || b == null) return a == b
        return NumericIp.canonical(a.serverIp) == NumericIp.canonical(b.serverIp) &&
            (':' in a.serverIp) == (':' in b.serverIp) &&
            a.port == b.port && normalizedHost(a.host) == normalizedHost(b.host) &&
            a.recordType == b.recordType && a.udp == b.udp && a.tcp == b.tcp
    }

    private fun normalizedHost(value: String?): String? = value?.removeSuffix(".")?.lowercase(Locale.ROOT)

    private fun sameEnvironment(a: NetworkSnapshot, b: NetworkSnapshot): Boolean =
        a.networkId == b.networkId && a.transports.toSet() == b.transports.toSet() &&
            a.vpnCapability == b.vpnCapability && a.internetCapability == b.internetCapability &&
            a.validatedCapability == b.validatedCapability && a.localAddresses.toSet() == b.localAddresses.toSet()

    private fun httpsUsable(report: RunReport): Boolean = report.https.let {
        report.config.endpoint != null && it.execution == Execution.COMPLETED && it.failure == null &&
            it.tlsValidated && it.statusCode == 200 && it.echoedRequestId == report.runId &&
            it.serverReportedSourceIp?.let(NumericIp::canonical) != null
    }
}
