package dev.proxyaudit.android

import dev.proxyaudit.core.*
import org.json.JSONArray
import org.json.JSONObject

/** Full URLs remain in process memory; exports continue to omit URL paths and queries. */
data class DeepRetestPlan(val websitePlan: WebsitePlan?, val expectedProxy: String, val rawServer: String?,
                         val sourceRunId: String, val usesBaseline: Boolean)

data class DeepReportComparison(
    val baseline: DeepReport, val current: DeepReport, val comparable: Boolean,
    val summary: String, val blockers: List<String>, val cautions: List<String>, val changes: List<String>
) {
    fun toJson(full: Boolean = false): String = JSONObject().apply {
        put("schemaVersion", 1); put("reportKind", "NETWORK_DEEP_COMPARISON")
        put("appVersion", current.appVersion); put("comparable", comparable)
        put("evidenceEnvelope", JSONObject(EvidenceEnvelope.toJson("NETWORK_DEEP_COMPARISON", current.appVersion,
            current.id, current.origin, "THIS_APP_OBSERVED_COMPARISON", listOf("BASELINE_REPORT", "CURRENT_REPORT"),
            baseline.stopReason != null || current.stopReason != null)))
        put("comparisonScope", "OBSERVED_AVAILABILITY_AND_STAGES_ONLY")
        put("safetyOrPrivacyVerdict", "NOT_ASSESSED")
        put("urlPathAndQueryIncluded", false); put("networkIdentifiersIncluded", full)
        put("summary", summary); put("blockers", JSONArray(blockers)); put("cautions", JSONArray(cautions))
        put("changes", JSONArray(changes))
        put("baseline", JSONObject(baseline.toJson(full))); put("current", JSONObject(current.toJson(full)))
    }.toString(2)
}

/** A baseline can contain real failures; it must contain all planned terminal observations. */
object DeepReportComparisons {
    fun baselineBlockers(report: DeepReport): List<String> = buildList {
        if (report.origin != "ANDROID_RUNTIME") add("报告不是 Android 真实运行来源。")
        if (report.stopReason != null) add("本次已停止或网络条件改变，不能作为完整基线。")
        if (report.appVersion.isBlank()) add("应用版本缺失。")
        if (!networkKnown(report.before) || !networkKnown(report.after)) add("缺少可核对的默认网络条件。")
        if (report.before != null && report.after != null && networkKey(report.before, true) != networkKey(report.after, true))
            add("运行前后网络条件不同。")
        val self = report.selfTest
        if (self == null || self.cancelled || self.timedOut || !self.serverTerminated || self.checks.isEmpty() ||
            self.checks.any { it.status in setOf(SelfTestStatus.CANCELLED, SelfTestStatus.NOT_STARTED) })
            add("本机受控检查未完整结束。")
        if (report.plannedWebsite != null) {
            val site = report.website
            if (site == null || site.attempts.isEmpty() || site.execution !in setOf(Execution.COMPLETED, Execution.ERROR) ||
                site.failure in setOf(WebsiteFailure.CANCELLED, WebsiteFailure.BUSY, WebsiteFailure.INTERNAL_ERROR) ||
                site.attempts.any { it.execution !in setOf(Execution.COMPLETED, Execution.ERROR) ||
                    it.failure in setOf(WebsiteFailure.CANCELLED, WebsiteFailure.BUSY, WebsiteFailure.INTERNAL_ERROR) })
                add("网站计划缺少终态观察。")
            if (site != null && planKey(site.plan) != planKey(report.plannedWebsite)) add("网站执行与冻结计划不一致。")
        } else if (report.website != null) add("网站结果没有对应计划。")
        if (report.dnsServer != null) {
            val expected = DnsRecordType.entries.flatMap { t -> DnsTransport.entries.map { t to it } }.toSet()
            if (report.plannedWebsite == null || report.dns.size != expected.size ||
                report.dns.map { it.recordType to it.observation.transport }.toSet() != expected ||
                report.dns.any { it.observation.execution !in setOf(Execution.COMPLETED, Execution.ERROR) })
                add("原始 DNS 四项计划未完整结束。")
        } else if (report.dns.isNotEmpty()) add("原始 DNS 结果没有冻结目标。")
    }.distinct()

    fun compare(baseline: DeepReport, current: DeepReport): DeepReportComparison {
        val blockers = buildList {
            if (baseline.id == current.id) add("基线与当前报告是同一次运行。")
            if (baselineBlockers(baseline).isNotEmpty()) add("基线不完整或不符合真实运行条件。")
            if (baselineBlockers(current).isNotEmpty()) add("当前报告不完整或不符合真实运行条件。")
            if (baseline.appVersion != current.appVersion) add("应用版本不同，不能将实现变化当作网络变化。")
            if (planKey(baseline.plannedWebsite) != planKey(current.plannedWebsite)) add("网站完整网址或尝试预算不同，未保持原计划。")
            if (baseline.expectedProxy != current.expectedProxy) add("用户声明的代理状态不同。")
            if (canonicalServer(baseline.dnsServer) != canonicalServer(current.dnsServer)) add("原始 DNS 目标或启用状态不同。")
            if (baseline.before != null && current.before != null &&
                networkKey(baseline.before, false) != networkKey(current.before, false))
                add("默认网络、VPN、HTTP 代理、绑定或链路条件不同；本次不形成修复前后比较。")
        }.distinct()
        val cautions = buildList {
            add("比较仅描述本应用的可用性与阶段观察，不给出安全通过、无 DNS 泄露或修复因果结论。")
            if (baseline.before != null && current.before != null && dnsKey(baseline.before) != dnsKey(current.before))
                add("系统 DNS / Private DNS 配置改变；可以列出观察变化，但时间、缓存、服务端与代理内部策略仍可能变化，不能归因于该配置。原始 DNS 仍查询冻结的原目标。")
            if (baseline.website?.attempts.orEmpty().size > 1 || current.website?.attempts.orEmpty().size > 1)
                add("包含附加尝试；阶段和耗时按首次尝试比较，所有失败与后续尝试在两份原报告中保留。")
        }
        val changes = if (blockers.isEmpty()) describeChanges(baseline, current) else emptyList()
        return DeepReportComparison(baseline, current, blockers.isEmpty(),
            if (blockers.isEmpty()) "同计划观察可比较：查看可用性、阶段与 DNS 变化，并按同条件复测确认稳定性。"
            else "条件不满足，无法形成同计划比较；两份原始报告保留供分别查看。", blockers, cautions, changes)
    }

    private fun describeChanges(before: DeepReport, after: DeepReport): List<String> = buildList {
        val first = before.website; val second = after.website
        if (first != null && second != null) {
            add("网站首次观察：${availability(first)} → ${availability(second)}。")
            add("网站全部尝试：${attempts(first)} → ${attempts(second)}；后续成功不覆盖首次失败。")
            val a = first.attempts.firstOrNull(); val b = second.attempts.firstOrNull()
            val firstStages = a?.stages ?: first.stages; val secondStages = b?.stages ?: second.stages
            for (stage in WebsiteStage.entries) {
                val x = firstStages.singleOrNull { it.stage == stage }; val y = secondStages.singleOrNull { it.stage == stage }
                if (x != null || y != null) add("${stage.name} 首次阶段：${x?.status?.name ?: "未观测"} → ${y?.status?.name ?: "未观测"}；耗时 ${millis(x?.durationMillis)} → ${millis(y?.durationMillis)}。")
            }
            add("网站首次耗时：${a?.durationMillis ?: first.durationMillis} ms → ${b?.durationMillis ?: second.durationMillis} ms；单次耗时变化不等于稳定改善。")
        }
        for (type in DnsRecordType.entries) for (transport in DnsTransport.entries) {
            val a = before.dns.singleOrNull { it.recordType == type && it.observation.transport == transport }?.observation
            val b = after.dns.singleOrNull { it.recordType == type && it.observation.transport == transport }?.observation
            if (a != null && b != null) {
                val same = a.addresses.mapNotNull(NumericIp::canonical).toSet() == b.addresses.mapNotNull(NumericIp::canonical).toSet()
                add("$type / $transport：${dnsOutcome(a)} → ${dnsOutcome(b)}；地址集合${if (same) "相同" else "变化"}；耗时 ${millis(a.durationMillis)} → ${millis(b.durationMillis)}。")
            }
        }
        if (first == null && second == null) add("本次只比较本机受控检查，未访问外部网站。")
        add("本机检查：${before.selfTest?.checks?.count { it.status == SelfTestStatus.PASS }} 项符合预期 → ${after.selfTest?.checks?.count { it.status == SelfTestStatus.PASS }} 项符合预期。")
    }

    private fun availability(site: WebsiteReport): String {
        val first = site.attempts.firstOrNull()
        val failure = if (first != null) first.failure else site.failure
        val code = if (first != null) first.statusCode else site.statusCode
        return if (failure != null) "${first?.execution ?: site.execution} / $failure${code?.let { " / HTTP $it" } ?: ""}"
        else code?.let { "取得 HTTP $it 响应" } ?: (first?.execution ?: site.execution).name
    }
    private fun attempts(site: WebsiteReport) = if (site.attempts.isEmpty()) "${site.execution}（无逐次记录）" else
        site.attempts.joinToString("，") { "#${it.number} ${it.execution}${it.failure?.let { f -> "/$f" } ?: ""}${it.statusCode?.let { c -> "/HTTP$c" } ?: ""}" }
    private fun millis(value: Long?) = value?.let { "$it ms" } ?: "未观测"
    private fun dnsOutcome(o: RawDnsObservation): String = when {
        o.failure != null -> "${o.execution}/${o.failure}"
        o.execution != Execution.COMPLETED -> o.execution.name
        o.truncated -> "截断响应"
        o.responseCode != 0 -> "RCODE ${o.responseCode ?: "未观测"}"
        o.addresses.isEmpty() -> "NOERROR 空地址"
        else -> "NOERROR ${o.addresses.size} 个地址"
    }
    private fun canonicalServer(value: String?) = value?.let { NumericIp.canonical(it) ?: it }
    private fun planKey(plan: WebsitePlan?): Any? = plan?.let { listOf(it.url, it.timeoutMillis, it.totalTimeoutMillis, it.maxAttempts) }
    private fun networkKnown(report: NetworkInventoryReport?) = report != null && report.accessNetworkStateGranted &&
        report.activeNetworkId != null && report.issues.none { it.contains("CHANGED_DURING_COLLECTION") } &&
        report.networks.singleOrNull { it.isDefault }?.let {
            it.networkId == report.activeNetworkId && it.capabilities != null && it.transports.isNotEmpty() &&
                it.interfaceName != null && it.addresses.isNotEmpty() && it.issues.none { issue ->
                    issue.startsWith("CAPABILITIES:") || issue.startsWith("LINK_PROPERTIES:") ||
                        issue.startsWith("ADDRESSES:") || issue.startsWith("ROUTES:") || issue.startsWith("DNS_SERVERS:")
                }
        } == true
    private fun dnsKey(report: NetworkInventoryReport): List<Any?> {
        val network = report.networks.singleOrNull { it.isDefault }
        return listOf(network?.dnsServers?.toSet(), network?.dnsSearchDomains, network?.privateDnsActive, network?.privateDnsServerName)
    }
    private fun proxyKey(proxy: InventoryProxy?): Any? = proxy?.let { listOf(it.host, it.port, it.pacPresent, it.pacUrl, it.exclusions.toSet()) }
    private fun networkKey(report: NetworkInventoryReport, includeDns: Boolean): List<Any?> {
        val network = report.networks.singleOrNull { it.isDefault }
        return listOf(report.androidApi, report.activeNetworkId, report.boundNetworkId,
            report.accessNetworkStateGranted, report.internetPermissionGranted, proxyKey(report.defaultProxy),
            network?.transports?.toSet(), network?.capabilities, network?.interfaceName, network?.addresses?.toSet(),
            network?.routes?.toSet(), network?.mtu, proxyKey(network?.httpProxy),
            if (includeDns) dnsKey(report) else null)
    }
}
