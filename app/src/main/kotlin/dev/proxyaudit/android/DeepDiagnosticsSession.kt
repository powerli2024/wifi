package dev.proxyaudit.android

import android.os.Handler
import android.os.Looper
import dev.proxyaudit.core.*
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

data class DeepDnsResult(val recordType: DnsRecordType, val observation: RawDnsObservation)

data class DeepReport(
    val id: String, val startedAt: String, val expectedProxy: String,
    val before: NetworkInventoryReport?, val after: NetworkInventoryReport?,
    val selfTest: DeviceSelfTestReport?, val website: WebsiteReport?,
    val dnsServer: String?, val dns: List<DeepDnsResult>, val stopReason: String?,
    val findings: List<String>,
    val appVersion: String = AppIdentity.version,
    val plannedWebsite: WebsitePlan? = website?.plan,
    val origin: String = "ANDROID_RUNTIME"
) {
    fun toJson(full: Boolean = false): String = JSONObject().apply {
        put("schemaVersion", 1); put("reportKind", "NETWORK_DEEP_DIAGNOSTICS")
        put("runId", id); put("startedAtUtc", startedAt); put("appVersion", appVersion)
        put("evidenceEnvelope", JSONObject(EvidenceEnvelope.toJson("NETWORK_DEEP_DIAGNOSTICS", appVersion, id,
            origin, "THIS_APP_AND_ANDROID_VISIBLE_NETWORKS", buildList {
                if (before != null || after != null) add("ANDROID_FRAMEWORK")
                if (selfTest?.checks?.any { it.status != SelfTestStatus.NOT_STARTED } == true) add("LOCAL_LOOPBACK")
                if (website?.attempts?.any { it.execution != Execution.NOT_STARTED } == true) add("WEBSITE_PROBE")
                if (dns.any { it.observation.execution != Execution.NOT_STARTED }) add("RAW_DNS_PROBE")
            }, stopReason != null)))
        put("scope", "THIS_APP_AND_ANDROID_VISIBLE_NETWORKS")
        put("networkIdentifiersIncluded", full); put("userDeclaredProxy", expectedProxy)
        put("frozenPlan", JSONObject().apply {
            put("websitePlanned", plannedWebsite != null)
            put("targetOrigin", plannedWebsite?.displayTarget?.let { if (full) it else "[REDACTED]" } ?: JSONObject.NULL)
            put("urlPathAndQueryIncluded", false)
            put("attemptTimeoutMillis", plannedWebsite?.timeoutMillis ?: JSONObject.NULL)
            put("totalTimeoutMillis", plannedWebsite?.totalTimeoutMillis ?: JSONObject.NULL)
            put("maxAttempts", plannedWebsite?.maxAttempts ?: JSONObject.NULL)
            put("rawDnsPlanned", dnsServer != null)
        })
        put("networkBefore", before?.let { JSONObject(NetworkInventory.toJson(it, full)) } ?: JSONObject.NULL)
        put("networkAfter", after?.let { JSONObject(NetworkInventory.toJson(it, full)) } ?: JSONObject.NULL)
        put("localSelfTest", selfTest?.let { JSONObject(DeviceSelfTest.toJson(it)) } ?: JSONObject.NULL)
        put("website", website?.let { JSONObject(it.toJson(full)) } ?: JSONObject.NULL)
        put("rawDnsServer", dnsServer?.let { if (full) it else "[REDACTED]" } ?: JSONObject.NULL)
        put("rawDns", JSONArray().apply { dns.forEach { item -> put(JSONObject().apply {
            val o = item.observation
            put("recordType", item.recordType.name); put("transport", o.transport.name)
            put("execution", o.execution.name); put("durationMillis", o.durationMillis ?: JSONObject.NULL)
            put("responseCode", o.responseCode ?: JSONObject.NULL); put("truncated", o.truncated)
            put("failure", o.failure?.name ?: JSONObject.NULL); put("addressCount", o.addresses.size)
            put("addresses", JSONArray(o.addresses.map { if (full) it else "[REDACTED]" }))
        }) } })
        put("stopReason", stopReason ?: JSONObject.NULL); put("findings", JSONArray(findings))
    }.toString(2)
}

/** Injectable operations keep framework tests offline. */
internal interface DeepOperation<T> : AutoCloseable { fun execute(): T }
internal interface DeepDiagnosticsBackend {
    fun controllerBusy(): Boolean
    fun websitePending(): Boolean
    fun snapshot(): NetworkSnapshot
    fun inventory(): NetworkInventoryReport
    fun selfTest(): DeepOperation<DeviceSelfTestReport>
    fun website(plan: WebsitePlan): DeepOperation<WebsiteReport>
    fun raw(config: RawDnsConfig, transport: DnsTransport, timeoutMillis: Int): DeepOperation<RawDnsObservation>
}
private class AndroidDeepBackend(private val app: DiagnosticsApplication) : DeepDiagnosticsBackend {
    override fun controllerBusy() = app.controller.busy || app.proxyCooperation.busy || ProxyCooperationProbe.hasPendingWork()
    override fun websitePending() = WebsiteDiagnostics.hasPendingWork()
    override fun snapshot() = app.controller.snapshot()
    override fun inventory() = NetworkInventory.collect(app)
    override fun selfTest(): DeepOperation<DeviceSelfTestReport> {
        val probe = DeviceSelfTest()
        return object : DeepOperation<DeviceSelfTestReport> {
            override fun execute() = probe.execute()
            override fun close() = probe.close()
        }
    }
    override fun website(plan: WebsitePlan): DeepOperation<WebsiteReport> {
        val probe = WebsiteDiagnostics(plan)
        return object : DeepOperation<WebsiteReport> {
            override fun execute() = probe.execute()
            override fun close() = probe.close()
        }
    }
    override fun raw(config: RawDnsConfig, transport: DnsTransport, timeoutMillis: Int): DeepOperation<RawDnsObservation> {
        val probe = RawDnsProbe(config, transport, timeoutMillis)
        return object : DeepOperation<RawDnsObservation> {
            override fun execute() = probe.execute()
            override fun close() = probe.close()
        }
    }
}

/** Application-owned run identity survives rotation. Opening the screen performs no probe. */
class DeepDiagnosticsSession internal constructor(
    private val backend: DeepDiagnosticsBackend,
    private val budgetMillis: Long = 60_000,
    private val monitorMillis: Long = 500
) {
    constructor(app: DiagnosticsApplication) : this(AndroidDeepBackend(app))
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "deep-diagnostics").apply { isDaemon = true } }
    private val scheduler = java.util.concurrent.ScheduledThreadPoolExecutor(1) { r -> Thread(r, "deep-deadline").apply { isDaemon = true } }
        .apply { removeOnCancelPolicy = true }
    private val networkMonitor = java.util.concurrent.ScheduledThreadPoolExecutor(1) { r -> Thread(r, "deep-network-observer").apply { isDaemon = true } }
        .apply { removeOnCancelPolicy = true }
    private val cleanup = java.util.concurrent.ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS,
        java.util.concurrent.ArrayBlockingQueue<Runnable>(1),
        { r -> Thread(r, "deep-cleanup").apply { isDaemon = true } },
        java.util.concurrent.ThreadPoolExecutor.DiscardPolicy())
    private val main = Handler(Looper.getMainLooper())
    private val observers = java.util.concurrent.CopyOnWriteArraySet<() -> Unit>()
    private val lock = Any()
    private var active: Run? = null
    @Volatile var busy = false; private set
    @Volatile var status = "输入网址或选择预设，确认后收集网络信息并逐层诊断。"; private set
    @Volatile var report: DeepReport? = null; private set
    @Volatile var baseline: DeepReport? = null; private set
    val comparison: DeepReportComparison? get() = synchronized(lock) {
        val saved = baseline; val current = report
        if (saved == null || current == null || saved.id == current.id) null else DeepReportComparisons.compare(saved, current)
    }
    val baselineSaveBlockers: List<String> get() = synchronized(lock) {
        when {
            busy -> listOf("正在执行实验，完成后才能保存基线。")
            report == null -> listOf("先完成一次实际诊断，再保存基线。")
            else -> DeepReportComparisons.baselineBlockers(report!!)
        }
    }
    var urlDraft = "https://chatgpt.com/"
    var proxyDraft = 0
    var rawDraft = false
    data class ExportTicket(val id: String, val requestCode: Int, val suggestedName: String)
    private data class PendingExport(val ticket: ExportTicket, val payload: String)
    private var pendingExport: PendingExport? = null
    private var nextExportCode = 6200
    val exportPending get() = synchronized(lock) { pendingExport != null }
    private class Run {
        val id = UUID.randomUUID().toString()
        val startedAt = Instant.now().toString()
        val startedNanos = System.nanoTime()
        @Volatile var stop: String? = null
        var resource: AutoCloseable? = null
        var finishing = false
    }

    fun observe(observer: () -> Unit) { observers.add(observer); observer() }
    fun removeObserver(observer: () -> Unit) { observers.remove(observer) }
    private fun notifyChanged() { main.post { observers.forEach { it() } } }
    private fun progress(run: Run, value: String) {
        synchronized(lock) { if (active !== run || run.stop != null || run.finishing) return; status = value }
        notifyChanged()
    }
    private fun remaining(run: Run) = budgetMillis - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - run.startedNanos)
    fun start(plan: WebsitePlan?, expectedProxy: String, rawServer: String?): Boolean {
        if (expectedProxy !in setOf("UNKNOWN", "ENABLED", "DISABLED")) return false
        if (rawServer != null && (plan == null || NumericIp.canonical(rawServer) == null ||
                !isDnsHost(runCatching { URI(plan.url).host }.getOrNull() ?: ""))) return false
        val run = synchronized(lock) {
            if (busy || backend.controllerBusy() || backend.websitePending()) return false
            Run().also {
                active = it; busy = true; report = null
                status = "正在收集 Android 网络画像…"
            }
        }
        notifyChanged()
        worker.execute { execute(run, plan, expectedProxy, rawServer) }
        return true
    }
    fun cancel(reason: String = "USER_CANCELLED") {
        val run = synchronized(lock) { active } ?: return
        cancelRun(run, reason.takeIf { it in setOf("USER_CANCELLED", "NETWORK_CHANGED", "TOTAL_DEADLINE") } ?: "USER_CANCELLED")
    }
    private fun cancelRun(run: Run, reason: String) {
        val resource = synchronized(lock) {
            if (active !== run || run.finishing || run.stop != null) return
            run.stop = reason
            status = if (reason == "NETWORK_CHANGED") "检测到网络条件改变，停止后续实验并清理…" else "已请求停止，正在清理实验资源…"
            run.resource
        }
        notifyChanged()
        cleanup.execute { runCatching { resource?.close() } }
    }
    private fun accepting(run: Run): Boolean {
        if (remaining(run) <= 0) cancelRun(run, "TOTAL_DEADLINE")
        return synchronized(lock) { active === run && run.stop == null && !run.finishing }
    }
    private fun checkpoint(run: Run, initial: NetworkSnapshot): Boolean {
        if (!accepting(run)) return false
        if (backend.snapshot() != initial) cancelRun(run, "NETWORK_CHANGED")
        return accepting(run)
    }
    private fun <T> withOperation(run: Run, create: () -> DeepOperation<T>): T? {
        if (!accepting(run)) return null
        val operation = create()
        val registered = synchronized(lock) {
            if (active !== run || run.stop != null || run.finishing) false
            else { run.resource = operation; true }
        }
        // Never close a provider/socket while holding the session monitor.
        if (!registered) { runCatching { operation.close() }; return null }
        return try { if (!accepting(run)) null else operation.execute() }
        finally {
            runCatching { operation.close() }
            synchronized(lock) { if (run.resource === operation) run.resource = null }
        }
    }
    private fun execute(run: Run, plan: WebsitePlan?, expectedProxy: String, rawServer: String?) {
        var before: NetworkInventoryReport? = null
        var after: NetworkInventoryReport? = null
        var initial: NetworkSnapshot? = null
        var self: DeviceSelfTestReport? = null
        var site: WebsiteReport? = null
        val dns = mutableListOf<DeepDnsResult>()
        val deadline = scheduler.schedule({ cancelRun(run, "TOTAL_DEADLINE") },
            remaining(run).coerceAtLeast(0), TimeUnit.MILLISECONDS)
        var monitor: java.util.concurrent.ScheduledFuture<*>? = null
        try {
            val initialSnapshot = backend.snapshot()
            initial = initialSnapshot
            monitor = networkMonitor.scheduleWithFixedDelay({
                if (accepting(run)) {
                    try { if (backend.snapshot() != initialSnapshot) cancelRun(run, "NETWORK_CHANGED") }
                    catch (_: Exception) { cancelRun(run, "NETWORK_OBSERVATION_UNAVAILABLE") }
                }
            }, monitorMillis, monitorMillis, TimeUnit.MILLISECONDS)
            before = backend.inventory()
            if (checkpoint(run, initialSnapshot)) {
                progress(run, "本机实验：正常响应 / 受控超时 / 拒绝连接…")
                self = withOperation(run) { backend.selfTest() }
            }
            if (plan != null && checkpoint(run, initialSnapshot)) {
                progress(run, "网站分层诊断：DNS → 连接 → TLS → HTTP；暂时性失败复核…")
                site = withOperation(run) { backend.website(plan) }
            }
            if (plan != null && rawServer != null && accepting(run) && !backend.websitePending()) {
                val host = URI(plan.url).host
                rawLoop@ for (type in DnsRecordType.entries) for (transport in DnsTransport.entries) {
                    if (!checkpoint(run, initialSnapshot)) break@rawLoop
                    progress(run, "交叉验证：当前 DNS · $type / $transport…")
                    val config = RawDnsConfig(rawServer, host = host, recordType = type)
                    withOperation(run) { backend.raw(config, transport, minOf(4000L, remaining(run).coerceAtLeast(1)).toInt()) }
                        ?.let { dns.add(DeepDnsResult(type, it)) }
                }
            }
            if (accepting(run) && backend.snapshot() != initialSnapshot) cancelRun(run, "NETWORK_CHANGED")
        } catch (_: Exception) { cancelRun(run, "LOCAL_EXECUTION_ERROR") }
        finally {
            synchronized(lock) { run.finishing = true }
            deadline.cancel(false); monitor?.cancel(false)
            after = runCatching { backend.inventory() }.getOrNull()
            if (run.stop == null) {
                val finalSnapshot = runCatching { backend.snapshot() }.getOrNull()
                if (finalSnapshot == null || before == null || after == null) run.stop = "NETWORK_OBSERVATION_UNAVAILABLE"
                else if (initial != finalSnapshot || conditionsChanged(before, after)) run.stop = "NETWORK_CHANGED"
            }
            val reason = run.stop
            val findings = buildList {
                when (reason) {
                    "NETWORK_CHANGED" -> add("运行期间 Android 网络条件改变；结果属于不同条件，不能据此判定修复或路径，请稳定后复测。")
                    "NETWORK_OBSERVATION_UNAVAILABLE" -> add("运行期间无法继续取得网络状态；已停止后续实验，环境稳定性未知。")
                    "TOTAL_DEADLINE" -> add("整体证据预算已用完，停止后续实验；未执行项目未计为成功。")
                    "USER_CANCELLED" -> add("本次由用户停止，已保存探针返回的部分观察；不代表完成全部实验。")
                    "LOCAL_EXECUTION_ERROR" -> add("工具内部采集或执行发生异常；已保留取得的结果，原始异常文本未导出。")
                }
                site?.let { if (reason == null) { add(it.summary); addAll(it.nextSteps) }
                    else add("网站分层记录仅作部分观察保留；本次已提前停止或环境改变，不形成完整访问结论。") }
                if (expectedProxy == "ENABLED" && initial?.vpnCapability == false) add(
                    "你声明代理已开启，但本应用默认网络快照未显示 VPN。请核对客户端模式与分应用是否包含 dev.proxyaudit.android；HTTP/SOCKS 模式与 VPN 标签不同，此现象不能证明代理关闭或请求直连。")
                if (initial?.networkId == null) add("Android 未提供本应用默认网络。请先确认 Wi-Fi 或移动网络已连接，再检查本应用是否允许联网并重试；此现象不能证明代理客户端关闭。")
                fun usable(o: RawDnsObservation?) = o?.execution == Execution.COMPLETED && o.failure == null &&
                    o.responseCode == 0 && !o.truncated && o.addresses.any { NumericIp.canonical(it) != null }
                val expected = DnsRecordType.entries.flatMap { type -> DnsTransport.entries.map { type to it } }.toSet()
                if (reason == null && dns.size == 4 && dns.map { it.recordType to it.observation.transport }.toSet() == expected &&
                    dns.all { usable(it.observation) }) {
                    add("当前 DNS 的 A/AAAA、UDP/TCP 四项均取得地址；有地址仍不证明 DNS 保密或网站功能正常。")
                    site?.stages?.firstOrNull { it.status == WebsiteStageStatus.FAILED }?.let {
                        if (site?.attempts?.drop(1)?.any { attempt -> attempt.execution == Execution.COMPLETED && attempt.failure == null } == true) {
                            val stage = when (it.stage) {
                                WebsiteStage.DNS -> "DNS 解析"; WebsiteStage.CONNECT -> "连接"
                                WebsiteStage.TLS -> "TLS"; WebsiteStage.HTTP -> "HTTP"; WebsiteStage.BODY -> "正文读取"
                            }
                            add("网站首次在${stage}阶段失败，附加复核成功。先保持相同网址、网络与代理配置复测稳定性；不能据此认定该阶段持续失败、已修复或网站全部功能正常。")
                        } else add(when (it.stage) {
                            WebsiteStage.DNS -> "网站 DNS 阶段仍失败：请先比较系统解析与原始查询使用的解析方式和域名，核对 Private DNS 与客户端 DNS 接管；不要仅凭原始查询成功更换所有 DNS。"
                            WebsiteStage.CONNECT -> "网站连接阶段失败：优先检查代理节点、目标端口与 IPv4/IPv6 连接条件，DNS 已返回地址不是连接成功。"
                            WebsiteStage.TLS -> "网站 TLS 阶段失败：优先核对设备时间、证书与服务器名称；不要关闭证书校验来绕过错误。"
                            WebsiteStage.HTTP -> "网站 HTTP 阶段失败：优先查看状态码和代理/服务端响应；先核对目标服务可用性，再判断是否涉及 DNS。"
                            WebsiteStage.BODY -> "网站响应正文阶段失败：优先检查读取超时、链路稳定性和服务端行为；已有 DNS 地址不足以解释该阶段失败。"
                        })
                    }
                }
                if (plan == null) add(if (reason == null) "本次仅做本机环境与回环检查，没有访问外部网站或发送原始 DNS 查询。"
                    else "本次计划仅含本机检查，且未全部完成；未访问外部网站或发送原始 DNS 查询。")
            }.distinct()
            val observed = DeepReport(run.id, run.startedAt, expectedProxy, before, after, self, site, rawServer,
                dns.toList(), reason, findings, plannedWebsite = plan)
            val frozen = observed.copy(findings = (DeepReportAnalysis.findings(observed) + findings).distinct())
            synchronized(lock) {
                if (active === run) {
                    report = frozen; active = null; busy = false
                    status = when {
                        backend.websitePending() -> "报告已冻结；系统解析仍在释放，暂不能启动新网络实验。"
                        reason != null -> "本次已停止或条件改变；已保留部分证据，未执行项目不代表通过。"
                        else -> "检查完成：查看分层观察与下一步。"
                    }
                }
            }
            notifyChanged()
        }
    }
    private fun conditionsChanged(before: NetworkInventoryReport?, after: NetworkInventoryReport?): Boolean {
        if (before == null || after == null) return true
        fun condition(value: NetworkInventoryReport): List<Any?> {
            val network = value.networks.singleOrNull { it.isDefault }
            return listOf(value.activeNetworkId, value.boundNetworkId, value.defaultProxy,
                network?.transports, network?.capabilities, network?.interfaceName, network?.addresses,
                network?.routes, network?.dnsServers, network?.mtu, network?.privateDnsActive,
                network?.privateDnsServerName, network?.httpProxy)
        }
        return condition(before) != condition(after)
    }
    fun reserveRestoredExportCode(code: Int) = synchronized(lock) {
        if (code in 0..65535) nextExportCode = maxOf(nextExportCode, code + 1)
    }
    /** No collection is performed here. The UI must confirm the frozen plan before calling start. */
    fun retestPlan(): DeepRetestPlan? = synchronized(lock) {
        if (busy) return null
        val source = baseline ?: report ?: return null
        if (DeepReportComparisons.baselineBlockers(source).isNotEmpty()) return null
        DeepRetestPlan(source.plannedWebsite, source.expectedProxy, source.dnsServer, source.id, baseline != null)
    }
    fun saveBaseline(): Boolean = synchronized(lock) {
        if (baselineSaveBlockers.isNotEmpty()) return false
        baseline = report
        notifyChanged()
        true
    }
    fun clearBaseline() {
        synchronized(lock) { if (busy) return; baseline = null }
        notifyChanged()
    }
    fun comparisonToJson(full: Boolean = false): String? = comparison?.toJson(full)
    fun freezeComparisonExport(full: Boolean = false): ExportTicket? = synchronized(lock) {
        if (busy || pendingExport != null || nextExportCode > 65535) return null
        val value = comparison ?: return null
        val ticket = ExportTicket(UUID.randomUUID().toString(), nextExportCode++,
            "network-comparison-${value.current.id.take(8)}-${if (full) "full" else "redacted"}.json")
        pendingExport = PendingExport(ticket, value.toJson(full))
        notifyChanged()
        ticket
    }
    fun freezeExport(full: Boolean = false): ExportTicket? = synchronized(lock) {
        if (busy || pendingExport != null || nextExportCode > 65535) return null
        val current = report ?: return null
        val ticket = ExportTicket(UUID.randomUUID().toString(), nextExportCode++,
            "network-deep-${current.id.take(8)}-${if (full) "full" else "redacted"}.json")
        pendingExport = PendingExport(ticket, current.toJson(full))
        notifyChanged()
        ticket
    }
    fun takeExport(id: String?): String? = synchronized(lock) {
        val pending = pendingExport ?: return null
        if (id != pending.ticket.id) return null
        pendingExport = null; notifyChanged()
        pending.payload
    }
    fun discardExport(id: String?) { takeExport(id) }
    fun clear() {
        synchronized(lock) { if (busy) return; report = null; status = "结果已清除；可以开始新的检查。" }
        notifyChanged()
    }
}
