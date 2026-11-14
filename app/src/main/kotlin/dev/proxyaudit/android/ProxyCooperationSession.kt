package dev.proxyaudit.android

import android.os.Handler
import android.os.Looper
import dev.proxyaudit.core.*
import org.json.JSONObject
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Executors

internal interface ProxyCooperationOperation : AutoCloseable { fun execute(): ProxyCooperationReport }
internal interface ProxyCooperationBackend {
    fun unavailable(): Boolean
    fun operation(plan: ProxyCooperationPlan): ProxyCooperationOperation
}
private class AndroidProxyCooperationBackend(private val app: DiagnosticsApplication) : ProxyCooperationBackend {
    override fun unavailable() = app.controller.busy || app.deepDiagnostics.busy ||
        WebsiteDiagnostics.hasPendingWork() || ProxyCooperationProbe.hasPendingWork()
    override fun operation(plan: ProxyCooperationPlan): ProxyCooperationOperation {
        val probe = ProxyCooperationProbe(plan)
        return object : ProxyCooperationOperation {
            override fun execute() = probe.execute()
            override fun close() = probe.close()
        }
    }
}

data class ProxyCooperationRecord(val id: String, val startedAt: String, val appVersion: String,
                                  val result: ProxyCooperationReport) {
    fun toJson(): String = JSONObject().apply {
        put("reportKind", "PROXY_READ_ONLY_COOPERATION"); put("schemaVersion", 1)
        put("runId", id); put("startedAtUtc", startedAt); put("appVersion", appVersion)
        put("evidenceEnvelope", JSONObject(EvidenceEnvelope.toJson("PROXY_READ_ONLY_COOPERATION", appVersion,
            id, "ANDROID_RUNTIME_USER_DECLARED_API", "USER_DECLARED_PROXY_API_SNAPSHOT",
            result.requests.map { "PROXY_API_GET${it.path}" }, result.execution == Execution.CANCELLED)))
        put("apiSnapshot", JSONObject(result.toJson()))
    }.toString(2)
}

/** Retains no credential drafts or raw responses. Starting always requires an explicit plan. */
class ProxyCooperationSession internal constructor(private val backend: ProxyCooperationBackend) {
    constructor(app: DiagnosticsApplication) : this(AndroidProxyCooperationBackend(app))
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "proxy-cooperation-session").apply { isDaemon = true } }
    private val observers = java.util.concurrent.CopyOnWriteArraySet<() -> Unit>()
    private var active: ProxyCooperationOperation? = null
    @Volatile var busy = false; private set
    @Volatile var record: ProxyCooperationRecord? = null; private set
    @Volatile var status = "未连接。填写代理提供的 HTTPS 控制 API，再确认读取。"; private set
    var endpointDraft = ""
    data class ExportTicket(val id: String, val requestCode: Int, val suggestedName: String)
    private var export: Pair<ExportTicket, String>? = null
    private var nextRequestCode = 18000

    fun observe(listener: () -> Unit) { observers.add(listener); listener() }
    fun removeObserver(listener: () -> Unit) { observers.remove(listener) }
    private fun notifyChanged() { main.post { observers.forEach { it() } } }

    @Synchronized fun start(plan: ProxyCooperationPlan): Boolean {
        if (busy || backend.unavailable()) return false
        val operation = try { backend.operation(plan) } catch (_: Exception) {
            status = "无法建立只读操作，未保存凭据。"; notifyChanged(); return false
        }
        val id = UUID.randomUUID().toString(); val started = Instant.now().toString(); val version = AppIdentity.version
        active = operation; busy = true; record = null
        status = "读取版本和连接快照；最多 15 秒，可取消。"; notifyChanged()
        worker.execute {
            val result = try { operation.execute() } catch (_: Exception) { null }
            finally { runCatching { operation.close() } }
            synchronized(this) {
                active = null; busy = false
                record = result?.let { ProxyCooperationRecord(id, started, version, it) }
                status = result?.summary ?: "读取未完成：内部操作错误。未保留异常正文，请检查端点后重试。"
            }
            notifyChanged()
        }
        return true
    }
    @Synchronized fun cancel() {
        active?.close(); if (busy) status = "正在取消只读请求。"; notifyChanged()
    }
    @Synchronized fun clear(): Boolean {
        if (busy) { cancel(); return false }
        record = null; endpointDraft = ""; export = null
        status = "已清除进程内连接信息与报告。"; notifyChanged(); return true
    }
    @Synchronized fun freezeExport(): ExportTicket? {
        val frozen = record ?: return null
        if (busy || nextRequestCode >= 30000) return null
        val ticket = ExportTicket(UUID.randomUUID().toString(), nextRequestCode++, "proxy-cooperation-${frozen.id.take(8)}-redacted.json")
        export = ticket to frozen.toJson(); return ticket
    }
    @Synchronized fun takeExport(id: String): String? {
        val pending = export ?: return null
        if (pending.first.id != id) return null
        export = null; return pending.second
    }
    @Synchronized fun discardExport(id: String?) { if (export?.first?.id == id) export = null }
    @Synchronized fun hasExport(id: String?): Boolean = id != null && export?.first?.id == id
    @Synchronized fun reserveRestoredExportCode(code: Int) {
        if (code in 18000..29999) nextRequestCode = maxOf(nextRequestCode, code + 1)
    }
}
