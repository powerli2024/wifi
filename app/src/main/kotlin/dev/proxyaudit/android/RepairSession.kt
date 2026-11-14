package dev.proxyaudit.android

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import dev.proxyaudit.core.*
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

enum class CopyExportState {
    NONE, PLAN_READY, WRITING, VERIFYING, COPY_WRITTEN_UNVERIFIED,
    COPY_READBACK_VERIFIED, FAILED, CANCELLED_NO_WRITE, CANCELLED_WRITE_UNKNOWN
}
enum class CopyReadbackIssue { READ_UNAVAILABLE, CONTENT_MISMATCH, TOO_LARGE, INVALID_CONFIG, WRITE_FAILED, CANCELLED, ORIGINAL_PROTECTED, INVALID_TARGET }

/** In-memory evidence about one selected copy, never a client application acknowledgement. */
data class CopyEvidence(
    val exportId: String,
    val sourceSha256: String,
    val expectedSha256: String,
    val expectedByteCount: Int,
    val readbackSha256: String? = null,
    val readbackByteCount: Int? = null,
    val issue: CopyReadbackIssue? = null
)

/** All configuration content stays in the application process; pickers carry only opaque identities. */
class RepairSession(context: Context) {
    private val resolver = context.applicationContext.contentResolver
    private val main = Handler(Looper.getMainLooper())
    // The busy slot prevents a queue of provider jobs, including after cancellation. A provider may
    // block inside open/read/write/close: byte limits are not a guaranteed wall-clock I/O deadline.
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "config-repair").apply { isDaemon = true } }
    private val observers = CopyOnWriteArrayList<() -> Unit>()
    private var source: String? = null
    private var sourceUri: Uri? = null
    private var nextCode = 100
    private var pending: Pending? = null
    private var generation = 0
    private var active: Operation? = null
    data class Ticket(val id: String, val code: Int, val export: Boolean)
    private data class Pending(val ticket: Ticket, val frozenOutput: String?, val originalUri: Uri?, val sourceSha256: String?)
    private class Operation(val epoch: Int, val export: Boolean) {
        var cancelled = false
        var writeStarted = false
        var writeCompleted = false
    }
    private class OperationCancelled : Exception()
    private class TooLarge : Exception()
    @Volatile var inspection: ConfigInspection? = null; private set
    @Volatile var plan: ConfigRepairPlan? = null; private set
    @Volatile var busy = false; private set
    @Volatile var providerIndex = 0; private set
    @Volatile var exportState = CopyExportState.NONE; private set
    @Volatile var copyEvidence: CopyEvidence? = null; private set
    @Volatile var userReportedApplied = false; private set
    @Volatile var baselineRunId: String? = null; private set
    @Volatile var status = "选择 Mihomo / Clash.Meta 的完整 YAML 配置，在本机审查。"; private set
    val hasSource get() = synchronized(this) { source != null }
    val pickerPending get() = synchronized(this) { pending != null }
    /** Local recovery hint only; never serialized into Activity state, logs, or exported reports. */
    val sourceDocumentUri: Uri? get() = synchronized(this) { sourceUri }
    val canMarkUserReportedApplied get() = synchronized(this) {
        !busy && pending == null && exportState == CopyExportState.COPY_READBACK_VERIFIED && !userReportedApplied
    }
    fun observe(listener: () -> Unit) { observers.add(listener); listener() }
    fun removeObserver(listener: () -> Unit) { observers.remove(listener) }
    private fun notifyUi() { main.post { observers.forEach { it() } } }

    @Synchronized fun reserveCode(code: Int) { if (code in 0..65535) nextCode = maxOf(nextCode, code + 1) }
    @Synchronized fun beginImport(): Ticket? = begin(false)
    @Synchronized fun beginExport(): Ticket? {
        if (plan == null || plan!!.changes.isEmpty()) return null
        return begin(true)
    }
    private fun begin(export: Boolean): Ticket? {
        if (busy || pending != null || nextCode > 65535) return null
        val ticket = Ticket(UUID.randomUUID().toString(), nextCode++, export)
        pending = Pending(ticket, if (export) plan!!.repairedYaml else null, sourceUri, if (export) plan!!.sourceSha256 else null)
        if (export) resetCopy(CopyExportState.PLAN_READY)
        notifyUi()
        return ticket
    }
    @Synchronized fun cancel(id: String) {
        val item = pending?.takeIf { it.ticket.id == id } ?: return
        pending = null
        if (item.ticket.export) {
            exportState = CopyExportState.CANCELLED_NO_WRITE
            status = "已取消保存位置选择，未写入副本。"
        }
        notifyUi()
    }
    /** Cooperative cancellation: no new job starts until the provider operation actually returns. */
    @Synchronized fun cancelActive(): Boolean {
        val operation = active ?: return false
        if (operation.cancelled) return false
        operation.cancelled = true
        status = "已请求取消，正在等待当前文件操作返回；完成前不能开始另一项操作。"
        notifyUi()
        return true
    }
    /** The caller must supply the selected controller baseline; this stores identity, not proof. */
    @Synchronized fun associateBaseline(runId: String?): Boolean {
        if (busy || pending != null) return false
        if (!validBaselineId(runId)) return false
        baselineRunId = runId
        notifyUi()
        return true
    }
    @Synchronized fun markUserReportedApplied(): Boolean {
        if (!canMarkUserReportedApplied) return false
        userReportedApplied = true
        status = "已记录你手动导入此副本的确认；客户端生效状态未独立核验，运行效果尚未验证。可按关联基线主动复测。"
        notifyUi()
        return true
    }
    @Synchronized fun selectProvider(index: Int) {
        require(index in DnsProviders.public.indices)
        if (busy || pending != null || providerIndex == index) return
        providerIndex = index; plan = null
        invalidatePlanEvidence()
        status = "解析器方案已变更，请重新生成修改预览。"; notifyUi()
    }
    @Synchronized fun clear() {
        if (busy) return
        generation++
        source = null; sourceUri = null; inspection = null; plan = null; pending = null
        invalidatePlanEvidence()
        status = "已清除本进程中的配置、预览与手动确认，导出的文件不受影响。"; notifyUi()
    }
    /** A stale picker never writes a newer plan or reads a replacement selection. */
    @Synchronized fun accept(id: String, code: Int, uri: Uri): Boolean {
        val item = pending?.takeIf { it.ticket.id == id && it.ticket.code == code } ?: return false
        pending = null
        if (uri.scheme != "content") {
            if (item.ticket.export) rejectedExport(item, CopyReadbackIssue.INVALID_TARGET)
            status = "请选择系统文档提供者中的文件。"; notifyUi(); return true
        }
        if (item.ticket.export && sameDocument(uri, item.originalUri)) {
            rejectedExport(item, CopyReadbackIssue.ORIGINAL_PROTECTED)
            status = "拒绝覆盖原配置，请创建另一个文件。"; notifyUi(); return true
        }
        busy = true
        val operation = Operation(++generation, item.ticket.export)
        active = operation
        status = if (item.ticket.export) "正在保存修复副本…" else "正在读取并检查本地配置…"
        if (item.ticket.export) {
            exportState = CopyExportState.WRITING
            copyEvidence = evidenceFor(item)
        } else {
            source = null; sourceUri = null; inspection = null; plan = null
            invalidatePlanEvidence()
        }
        notifyUi()
        worker.execute {
            try {
                checkActive(operation)
                if (item.ticket.export) writeAndVerify(operation, item, uri)
                else {
                    val text = resolver.openInputStream(uri)?.use { decode(readBounded(it, operation)) }
                        ?: throw IllegalStateException()
                    checkActive(operation)
                    val checked = MihomoConfigDoctor.inspect(text)
                    finish(operation) {
                        source = text; sourceUri = uri; inspection = checked
                        status = "配置已读取，仅保留在当前进程中。请选择解析器方案并生成修改预览。"
                    }
                }
            } catch (_: OperationCancelled) {
                finish(operation) {}
            } catch (error: ConfigRejectedException) {
                finish(operation) { status = error.message ?: "配置未通过安全审查，原文件未修改。" }
            } catch (_: Exception) {
                // Provider/parser exceptions may contain URI, source text or credentials: never expose them.
                finish(operation) {
                    if (item.ticket.export) copyFailure(CopyReadbackIssue.WRITE_FAILED)
                    else status = "未能安全读取配置。需 UTF-8、单文档、256 KiB 以内的完整 Mihomo YAML；不支持重复键、锚点、合并和自定义标签。"
                }
            }
        }
        return true
    }
    private fun writeAndVerify(operation: Operation, item: Pending, uri: Uri) {
        val bytes = (item.frozenOutput ?: throw IllegalStateException()).toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_BYTES)
        synchronized(this) {
            checkActive(operation)
            // Opening in truncation mode may itself change the target, even before the first write.
            operation.writeStarted = true
        }
        resolver.openOutputStream(uri, "wt")?.use { output ->
            checkActive(operation)
            output.write(bytes)
        } ?: throw IllegalStateException()
        synchronized(this) {
            operation.writeCompleted = true
            checkActive(operation)
            exportState = CopyExportState.VERIFYING
            status = "副本写入完成，正在读回核对内容；尚未确认客户端导入。"
            notifyUi()
        }
        try {
            val actual = resolver.openInputStream(uri)?.use { readBounded(it, operation) }
                ?: throw IllegalStateException()
            checkActive(operation)
            val actualSha = sha256(actual)
            val expectedSha = sha256(bytes)
            if (actual.size != bytes.size || actualSha != expectedSha) {
                finish(operation) {
                    copyEvidence = copyEvidence?.copy(readbackSha256 = actualSha, readbackByteCount = actual.size)
                    copyFailure(CopyReadbackIssue.CONTENT_MISMATCH)
                }
                return
            }
            // The memory plan was already checked, but re-parse the bytes returned by the provider.
            MihomoConfigDoctor.inspect(decode(actual))
            finish(operation) {
                exportState = CopyExportState.COPY_READBACK_VERIFIED
                copyEvidence = copyEvidence?.copy(readbackSha256 = actualSha, readbackByteCount = actual.size)
                status = "副本已读回核对，字节摘要与冻结方案一致；尚未确认导入客户端，运行效果尚未验证。"
            }
        } catch (error: OperationCancelled) {
            throw error
        } catch (_: TooLarge) {
            finish(operation) { copyFailure(CopyReadbackIssue.TOO_LARGE) }
        } catch (_: ConfigRejectedException) {
            finish(operation) { copyFailure(CopyReadbackIssue.INVALID_CONFIG) }
        } catch (_: Exception) {
            finish(operation) {
                exportState = CopyExportState.COPY_WRITTEN_UNVERIFIED
                copyEvidence = copyEvidence?.copy(issue = CopyReadbackIssue.READ_UNAVAILABLE)
                status = "副本已写入，但提供者未允许或未完成读回，内容未核实。请先自行核对或重新导出；运行效果尚未验证。"
            }
        }
    }
    @Synchronized fun generate(baselineRunId: String? = null): Boolean {
        val frozenSource = source ?: return false
        if (busy || pending != null || !validBaselineId(baselineRunId)) return false
        val provider = DnsProviders.public[providerIndex]
        busy = true; plan = null; invalidatePlanEvidence()
        status = "正在生成并核对内存中的 DNS 修改…"
        val operation = Operation(++generation, false)
        active = operation
        notifyUi()
        worker.execute {
            try {
                checkActive(operation)
                val generated = MihomoConfigDoctor.repair(frozenSource, provider)
                finish(operation) {
                    plan = generated; exportState = CopyExportState.PLAN_READY
                    this.baselineRunId = baselineRunId
                    status = if (generated.changes.isEmpty()) "此方案没有需要修改的字段。仍需在客户端验证运行效果。"
                        else "修改预览已生成，尚未写入文件或应用到代理客户端。"
                }
            } catch (_: OperationCancelled) {
                finish(operation) {}
            } catch (error: ConfigRejectedException) {
                finish(operation) { status = error.message ?: "配置无法安全自动修改，原文件未修改。" }
            } catch (_: Exception) {
                finish(operation) { status = "此配置无法安全自动修改。可能存在不支持的 DNS 结构、H3 路由冲突或语义歧义；请保留原文件并使用专业方式调整。" }
            }
        }
        return true
    }
    @Synchronized private fun checkActive(operation: Operation) {
        if (active !== operation || operation.epoch != generation || operation.cancelled) throw OperationCancelled()
    }
    @Synchronized private fun finish(operation: Operation, update: () -> Unit) {
        if (active !== operation || operation.epoch != generation) return
        if (operation.cancelled) {
            if (operation.export) {
                exportState = if (operation.writeCompleted) CopyExportState.COPY_WRITTEN_UNVERIFIED
                    else if (operation.writeStarted) CopyExportState.CANCELLED_WRITE_UNKNOWN else CopyExportState.CANCELLED_NO_WRITE
                copyEvidence = copyEvidence?.copy(issue = CopyReadbackIssue.CANCELLED)
                status = if (operation.writeCompleted) "已取消核对；副本已写入但读回未确认，请先核对内容，运行效果尚未验证。"
                    else if (operation.writeStarted) "已取消保存；目标可能留下不完整副本，请不要导入，原配置未主动修改。"
                    else "已取消保存，未开始写入副本。"
            } else status = "操作已取消，未生成新的配置或预览；原文件未修改。"
        } else update()
        active = null; busy = false; notifyUi()
    }
    private fun evidenceFor(item: Pending): CopyEvidence {
        val bytes = (item.frozenOutput ?: "").toByteArray(Charsets.UTF_8)
        return CopyEvidence(item.ticket.id, item.sourceSha256 ?: "", sha256(bytes), bytes.size)
    }
    private fun rejectedExport(item: Pending, issue: CopyReadbackIssue) {
        exportState = CopyExportState.FAILED
        copyEvidence = evidenceFor(item).copy(issue = issue)
    }
    private fun copyFailure(issue: CopyReadbackIssue) {
        exportState = CopyExportState.FAILED
        copyEvidence = copyEvidence?.copy(issue = issue)
        status = "副本保存或核对失败；目标可能包含截断或不一致的内容。请勿导入此副本，重新导出到新文件；原配置未主动修改。"
    }
    private fun resetCopy(state: CopyExportState = CopyExportState.NONE) {
        exportState = state; copyEvidence = null; userReportedApplied = false
    }
    private fun invalidatePlanEvidence() { resetCopy(); baselineRunId = null }
    private fun validBaselineId(value: String?) = value == null || value.matches(Regex("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"))
    private fun readBounded(input: InputStream, operation: Operation): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            checkActive(operation)
            // Read at most MAX_BYTES + 1, including the one byte needed to detect oversize content.
            val count = input.read(buffer, 0, minOf(buffer.size, MAX_BYTES + 1 - output.size()))
            checkActive(operation)
            if (count < 0) break
            if (count == 0) {
                val one = input.read()
                checkActive(operation)
                if (one < 0) break
                output.write(one)
            } else output.write(buffer, 0, count)
            if (output.size() > MAX_BYTES) throw TooLarge()
        }
        return output.toByteArray()
    }
    private fun decode(bytes: ByteArray) = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun sameDocument(a: Uri, b: Uri?): Boolean {
        if (b == null) return false
        if (a == b) return true
        return try { a.authority == b.authority && DocumentsContract.getDocumentId(a) == DocumentsContract.getDocumentId(b) }
        catch (_: Exception) { false }
    }
    companion object { const val MAX_BYTES = 256 * 1024 }
}
