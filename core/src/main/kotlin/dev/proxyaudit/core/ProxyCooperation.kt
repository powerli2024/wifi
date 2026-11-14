package dev.proxyaudit.core

import okhttp3.Authenticator
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.cert.CertificateException
import java.security.cert.CertPathValidatorException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLPeerUnverifiedException

/** Explicit user-supplied HTTPS origin. Credentials stay in memory and never enter a report. */
class ProxyCooperationPlan private constructor(internal val origin: HttpUrl, private val secret: String) {
    internal fun authorization(): String? = secret.takeIf { it.isNotEmpty() }?.let { "Bearer $it" }
    internal fun safe(value: String, max: Int = 256): String {
        val scrubbed = if (secret.isEmpty()) value else value.replace(secret, "[REDACTED_SECRET]")
        // Metadata is a small allowlist, never response bodies, headers, URLs or rule payloads.
        if (scrubbed.any { it.isISOControl() } || scrubbed.contains(Regex("(?i)(authorization|password|passwd|token|secret)\\s*[:=]")) ||
            scrubbed.contains(Regex("(?i)[a-z][a-z0-9+.-]*://.*@"))) return "[REDACTED_UNSAFE_METADATA]"
        return if (scrubbed.length > max) scrubbed.take(max) + "…" else scrubbed
    }
    override fun toString() = "ProxyCooperationPlan(endpoint=[REDACTED], credentials=[REDACTED])"
    companion object {
        fun parse(endpoint: String, secret: String = ""): ProxyCooperationPlan {
            require(endpoint.length <= 2048 && endpoint.isNotBlank() &&
                endpoint.none { it.isWhitespace() || it.isISOControl() || it == '\\' }) { "请输入显式 HTTPS 来源地址，不含空白、凭据或路径" }
            require(secret.length <= 4096 && secret.all { it.code in 33..126 }) { "Secret 必须是至多 4096 个可打印 ASCII 字符，不含空白" }
            val uri = try { URI(endpoint) } catch (_: Exception) { throw IllegalArgumentException("代理 API 地址格式不正确") }
            require(uri.scheme.equals("https", true) && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null &&
                uri.rawPath.orEmpty() in listOf("", "/") && uri.rawAuthority != null && '@' !in uri.rawAuthority &&
                uri.port != 0 && !uri.rawAuthority.endsWith(":")) { "只接受 HTTPS origin，不得包含凭据、路径、查询参数或片段" }
            val url = endpoint.toHttpUrlOrNull() ?: throw IllegalArgumentException("代理 API 地址格式不正确")
            require(url.isHttps && url.username.isEmpty() && url.password.isEmpty() && url.host.isNotEmpty()) { "代理 API 地址格式不正确" }
            return ProxyCooperationPlan(url, secret)
        }
    }
}

enum class ProxyCooperationFailure {
    UNAUTHORIZED, FORBIDDEN, NOT_FOUND, HTTP_ERROR, NON_JSON, RESPONSE_TOO_LARGE,
    MISSING_FIELD, INVALID_JSON, DUPLICATE_CONNECTION_ID, TLS_CERTIFICATE, TLS_PEER_IDENTITY,
    TIMEOUT, TOTAL_TIMEOUT, CANCELLED, BUSY, IO_FAILURE, INTERNAL_ERROR
}

data class ProxyRequestResult(val path: String, val execution: Execution, val failure: ProxyCooperationFailure?,
                              val statusCode: Int?, val durationMillis: Long, val bodyBytesRead: Int)

data class ProxyConnectionMetadata(
    val id: String, val network: String?, val type: String?, val sourceIp: String?, val sourcePort: Int?,
    val destinationIp: String?, val destinationPort: Int?, val host: String?, val chains: List<String>, val rule: String?
) {
    override fun toString() = "ProxyConnectionMetadata(identifiers=[REDACTED])"
}

data class ProxyCooperationReport(
    val endpointOrigin: String, val execution: Execution, val failure: ProxyCooperationFailure?, val durationMillis: Long,
    val backendVersion: String?, val connectionCount: Int?, val connections: List<ProxyConnectionMetadata>,
    val sampleIncomplete: Boolean, val requests: List<ProxyRequestResult>, val summary: String,
    val nextSteps: List<String>, val limitations: List<String>
) {
    override fun toString(): String = toText()
    fun toJson(includeIdentifiers: Boolean = false): String {
        fun identifier(value: String?) = value?.let { if (includeIdentifiers) it else "[REDACTED]" }
        return Json.write(linkedMapOf("schemaVersion" to 1, "scope" to "READ_ONLY_USER_DECLARED_PROXY_API",
            "sourceDeclaration" to "USER_DECLARED_ENDPOINT", "association" to "NOT_CORRELATED_WITH_THIS_APP",
            "proxyPathVerified" to false, "identifiersIncluded" to includeIdentifiers,
            "endpointOrigin" to identifier(endpointOrigin), "execution" to execution.name, "failure" to failure?.name,
            "durationMillis" to durationMillis, "backendVersion" to identifier(backendVersion),
            "connectionCount" to connectionCount, "sampleCount" to connections.size, "sampleIncomplete" to sampleIncomplete,
            "requestTimeoutMillis" to ProxyCooperationProbe.REQUEST_TIMEOUT_MILLIS,
            "totalTimeoutMillis" to ProxyCooperationProbe.TOTAL_TIMEOUT_MILLIS,
            "responseLimitBytes" to ProxyCooperationProbe.RESPONSE_LIMIT_BYTES,
            "redirectsFollowed" to false, "libraryRetriesEnabled" to false, "rawJsonIncluded" to false,
            "requests" to requests.map { linkedMapOf("path" to it.path, "execution" to it.execution.name,
                "failure" to it.failure?.name, "statusCode" to it.statusCode, "durationMillis" to it.durationMillis,
                "bodyBytesRead" to it.bodyBytesRead) },
            "connections" to connections.map { linkedMapOf("id" to identifier(it.id), "network" to identifier(it.network),
                "type" to identifier(it.type), "sourceIp" to identifier(it.sourceIp), "sourcePort" to if (includeIdentifiers) it.sourcePort else null,
                "destinationIp" to identifier(it.destinationIp), "destinationPort" to if (includeIdentifiers) it.destinationPort else null,
                "host" to identifier(it.host), "chains" to it.chains.map(::identifier), "rule" to identifier(it.rule)) },
            "summary" to summary, "nextSteps" to nextSteps, "limitations" to limitations)) + "\n"
    }
    fun toText(includeIdentifiers: Boolean = false): String = buildString {
        appendLine(summary)
        appendLine("来源：用户明确提供的代理只读 API；来源地址：${if (includeIdentifiers) endpointOrigin else "[已隐藏]"}")
        appendLine("执行：${execution.name}；失败类型：${failure?.name ?: "无"}；耗时：${durationMillis} ms")
        appendLine("后端版本：${if (includeIdentifiers) backendVersion ?: "未取得" else if (backendVersion == null) "未取得" else "已取得（已隐藏）"}")
        appendLine("快照连接数：${connectionCount ?: "未取得"}；保留样本：${connections.size}；采样不完整：$sampleIncomplete")
        requests.forEach { appendLine("GET ${it.path}：${it.execution.name}；HTTP ${it.statusCode ?: "未取得"}；${it.durationMillis} ms；${it.failure?.name ?: "无失败"}") }
        if (includeIdentifiers) connections.forEach {
            appendLine("连接 ${it.id}：${it.network ?: "?"}/${it.type ?: "?"}；${it.sourceIp ?: "?"}:${it.sourcePort ?: "?"} → ${it.destinationIp ?: "?"}:${it.destinationPort ?: "?"}；主机 ${it.host ?: "?"}；链 ${it.chains.joinToString(" → ")}；规则 ${it.rule ?: "?"}")
        }
        appendLine("下一步：")
        nextSteps.forEach { appendLine("• $it") }
        appendLine("解释边界：")
        limitations.forEach { appendLine("• $it") }
    }
}

/** Single global worker bounds even a platform resolver which ignores cancellation. */
class ProxyCooperationProbe internal constructor(private val plan: ProxyCooperationPlan, private val baseClient: OkHttpClient) : AutoCloseable {
    constructor(plan: ProxyCooperationPlan) : this(plan, OkHttpClient())
    private val started = AtomicBoolean()
    private val closed = AtomicBoolean()
    private val activeCall = AtomicReference<Call?>()
    private val wake = CountDownLatch(1)
    private val state = State()
    @Volatile private var requestDeadline = Long.MAX_VALUE
    @Volatile private var totalDeadline = Long.MAX_VALUE

    fun execute(): ProxyCooperationReport {
        check(started.compareAndSet(false, true)) { "每个代理协同计划只能执行一次" }
        val start = System.nanoTime()
        totalDeadline = start + TimeUnit.MILLISECONDS.toNanos(TOTAL_TIMEOUT_MILLIS.toLong())
        if (closed.get()) return state.freeze(start, ProxyCooperationFailure.CANCELLED)
        if (cleanupBusy.get() || !workerBusy.compareAndSet(false, true)) return state.freeze(start, ProxyCooperationFailure.BUSY)
        try {
            worker.execute {
                try { runRequests() }
                catch (error: Exception) { state.fail(if (closed.get()) ProxyCooperationFailure.CANCELLED else classifyProxyFailure(error)) }
                finally { activeCall.set(null); workerBusy.set(false); state.done(); wake.countDown() }
            }
        } catch (_: RuntimeException) {
            workerBusy.set(false)
            return state.freeze(start, ProxyCooperationFailure.BUSY)
        }
        var stop: ProxyCooperationFailure? = null
        while (!state.isDone()) {
            stop = when {
                closed.get() -> ProxyCooperationFailure.CANCELLED
                System.nanoTime() >= totalDeadline -> ProxyCooperationFailure.TOTAL_TIMEOUT
                System.nanoTime() >= requestDeadline -> ProxyCooperationFailure.TIMEOUT
                else -> null
            }
            if (stop != null) break
            try { wake.await(10, TimeUnit.MILLISECONDS) }
            catch (_: InterruptedException) { Thread.currentThread().interrupt(); stop = ProxyCooperationFailure.CANCELLED; break }
        }
        val report = state.freeze(start, stop)
        if (stop != null) close()
        return report
    }

    override fun close() {
        closed.set(true)
        wake.countDown()
        val call = activeCall.get() ?: return
        if (cleanupBusy.compareAndSet(false, true)) {
            try { cleanup.execute { try { call.cancel() } finally { cleanupBusy.set(false) } } }
            catch (_: RuntimeException) { cleanupBusy.set(false) }
        }
    }

    private fun checkRunning() {
        if (closed.get()) throw ProbeFailure(ProxyCooperationFailure.CANCELLED)
        if (System.nanoTime() >= totalDeadline) throw ProbeFailure(ProxyCooperationFailure.TOTAL_TIMEOUT)
        if (System.nanoTime() >= requestDeadline) throw ProbeFailure(ProxyCooperationFailure.TIMEOUT)
    }

    private fun runRequests() {
        val pool = ConnectionPool(1, 1, TimeUnit.SECONDS)
        try {
            val client = baseClient.newBuilder().connectionPool(pool).cache(null).cookieJar(CookieJar.NO_COOKIES)
                .authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
                .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
                .callTimeout(REQUEST_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
                .connectTimeout(REQUEST_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
                .readTimeout(REQUEST_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
                .writeTimeout(REQUEST_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS).build()
            for (path in listOf("/version", "/connections")) {
                checkRunning()
                requestDeadline = minOf(totalDeadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(REQUEST_TIMEOUT_MILLIS.toLong()))
                state.begin(path)
                try {
                    val builder = Request.Builder().url(plan.origin.newBuilder().encodedPath(path).build()).get()
                        .header("Accept", "application/json").header("Accept-Encoding", "identity")
                        .header("Cache-Control", "no-store").header("User-Agent", "ProxyAudit-ReadOnly-Cooperation/1")
                    plan.authorization()?.let { builder.header("Authorization", it) }
                    val sent = AtomicBoolean()
                    val strictClient = client.newBuilder().addNetworkInterceptor { chain ->
                        if (!sent.compareAndSet(false, true)) throw IOException("Repeated request disabled")
                        val response = chain.proceed(chain.request())
                        // OkHttp may otherwise follow 503 Retry-After: 0 despite retryOnConnectionFailure(false).
                        if (response.code == 503) response.newBuilder().header("Retry-After", "86400").build() else response
                    }.build()
                    val call = strictClient.newCall(builder.build())
                    activeCall.set(call)
                    checkRunning()
                    call.execute().use { response ->
                        checkRunning()
                        state.status(response.code)
                        if (response.code != 200) throw ProbeFailure(when (response.code) {
                            401 -> ProxyCooperationFailure.UNAUTHORIZED
                            403 -> ProxyCooperationFailure.FORBIDDEN
                            404 -> ProxyCooperationFailure.NOT_FOUND
                            else -> ProxyCooperationFailure.HTTP_ERROR
                        })
                        val contentType = response.header("Content-Type")?.substringBefore(';')?.trim()?.lowercase()
                        if (contentType != null && contentType != "application/json" && !(contentType.startsWith("application/") && contentType.endsWith("+json")))
                            throw ProbeFailure(ProxyCooperationFailure.NON_JSON)
                        val body = response.body ?: throw ProbeFailure(ProxyCooperationFailure.NON_JSON)
                        if (body.contentLength() > RESPONSE_LIMIT_BYTES) throw ProbeFailure(ProxyCooperationFailure.RESPONSE_TOO_LARGE)
                        val bytes = ByteArrayOutputStream()
                        body.byteStream().use { input ->
                            val buffer = ByteArray(4096)
                            while (true) {
                                checkRunning()
                                if (bytes.size() == RESPONSE_LIMIT_BYTES) {
                                    if (body.contentLength() == RESPONSE_LIMIT_BYTES.toLong()) break
                                    throw ProbeFailure(ProxyCooperationFailure.RESPONSE_TOO_LARGE)
                                }
                                val n = input.read(buffer, 0, minOf(buffer.size, RESPONSE_LIMIT_BYTES - bytes.size()))
                                checkRunning()
                                if (n == -1) break
                                bytes.write(buffer, 0, n)
                                state.bytes(bytes.size())
                            }
                        }
                        val text = try { Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes.toByteArray())).toString() }
                        catch (_: Exception) { throw ProbeFailure(ProxyCooperationFailure.INVALID_JSON) }
                        val root = BoundedJson(text, ::checkRunning).parse() as? Map<*, *> ?: throw ProbeFailure(ProxyCooperationFailure.NON_JSON)
                        if (path == "/version") {
                            val version = root["version"] as? String
                            if (version.isNullOrBlank()) throw ProbeFailure(ProxyCooperationFailure.MISSING_FIELD)
                            state.version(plan.safe(version, 128))
                        } else parseConnections(root)
                    }
                    checkRunning()
                    state.finish()
                } catch (error: Exception) {
                    state.fail(when {
                        closed.get() -> ProxyCooperationFailure.CANCELLED
                        System.nanoTime() >= totalDeadline -> ProxyCooperationFailure.TOTAL_TIMEOUT
                        System.nanoTime() >= requestDeadline -> ProxyCooperationFailure.TIMEOUT
                        else -> classifyProxyFailure(error)
                    })
                    return
                } finally { activeCall.set(null); requestDeadline = Long.MAX_VALUE }
            }
        } finally { pool.evictAll() }
    }

    private fun parseConnections(root: Map<*, *>) {
        if (!root.containsKey("connections")) throw ProbeFailure(ProxyCooperationFailure.MISSING_FIELD)
        // Clash-family implementations may encode an empty slice as null.
        val rows = root["connections"]?.let { it as? List<*> ?: throw ProbeFailure(ProxyCooperationFailure.INVALID_JSON) } ?: emptyList<Any?>()
        val ids = HashSet<String>()
        val samples = mutableListOf<ProxyConnectionMetadata>()
        for (row in rows) {
            checkRunning()
            val connection = row as? Map<*, *> ?: throw ProbeFailure(ProxyCooperationFailure.INVALID_JSON)
            val id = connection["id"] as? String
            if (id.isNullOrBlank()) throw ProbeFailure(ProxyCooperationFailure.MISSING_FIELD)
            if (!ids.add(id)) throw ProbeFailure(ProxyCooperationFailure.DUPLICATE_CONNECTION_ID)
            if (samples.size >= SAMPLE_LIMIT) continue
            val metadata = connection["metadata"] as? Map<*, *> ?: emptyMap<Any?, Any?>()
            fun field(vararg keys: String): String? = keys.firstNotNullOfOrNull { key -> (metadata[key] as? String)?.let { plan.safe(it) } }
            fun port(vararg keys: String): Int? = keys.firstNotNullOfOrNull { key -> when (val value = metadata[key]) {
                is JsonNumber -> value.text.toIntOrNull()
                is String -> value.toIntOrNull()
                else -> null
            }?.takeIf { it in 0..65535 } }
            val chains = (connection["chains"] as? List<*>)?.take(16)?.mapNotNull { (it as? String)?.let(plan::safe) } ?: emptyList()
            samples += ProxyConnectionMetadata(plan.safe(id), field("network"), field("type"), field("sourceIP", "sourceIp"),
                port("sourcePort"), field("destinationIP", "destinationIp"), port("destinationPort"), field("host"), chains,
                (connection["rule"] as? String)?.let(plan::safe))
        }
        state.connections(rows.size, samples)
    }

    private inner class State {
        private var done = false
        private var frozen = false
        private var version: String? = null
        private var count: Int? = null
        private var samples = emptyList<ProxyConnectionMetadata>()
        private val requests = mutableListOf<ProxyRequestResult>()
        private var currentPath: String? = null
        private var currentStart = 0L
        private var currentStatus: Int? = null
        private var bytes = 0
        private var failure: ProxyCooperationFailure? = null
        @Synchronized fun begin(path: String) { if (!frozen) { currentPath = path; currentStart = System.nanoTime(); currentStatus = null; bytes = 0 } }
        @Synchronized fun status(code: Int) { if (!frozen) currentStatus = code }
        @Synchronized fun bytes(value: Int) { if (!frozen) bytes = value }
        @Synchronized fun version(value: String) { if (!frozen) version = value }
        @Synchronized fun connections(value: Int, items: List<ProxyConnectionMetadata>) { if (!frozen) { count = value; samples = items.toList() } }
        @Synchronized fun finish() { if (!frozen) end(null) }
        @Synchronized fun fail(value: ProxyCooperationFailure) { if (!frozen) { failure = value; end(value) } }
        @Synchronized fun done() { done = true }
        @Synchronized fun isDone() = done
        private fun end(value: ProxyCooperationFailure?) {
            currentPath?.let { requests += ProxyRequestResult(it, proxyExecution(value), value, currentStatus,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - currentStart), bytes) }
            currentPath = null
        }
        @Synchronized fun freeze(start: Long, stop: ProxyCooperationFailure?): ProxyCooperationReport {
            if (!frozen) { if (stop != null) failure = stop; end(failure); frozen = true }
            val actual = failure
            val summary = if (actual == null) "已取得代理 API 的版本与连接快照；尚未验证本应用的代理路径"
                else "代理只读协同未完整完成：${proxyFailureLabel(actual)}"
            return ProxyCooperationReport(plan.safe(plan.origin.toString().removeSuffix("/")), proxyExecution(actual), actual,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start), version, count, samples.toList(),
                count != null && count!! > samples.size, requests.toList(), summary, proxyNextSteps(actual), listOf(
                    "来源由用户声明；TLS 验证仅确认所填写地址的服务器身份，不确认它就是待测代理核心。",
                    "API 连通不等于代理路径已验证；此快照尚未按连接、目标和时间关联本应用实验。",
                    "连接快照可能包含其他应用流量，且会随时间变化；最多保存 100 条、每条至多 16 个链名，字段长度有界。",
                    "只调用 GET /version 与 GET /connections，不调用测速、修改配置或断开连接接口；不保存原始 JSON、Secret 或响应头。",
                    "使用系统默认代理选择与平台 TLS；单项最多 3 秒、总预算 15 秒、每响应最多 256 KiB，不跟随跳转或自动重试。"))
        }
    }

    companion object {
        const val REQUEST_TIMEOUT_MILLIS = 3_000
        const val TOTAL_TIMEOUT_MILLIS = 15_000
        const val RESPONSE_LIMIT_BYTES = 256 * 1024
        const val SAMPLE_LIMIT = 100
        private val workerBusy = AtomicBoolean()
        private val cleanupBusy = AtomicBoolean()
        private val worker = executor("proxy-api-worker")
        private val cleanup = executor("proxy-api-cleanup")
        private fun executor(name: String) = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(1),
            { task -> Thread(task, name).apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
        fun hasPendingWork(): Boolean = workerBusy.get() || cleanupBusy.get()
    }
}

private fun proxyExecution(failure: ProxyCooperationFailure?) = when (failure) {
    null -> Execution.COMPLETED
    ProxyCooperationFailure.CANCELLED -> Execution.CANCELLED
    else -> Execution.ERROR
}
private class ProbeFailure(val kind: ProxyCooperationFailure) : Exception("代理只读实验失败")
private fun classifyProxyFailure(error: Exception): ProxyCooperationFailure {
    if (error is ProbeFailure) return error.kind
    val causes = generateSequence<Throwable>(error) { it.cause }.take(12).toList()
    return when {
        causes.any { it is CertificateException || it is CertPathValidatorException } -> ProxyCooperationFailure.TLS_CERTIFICATE
        causes.any { it is SSLPeerUnverifiedException } -> ProxyCooperationFailure.TLS_PEER_IDENTITY
        causes.any { it is SocketTimeoutException || it is InterruptedIOException } -> ProxyCooperationFailure.TIMEOUT
        else -> ProxyCooperationFailure.IO_FAILURE
    }
}
private fun proxyFailureLabel(value: ProxyCooperationFailure) = when (value) {
    ProxyCooperationFailure.UNAUTHORIZED -> "认证失败（401）"
    ProxyCooperationFailure.FORBIDDEN -> "访问被拒绝（403）"
    ProxyCooperationFailure.NOT_FOUND -> "接口不存在（404）"
    ProxyCooperationFailure.NON_JSON -> "响应不是 JSON"
    ProxyCooperationFailure.RESPONSE_TOO_LARGE -> "响应超过 256 KiB 上限"
    ProxyCooperationFailure.MISSING_FIELD -> "响应缺少必要字段"
    ProxyCooperationFailure.INVALID_JSON -> "响应结构无效或超过解析预算"
    ProxyCooperationFailure.DUPLICATE_CONNECTION_ID -> "连接 ID 重复，快照不可可靠关联"
    ProxyCooperationFailure.TLS_CERTIFICATE -> "证书信任验证失败"
    ProxyCooperationFailure.TLS_PEER_IDENTITY -> "TLS 主机名验证失败"
    ProxyCooperationFailure.TIMEOUT -> "单项 3 秒预算耗尽"
    ProxyCooperationFailure.TOTAL_TIMEOUT -> "总预算耗尽"
    ProxyCooperationFailure.CANCELLED -> "用户取消"
    ProxyCooperationFailure.BUSY -> "上一项代理协同仍在退出"
    ProxyCooperationFailure.HTTP_ERROR -> "收到不支持的 HTTP 状态"
    ProxyCooperationFailure.IO_FAILURE -> "连接或传输失败"
    ProxyCooperationFailure.INTERNAL_ERROR -> "本地执行失败"
}
private fun proxyNextSteps(value: ProxyCooperationFailure?): List<String> = when (value) {
    null -> listOf("结合网站诊断的目标、时间和代理连接元数据核对路径；本版不会将 API 可达自动判为代理已生效。")
    ProxyCooperationFailure.UNAUTHORIZED, ProxyCooperationFailure.FORBIDDEN -> listOf("核对代理客户端中已启用的只读 API 地址及 Secret；凭据仅用于本次内存请求。")
    ProxyCooperationFailure.TLS_CERTIFICATE, ProxyCooperationFailure.TLS_PEER_IDENTITY -> listOf("检查 HTTPS 地址、证书链和设备时间，使用平台信任且主机名匹配的证书；不要关闭证书校验。")
    ProxyCooperationFailure.NOT_FOUND, ProxyCooperationFailure.MISSING_FIELD, ProxyCooperationFailure.NON_JSON,
    ProxyCooperationFailure.INVALID_JSON, ProxyCooperationFailure.DUPLICATE_CONNECTION_ID -> listOf("确认该地址提供兼容 Clash/Mihomo 的 /version 和 /connections JSON 接口；检查版本或中间转发服务。")
    ProxyCooperationFailure.RESPONSE_TOO_LARGE -> listOf("连接快照超过安全读取上限；本次没有保存不完整 JSON，请在活动连接较少时重试。")
    ProxyCooperationFailure.CANCELLED -> listOf("已停止本次实验；等待资源释放后可重新执行。")
    ProxyCooperationFailure.BUSY -> listOf("等待上一项系统解析或网络调用释放后再试，不会为卡住的调用无限创建工作线程。")
    else -> listOf("核对 API 地址和当前网络路径后再试；本次没有改变代理或系统设置。")
}

private data class JsonNumber(val text: String)

/** Strict JSON, duplicate keys forbidden, bounded text/nodes/depth; no YAML or reflection parser. */
private class BoundedJson(private val text: String, private val checkpoint: () -> Unit) {
    private var position = 0
    private var nodes = 0
    fun parse(): Any? {
        val value = value(0)
        whitespace()
        if (position != text.length) invalid()
        return value
    }
    private fun value(depth: Int): Any? {
        checkpoint()
        if (depth > 20 || ++nodes > 30_000) invalid()
        whitespace()
        if (position >= text.length) invalid()
        return when (text[position]) {
            '{' -> {
                position++; whitespace()
                val map = linkedMapOf<String, Any?>()
                if (take('}')) map else {
                    while (true) {
                        whitespace(); if (position >= text.length || text[position] != '"') invalid()
                        val key = string(); if (map.containsKey(key)) invalid()
                        whitespace(); if (!take(':')) invalid()
                        map[key] = value(depth + 1)
                        whitespace(); if (take('}')) break
                        if (!take(',')) invalid()
                    }
                    map
                }
            }
            '[' -> {
                position++; whitespace()
                val list = mutableListOf<Any?>()
                if (take(']')) list else {
                    while (true) {
                        list += value(depth + 1)
                        whitespace(); if (take(']')) break
                        if (!take(',')) invalid()
                    }
                    list
                }
            }
            '"' -> string()
            't' -> literal("true", true)
            'f' -> literal("false", false)
            'n' -> literal("null", null)
            '-', in '0'..'9' -> number()
            else -> invalid()
        }
    }
    private fun string(): String {
        if (!take('"')) invalid()
        val result = StringBuilder()
        while (position < text.length) {
            if (result.length > 32_768) invalid()
            val c = text[position++]
            if (c == '"') return result.toString()
            if (c < ' ') invalid()
            if (c != '\\') { result.append(c); continue }
            if (position >= text.length) invalid()
            result.append(when (val escape = text[position++]) {
                '"', '\\', '/' -> escape
                'b' -> '\b'; 'f' -> '\u000c'; 'n' -> '\n'; 'r' -> '\r'; 't' -> '\t'
                'u' -> {
                    if (position + 4 > text.length) invalid()
                    val number = text.substring(position, position + 4).toIntOrNull(16) ?: invalid()
                    position += 4; number.toChar()
                }
                else -> invalid()
            })
        }
        invalid()
    }
    private fun number(): JsonNumber {
        val start = position
        take('-')
        if (!take('0')) {
            if (position >= text.length || text[position] !in '1'..'9') invalid()
            while (position < text.length && text[position] in '0'..'9') position++
        }
        if (take('.')) digits()
        if (take('e') || take('E')) { if (!take('+')) take('-'); digits() }
        return JsonNumber(text.substring(start, position))
    }
    private fun digits() {
        val start = position
        while (position < text.length && text[position] in '0'..'9') position++
        if (start == position) invalid()
    }
    private fun literal(token: String, value: Any?): Any? {
        if (!text.startsWith(token, position)) invalid()
        position += token.length
        return value
    }
    private fun whitespace() { while (position < text.length && text[position] in " \n\r\t") position++ }
    private fun take(c: Char): Boolean = if (position < text.length && text[position] == c) { position++; true } else false
    private fun invalid(): Nothing = throw ProbeFailure(ProxyCooperationFailure.INVALID_JSON)
}
