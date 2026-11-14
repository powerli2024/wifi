package dev.proxyaudit.core

import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.EventListener
import okhttp3.Handshake
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ProtocolException
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CertPathValidatorException
import java.security.cert.X509Certificate
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException

/** Full URL is used only in memory for this request. Export never includes path/query. */
class WebsitePlan private constructor(
    val url: String, val displayTarget: String, val timeoutMillis: Int,
    val totalTimeoutMillis: Int, val maxAttempts: Int
) {
    override fun toString(): String = "WebsitePlan(target=[REDACTED], maxAttempts=$maxAttempts)"
    companion object {
        fun parse(input: String, timeoutMillis: Int = 15_000, totalTimeoutMillis: Int = 30_000,
                  maxAttempts: Int = 2): WebsitePlan {
            require(timeoutMillis in 250..15_000 && totalTimeoutMillis in 250..30_000 &&
                timeoutMillis <= totalTimeoutMillis && maxAttempts in 1..2) { "网站测试预算或尝试次数不正确" }
            require(input.none { it.isISOControl() }) { "网址不得包含控制字符" }
            val text = input.trim()
            require(text.isNotEmpty() && text.length <= 4096 && text.none { it.isWhitespace() || it.code < 32 || it == '\\' }) {
                "请输入完整 HTTPS 网址或域名，不要包含空白或控制字符"
            }
            val full = if (text.contains("://")) text else "https://$text"
            val uri = try { URI(full) } catch (_: Exception) { throw IllegalArgumentException("网址格式不正确") }
            require(uri.scheme.equals("https", true) && uri.rawUserInfo == null && uri.rawFragment == null) {
                "只接受 HTTPS 网址，且不得包含账号、密码或片段标记"
            }
            val parsed = full.toHttpUrlOrNull() ?: throw IllegalArgumentException("网址格式不正确")
            require(parsed.isHttps && parsed.username.isEmpty() && parsed.password.isEmpty() && parsed.host.isNotEmpty()) {
                "只接受有效 HTTPS 网址"
            }
            // Strict URI authority prevents ambiguous userinfo, malformed ports and silent URL repairs.
            require(uri.rawAuthority != null && '@' !in uri.rawAuthority && uri.port != 0 &&
                !uri.rawAuthority.endsWith(":")) { "网址主机或端口不正确" }
            return WebsitePlan(parsed.toString(), origin(parsed), timeoutMillis, totalTimeoutMillis, maxAttempts)
        }
    }
}

private fun origin(url: HttpUrl): String = "${url.scheme}://${if (':' in url.host) "[${url.host}]" else url.host}" +
    if (url.port == 443 && url.isHttps || url.port == 80 && !url.isHttps) "" else ":${url.port}"

enum class WebsiteStage { DNS, CONNECT, TLS, HTTP, BODY }
enum class WebsiteStageStatus { NOT_RUN, SUCCEEDED, FAILED, CANCELLED, NOT_OBSERVED, PARTIAL }
enum class WebsiteFailure {
    DNS_FAILURE, CONNECT_FAILURE, TIMEOUT, TOTAL_TIMEOUT, TLS_CERTIFICATE_EXPIRED,
    TLS_CERTIFICATE_NOT_YET_VALID, TLS_CERTIFICATE, TLS_PEER_IDENTITY, TLS_NEGOTIATION,
    PROTOCOL_FAILURE, IO_FAILURE, LOCAL_POLICY, INTERNAL_ERROR, CANCELLED, BUSY
}
data class WebsiteStageResult(val stage: WebsiteStage, val status: WebsiteStageStatus,
                              val detail: String, val durationMillis: Long? = null)
data class WebsiteDnsResult(val role: String, val addresses: List<String>, val durationMillis: Long)
data class WebsiteConnectionResult(val proxyType: String, val addressFamily: String, val socketAddress: String?)
data class WebsiteAttemptResult(
    val number: Int, val execution: Execution, val stages: List<WebsiteStageResult>,
    val durationMillis: Long, val failure: WebsiteFailure?, val statusCode: Int?,
    val tlsVersion: String?, val cipherSuite: String?, val certificateNotAfterUtc: String?,
    val dns: List<WebsiteDnsResult>, val connections: List<WebsiteConnectionResult>,
    val bodyBytesRead: Long, val bodyTruncated: Boolean, val redirectOrigin: String?,
    val httpProtocol: String? = null
)

data class WebsiteReport(
    val plan: WebsitePlan, val execution: Execution, val stages: List<WebsiteStageResult>,
    val attempts: List<WebsiteAttemptResult>, val statusCode: Int?, val tlsVersion: String?,
    val cipherSuite: String?, val durationMillis: Long, val summary: String,
    val nextSteps: List<String>, val limitations: List<String>,
    val failure: WebsiteFailure? = null, val bodyBytesRead: Long = 0,
    val bodyTruncated: Boolean = false, val redirectOrigin: String? = null,
    val certificateNotAfterUtc: String? = null, val httpProtocol: String? = null
) {
    fun toJson(includeIdentifiers: Boolean = false): String {
        fun identifier(value: String?): String? = value?.let { if (includeIdentifiers) it else "[REDACTED]" }
        fun stage(value: WebsiteStageResult) = linkedMapOf("stage" to value.stage.name,
            "status" to value.status.name, "detail" to value.detail, "durationMillis" to value.durationMillis)
        return Json.write(linkedMapOf(
            "schemaVersion" to 1, "scope" to "THIS_APP_HTTPS_GET_ONLY",
            "identifiersIncluded" to includeIdentifiers, "targetOrigin" to identifier(plan.displayTarget),
            "urlPathAndQueryIncluded" to false, "method" to "GET", "redirectsFollowed" to false,
            "bodyLimitBytes" to WebsiteDiagnostics.BODY_LIMIT_BYTES,
            "attemptTimeoutMillis" to plan.timeoutMillis, "totalTimeoutMillis" to plan.totalTimeoutMillis,
            "maxAttempts" to plan.maxAttempts, "execution" to execution.name,
            "failure" to failure?.name, "durationMillis" to durationMillis,
            "summary" to summary, "aggregatePolicy" to "FIRST_ATTEMPT_PRESERVED",
            "stages" to stages.map(::stage), "attempts" to attempts.map { item -> linkedMapOf(
                "number" to item.number, "execution" to item.execution.name,
                "failure" to item.failure?.name, "durationMillis" to item.durationMillis,
                "stages" to item.stages.map(::stage), "statusCode" to item.statusCode,
                "httpProtocol" to item.httpProtocol,
                "tlsVersion" to item.tlsVersion, "cipherSuite" to item.cipherSuite,
                "certificateNotAfterUtc" to item.certificateNotAfterUtc,
                "dns" to item.dns.map { linkedMapOf("role" to it.role,
                    "addresses" to it.addresses.map(::identifier), "durationMillis" to it.durationMillis) },
                "connections" to item.connections.map { linkedMapOf("proxyType" to it.proxyType,
                    "socketTargetFamily" to it.addressFamily, "socketAddress" to identifier(it.socketAddress)) },
                "bodyBytesRead" to item.bodyBytesRead, "bodyTruncated" to item.bodyTruncated,
                "redirectOrigin" to identifier(item.redirectOrigin)
            ) }, "nextSteps" to nextSteps, "limitations" to limitations
        )) + "\n"
    }

    fun toText(includeIdentifiers: Boolean = false): String = buildString {
        appendLine(summary)
        appendLine("目标：${if (includeIdentifiers) plan.displayTarget else "[已隐藏]"}；GET；不跟随跳转")
        appendLine("总耗时：${durationMillis} ms；结果：${executionLabel(execution)}")
        for (attempt in attempts) {
            appendLine("\n第 ${attempt.number} 次尝试：${executionLabel(attempt.execution)}（${attempt.durationMillis} ms）")
            for (stage in attempt.stages) appendLine("${stageName(stage.stage)}：${statusLabel(stage.status)} · ${stage.detail}")
            attempt.statusCode?.let { appendLine("HTTP：$it；响应协议：${attempt.httpProtocol ?: "未观测"}") }
            attempt.tlsVersion?.let { appendLine("TLS：$it；${attempt.cipherSuite}") }
            attempt.certificateNotAfterUtc?.let { appendLine("已验证证书到期：$it") }
            appendLine("正文仅读取计数：${attempt.bodyBytesRead} 字节；达到上限：${attempt.bodyTruncated}")
            attempt.connections.forEach { appendLine("显式代理类型：${it.proxyType}；socket 目标地址族：${it.addressFamily}（DIRECT 不证明无 VPN）") }
            if (includeIdentifiers) {
                attempt.dns.forEach { appendLine("解析候选（${it.role}）：${it.addresses.joinToString()}") }
                attempt.connections.forEach { appendLine("连接目标：${it.socketAddress ?: "未观测"}；${it.addressFamily}；显式代理类型 ${it.proxyType}") }
                attempt.redirectOrigin?.let { appendLine("跳转来源站点：$it（路径与参数始终省略）") }
            }
        }
        appendLine("\n下一步：")
        nextSteps.forEach { appendLine("• $it") }
        appendLine("\n边界：")
        limitations.forEach { appendLine("• $it") }
    }
}

/** One admitted global worker bounds even uninterruptible platform DNS. No custom production trust. */
class WebsiteDiagnostics internal constructor(private val plan: WebsitePlan, private val baseClient: OkHttpClient) : AutoCloseable {
    constructor(plan: WebsitePlan) : this(plan, OkHttpClient())
    private val started = AtomicBoolean()
    private val closed = AtomicBoolean()
    private val activeCall = AtomicReference<Call?>()
    private val wake = CountDownLatch(1)
    private val cancellationSent = AtomicBoolean()
    private val dnsRunning = AtomicBoolean()
    private val recorder = Recorder()
    @Volatile private var deadlineNanos = Long.MAX_VALUE
    @Volatile private var attemptDeadlineNanos = Long.MAX_VALUE

    fun execute(): WebsiteReport {
        check(started.compareAndSet(false, true)) { "每个网站计划只能执行一次" }
        val start = System.nanoTime()
        deadlineNanos = start + TimeUnit.MILLISECONDS.toNanos(plan.totalTimeoutMillis.toLong())
        if (closed.get()) return recorder.freeze(start, WebsiteFailure.CANCELLED)
        if (cleanupCount.get() != 0 || !workerBusy.compareAndSet(false, true)) return recorder.freeze(start, WebsiteFailure.BUSY)
        try {
            worker.execute {
                try { runAttempts() }
                catch (_: Exception) { recorder.fail(WebsiteFailure.INTERNAL_ERROR) }
                finally {
                    activeCall.set(null)
                    workerBusy.set(false)
                    recorder.markDone()
                    wake.countDown()
                }
            }
        } catch (_: RuntimeException) {
            workerBusy.set(false)
            return recorder.freeze(start, WebsiteFailure.BUSY)
        }
        var stop: WebsiteFailure? = null
        while (true) {
            val now = System.nanoTime()
            if (closed.get()) { stop = WebsiteFailure.CANCELLED; break }
            if (now >= deadlineNanos) { stop = WebsiteFailure.TOTAL_TIMEOUT; break }
            if (recorder.isDone()) break
            // If system DNS ignores cancellation, return without creating another DNS worker.
            if (now >= attemptDeadlineNanos && dnsRunning.get()) { stop = WebsiteFailure.TIMEOUT; break }
            try { wake.await(20, TimeUnit.MILLISECONDS) }
            catch (_: InterruptedException) { Thread.currentThread().interrupt(); stop = WebsiteFailure.CANCELLED; break }
        }
        val result = recorder.freeze(start, stop)
        if (stop != null) { closed.set(true); cancelCall() }
        return result
    }

    override fun close() {
        closed.set(true)
        wake.countDown()
        cancelCall()
    }

    private fun cancelCall() {
        val call = activeCall.get() ?: return
        if (!cancellationSent.compareAndSet(false, true)) return
        cleanupCount.incrementAndGet()
        try {
            cleanup.execute { try { call.cancel() } finally { cleanupCount.decrementAndGet() } }
        } catch (_: RuntimeException) { cleanupCount.decrementAndGet() }
    }

    private fun checkRunning() {
        if (closed.get()) throw InterruptedIOException()
        if (System.nanoTime() >= deadlineNanos || System.nanoTime() >= attemptDeadlineNanos) throw SocketTimeoutException()
    }

    private fun runAttempts() {
        for (number in 1..plan.maxAttempts) {
            if (closed.get() || System.nanoTime() >= deadlineNanos) return
            val remaining = TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime()).coerceAtLeast(1)
            val budget = minOf(remaining, plan.timeoutMillis.toLong())
            attemptDeadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budget)
            recorder.begin(number)
            val pool = ConnectionPool(0, 1, TimeUnit.SECONDS)
            var failed: WebsiteFailure? = null
            try {
                val originalDns = baseClient.dns
                val client = baseClient.newBuilder().connectionPool(pool).cache(null)
                    .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
                    .callTimeout(budget, TimeUnit.MILLISECONDS)
                    .connectTimeout(minOf(5_000, budget), TimeUnit.MILLISECONDS)
                    .readTimeout(minOf(5_000, budget), TimeUnit.MILLISECONDS)
                    .writeTimeout(minOf(5_000, budget), TimeUnit.MILLISECONDS)
                    .dns(object : Dns {
                        override fun lookup(hostname: String): List<InetAddress> {
                            checkRunning()
                            dnsRunning.set(true)
                            val answer = try { originalDns.lookup(hostname) } finally { dnsRunning.set(false) }
                            checkRunning()
                            return answer
                        }
                    })
                    .eventListener(recorder.listener()).build()
                val request = Request.Builder().url(plan.url).get()
                    .header("User-Agent", "ProxyAudit-Website-Diagnostic/1")
                    .header("Accept-Encoding", "identity").header("Cache-Control", "no-store").build()
                val call = client.newCall(request)
                activeCall.set(call)
                checkRunning()
                call.execute().use { response ->
                    checkRunning()
                    recorder.headers(response)
                    recorder.start(WebsiteStage.BODY)
                    val input = response.body?.byteStream()
                    if (input == null) recorder.body(0, false)
                    else {
                        val buffer = ByteArray(2048)
                        var count = 0L
                        var eof = false
                        while (count < BODY_LIMIT_BYTES) {
                            checkRunning()
                            val read = input.read(buffer, 0, minOf(buffer.size.toLong(), BODY_LIMIT_BYTES - count).toInt())
                            checkRunning()
                            if (read == -1) { eof = true; break }
                            count += read
                            recorder.bodyProgress(count)
                        }
                        recorder.body(count, !eof && count == BODY_LIMIT_BYTES.toLong())
                    }
                }
                checkRunning()
                recorder.finish()
            } catch (error: Exception) {
                failed = when {
                    closed.get() -> WebsiteFailure.CANCELLED
                    System.nanoTime() >= deadlineNanos -> WebsiteFailure.TOTAL_TIMEOUT
                    System.nanoTime() >= attemptDeadlineNanos -> WebsiteFailure.TIMEOUT
                    else -> classify(error)
                }
                recorder.fail(failed)
            } finally {
                activeCall.set(null)
                pool.evictAll()
                attemptDeadlineNanos = Long.MAX_VALUE
            }
            if (failed !in setOf(WebsiteFailure.TIMEOUT, WebsiteFailure.CONNECT_FAILURE) ||
                number == plan.maxAttempts || closed.get()) return
            // A later successful response cannot overwrite this attempt. No changed target or protocol.
            val resumeAt = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500)
            if (resumeAt + TimeUnit.MILLISECONDS.toNanos(250) >= deadlineNanos) return
            while (System.nanoTime() < resumeAt) {
                if (closed.get() || System.nanoTime() >= deadlineNanos) return
                try { Thread.sleep(20) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); return }
            }
        }
    }

    private inner class Recorder {
        private val records = mutableListOf<MutableAttempt>()
        private var frozen = false
        private var done = false
        @Synchronized fun isDone() = done
        @Synchronized fun markDone() { done = true }
        @Synchronized fun begin(number: Int) { if (!frozen) records.add(MutableAttempt(number)) }
        private fun current(): MutableAttempt? = if (frozen) null else records.lastOrNull()
        @Synchronized fun start(stage: WebsiteStage) { current()?.start(stage) }
        @Synchronized fun headers(response: Response) {
            current()?.apply {
                code = response.code
                protocol = response.protocol.toString()
                success(WebsiteStage.HTTP, "已收到 HTTP 响应首部；状态码描述服务端响应，不表示页面功能通过")
                redirect = response.header("Location")?.let { location ->
                    try { response.request.url.resolve(location)?.takeIf { it.username.isEmpty() && it.password.isEmpty() }?.let(::origin) }
                    catch (_: Exception) { null }
                }
            }
        }
        @Synchronized fun bodyProgress(count: Long) { current()?.bytes = count }
        @Synchronized fun body(count: Long, truncated: Boolean) {
            current()?.apply {
                bytes = count; capped = truncated
                result(WebsiteStage.BODY, if (truncated) WebsiteStageStatus.PARTIAL else WebsiteStageStatus.SUCCEEDED,
                    if (truncated) "达到 16 KiB 计数上限，停止读取；不是网站故障，也未验证完整页面" else "本次响应正文已读到结束；只统计字节，不保存或执行内容")
            }
        }
        @Synchronized fun finish() { current()?.apply { finished = System.nanoTime(); execution = Execution.COMPLETED } }
        @Synchronized fun fail(failure: WebsiteFailure) { current()?.fail(failure) }
        fun listener() = object : EventListener() {
            override fun dnsStart(call: Call, domainName: String) = synchronized(this@Recorder) {
                current()?.apply { dnsStart = System.nanoTime(); dnsRole = if (domainName == call.request().url.host) "ORIGIN" else "PROXY_OR_OTHER"; start(WebsiteStage.DNS) }; Unit
            }
            override fun dnsEnd(call: Call, domainName: String, inetAddressList: List<InetAddress>) = synchronized(this@Recorder) {
                current()?.apply {
                    dnsResults.add(WebsiteDnsResult(dnsRole, inetAddressList.take(64).mapNotNull { it.hostAddress }, elapsed(dnsStart)))
                    success(WebsiteStage.DNS, if (dnsRole == "ORIGIN") "系统解析返回候选地址；解析器、缓存及线上 DNS 路径未观测" else "解析的是代理或连接基础设施；目标站点的 DNS 尚未观测")
                }; Unit
            }
            override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) = synchronized(this@Recorder) {
                current()?.apply {
                    connections.add(WebsiteConnectionResult(proxy.type().name,
                        when (inetSocketAddress.address) { is Inet6Address -> "IPv6"; null -> "UNRESOLVED"; else -> "IPv4" },
                        inetSocketAddress.address?.hostAddress))
                    start(WebsiteStage.CONNECT)
                }; Unit
            }
            override fun secureConnectStart(call: Call) = synchronized(this@Recorder) {
                current()?.apply {
                    success(WebsiteStage.CONNECT, "已建立连接并进入 TLS；可能包含 HTTP 代理隧道，不证明物理直连")
                    start(WebsiteStage.TLS)
                }; Unit
            }
            override fun secureConnectEnd(call: Call, handshake: Handshake?) = synchronized(this@Recorder) {
                current()?.apply {
                    tls = handshake?.tlsVersion?.javaName
                    cipher = handshake?.cipherSuite?.javaName
                    certificateExpiry = (handshake?.peerCertificates?.firstOrNull() as? X509Certificate)?.notAfter?.toInstant()?.toString()
                    success(WebsiteStage.TLS, "平台证书信任与主机名校验通过；不证明代理路径或无泄露")
                    start(WebsiteStage.HTTP)
                }; Unit
            }
            override fun requestHeadersEnd(call: Call, request: Request) = synchronized(this@Recorder) {
                current()?.start(WebsiteStage.HTTP); Unit
            }
        }

        @Synchronized fun freeze(start: Long, stop: WebsiteFailure?): WebsiteReport {
            if (!frozen && stop != null) {
                val last = records.lastOrNull()
                if (last?.finished == null) last?.fail(stop)
            }
            frozen = true
            val attempts = records.map { it.snapshot() }
            val first = attempts.firstOrNull()
            val outcome = when {
                stop == WebsiteFailure.CANCELLED -> Execution.CANCELLED
                stop != null -> Execution.ERROR
                attempts.any { it.execution != Execution.COMPLETED } -> Execution.ERROR
                attempts.isEmpty() -> Execution.NOT_STARTED
                else -> Execution.COMPLETED
            }
            val primaryFailure = stop ?: first?.failure
            val summary = summary(attempts, stop)
            val stages = first?.stages ?: WebsiteStage.entries.map { WebsiteStageResult(it, WebsiteStageStatus.NOT_RUN, "未执行") }
            return WebsiteReport(plan, outcome, stages, attempts, first?.statusCode, first?.tlsVersion,
                first?.cipherSuite, elapsed(start), summary, nextSteps(attempts, primaryFailure), LIMITATIONS,
                primaryFailure, first?.bodyBytesRead ?: 0, first?.bodyTruncated ?: false, first?.redirectOrigin, first?.certificateNotAfterUtc,
                first?.httpProtocol)
        }
    }

    private class MutableAttempt(val number: Int) {
        val began = System.nanoTime()
        var finished: Long? = null
        var execution = Execution.NOT_STARTED
        var failure: WebsiteFailure? = null
        var active = WebsiteStage.CONNECT
        val stages = linkedMapOf<WebsiteStage, WebsiteStageResult>()
        val starts = mutableMapOf<WebsiteStage, Long>()
        val dnsResults = mutableListOf<WebsiteDnsResult>()
        val connections = mutableListOf<WebsiteConnectionResult>()
        var dnsStart = began
        var dnsRole = "ORIGIN"
        var code: Int? = null
        var protocol: String? = null
        var tls: String? = null
        var cipher: String? = null
        var certificateExpiry: String? = null
        var bytes = 0L
        var capped = false
        var redirect: String? = null
        fun start(stage: WebsiteStage) { active = stage; starts.putIfAbsent(stage, System.nanoTime()) }
        fun result(stage: WebsiteStage, status: WebsiteStageStatus, detail: String) {
            stages[stage] = WebsiteStageResult(stage, status, detail, starts[stage]?.let(::elapsed))
        }
        fun success(stage: WebsiteStage, detail: String) = result(stage, WebsiteStageStatus.SUCCEEDED, detail)
        fun fail(value: WebsiteFailure) {
            if (finished != null) return
            failure = value; execution = if (value == WebsiteFailure.CANCELLED) Execution.CANCELLED else Execution.ERROR
            result(active, if (value == WebsiteFailure.CANCELLED) WebsiteStageStatus.CANCELLED else WebsiteStageStatus.FAILED, failureDetail(value))
            finished = System.nanoTime()
        }
        fun snapshot() = WebsiteAttemptResult(number, execution,
            WebsiteStage.entries.map { stage -> stages[stage] ?: WebsiteStageResult(stage,
                if (stage == WebsiteStage.DNS && connections.isNotEmpty()) WebsiteStageStatus.NOT_OBSERVED else WebsiteStageStatus.NOT_RUN,
                if (stage == WebsiteStage.DNS && connections.isNotEmpty()) "未观察到本地 DNS 回调；数字目标或代理代解析均可能如此" else "未执行") },
            TimeUnit.NANOSECONDS.toMillis((finished ?: System.nanoTime()) - began).coerceAtLeast(0),
            failure, code, tls, cipher, certificateExpiry, dnsResults.toList(), connections.toList(), bytes, capped, redirect, protocol)
    }

    companion object {
        const val BODY_LIMIT_BYTES = 16 * 1024
        private val workerBusy = AtomicBoolean()
        private val cleanupCount = AtomicInteger()
        // Admission CAS allows only one network task. The single queue entry bridges the interval
        // between publishing idle and ThreadPoolExecutor returning its old worker to getTask().
        // A SynchronousQueue rejects that valid handoff despite the published idle state.
        private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1),
            { runnable -> Thread(runnable, "website-probe-worker").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
        private val cleanup = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1),
            { runnable -> Thread(runnable, "website-probe-cleanup").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
        fun hasPendingWork(): Boolean = workerBusy.get() || cleanupCount.get() != 0
        private val LIMITATIONS = listOf(
            "只测试本应用的一次 HTTPS GET 及至多一次同计划复核；不运行 JavaScript、登录、页面子资源或其他应用。",
            "使用平台 DNS、默认 ProxySelector 和正常 TLS 校验，不主动绑定底层网络；DIRECT 仅表示未选显式 HTTP/SOCKS 代理，不证明流量未经过 VPN 或透明代理。",
            "解析地址与 socket 目标仅是本次候选/连接观测；本轮没有独立 IPv4/IPv6 定向对照、QUIC、WebRTC 或 DNS 泄露检测。",
            "HTTP 状态、证书校验及响应字节数不证明网站完整可用、出口符合策略、代理身份或没有 DNS 泄露。",
            "路径、查询参数、响应正文、Cookie、代理名称和证书名称不写入报告；完整导出仅增加站点来源和地址标识。",
            "系统 DNS 可能使用缓存或无法立即中断；冻结返回后若仍有工作未退出，将禁止新网站测试。"
        )
    }
}

private fun elapsed(start: Long): Long = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start).coerceAtLeast(0)
private fun classify(error: Exception): WebsiteFailure {
    val causes = generateSequence<Throwable>(error) { it.cause }.take(12).toList()
    return when {
        causes.any { it is CertificateExpiredException || it is CertPathValidatorException && it.reason == CertPathValidatorException.BasicReason.EXPIRED } -> WebsiteFailure.TLS_CERTIFICATE_EXPIRED
        causes.any { it is CertificateNotYetValidException || it is CertPathValidatorException && it.reason == CertPathValidatorException.BasicReason.NOT_YET_VALID } -> WebsiteFailure.TLS_CERTIFICATE_NOT_YET_VALID
        causes.any { it is CertificateException } -> WebsiteFailure.TLS_CERTIFICATE
        error is SSLPeerUnverifiedException -> WebsiteFailure.TLS_PEER_IDENTITY
        error is SSLException -> WebsiteFailure.TLS_NEGOTIATION
        error is UnknownHostException -> WebsiteFailure.DNS_FAILURE
        error is ConnectException -> WebsiteFailure.CONNECT_FAILURE
        error is SocketTimeoutException || error is InterruptedIOException -> WebsiteFailure.TIMEOUT
        error is ProtocolException -> WebsiteFailure.PROTOCOL_FAILURE
        error is SecurityException -> WebsiteFailure.LOCAL_POLICY
        error is IOException -> WebsiteFailure.IO_FAILURE
        else -> WebsiteFailure.INTERNAL_ERROR
    }
}
private fun failureDetail(failure: WebsiteFailure): String = when (failure) {
    WebsiteFailure.DNS_FAILURE -> "系统未返回可用解析结果；不能据此判定 DNS 泄露"
    WebsiteFailure.CONNECT_FAILURE -> "本次连接目标或代理入口未建立连接；需要结合代理与网络证据排查"
    WebsiteFailure.TIMEOUT -> "本阶段未在时间预算内完成；保留此前成功层，原因尚未确定"
    WebsiteFailure.TOTAL_TIMEOUT -> "整体时间预算已用完，停止获取新证据"
    WebsiteFailure.TLS_CERTIFICATE_EXPIRED -> "证书验证发现已过期；检查设备时间和服务端证书，不跳过验证"
    WebsiteFailure.TLS_CERTIFICATE_NOT_YET_VALID -> "证书尚未生效；检查设备时间和服务端证书，不跳过验证"
    WebsiteFailure.TLS_CERTIFICATE -> "平台证书信任验证失败；不能据此认定被劫持"
    WebsiteFailure.TLS_PEER_IDENTITY -> "TLS 对端身份或主机名验证失败；没有跳过验证"
    WebsiteFailure.TLS_NEGOTIATION -> "TLS 协商未完成；未获得已验证连接"
    WebsiteFailure.PROTOCOL_FAILURE -> "响应未符合客户端可接受的 HTTP 协议"
    WebsiteFailure.IO_FAILURE -> "当前阶段出现输入输出错误；不输出可能包含网址的原始错误"
    WebsiteFailure.LOCAL_POLICY -> "本机权限或平台策略拒绝请求；不应直接更换 DNS"
    WebsiteFailure.INTERNAL_ERROR -> "本次测试遇到内部错误，证据不足"
    WebsiteFailure.CANCELLED -> "测试已取消；未完成部分不判定为站点故障"
    WebsiteFailure.BUSY -> "上一网站工作尚未退出，本次未发起请求"
}
private fun stageName(stage: WebsiteStage) = when (stage) {
    WebsiteStage.DNS -> "系统解析"; WebsiteStage.CONNECT -> "连接/代理隧道"; WebsiteStage.TLS -> "TLS 校验"
    WebsiteStage.HTTP -> "HTTP 响应"; WebsiteStage.BODY -> "正文读取"
}
private fun executionLabel(execution: Execution) = when (execution) {
    Execution.NOT_STARTED -> "未开始"; Execution.COMPLETED -> "已完成"
    Execution.ERROR -> "出现错误"; Execution.CANCELLED -> "已取消"
}
private fun statusLabel(status: WebsiteStageStatus) = when (status) {
    WebsiteStageStatus.NOT_RUN -> "未执行"; WebsiteStageStatus.SUCCEEDED -> "已取得成功证据"
    WebsiteStageStatus.FAILED -> "未完成/失败"; WebsiteStageStatus.CANCELLED -> "已取消"
    WebsiteStageStatus.NOT_OBSERVED -> "未观测"; WebsiteStageStatus.PARTIAL -> "部分完成"
}
private fun summary(attempts: List<WebsiteAttemptResult>, stop: WebsiteFailure?): String {
    if (stop == WebsiteFailure.BUSY) return "上一网站工作尚未退出，本次未运行"
    if (stop == WebsiteFailure.CANCELLED) return "网站测试已取消；已取得的阶段证据保留"
    if (stop == WebsiteFailure.TOTAL_TIMEOUT) return "网站测试达到总时限；已取得的阶段证据保留"
    val first = attempts.firstOrNull() ?: return "尚未取得网站测试证据"
    if (attempts.size > 1 && first.failure != null && attempts.drop(1).any { it.execution == Execution.COMPLETED })
        return "首次尝试失败，附加复核取得响应；网络稳定性尚未确认"
    val failed = first.stages.firstOrNull { it.status == WebsiteStageStatus.FAILED || it.status == WebsiteStageStatus.CANCELLED }
    if (failed != null) {
        val success = first.stages.filter { it.status == WebsiteStageStatus.SUCCEEDED }.joinToString("、") { stageName(it.stage) }
        return "最早未完成阶段：${stageName(failed.stage)}" + if (success.isNotEmpty()) "；已证实：$success" else "；后续层尚无证据"
    }
    return when (first.statusCode) {
        401, 403 -> "连接与 TLS 校验完成，网站返回 HTTP ${first.statusCode} 访问限制"
        429 -> "连接与 TLS 校验完成，网站返回 HTTP 429 限流响应"
        in 300..399 -> "收到 HTTP ${first.statusCode} 跳转响应；未跟随跳转"
        in 500..599 -> "连接与 TLS 校验完成，网站返回 HTTP ${first.statusCode} 服务端错误"
        else -> "连接与 TLS 校验完成，收到 HTTP ${first.statusCode ?: "响应"}" + if (first.bodyTruncated) "；正文仅检查前 16 KiB" else ""
    }
}
private fun nextSteps(attempts: List<WebsiteAttemptResult>, failure: WebsiteFailure?): List<String> {
    if (attempts.size > 1 && attempts.first().failure != null && attempts.last().execution == Execution.COMPLETED)
        return listOf("保留首次失败和复核响应，先检查网络是否切换或不稳定，不自动归因 DNS。", "以同一 URL、同一网络与相同代理设置再次复核；不挑选成功结果覆盖历史。")
    return when (failure) {
        WebsiteFailure.DNS_FAILURE -> listOf("检查当前网络的系统解析证据；如进行协议对照，使用相同域名、记录类型并明确授权明文 DNS。", "先核实代理规则及本应用是否被代理；不要因一次解析失败自动替换 DNS。")
        WebsiteFailure.CONNECT_FAILURE -> listOf("检查选中的代理入口是否可达、分应用规则及目标端口；保持原计划复核。", "DNS 成功只说明候选地址可用，不能证明连接路径或代理状态。")
        WebsiteFailure.TLS_CERTIFICATE_EXPIRED, WebsiteFailure.TLS_CERTIFICATE_NOT_YET_VALID,
        WebsiteFailure.TLS_CERTIFICATE, WebsiteFailure.TLS_PEER_IDENTITY, WebsiteFailure.TLS_NEGOTIATION ->
            listOf("检查设备日期时间、网址主机名、网站证书及代理 TLS 设置；保留正常证书与主机名校验。", "不要安装未知 CA 或关闭验证来把失败变成通过；本次错误本身不证明中间人攻击。")
        WebsiteFailure.CANCELLED, WebsiteFailure.TOTAL_TIMEOUT, WebsiteFailure.TIMEOUT -> listOf("保留成功层和未完成层，确认网络稳定后以同一目标复核；超时不能证明泄露或阻断正确。")
        WebsiteFailure.BUSY -> listOf("等待旧请求或系统 DNS 工作退出后再运行；不并行开新任务绕过工作槽。")
        WebsiteFailure.LOCAL_POLICY -> listOf("先排查本应用联网权限与系统网络策略，不自动修改 DNS。")
        else -> {
            val code = attempts.firstOrNull()?.statusCode
            when (code) {
                401, 403 -> listOf("连接/TLS 已取得证据；查看网站登录、地区或访问策略。此响应不是 DNS 失败；DNS 是否被观测应单独查看。", "本工具不登录、不执行浏览器脚本，浏览器行为可能不同。")
                429 -> listOf("遵循网站限流策略稍后再试；不自动重复请求或切换目标规避限制。")
                in 300..399 -> listOf("核对跳转站点后把它作为新的测试目标；本次未访问跳转地址。")
                in 500..599 -> listOf("先检查网站服务状态或服务端日志；HTTP 服务端错误不应直接改 DNS。")
                else -> listOf("本次结果仅覆盖有限 HTTPS 请求；若浏览器仍不可用，补查登录、脚本、子资源及浏览器自己的代理设置。", "若需验证出口策略，请使用可信回显端点与预期出口，不能从普通网站响应推断无泄露。")
            }
        }
    }
}
