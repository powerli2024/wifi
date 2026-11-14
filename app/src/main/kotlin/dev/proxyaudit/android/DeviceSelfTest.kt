package dev.proxyaudit.android

import org.json.JSONObject
import java.io.Closeable
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

enum class SelfTestStatus { PASS, FAIL, CANCELLED, NOT_STARTED }
data class SelfTestCheck(val id: String, val title: String, val status: SelfTestStatus,
    val durationMillis: Long? = null, val detail: String, val errorCode: String? = null)
data class DeviceSelfTestReport(val startedAtUtc: String, val finishedAtUtc: String,
    val durationMillis: Long, val timeoutMillis: Int, val cancelled: Boolean,
    val timedOut: Boolean, val serverTerminated: Boolean, val checks: List<SelfTestCheck>) {
    val summary: String get() = when {
        cancelled -> "本机回环自检已取消；不构成外网或代理路径证据。"
        timedOut -> "本机回环自检超出总预算；未完成项目保留为未执行。"
        checks.all { it.status == SelfTestStatus.PASS } && serverTerminated ->
            "本机受控实验符合预期；只验证本工具的回环 TCP/HTTP 执行，不证明外网可达、TLS 或 VPN 正常。"
        else -> "本机自检未全部符合预期；请查看各项结果，不能据此诊断外网或 DNS 泄露。"
    }
}

/** One-use bounded fixture. Uses only numeric 127.0.0.1 sockets; never changes process routing. */
class DeviceSelfTest internal constructor(private val timeoutMillis: Int,
    private val beforeDelayedAccept: () -> Unit
) : AutoCloseable {
    constructor(timeoutMillis: Int = 3_000) : this(timeoutMillis, {})
    init { require(timeoutMillis in 500..10_000) { "本机自检总预算必须为 500–10000 毫秒" } }
    private val lock = Any()
    private var started = false
    @Volatile private var cancelled = false
    @Volatile private var timedOut = false
    private val resources = mutableSetOf<Closeable>()
    private val releaseServer = CountDownLatch(1)
    // This wait belongs to the probe, not to the server callback: cancellation may prevent
    // accept/register from ever reaching the callback that normally signals readiness.
    private val acceptedSignal = CountDownLatch(1)
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    override fun close() {
        val current = synchronized(lock) { cancelled = true; resources.toList().also { resources.clear() } }
        releaseServer.countDown()
        acceptedSignal.countDown()
        current.forEach { runCatching { it.close() } }
    }

    fun execute(): DeviceSelfTestReport {
        synchronized(lock) { check(!started) { "每个自检对象只能执行一次" }; started = true }
        val start = System.nanoTime()
        val wallStart = Instant.now().toString()
        val deadline = start + TimeUnit.MILLISECONDS.toNanos(timeoutMillis.toLong())
        val server = Executors.newSingleThreadExecutor { task -> Thread(task, "device-self-test-fixture").apply { isDaemon = true } }
        val timer = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "device-self-test-deadline").apply { isDaemon = true } }
        val alarm = timer.schedule({
            val current = synchronized(lock) {
                timedOut = true; resources.toList().also { resources.clear() }
            }
            releaseServer.countDown()
            acceptedSignal.countDown()
            current.forEach { runCatching { it.close() } }
        }, timeoutMillis.toLong(), TimeUnit.MILLISECONDS)
        val checks = mutableListOf<SelfTestCheck>()
        fun check(id: String, title: String, detail: String, block: () -> Unit) {
            if (cancelled || timedOut || System.nanoTime() >= deadline) {
                if (!cancelled && System.nanoTime() >= deadline) timedOut = true
                checks += SelfTestCheck(id, title, SelfTestStatus.NOT_STARTED, detail = "停止后未执行；不代表通过。")
                return
            }
            val began = System.nanoTime()
            try {
                block()
                ensureActive(deadline)
                checks += SelfTestCheck(id, title, SelfTestStatus.PASS, elapsed(began), detail)
            } catch (error: Exception) {
                val code = when {
                    cancelled -> "CANCELLED"
                    timedOut || System.nanoTime() >= deadline -> { timedOut = true; "TOTAL_TIMEOUT" }
                    error is SocketTimeoutException -> "UNEXPECTED_TIMEOUT"
                    error is InterruptedException -> "INTERRUPTED"
                    error is SelfTestFailure -> error.code
                    error is IOException -> "IO_ERROR"
                    else -> "LOCAL_ERROR"
                }
                checks += SelfTestCheck(id, title, if (cancelled) SelfTestStatus.CANCELLED else SelfTestStatus.FAIL,
                    elapsed(began), "未得到本场景预定的本机结果；未记录原始异常文本。", code)
            } finally { closeResources() }
        }
        try {
            check("LOOPBACK_HTTP", "本机 TCP / HTTP 正常回应", "本机受控服务返回了固定 HTTP 200 与预期正文。") {
                val listener = register(ServerSocket()).apply {
                    bind(InetSocketAddress(loopback, 0)); soTimeout = remaining(deadline)
                }
                val reply = server.submit {
                    register(listener.accept()).use { accepted ->
                        accepted.soTimeout = remaining(deadline)
                        readHeaders(accepted, deadline)
                        accepted.getOutputStream().write(RESPONSE)
                    }
                }
                register(Socket()).use { client ->
                    client.connect(InetSocketAddress(loopback, listener.localPort), remaining(deadline))
                    client.soTimeout = remaining(deadline)
                    client.getOutputStream().write(REQUEST)
                    val actual = client.getInputStream().readBytesBounded(deadline)
                    if (!actual.contentEquals(RESPONSE)) throw SelfTestFailure("UNEXPECTED_RESPONSE")
                }
                reply.get(remaining(deadline).toLong(), TimeUnit.MILLISECONDS)
            }
            check("CONTROLLED_READ_TIMEOUT", "本机延迟回应识别", "受控服务保持连接但暂不回应，读取按设定短时限超时。") {
                val listener = register(ServerSocket()).apply {
                    bind(InetSocketAddress(loopback, 0)); soTimeout = remaining(deadline)
                }
                val reply = server.submit {
                    try {
                        beforeDelayedAccept()
                        register(listener.accept()).use {
                            acceptedSignal.countDown()
                            releaseServer.await(remaining(deadline).toLong(), TimeUnit.MILLISECONDS)
                        }
                    } finally { acceptedSignal.countDown() }
                }
                try {
                    register(Socket()).use { client ->
                        client.connect(InetSocketAddress(loopback, listener.localPort), remaining(deadline))
                        if (!acceptedSignal.await(remaining(deadline).toLong(), TimeUnit.MILLISECONDS)) throw SocketTimeoutException()
                        ensureActive(deadline)
                        client.soTimeout = minOf(150, remaining(deadline))
                        try { client.getInputStream().read(); throw SelfTestFailure("TIMEOUT_NOT_OBSERVED") }
                        catch (_: SocketTimeoutException) { ensureActive(deadline) }
                    }
                } finally { releaseServer.countDown() }
                reply.get(remaining(deadline).toLong(), TimeUnit.MILLISECONDS)
            }
            check("CONTROLLED_REFUSAL", "本机拒绝连接识别", "向本机已绑定但未监听的端口连接，取得明确连接拒绝。") {
                // Reserve a TCP port without listening, avoiding the close-and-rebind race of a server port.
                val reservation = register(Socket()).apply { bind(InetSocketAddress(loopback, 0)) }
                register(Socket()).use { client ->
                    try {
                        client.connect(InetSocketAddress(loopback, reservation.localPort), remaining(deadline))
                        throw SelfTestFailure("REFUSAL_NOT_OBSERVED")
                    } catch (_: ConnectException) { ensureActive(deadline) }
                }
            }
        } finally {
            alarm.cancel(false)
            releaseServer.countDown()
            acceptedSignal.countDown()
            closeResources()
            server.shutdownNow(); timer.shutdownNow()
        }
        // Bounded cleanup grace does not extend the experiment's evidence deadline.
        val terminated = try { server.awaitTermination(250, TimeUnit.MILLISECONDS) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); false }
        return DeviceSelfTestReport(wallStart, Instant.now().toString(), elapsed(start), timeoutMillis,
            cancelled, timedOut, terminated, checks.toList())
    }

    private fun <T : Closeable> register(resource: T): T = synchronized(lock) {
        if (cancelled || timedOut) { resource.close(); throw SelfTestFailure("STOPPED") }
        resources += resource
        resource
    }
    private fun closeResources() {
        val current = synchronized(lock) { resources.toList().also { resources.clear() } }
        current.forEach { runCatching { it.close() } }
    }
    private fun ensureActive(deadline: Long) {
        if (cancelled || timedOut) throw SelfTestFailure("STOPPED")
        if (System.nanoTime() >= deadline) throw SocketTimeoutException()
    }
    private fun remaining(deadline: Long): Int {
        ensureActive(deadline)
        return TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()).coerceAtLeast(1).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }
    private fun readHeaders(socket: Socket, deadline: Long) {
        val input = socket.getInputStream()
        val bytes = ArrayList<Byte>()
        while (bytes.size < 1024) {
            socket.soTimeout = remaining(deadline)
            val next = input.read()
            if (next < 0) throw SelfTestFailure("INCOMPLETE_REQUEST")
            bytes += next.toByte()
            if (bytes.takeLast(4) == listOf(13.toByte(), 10.toByte(), 13.toByte(), 10.toByte())) return
        }
        throw SelfTestFailure("REQUEST_TOO_LARGE")
    }
    private fun java.io.InputStream.readBytesBounded(deadline: Long): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(256)
        while (true) {
            ensureActive(deadline)
            val count = read(buffer)
            if (count < 0) return out.toByteArray()
            if (out.size() + count > 4096) throw SelfTestFailure("RESPONSE_TOO_LARGE")
            out.write(buffer, 0, count)
        }
    }
    private class SelfTestFailure(val code: String) : IOException()

    companion object {
        private val REQUEST = "GET /self-test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
        private val RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".toByteArray(Charsets.US_ASCII)
        private fun elapsed(start: Long) = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
        fun toJson(report: DeviceSelfTestReport): String = JSONObject(linkedMapOf(
            "schemaVersion" to 1, "artifactType" to "DEVICE_LOOPBACK_SELF_TEST",
            "scope" to "THIS_PROCESS_LOOPBACK_ONLY", "externalNetworkTested" to false,
            "tlsTested" to false, "vpnPathVerified" to false, "dnsLeakTested" to false,
            "startedAtUtc" to report.startedAtUtc, "finishedAtUtc" to report.finishedAtUtc,
            "durationMillis" to report.durationMillis, "timeoutMillis" to report.timeoutMillis,
            "cancelled" to report.cancelled, "timedOut" to report.timedOut,
            "serverTerminated" to report.serverTerminated, "summary" to report.summary,
            "checks" to report.checks.map { linkedMapOf("id" to it.id, "title" to it.title,
                "status" to it.status.name, "durationMillis" to it.durationMillis, "detail" to it.detail,
                "errorCode" to it.errorCode) }
        )).toString(2) + "\n"
    }
}
