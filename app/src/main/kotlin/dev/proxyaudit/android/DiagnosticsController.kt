package dev.proxyaudit.android

import android.content.Context
import android.net.DnsResolver
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dev.proxyaudit.core.*
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.URL
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/** One bounded run slot. Rotation cannot start another run, and callbacks never mix run IDs. */
class DiagnosticsController(context: Context) {
    private val monitor = NetworkMonitor(context)
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "probe-worker").apply { isDaemon = true } }
    private val dnsCallbacks = Executors.newSingleThreadExecutor { Thread(it, "dns-callback").apply { isDaemon = true } }
    private val timer = Executors.newSingleThreadScheduledExecutor { Thread(it, "probe-deadline").apply { isDaemon = true } }
    private val cleanup = ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS, ArrayBlockingQueue<Runnable>(1),
        { task -> Thread(task, "probe-cleanup").apply { isDaemon = true } }, ThreadPoolExecutor.DiscardPolicy())
    private val listeners = CopyOnWriteArrayList<() -> Unit>()
    private var token: Token? = null
    private var pendingExport: PendingExport? = null
    private var nextExportRequestCode = 21
    val exportPending: Boolean get() = synchronized(this) { pendingExport != null }
    data class ExportTicket(val requestId: String, val requestCode: Int, val suggestedName: String)
    private data class PendingExport(val ticket: ExportTicket, val json: String)

    /** Never reuse the code of a picker that may still return after process recreation. */
    @Synchronized fun reserveRestoredExportCode(requestCode: Int) {
        if (requestCode in 0..65535) nextExportRequestCode = maxOf(nextExportRequestCode, requestCode + 1)
    }

    /** Retained only in this application process, never placed in Activity saved-state or on disk. */
    @Synchronized fun beginExport(snapshot: RunReport, includeNetworkIdentifiers: Boolean): ExportTicket? {
        if (pendingExport != null || nextExportRequestCode > 65535) return null
        val demoPrefix = if (snapshot.evidenceOrigin == EvidenceOrigin.SYNTHETIC_FIXTURE) "DEMO-" else ""
        val suffix = if (includeNetworkIdentifiers) "full" else "redacted"
        val ticket = ExportTicket(UUID.randomUUID().toString(), nextExportRequestCode++, "proxy-evidence-$demoPrefix${snapshot.runId.take(8)}-$suffix.json")
        pendingExport = PendingExport(ticket, ReportExporter.toJson(snapshot, includeNetworkIdentifiers))
        notifyUi()
        return ticket
    }
    @Synchronized fun consumeExport(requestId: String): String? {
        val pending = pendingExport?.takeIf { it.ticket.requestId == requestId } ?: return null
        pendingExport = null; notifyUi(); return pending.json
    }
    @Synchronized fun beginComparisonExport(includeNetworkIdentifiers: Boolean): ExportTicket? {
        val before = baseline ?: return null
        val after = report ?: return null
        if (pendingExport != null || nextExportRequestCode > 65535) return null
        val suffix = if (includeNetworkIdentifiers) "full" else "redacted"
        val ticket = ExportTicket(UUID.randomUUID().toString(), nextExportRequestCode++,
            "proxy-comparison-${after.runId.take(8)}-$suffix.json")
        pendingExport = PendingExport(ticket, ReportComparison.toJson(before, after, includeNetworkIdentifiers))
        notifyUi()
        return ticket
    }
    @Synchronized fun cancelExport(requestId: String) {
        if (pendingExport?.ticket?.requestId == requestId) { pendingExport = null; notifyUi() }
    }
    @Volatile var report: RunReport? = null; private set
    @Volatile var baseline: RunReport? = null; private set
    @Synchronized fun pinBaseline(): Boolean {
        val current = report ?: return false
        if (busy || current.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME) return false
        baseline = current
        notifyUi()
        return true
    }
    @Volatile var busy = false; private set
    @Volatile var status = "尚未执行。所有网络探测都必须由你手动开始。"; private set
    @Volatile var isDemo = false; private set
    /** Unsubmitted form values survive rotation only; never saved to disk or Bundle. */
    @Volatile var inputDraft: Map<String, String> = emptyMap()

    fun observe(listener: () -> Unit) { listeners.add(listener); listener() }
    fun removeObserver(listener: () -> Unit) { listeners.remove(listener) }
    private fun notifyUi() { main.post { listeners.forEach { it() } } }
    fun snapshot() = monitor.snapshot()

    @Synchronized fun showDemo() {
        if (busy) return
        report = DemoFixture.report(); isDemo = true
        status = "演示数据：完全虚构，未发送网络请求，不是设备测试结果。"; notifyUi()
    }
    @Synchronized fun clear() {
        if (busy) return
        report = null; baseline = null; isDemo = false; status = "已清除本进程中的结果及对照基线。导出的文件不受影响。"; notifyUi()
    }
    @Synchronized fun start(config: RunConfig): Boolean {
        if (token != null) return false
        require(config.policy.runHttps || config.policy.runDns || config.rawDns != null)
        require(!config.policy.runHttps || config.endpoint != null)
        require(!config.policy.runDns || config.dnsHost?.let(::isDnsHost) == true)
        val generationBeforeSnapshot = monitor.generation.get()
        val frozenConfig = config.copy(policy = config.policy.copy(expectedSourceIps = config.policy.expectedSourceIps.toSet()))
        val t = Token(frozenConfig, monitor.snapshot(), generationBeforeSnapshot)
        token = t; busy = true; report = null; isDemo = false
        status = "开始本应用探测。最多 ${config.evidenceBudgetMillis / 1000} 秒后停止等待新证据。"; notifyUi()
        val deadline = timer.schedule({ stop(t, Failure.TIMEOUT) }, remainingBudget(t).coerceAtLeast(0), TimeUnit.MILLISECONDS)
        val networkWatch = timer.scheduleWithFixedDelay({
            if (monitor.generation.get() != t.generation) stop(t, Failure.NETWORK_CHANGED)
        }, 100, 100, TimeUnit.MILLISECONDS)
        worker.execute {
            try {
                if (config.policy.runDns) runProbe(t, ProbeKind.SYSTEM_DNS)
                if (config.policy.runHttps) runProbe(t, ProbeKind.HTTPS)
                if (config.rawDns?.udp == true) runProbe(t, ProbeKind.RAW_UDP)
                if (config.rawDns?.tcp == true) runProbe(t, ProbeKind.RAW_TCP)
            } catch (_: Exception) {
                stop(t, Failure.INTERNAL_ERROR)
            } finally {
                deadline.cancel(false)
                networkWatch.cancel(false)
                synchronized(this) { t.workerFinished = true }
                publish(t)
                synchronized(this) { releaseFinished(t) }
                notifyUi()
            }
        }
        return true
    }

    private fun remainingBudget(t: Token) = t.config.evidenceBudgetMillis - elapsed(t.start)

    /** Platform snapshots are sampled outside the controller monitor, never before cleanup. */
    private fun mayStartAttempt(t: Token): Boolean {
        if (t.stopReason.get() != null) return false
        if (remainingBudget(t) <= 0) { stop(t, Failure.TIMEOUT); return false }
        if (monitor.generation.get() != t.generation || monitor.snapshot() != t.before) {
            stop(t, Failure.NETWORK_CHANGED)
            return false
        }
        return t.stopReason.get() == null
    }

    private fun runProbe(t: Token, kind: ProbeKind) {
        for (number in 1..t.config.maxAttempts) {
            if (!mayStartAttempt(t)) return
            val attempt = synchronized(this) {
                val timeout = minOf(t.config.timeoutMillis.toLong(), remainingBudget(t)).toInt()
                if (t.stopReason.get() != null || timeout <= 0 || monitor.generation.get() != t.generation) null
                else {
                    val id = if (kind == ProbeKind.HTTPS && number == 1) t.id else UUID.randomUUID().toString()
                    ProbeAttempt(id, kind, number, elapsed(t.start), timeout).also {
                        t.phase = phase(kind); t.activeAttemptId = id; t.attempts = t.attempts + it
                        status = "正在执行 ${kind.name}，第 $number/${t.config.maxAttempts} 次；全部尝试保留。"
                    }
                }
            }
            if (attempt == null) {
                if (t.stopReason.get() == null) stop(t,
                    if (monitor.generation.get() != t.generation) Failure.NETWORK_CHANGED else Failure.TIMEOUT)
                return
            }
            notifyUi()
            var result = try {
                when (kind) {
                    ProbeKind.SYSTEM_DNS -> attempt.copy(dns = dns(t, attempt.timeoutMillis))
                    ProbeKind.HTTPS -> https(t, attempt.timeoutMillis, attempt.attemptId, t.start + attempt.startedAfterMillis).let {
                        attempt.copy(https = it.observation, retryTrigger = it.retryTrigger)
                    }
                    ProbeKind.RAW_UDP, ProbeKind.RAW_TCP -> {
                        val transport = if (kind == ProbeKind.RAW_UDP) DnsTransport.UDP else DnsTransport.TCP
                        val probe = RawDnsProbe(t.config.rawDns!!, transport, attempt.timeoutMillis)
                        t.rawProbe = probe
                        val observation = try {
                            if (t.stopReason.get() != null) probe.close()
                            probe.execute()
                        } finally { probe.close(); t.rawProbe = null }
                        attempt.copy(rawDns = observation)
                    }
                }
            } catch (_: Exception) { stoppedAttempt(attempt, Failure.INTERNAL_ERROR, elapsed(t.start)) }
            result = result.copy(finishedAfterMillis = elapsed(t.start),
                retryTrigger = if (failure(result) == Failure.TIMEOUT) RetryTrigger.TIMEOUT else result.retryTrigger)
            var rejectedBecause: Failure? = null
            val accepted = synchronized(this) {
                if (t.stopReason.get() != null) {
                    // stop() set the reason and froze terminal evidence under this same monitor.
                    // I/O has now returned, so clear live lifecycle state without altering that evidence.
                    t.activeAttemptId = null; t.phase = "NONE"
                    false
                }
                else if (remainingBudget(t) <= 0) {
                    // A delayed timer must not let the final callback bypass the absolute run deadline.
                    rejectedBecause = Failure.TIMEOUT
                    false
                } else if (monitor.generation.get() != t.generation) {
                    rejectedBecause = Failure.NETWORK_CHANGED
                    false
                } else {
                    t.activeAttemptId = null; t.phase = "NONE"
                    t.attempts = t.attempts.map { if (it.attemptId == result.attemptId) result else it }
                    // An additional success must never overwrite the first failure in legacy summaries.
                    if (number == 1) {
                        result.dns?.let { t.dns = it }; result.https?.let { t.https = it }
                        result.rawDns?.let { observation ->
                            t.rawDns = t.rawDns.map { if (it.transport == observation.transport) observation else it }
                        }
                    }
                    true
                }
            }
            // Keep the active attempt until stop freezes it; never perform cleanup/snapshot I/O under the lock.
            rejectedBecause?.let { stop(t, it) }
            if (!accepted || number == t.config.maxAttempts || result.retryTrigger == null) return
            if (!waitBeforeRetry(t, result.attemptId)) return
        }
    }

    private fun waitBeforeRetry(t: Token, attemptId: String): Boolean {
        val latch = CountDownLatch(1)
        val started = SystemClock.elapsedRealtime()
        synchronized(this) {
            if (t.stopReason.get() != null) return false
            t.retryLatch = latch; t.backoffAttemptId = attemptId; t.backoffStarted = started
            t.phase = "BACKOFF"
            t.attempts = t.attempts.map { if (it.attemptId == attemptId) it.copy(retryScheduled = true) else it }
            status = "暂时错误后等待最多 500 毫秒，再按相同目标尝试一次；可随时取消。"
        }
        notifyUi()
        val wait = minOf(RETRY_DELAY_MILLIS, remainingBudget(t).coerceAtLeast(0))
        latch.await(wait, TimeUnit.MILLISECONDS)
        synchronized(this) {
            if (t.stopReason.get() == null) t.attempts = t.attempts.map {
                if (it.attemptId == attemptId) it.copy(retryDelayMillis = elapsed(started)) else it
            }
            t.retryLatch = null; t.backoffAttemptId = null; t.phase = "NONE"
        }
        if (t.stopReason.get() != null) return false
        if (remainingBudget(t) <= 0) { stop(t, Failure.TIMEOUT); return false }
        return true
    }

    private fun phase(kind: ProbeKind) = when (kind) {
        ProbeKind.SYSTEM_DNS -> "DNS"; ProbeKind.HTTPS -> "HTTPS"
        ProbeKind.RAW_UDP -> "RAW_UDP"; ProbeKind.RAW_TCP -> "RAW_TCP"
    }
    private fun failure(attempt: ProbeAttempt) = attempt.dns?.failure ?: attempt.https?.failure ?: attempt.rawDns?.failure
    private fun stoppedAttempt(attempt: ProbeAttempt, reason: Failure, ended: Long): ProbeAttempt {
        val execution = if (reason == Failure.CANCELLED) Execution.CANCELLED else Execution.ERROR
        val duration = (ended - attempt.startedAfterMillis).coerceAtLeast(0)
        return when (attempt.probe) {
            ProbeKind.SYSTEM_DNS -> attempt.copy(dns = DnsObservation(execution, durationMillis = duration, failure = reason))
            ProbeKind.HTTPS -> attempt.copy(https = HttpsObservation(execution, durationMillis = duration, failure = reason))
            ProbeKind.RAW_UDP, ProbeKind.RAW_TCP -> attempt.copy(rawDns = RawDnsObservation(
                if (attempt.probe == ProbeKind.RAW_UDP) DnsTransport.UDP else DnsTransport.TCP,
                execution, durationMillis = duration, failure = reason))
        }.copy(finishedAfterMillis = ended)
    }
    fun cancel() { synchronized(this) { token }?.let { t -> timer.execute { stop(t, Failure.CANCELLED) } } }
    private fun stop(t: Token, reason: Failure) {
        synchronized(this) {
            // Once normal publication is claimed, the worker has finished and evidence is frozen.
            // A late cancel must not relabel completion while its metadata snapshot is pending.
            if (token !== t || t.publishing || t.published || !t.stopReason.compareAndSet(null, reason)) return
            // Freeze before cleanup can wake the worker and advance its phase or observations.
            t.terminal = freezeEvidence(t)
            status = "已停止接收结果；正在释放系统网络操作。释放前不会允许新任务。"
        }
        notifyUi()
        t.dnsLatch?.countDown()
        t.retryLatch?.countDown()
        val rawProbe = t.rawProbe
        val dnsCancellation = t.dnsCancellation
        val httpsResources = t.httpsResources
        // Submit cleanup before metadata sampling, which may wait on Android system services.
        // Capture this operation's resources: queued cleanup must never target a later attempt.
        cleanup.execute {
            rawProbe?.close()
            try { dnsCancellation?.cancel() } finally { httpsResources?.close() }
        }
        publish(t)
    }
    /** Called while holding the controller lock; performs no platform or socket I/O. */
    private fun freezeEvidence(t: Token): TerminalEvidence {
        val stop = t.stopReason.get()
        val ended = elapsed(t.start)
        val active = t.attempts.singleOrNull { it.attemptId == t.activeAttemptId }
        val stopped = if (stop != null && active != null) stoppedAttempt(active, stop, ended) else null
        var dns = t.dns; var https = t.https; var rawDns = t.rawDns
        // Only the first attempt owns the aggregate. A stopped retry belongs solely to its own
        // attempt plus the run-level stopReason, leaving the already recorded first failure intact.
        if (stopped?.attemptNumber == 1) {
            stopped.dns?.let { dns = it }
            stopped.https?.let { https = it }
            stopped.rawDns?.let { observation ->
                rawDns = rawDns.map { if (it.transport == observation.transport) observation else it }
            }
        }
        val attempts = t.attempts.map { attempt ->
            when {
                stopped != null && attempt.attemptId == stopped.attemptId -> stopped
                attempt.attemptId == t.backoffAttemptId -> attempt.copy(retryDelayMillis = elapsed(t.backoffStarted))
                else -> attempt
            }
        }
        return TerminalEvidence(dns, https, rawDns.toList(), attempts, Instant.now().toString(), ended)
    }
    private fun publish(t: Token) {
        val frozen = synchronized(this) {
            if (t.publishing || t.published) return
            t.publishing = true
            (t.terminal ?: freezeEvidence(t)).also { t.terminal = it }
        }
        // Never hold the controller lock across synchronous ConnectivityManager calls.
        val after = monitor.snapshot()
        val completed = RunReport(t.id, t.wallStart, frozen.endedAtUtc, frozen.durationMillis, Build.VERSION.SDK_INT, AppIdentity.version, t.config,
            t.before, after, t.stopReason.get() == Failure.NETWORK_CHANGED || t.generation != monitor.generation.get() || t.before != after,
            frozen.dns, frozen.https, rawDns = frozen.rawDns, attempts = frozen.attempts, stopReason = t.stopReason.get())
        synchronized(this) {
            if (token === t) {
                report = completed
                t.published = true
                releaseFinished(t)
            }
        }
        notifyUi()
    }
    /** Publication may finish before cleanup; neither side alone may reopen the run slot. */
    private fun releaseFinished(t: Token) {
        if (token === t && t.workerFinished && t.published) {
            token = null; busy = false
            status = if (t.stopReason.get() != null) "探测已停止。未取得证据的项目保留为观察不足或未执行。"
                else "本次探测结束。请逐项查看证据和局限。"
        }
    }
    private fun dns(t: Token, timeoutMillis: Int): DnsObservation {
        val start = SystemClock.elapsedRealtime()
        val latch = CountDownLatch(1)
        val signal = CancellationSignal()
        val result = AtomicReference<DnsObservation?>(null)
        t.dnsCancellation = signal; t.dnsLatch = latch
        if (t.stopReason.get() != null) return DnsObservation(Execution.CANCELLED, failure = t.stopReason.get())
        try {
            DnsResolver.getInstance().query(null, t.config.dnsHost!!, DnsResolver.FLAG_EMPTY, dnsCallbacks, signal,
                object : DnsResolver.Callback<List<InetAddress>> {
                    override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                        val addresses = answer.mapNotNull { it.hostAddress?.substringBefore('%')?.let(NumericIp::canonical) }.distinct().take(64)
                        result.compareAndSet(null, if (rcode == 0 && addresses.isNotEmpty())
                            DnsObservation(Execution.COMPLETED, addresses, elapsed(start),
                                diagnosticStage = SystemDnsStage.ANSWER_CALLBACK, responseCode = rcode)
                            else DnsObservation(Execution.ERROR, durationMillis = elapsed(start), failure = Failure.DNS_FAILURE,
                                diagnosticStage = SystemDnsStage.ANSWER_CALLBACK, responseCode = rcode))
                        latch.countDown()
                    }
                    override fun onError(error: DnsResolver.DnsException) {
                        result.compareAndSet(null, DnsObservation(Execution.ERROR, durationMillis = elapsed(start), failure = Failure.DNS_FAILURE,
                            diagnosticStage = SystemDnsStage.ERROR_CALLBACK, resolverErrorCode = error.code,
                            systemErrno = (error.cause as? android.system.ErrnoException)?.errno))
                        latch.countDown()
                    }
                })
            val completed = latch.await(timeoutMillis.toLong(), TimeUnit.MILLISECONDS)
            val stopped = t.stopReason.get()
            return when {
                stopped != null -> DnsObservation(if (stopped == Failure.CANCELLED) Execution.CANCELLED else Execution.ERROR, durationMillis = elapsed(start), failure = stopped)
                !completed -> DnsObservation(Execution.ERROR, durationMillis = elapsed(start), failure = Failure.TIMEOUT)
                else -> result.get() ?: DnsObservation(Execution.ERROR, durationMillis = elapsed(start), failure = Failure.DNS_FAILURE)
            }
        } catch (error: Exception) {
            return DnsObservation(Execution.ERROR, durationMillis = elapsed(start), failure = Failure.DNS_FAILURE,
                diagnosticStage = SystemDnsStage.LOCAL_EXCEPTION, exceptionKind = when (error) {
                    is SecurityException -> SystemDnsExceptionKind.SECURITY
                    is IllegalArgumentException -> SystemDnsExceptionKind.INVALID_ARGUMENT
                    is InterruptedException -> SystemDnsExceptionKind.INTERRUPTED
                    else -> SystemDnsExceptionKind.OTHER
                })
        } finally { signal.cancel(); t.dnsCancellation = null; t.dnsLatch = null }
    }
    private data class HttpsResult(val observation: HttpsObservation, val retryTrigger: RetryTrigger? = null)
    private fun https(t: Token, timeoutMillis: Int, requestId: String, start: Long): HttpsResult {
        var code: Int? = null; var tls = false
        val connection = URL(t.config.endpoint!!.requestUrl(requestId)).openConnection() as HttpsURLConnection
        val resources = HttpsResources(connection)
        t.httpsResources = resources
        val state = AtomicReference(HttpsAttemptState.ACTIVE)
        fun remaining(): Int {
            t.stopReason.get()?.let { throw ProbeFailure(it) }
            val left = timeoutMillis.toLong() - elapsed(start)
            if (left <= 0) state.compareAndSet(HttpsAttemptState.ACTIVE, HttpsAttemptState.TIMED_OUT)
            if (state.get() == HttpsAttemptState.TIMED_OUT) throw ProbeFailure(Failure.TIMEOUT)
            return left.coerceAtLeast(1).toInt()
        }
        // Socket read timeouts alone restart for every read. This absolute deadline also asks
        // the platform to unblock headers/body I/O; slow chunks never extend the attempt budget.
        val deadline = timer.schedule({
            if (state.compareAndSet(HttpsAttemptState.ACTIVE, HttpsAttemptState.TIMED_OUT)) {
                cleanup.execute { resources.close() }
            }
        }, (timeoutMillis.toLong() - elapsed(start)).coerceAtLeast(0), TimeUnit.MILLISECONDS)
        try {
            connection.connectTimeout = remaining()
            connection.readTimeout = remaining()
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.requestMethod = "GET"
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("Cache-Control", "no-store")
            connection.setRequestProperty("Connection", "close")
            connection.setRequestProperty("User-Agent", "AndroidProxyDiagnostics/0.5")
            // No custom trust manager, hostname verifier, proxy override, or insecure certificate fallback.
            code = connection.responseCode; tls = true
            remaining()
            if (code in 300..399) throw ProbeFailure(Failure.REDIRECT_REJECTED)
            if (code != 200) throw ProbeFailure(Failure.HTTP_STATUS)
            if (connection.contentType?.substringBefore(';')?.trim()?.lowercase() != "application/json") throw ProbeFailure(Failure.INVALID_ECHO)
            if (!connection.contentEncoding.isNullOrBlank() && connection.contentEncoding != "identity") throw ProbeFailure(Failure.INVALID_ECHO)
            if (connection.contentLengthLong > MAX_BODY) throw ProbeFailure(Failure.RESPONSE_TOO_LARGE)
            val bytes = connection.inputStream.use { input ->
                resources.input = input
                val buffer = ByteArray(1024); val out = ByteArrayOutputStream()
                while (true) {
                    connection.readTimeout = remaining()
                    val n = input.read(buffer)
                    remaining() // Reject an EOF or a final chunk received after the absolute deadline.
                    if (n == -1) break
                    if (out.size() + n > MAX_BODY) throw ProbeFailure(Failure.RESPONSE_TOO_LARGE)
                    out.write(buffer, 0, n)
                }
                out.toByteArray()
            }
            val text = try { Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString() }
                catch (_: Exception) { throw ProbeFailure(Failure.INVALID_ECHO) }
            val echo = try { EchoParser.parse(text, requestId) } catch (_: IllegalArgumentException) { throw ProbeFailure(Failure.INVALID_ECHO) }
            remaining()
            if (!state.compareAndSet(HttpsAttemptState.ACTIVE, HttpsAttemptState.FINISHED)) throw ProbeFailure(Failure.TIMEOUT)
            return HttpsResult(HttpsObservation(Execution.COMPLETED, code, elapsed(start), tls, echo.requestId, echo.sourceIp))
        } catch (e: Exception) {
            val failure = t.stopReason.get() ?: if (state.get() == HttpsAttemptState.TIMED_OUT || elapsed(start) >= timeoutMillis)
                Failure.TIMEOUT else when (e) {
                is ProbeFailure -> e.failure
                is SocketTimeoutException -> Failure.TIMEOUT
                is SSLException -> Failure.TLS_FAILURE
                is IOException -> Failure.IO_FAILURE
                else -> Failure.INTERNAL_ERROR
            }
            return HttpsResult(HttpsObservation(if (failure == Failure.CANCELLED) Execution.CANCELLED else Execution.ERROR,
                code, elapsed(start), tls, failure = failure),
                if (failure == Failure.IO_FAILURE && e is ConnectException) RetryTrigger.CONNECT_FAILURE else null)
        } finally {
            state.compareAndSet(HttpsAttemptState.ACTIVE, HttpsAttemptState.FINISHED)
            deadline.cancel(false)
            try { resources.close() } finally { t.httpsResources = null }
        }
    }
    private enum class HttpsAttemptState { ACTIVE, TIMED_OUT, FINISHED }
    private class HttpsResources(private val connection: HttpsURLConnection) {
        @Volatile var input: InputStream? = null
        // Platform I/O stays outside controller/state locks. Providers may ignore cancellation;
        // the worker retains the run slot until it actually returns and closes these resources.
        fun close() {
            try { connection.disconnect() } catch (_: Exception) { }
            try { input?.close() } catch (_: Exception) { }
        }
    }
    private class ProbeFailure(val failure: Failure) : IOException()
    private data class TerminalEvidence(
        val dns: DnsObservation, val https: HttpsObservation, val rawDns: List<RawDnsObservation>,
        val attempts: List<ProbeAttempt>,
        val endedAtUtc: String, val durationMillis: Long
    )
    private class Token(val config: RunConfig, val before: NetworkSnapshot, val generation: Long) {
        val id = UUID.randomUUID().toString()
        val start = SystemClock.elapsedRealtime()
        val wallStart = Instant.now().toString()
        val stopReason = AtomicReference<Failure?>(null)
        @Volatile var phase = "NONE"
        var attempts: List<ProbeAttempt> = emptyList()
        var activeAttemptId: String? = null
        @Volatile var retryLatch: CountDownLatch? = null
        var backoffAttemptId: String? = null
        var backoffStarted = 0L
        @Volatile var dns = DnsObservation()
        @Volatile var https = HttpsObservation()
        @Volatile var httpsResources: HttpsResources? = null
        @Volatile var dnsCancellation: CancellationSignal? = null
        @Volatile var dnsLatch: CountDownLatch? = null
        @Volatile var rawProbe: RawDnsProbe? = null
        @Volatile var rawDns: List<RawDnsObservation> = buildList {
            config.rawDns?.let {
                if (it.udp) add(RawDnsObservation(DnsTransport.UDP))
                if (it.tcp) add(RawDnsObservation(DnsTransport.TCP))
            }
        }
        var terminal: TerminalEvidence? = null
        var publishing = false
        var published = false
        var workerFinished = false
    }
    companion object {
        private const val MAX_BODY = 4096
        private const val RETRY_DELAY_MILLIS = 500L
        private fun elapsed(start: Long) = SystemClock.elapsedRealtime() - start
    }
}
