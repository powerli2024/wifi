package dev.proxyaudit.qa

import android.content.Context
import android.net.DnsResolver
import android.os.SystemClock
import dev.proxyaudit.android.DiagnosticsController
import dev.proxyaudit.android.NetworkMonitor
import dev.proxyaudit.core.*
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.Proxy
import java.net.URL
import java.net.URLConnection
import java.net.URLStreamHandler
import java.nio.charset.StandardCharsets
import java.security.Principal
import java.security.cert.Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Before
import org.junit.After
import org.junit.BeforeClass
import org.junit.Test
import javax.net.ssl.HttpsURLConnection

/** Runs production controller logic against fake APIs. This is NOT Android instrumentation. */
class ControllerConcurrencyTest {
    private fun config(dns: Boolean = false, https: Boolean = true, timeout: Int = 1000) = RunConfig(
        if (https) Endpoint.parse("https://fake.test") else null,
        if (dns) "controlled.test" else null,
        ProbePolicy(https, dns, setOf("203.0.113.7"), true, true), timeout)
    private fun waitFor(label: String, timeout: Long = 4000, block: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeout)
        while (!block() && System.nanoTime() < deadline) Thread.sleep(5)
        assertTrue("Timed out waiting for $label", block())
    }
    @Before fun reset() { DnsResolver.reset(); mode = Mode(); modeSequence.clear(); connections.set(0); latest = null; SystemClock.testOffsetMillis = 0 }
    @After fun resetClock() { SystemClock.testOffsetMillis = 0 }

    @Test fun `small successful reads cannot restart the absolute HTTPS attempt deadline`() {
        val reads = AtomicInteger()
        val closes = AtomicInteger()
        mode = Mode(bodyStream = { bytes -> object : ByteArrayInputStream(bytes) {
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                reads.incrementAndGet()
                SystemClock.testOffsetMillis += 400
                return super.read(buffer, offset, minOf(1, length))
            }
            override fun close() { closes.incrementAndGet(); super.close() }
        } })
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(config()))
        waitFor("absolute deadline after small chunks") { !controller.busy }
        val report = controller.report!!
        assertEquals(Failure.TIMEOUT, report.https.failure)
        assertEquals(Execution.ERROR, report.https.execution)
        assertNull(report.https.echoedRequestId)
        assertNull(report.stopReason) // A single-attempt timeout remains separately retryable.
        assertEquals(RetryTrigger.TIMEOUT, report.attempts.single().retryTrigger)
        assertTrue("must stop without reading the entire echo", reads.get() in 1..3)
        assertTrue(closes.get() > 0)
        assertTrue(latest!!.disconnectCalls.get() > 0)
        assertEquals(Verdict.INSUFFICIENT, report.egress.verdict)
    }

    @Test fun `late headers or EOF cannot be accepted when the scheduler has not fired`() {
        for (lateHeaders in listOf(true, false)) {
            SystemClock.testOffsetMillis = 0
            mode = if (lateHeaders) Mode(responseAction = { SystemClock.testOffsetMillis += 1100 })
                else Mode(bodyStream = { bytes -> object : ByteArrayInputStream(bytes) {
                    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                        val count = super.read(buffer, offset, length)
                        if (count < 0) SystemClock.testOffsetMillis += 1100
                        return count
                    }
                } })
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config()))
            waitFor("late HTTPS boundary") { !controller.busy }
            assertEquals(Failure.TIMEOUT, controller.report!!.https.failure)
            assertNull(controller.report!!.https.echoedRequestId)
            assertNull(controller.report!!.https.serverReportedSourceIp)
            assertNull(controller.report!!.stopReason)
        }
    }

    @Test(timeout = 6000) fun `absolute deadline disconnects and closes a pending body stream`() {
        val stream = BlockingBody()
        mode = Mode(bodyStream = { stream })
        val controller = DiagnosticsController(Context())
        try {
            val started = System.nanoTime()
            assertTrue(controller.start(config()))
            assertTrue(stream.entered.await(1, TimeUnit.SECONDS))
            waitFor("deadline resource release", 2500) { !controller.busy }
            val duration = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue("duration=$duration", duration in 900..2400)
            assertEquals(Failure.TIMEOUT, controller.report!!.https.failure)
            assertNull(controller.report!!.stopReason)
            assertTrue(stream.closed.get() > 0)
            assertTrue(latest!!.disconnectCalls.get() > 0)
        } finally { stream.close(); controller.cancel() }
    }

    @Test(timeout = 6000) fun `cancel closes the active HTTPS body and leaves a frozen cancelled report`() {
        val stream = BlockingBody()
        mode = Mode(bodyStream = { stream })
        val controller = DiagnosticsController(Context())
        try {
            assertTrue(controller.start(config(timeout = 15000)))
            assertTrue(stream.entered.await(1, TimeUnit.SECONDS))
            controller.cancel()
            waitFor("cancel resource release", 1500) { !controller.busy }
            val report = controller.report!!
            assertEquals(Failure.CANCELLED, report.stopReason)
            assertEquals(Failure.CANCELLED, report.https.failure)
            assertEquals(Execution.CANCELLED, report.https.execution)
            assertTrue(stream.closed.get() > 0)
            assertEquals(1, report.attempts.size)
            controller.cancel()
            assertSame(report, controller.report)
        } finally { stream.close(); controller.cancel() }
    }

    @Test(timeout = 6000) fun `attempt timeout retries the same endpoint with fresh nonce and cannot close the retry`() {
        val first = BlockingBody()
        val secondRelease = CountDownLatch(1)
        modeSequence.add(Mode(bodyStream = { first }))
        modeSequence.add(Mode(responseGate = secondRelease))
        val controller = DiagnosticsController(Context())
        try {
            assertTrue(controller.start(config().copy(maxAttempts = 2)))
            waitFor("second HTTPS attempt", 2500) { connections.get() == 2 && latest?.responseEntered?.count == 0L }
            val second = latest!!
            assertEquals("old deadline cleanup must only own the old connection", 0, second.disconnectCalls.get())
            secondRelease.countDown()
            waitFor("retry completed") { !controller.busy }
            val report = controller.report!!
            assertNull(report.stopReason)
            assertEquals(2, report.attempts.size)
            assertEquals(Failure.TIMEOUT, report.https.failure)
            assertEquals(RetryTrigger.TIMEOUT, report.attempts.first().retryTrigger)
            assertTrue(report.attempts.first().retryScheduled)
            assertEquals(Execution.COMPLETED, report.attempts.last().https!!.execution)
            assertEquals(report.attempts.last().attemptId, report.attempts.last().https!!.echoedRequestId)
            assertNotEquals(report.runId, report.attempts.last().attemptId)
            assertEquals(Verdict.INSUFFICIENT, report.egress.verdict)
        } finally { first.close(); secondRelease.countDown(); controller.cancel() }
    }

    @Test fun `explicit HTTPS retry preserves failure and uses a distinct second nonce`() {
        for (exception in listOf(java.net.ConnectException("PRIVATE-CONNECT-ERROR"), java.net.SocketTimeoutException("PRIVATE-TIMEOUT"))) {
            connections.set(0)
            modeSequence.add(Mode(responseException = exception)); modeSequence.add(Mode())
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config().copy(maxAttempts = 2)))
            waitFor("HTTPS retry") { !controller.busy }
            val report = controller.report!!
            assertEquals(2, connections.get()); assertEquals(2, report.attempts.size)
            assertEquals(Execution.ERROR, report.https.execution)
            assertEquals(report.attempts.first().https, report.https)
            assertEquals(Execution.COMPLETED, report.attempts.last().https!!.execution)
            assertEquals(report.runId, report.attempts.first().attemptId)
            assertNotEquals(report.runId, report.attempts.last().attemptId)
            assertEquals(report.attempts.last().attemptId, report.attempts.last().https!!.echoedRequestId)
            assertEquals(Verdict.INSUFFICIENT, report.egress.verdict)
            assertFalse(ReportExporter.toJson(report, true).contains("PRIVATE-"))
        }
    }

    @Test fun `TLS generic IO HTTP and parser failures are not retried even when enabled`() {
        for (nextMode in listOf(Mode(responseException = javax.net.ssl.SSLHandshakeException("fixture")),
            Mode(responseException = java.io.IOException()), Mode(status = 429), Mode(wrongNonce = true))) {
            connections.set(0); mode = nextMode
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config().copy(maxAttempts = 2)))
            waitFor("non-retryable HTTPS failure") { !controller.busy }
            assertEquals(1, connections.get())
            assertNull(controller.report!!.attempts.single().retryTrigger)
            assertFalse(controller.report!!.attempts.single().retryScheduled)
        }
    }

    @Test fun `construction demo and clear never open network`() {
        val controller = DiagnosticsController(Context())
        assertNull(controller.report); assertFalse(controller.busy)
        controller.showDemo()
        assertEquals(EvidenceOrigin.SYNTHETIC_FIXTURE, controller.report!!.evidenceOrigin)
        assertTrue(controller.isDemo)
        controller.clear()
        assertNull(controller.report)
        assertEquals(0, connections.get()); assertEquals(0, DnsResolver.calls.get())
    }

    @Test fun `controlled happy path uses exact fresh nonce and network default semantics`() {
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(config()))
        waitFor("HTTPS completion") { !controller.busy }
        val report = controller.report!!
        assertEquals(Execution.COMPLETED, report.https.execution)
        assertEquals(Verdict.MATCH, report.egress.verdict)
        assertEquals(EvidenceOrigin.ANDROID_RUNTIME, report.evidenceOrigin) // The source's value, not a runtime verification claim.
        assertEquals(report.runId, latest!!.url.query.substringAfter("requestId="))
        assertEquals(report.runId, report.https.echoedRequestId)
        assertFalse(latest!!.instanceFollowRedirects); assertFalse(latest!!.useCaches)
        assertEquals("no-store", latest!!.requestProperties["Cache-Control"]!!.single())
        assertEquals("close", latest!!.requestProperties["Connection"]!!.single())
        assertEquals("identity", latest!!.requestProperties["Accept-Encoding"]!!.single())
        assertTrue(latest!!.readTimeout in 1..1000); assertTrue(latest!!.connectTimeout in 1..1000)
        val firstId = report.runId
        assertTrue(controller.start(config()))
        waitFor("second HTTPS completion") { !controller.busy }
        assertNotEquals(firstId, controller.report!!.runId); assertEquals(2, connections.get())
    }

    @Test fun `wrong nonce redirect oversized malformed utf8 and non JSON cannot match`() {
        val modes = listOf(
            Mode(responseException = javax.net.ssl.SSLHandshakeException("PRIVATE-EXCEPTION-TOKEN")) to Failure.TLS_FAILURE,
            Mode(responseException = java.net.SocketTimeoutException("PRIVATE-EXCEPTION-TOKEN")) to Failure.TIMEOUT,
            Mode(responseException = java.io.IOException("PRIVATE-EXCEPTION-TOKEN")) to Failure.IO_FAILURE,
            Mode(responseException = IllegalStateException("PRIVATE-EXCEPTION-TOKEN")) to Failure.INTERNAL_ERROR,
            Mode(wrongNonce = true) to Failure.INVALID_ECHO,
            Mode(status = 302) to Failure.REDIRECT_REJECTED,
            Mode(contentLength = 4097) to Failure.RESPONSE_TOO_LARGE,
            Mode(body = byteArrayOf(0xc3.toByte(), 0x28)) to Failure.INVALID_ECHO,
            Mode(contentType = "text/html") to Failure.INVALID_ECHO,
            Mode(contentEncoding = "gzip") to Failure.INVALID_ECHO,
            Mode(body = ByteArray(4097) { 32 }, contentLength = -1) to Failure.RESPONSE_TOO_LARGE)
        for ((nextMode, expected) in modes) {
            mode = nextMode
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config()))
            waitFor("failure $expected") { !controller.busy }
            assertEquals(expected, controller.report!!.https.failure)
            assertEquals(Execution.ERROR, controller.report!!.https.execution)
            assertEquals(Verdict.INSUFFICIENT, controller.report!!.egress.verdict)
            assertFalse(ReportExporter.toJson(controller.report!!, true).contains("PRIVATE-EXCEPTION-TOKEN"))
            assertFalse(controller.status.contains("PRIVATE-EXCEPTION-TOKEN"))
            if (nextMode.responseException != null) assertFalse(controller.report!!.https.tlsValidated)
        }
    }

    @Test fun `cancel publishes promptly and rejects overlap until blocked cleanup releases`() {
        val release = CountDownLatch(1)
        mode = Mode(responseGate = release, disconnectGate = release)
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(config(timeout = 15000)))
        waitFor("blocked HTTPS") { latest?.responseEntered?.count == 0L }
        val started = System.nanoTime()
        controller.cancel()
        waitFor("cancelled evidence", 1000) { controller.report != null }
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 1000)
        val report = controller.report!!
        assertEquals(Execution.CANCELLED, report.https.execution)
        assertEquals(Failure.CANCELLED, report.https.failure)
        assertEquals(Verdict.INSUFFICIENT, report.egress.verdict)
        assertTrue(controller.busy); assertFalse(controller.start(config()))
        controller.showDemo(); assertFalse(controller.isDemo)
        controller.clear(); assertSame(report, controller.report)
        release.countDown()
        waitFor("resource release") { !controller.busy }
        assertSame("late worker cannot overwrite stopped evidence", report, controller.report)
        mode = Mode()
        assertTrue(controller.start(config()))
        waitFor("next run") { !controller.busy }
        assertNotEquals(report.runId, controller.report!!.runId)
    }

    @Test(timeout = 10000) fun `cancel starts cleanup despite blocked snapshot and keeps slot until worker releases`() {
        val responseRelease = CountDownLatch(1)
        val disconnectRelease = CountDownLatch(1)
        val snapshot = NetworkMonitor.SnapshotGate()
        val callers = java.util.concurrent.Executors.newSingleThreadExecutor()
        mode = Mode(responseGate = responseRelease, disconnectGate = disconnectRelease)
        val controller = DiagnosticsController(Context())
        try {
            assertTrue(controller.start(config(timeout = 15000)))
            waitFor("blocked HTTPS response") { latest?.responseEntered?.count == 0L }
            val connection = latest!!
            NetworkMonitor.snapshotGate = snapshot
            controller.cancel()
            assertTrue("terminal metadata was not requested", snapshot.entered.await(1, TimeUnit.SECONDS))
            assertTrue("cleanup must start before metadata returns", connection.disconnectEntered.await(1, TimeUnit.SECONDS))
            assertNull(controller.report)
            assertTrue(controller.busy)
            // A stalled system snapshot must not retain the controller monitor or freeze UI calls.
            assertFalse(callers.submit<Boolean> { controller.start(config()) }.get(1, TimeUnit.SECONDS))
            callers.submit { controller.cancel(); controller.clear() }.get(1, TimeUnit.SECONDS)

            snapshot.release.countDown()
            waitFor("frozen cancellation report") { controller.report != null }
            val stopped = controller.report!!
            assertEquals(Execution.CANCELLED, stopped.https.execution)
            assertEquals(Failure.CANCELLED, stopped.https.failure)
            assertTrue("publication alone must not release a running worker", controller.busy)
            assertFalse(controller.start(config()))

            responseRelease.countDown()
            waitFor("worker reached its own disconnect") { connection.disconnectCalls.get() >= 2 }
            assertTrue("worker still blocked in disconnect", controller.busy)
            assertSame(stopped, controller.report)
            disconnectRelease.countDown()
            waitFor("worker release") { !controller.busy }
            assertSame(stopped, controller.report)
            assertEquals("only one terminal snapshot may publish", 1, snapshot.calls.get())

            NetworkMonitor.snapshotGate = null
            mode = Mode()
            assertTrue(controller.start(config()))
            waitFor("next run after cleanup") { !controller.busy }
            assertNotEquals(stopped.runId, controller.report!!.runId)
        } finally {
            snapshot.release.countDown()
            responseRelease.countDown()
            disconnectRelease.countDown()
            NetworkMonitor.snapshotGate = null
            controller.cancel()
            callers.shutdownNow()
        }
    }

    @Test(timeout = 8000) fun `cancel wakes system DNS while terminal metadata is blocked and never starts HTTPS`() {
        val snapshot = NetworkMonitor.SnapshotGate()
        val controller = DiagnosticsController(Context())
        try {
            assertTrue(controller.start(config(dns = true, timeout = 15000)))
            waitFor("pending system DNS") { DnsResolver.lastCall != null }
            val call = DnsResolver.lastCall!!
            NetworkMonitor.snapshotGate = snapshot
            controller.cancel()
            assertTrue(snapshot.entered.await(1, TimeUnit.SECONDS))
            waitFor("DNS cancellation without metadata") { call.signal.isCanceled }
            assertNull(controller.report)
            assertTrue(controller.busy)
            assertEquals(0, connections.get())
            snapshot.release.countDown()
            waitFor("DNS worker completion") { !controller.busy }
            assertEquals(Execution.CANCELLED, controller.report!!.dns.execution)
            assertEquals(Failure.CANCELLED, controller.report!!.dns.failure)
            assertEquals(Execution.NOT_STARTED, controller.report!!.https.execution)
            assertEquals(0, connections.get())
            assertEquals(1, snapshot.calls.get())
        } finally {
            snapshot.release.countDown()
            NetworkMonitor.snapshotGate = null
            controller.cancel()
        }
    }

    @Test(timeout = 8000) fun `late cancel during frozen normal publication preserves completed result and status`() {
        val responseRelease = CountDownLatch(1)
        val snapshot = NetworkMonitor.SnapshotGate()
        mode = Mode(responseGate = responseRelease)
        val controller = DiagnosticsController(Context())
        try {
            assertTrue(controller.start(config()))
            waitFor("pending normal response") { latest?.responseEntered?.count == 0L }
            NetworkMonitor.snapshotGate = snapshot
            responseRelease.countDown()
            assertTrue("normal publication did not enter metadata sampling", snapshot.entered.await(1, TimeUnit.SECONDS))
            assertNull(controller.report)
            assertTrue(controller.busy)
            controller.cancel()
            // FIFO barrier proves the public cancel task ran while metadata remained blocked.
            val timer = DiagnosticsController::class.java.getDeclaredField("timer")
                .apply { isAccessible = true }.get(controller) as java.util.concurrent.ScheduledExecutorService
            timer.submit {}.get(1, TimeUnit.SECONDS)
            assertTrue(controller.busy)
            assertNull(controller.report)
            snapshot.release.countDown()
            waitFor("completed normal publication") { !controller.busy }
            assertEquals(Execution.COMPLETED, controller.report!!.https.execution)
            assertNull(controller.report!!.https.failure)
            assertEquals(Verdict.MATCH, controller.report!!.egress.verdict)
            assertEquals("本次探测结束。请逐项查看证据和局限。", controller.status)
            assertEquals(1, snapshot.calls.get())
        } finally {
            snapshot.release.countDown()
            responseRelease.countDown()
            NetworkMonitor.snapshotGate = null
            controller.cancel()
        }
    }

    @Test fun `caller mutation cannot change the frozen expected address policy mid run`() {
        val release = CountDownLatch(1)
        mode = Mode(responseGate = release)
        val callerIps = mutableSetOf("203.0.113.7")
        val input = config().let { it.copy(policy = it.policy.copy(expectedSourceIps = callerIps)) }
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(input))
        waitFor("pending HTTPS") { latest?.responseEntered?.count == 0L }
        callerIps.clear(); callerIps.add("192.0.2.200")
        release.countDown()
        waitFor("frozen-config run") { !controller.busy }
        assertEquals(setOf("203.0.113.7"), controller.report!!.config.policy.expectedSourceIps)
        assertEquals(Verdict.MATCH, controller.report!!.egress.verdict)
    }

    @Test fun `visible link changes prevent match even before callback generation updates`() {
        val before = dev.proxyaudit.android.NetworkMonitor.snapshotValue
        val release = CountDownLatch(1)
        try {
            mode = Mode(responseGate = release)
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config()))
            waitFor("pending response") { latest?.responseEntered?.count == 0L }
            // Same network handle; a delayed OS callback has not incremented generation.
            dev.proxyaudit.android.NetworkMonitor.snapshotValue =
                before.copy(configuredDnsServers = listOf("192.0.2.53"), privateDnsActive = true)
            release.countDown()
            waitFor("changed link completion") { !controller.busy }
            assertTrue(controller.report!!.networkChanged)
            assertEquals(Verdict.INSUFFICIENT, controller.report!!.egress.verdict)
        } finally {
            release.countDown()
            dev.proxyaudit.android.NetworkMonitor.snapshotValue = before
        }
    }

    @Test fun `concurrent repeated starts reserve exactly one slot and late cancel preserves result`() {
        val release = CountDownLatch(1)
        mode = Mode(responseGate = release)
        val controller = DiagnosticsController(Context())
        val accepted = AtomicInteger(0)
        val pool = java.util.concurrent.Executors.newFixedThreadPool(8)
        try {
            val jobs = (1..64).map { pool.submit { if (controller.start(config())) accepted.incrementAndGet() } }
            jobs.forEach { it.get(2, TimeUnit.SECONDS) }
            assertEquals(1, accepted.get())
            waitFor("single pending HTTPS") { latest?.responseEntered?.count == 0L }
            assertEquals(1, connections.get())
            release.countDown()
            waitFor("single completion") { !controller.busy }
            val completed = controller.report!!
            controller.cancel()
            Thread.sleep(50)
            assertSame(completed, controller.report)
            assertEquals(Verdict.MATCH, completed.egress.verdict)
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun `DNS timeout is bounded cancelled and not converted into privacy success`() {
        val controller = DiagnosticsController(Context())
        val started = System.nanoTime()
        assertTrue(controller.start(config(dns = true, https = false)))
        waitFor("DNS timeout", 2500) { !controller.busy }
        val duration = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertTrue("duration=$duration", duration in 900..2400)
        assertEquals(Execution.ERROR, controller.report!!.dns.execution)
        assertEquals(Failure.TIMEOUT, controller.report!!.dns.failure)
        assertTrue(DnsResolver.lastCall!!.signal.isCanceled)
        assertEquals(Verdict.INSUFFICIENT, controller.report!!.dnsPrivacy.verdict)
        assertEquals(Verdict.NOT_RUN, controller.report!!.egress.verdict)
        assertEquals(0, connections.get())
    }

    @Test fun `late DNS callback after cancellation cannot alter immutable report or start HTTPS`() {
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(config(dns = true)))
        waitFor("pending DNS") { DnsResolver.lastCall != null }
        val stale = DnsResolver.lastCall!!
        controller.cancel()
        waitFor("cancel complete") { !controller.busy }
        val stopped = controller.report!!
        assertEquals(Execution.CANCELLED, stopped.dns.execution)
        assertEquals(Execution.NOT_STARTED, stopped.https.execution)
        stale.executor.execute { stale.callback.onAnswer(listOf(java.net.InetAddress.getByAddress(byteArrayOf(1, 2, 3, 4))), 0) }
        Thread.sleep(60)
        assertSame(stopped, controller.report); assertEquals(0, connections.get())
        assertTrue(stale.signal.isCanceled)
    }

    @Test fun `global deadline publishes no match even if platform response ignores timeout`() {
        val release = CountDownLatch(1)
        mode = Mode(responseGate = release, disconnectGate = release)
        val controller = DiagnosticsController(Context())
        val started = System.nanoTime()
        assertTrue(controller.start(config(timeout = 15000)))
        waitFor("global 20 second deadline", 22000) { controller.report != null }
        val duration = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertTrue("duration=$duration", duration in 19500..21500)
        val stopped = controller.report!!
        assertEquals(Execution.ERROR, stopped.https.execution)
        assertEquals(Failure.TIMEOUT, stopped.https.failure)
        assertEquals(Verdict.INSUFFICIENT, stopped.egress.verdict)
        assertTrue(controller.busy); assertFalse(controller.start(config()))
        release.countDown()
        waitFor("late resource release") { !controller.busy }
        assertSame(stopped, controller.report)
    }

    data class Mode(
        val status: Int = 200, val contentType: String = "application/json; charset=utf-8", val contentEncoding: String? = null,
        val contentLength: Long = -1, val wrongNonce: Boolean = false, val body: ByteArray? = null,
        val responseGate: CountDownLatch? = null, val disconnectGate: CountDownLatch? = null, val responseException: Exception? = null,
        val bodyStream: ((ByteArray) -> InputStream)? = null, val responseAction: (() -> Unit)? = null)
    private class BlockingBody : InputStream() {
        val entered = CountDownLatch(1)
        val closed = AtomicInteger()
        private val release = CountDownLatch(1)
        override fun read(): Int { entered.countDown(); release.await(4, TimeUnit.SECONDS); return -1 }
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int = read()
        override fun close() { closed.incrementAndGet(); release.countDown() }
    }
    private class FakeConnection(url: URL, val mode: Mode) : HttpsURLConnection(url) {
        val responseEntered = CountDownLatch(1)
        val disconnectEntered = CountDownLatch(1)
        val disconnectCalls = AtomicInteger()
        override fun getResponseCode(): Int { responseEntered.countDown(); mode.responseGate?.await(30, TimeUnit.SECONDS); mode.responseException?.let { throw it }; mode.responseAction?.invoke(); return mode.status }
        override fun getContentType() = mode.contentType
        override fun getContentEncoding() = mode.contentEncoding
        override fun getContentLengthLong() = mode.contentLength
        override fun getInputStream(): InputStream {
            val nonce = if (mode.wrongNonce) "old-id" else url.query.substringAfter("requestId=")
            val bytes = mode.body ?: "{\"schemaVersion\":1,\"requestId\":\"$nonce\",\"observedSourceIp\":\"203.0.113.7\"}".toByteArray(StandardCharsets.UTF_8)
            return mode.bodyStream?.invoke(bytes) ?: ByteArrayInputStream(bytes)
        }
        override fun disconnect() {
            disconnectCalls.incrementAndGet(); disconnectEntered.countDown()
            mode.disconnectGate?.await(30, TimeUnit.SECONDS)
        }
        override fun connect() {}
        override fun usingProxy() = false
        override fun getCipherSuite() = "FAKE-NO-TLS"
        override fun getLocalCertificates(): Array<Certificate>? = null
        override fun getServerCertificates(): Array<Certificate> = emptyArray()
        override fun getPeerPrincipal(): Principal? = null
        override fun getLocalPrincipal(): Principal? = null
    }
    companion object {
        private var mode = Mode()
        private val modeSequence = java.util.concurrent.ConcurrentLinkedQueue<Mode>()
        private val connections = AtomicInteger(0)
        @Volatile private var latest: FakeConnection? = null
        @BeforeClass @JvmStatic fun installNetworkFreeHandler() {
            URL.setURLStreamHandlerFactory { protocol ->
                if (protocol != "https") null else object : URLStreamHandler() {
                    override fun openConnection(url: URL): URLConnection {
                        require(url.host == "fake.test") { "No external network is allowed by the QA harness" }
                        connections.incrementAndGet()
                        return FakeConnection(url, modeSequence.poll() ?: mode).also { latest = it }
                    }
                    override fun openConnection(url: URL, proxy: Proxy): URLConnection = throw AssertionError("Explicit proxy bypass is not allowed")
                }
            }
        }
    }
}
