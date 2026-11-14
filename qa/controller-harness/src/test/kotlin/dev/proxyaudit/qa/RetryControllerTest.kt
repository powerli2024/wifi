package dev.proxyaudit.qa

import android.content.Context
import android.net.DnsResolver
import android.os.SystemClock
import dev.proxyaudit.android.DiagnosticsController
import dev.proxyaudit.android.NetworkMonitor
import dev.proxyaudit.core.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Before
import org.junit.After
import org.junit.Test

/** Network-free system API tests and bounded loopback only; never Android/VPN path evidence. */
class RetryControllerTest {
    private fun config(attempts: Int = 2) = RunConfig(null, "retry.test",
        ProbePolicy(false, true, emptySet(), true, false), 1000, maxAttempts = attempts)
    private fun waitFor(label: String, predicate: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!predicate() && System.nanoTime() < end) Thread.sleep(5)
        assertTrue(label, predicate())
    }
    private fun answer(call: DnsResolver.Call, rcode: Int = 0) {
        call.executor.execute { call.callback.onAnswer(
            if (rcode == 0) listOf(InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 6))) else emptyList(), rcode) }
    }
    private fun monitor(controller: DiagnosticsController) = DiagnosticsController::class.java.getDeclaredField("monitor")
        .apply { isAccessible = true }.get(controller) as NetworkMonitor
    @Before fun reset() { DnsResolver.reset(); SystemClock.testOffsetMillis = 0 }
    @After fun resetClock() { SystemClock.testOffsetMillis = 0 }

    @Test fun `default single attempt does not retry timeout`() {
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(config(1)))
        waitFor("single timeout did not finish") { !controller.busy }
        assertEquals(1, DnsResolver.calls.get())
        val attempt = controller.report!!.attempts.single()
        assertEquals(1, attempt.attemptNumber); assertEquals(Failure.TIMEOUT, attempt.dns!!.failure)
        assertFalse(attempt.retryScheduled); assertEquals(0L, attempt.retryDelayMillis)
    }

    @Test fun `second DNS success is separate and never replaces first timeout`() {
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(config()))
        waitFor("first DNS call missing") { DnsResolver.lastCall != null }
        val stale = DnsResolver.lastCall!!
        waitFor("second DNS call missing") { DnsResolver.calls.get() == 2 }
        val current = DnsResolver.lastCall!!
        assertNotSame(stale, current)
        answer(stale, 3) // A late callback must remain attached to the timed-out first attempt.
        answer(current)
        waitFor("retry did not finish") { !controller.busy }
        val report = controller.report!!
        assertEquals(Failure.TIMEOUT, report.dns.failure)
        assertEquals(2, report.attempts.size)
        assertEquals(listOf(1, 2), report.attempts.map { it.attemptNumber })
        assertEquals(2, report.attempts.map { it.attemptId }.toSet().size)
        assertEquals(Failure.TIMEOUT, report.attempts[0].dns!!.failure)
        assertEquals(Execution.COMPLETED, report.attempts[1].dns!!.execution)
        assertTrue(report.attempts[0].retryScheduled)
        assertTrue(report.attempts[0].retryDelayMillis >= 450)
        assertEquals(report.attempts[0].dns, report.dns)
        assertEquals(Verdict.INSUFFICIENT, report.dnsPrivacy.verdict)
        assertNull(report.stopReason)
    }

    @Test fun `NXDOMAIN and system parse errors never retry`() {
        for (negativeAnswer in listOf(true, false)) {
            DnsResolver.reset()
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config()))
            waitFor("DNS call missing") { DnsResolver.lastCall != null }
            val call = DnsResolver.lastCall!!
            if (negativeAnswer) answer(call, 3) else call.executor.execute {
                call.callback.onError(DnsResolver.DnsException(DnsResolver.ERROR_PARSE))
            }
            waitFor("non-retryable result did not finish") { !controller.busy }
            assertEquals(1, DnsResolver.calls.get())
            assertNull(controller.report!!.attempts.single().retryTrigger)
            assertFalse(controller.report!!.attempts.single().retryScheduled)
        }
    }

    @Test fun `cancellation in backoff wakes promptly and starts no second call`() {
        val controller = DiagnosticsController(Context())
        val backoff = CountDownLatch(1)
        controller.observe { if (controller.status.contains("等待最多 500")) backoff.countDown() }
        assertTrue(controller.start(config()))
        assertTrue(backoff.await(3, TimeUnit.SECONDS))
        controller.cancel()
        waitFor("backoff cancellation did not finish") { !controller.busy }
        val report = controller.report!!
        assertEquals(Failure.CANCELLED, report.stopReason)
        assertEquals(Failure.TIMEOUT, report.dns.failure) // The first observation is not erased.
        assertEquals(1, report.attempts.size); assertEquals(1, DnsResolver.calls.get())
        assertTrue(report.attempts[0].retryScheduled)
        assertTrue(report.attempts[0].retryDelayMillis in 0..499)
        Thread.sleep(550)
        assertEquals(1, DnsResolver.calls.get()); assertSame(report, controller.report)
    }

    @Test fun `cancellation or network change during second DNS attempt preserves first failure`() {
        for (reason in listOf(Failure.CANCELLED, Failure.NETWORK_CHANGED)) {
            DnsResolver.reset()
            val controller = DiagnosticsController(Context())
            try {
                assertTrue(controller.start(config()))
                waitFor("second DNS call missing") { DnsResolver.calls.get() == 2 }
                val second = DnsResolver.lastCall!!
                if (reason == Failure.CANCELLED) controller.cancel()
                else monitor(controller).generation.incrementAndGet()
                waitFor("second-attempt stop did not finish") { !controller.busy }
                val report = controller.report!!
                assertEquals(reason, report.stopReason)
                assertEquals(2, report.attempts.size)
                assertEquals(Failure.TIMEOUT, report.dns.failure)
                assertEquals(Execution.ERROR, report.dns.execution)
                assertEquals(report.attempts[0].dns, report.dns)
                assertEquals(reason, report.attempts[1].dns!!.failure)
                assertTrue(second.signal.isCanceled)
                answer(second) // An already stopped retry must not replace either frozen observation.
                Thread.sleep(50)
                assertSame(report, controller.report)
                assertEquals(2, DnsResolver.calls.get())
            } finally { controller.cancel() }
        }
    }

    @Test fun `final callback after absolute budget is rejected even before deadline timer runs`() {
        val controller = DiagnosticsController(Context())
        try {
            assertTrue(controller.start(config(1)))
            waitFor("DNS call missing") { DnsResolver.lastCall != null }
            val call = DnsResolver.lastCall!!
            // The real timer is still scheduled twenty seconds away; advance the shared monotonic
            // budget clock and deliver a success now to exercise the result-acceptance boundary.
            SystemClock.testOffsetMillis = 20_100
            answer(call)
            waitFor("expired final callback did not finish") { !controller.busy }
            val report = controller.report!!
            assertEquals(Failure.TIMEOUT, report.stopReason)
            assertEquals(Failure.TIMEOUT, report.dns.failure)
            assertEquals(Execution.ERROR, report.dns.execution)
            assertTrue(report.dns.addresses.isEmpty())
            assertEquals(report.attempts.single().dns, report.dns)
            assertEquals(1, DnsResolver.calls.get())
            assertTrue(report.durationMillis >= report.config.evidenceBudgetMillis)
        } finally { controller.cancel(); SystemClock.testOffsetMillis = 0 }
    }

    @Test fun `cancellation during second raw UDP attempt leaves initial timeout aggregated`() {
        DatagramSocket(0, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { server ->
            server.soTimeout = 4000
            val controller = DiagnosticsController(Context())
            val plan = RunConfig(null, null, ProbePolicy(false, false, emptySet(), true, false), 1000,
                RawDnsConfig("127.0.0.1", server.localPort, "retry.test", tcp = false), 2)
            try {
                assertTrue(controller.start(plan))
                server.receive(DatagramPacket(ByteArray(512), 512))
                server.receive(DatagramPacket(ByteArray(512), 512))
                controller.cancel()
                waitFor("second UDP cancellation did not finish") { !controller.busy }
                val report = controller.report!!
                assertEquals(Failure.CANCELLED, report.stopReason)
                assertEquals(Failure.TIMEOUT, report.rawDns.single().failure)
                assertEquals(report.attempts[0].rawDns, report.rawDns.single())
                assertEquals(Failure.CANCELLED, report.attempts[1].rawDns!!.failure)
                assertEquals(2, report.attempts.size)
            } finally { controller.cancel() }
        }
    }

    @Test fun `network generation change cancels in flight DNS and prevents all remaining probes`() {
        val controller = DiagnosticsController(Context())
        val plan = config().copy(timeoutMillis = 15000, rawDns = RawDnsConfig("127.0.0.1", 9, "retry.test"))
        assertTrue(controller.start(plan))
        waitFor("DNS call missing") { DnsResolver.lastCall != null }
        val call = DnsResolver.lastCall!!
        monitor(controller).generation.incrementAndGet()
        waitFor("network cancellation did not finish") { !controller.busy }
        val report = controller.report!!
        assertEquals(Failure.NETWORK_CHANGED, report.stopReason)
        assertTrue(report.networkChanged); assertTrue(call.signal.isCanceled)
        assertEquals(Failure.NETWORK_CHANGED, report.dns.failure)
        assertEquals(Failure.NETWORK_CHANGED, report.attempts.single().dns!!.failure)
        assertTrue(report.rawDns.all { it.execution == Execution.NOT_STARTED })
        assertEquals(1, DnsResolver.calls.get())
    }

    @Test fun `changed DNS snapshot without callback prevents second attempt`() {
        val before = NetworkMonitor.snapshotValue
        val controller = DiagnosticsController(Context())
        controller.observe {
            if (controller.status.contains("等待最多 500"))
                NetworkMonitor.snapshotValue = before.copy(configuredDnsServers = listOf("192.0.2.54"))
        }
        try {
            assertTrue(controller.start(config()))
            waitFor("changed snapshot run did not finish") { !controller.busy }
            assertEquals(Failure.NETWORK_CHANGED, controller.report!!.stopReason)
            assertEquals(1, DnsResolver.calls.get())
            assertEquals(1, controller.report!!.attempts.size)
        } finally { controller.cancel(); NetworkMonitor.snapshotValue = before }
    }

    @Test fun `all retries and backoff share original twenty second budget`() {
        val controller = DiagnosticsController(Context())
        controller.observe {
            // Advance only the fake monotonic clock; the existing real-deadline test remains separate.
            if (controller.status.contains("等待最多 500")) SystemClock.testOffsetMillis = 18_200
        }
        assertTrue(controller.start(config().copy(policy = config().policy.copy(runHttps = true), endpoint = Endpoint.parse("https://fake.test"))))
        waitFor("budget-limited run did not finish") { !controller.busy }
        val report = controller.report!!
        assertEquals(20000L, report.config.evidenceBudgetMillis)
        assertEquals(Failure.TIMEOUT, report.stopReason)
        assertEquals(2, DnsResolver.calls.get())
        assertTrue(report.attempts[1].timeoutMillis in 1..800)
        assertEquals(Execution.NOT_STARTED, report.https.execution)
        assertTrue(report.durationMillis in 19_900..21_000)
    }

    @Test fun `loopback UDP retry sends once per attempt and preserves initial timeout`() {
        DatagramSocket(0, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { server ->
            server.soTimeout = 4000
            val first = DatagramPacket(ByteArray(512), 512)
            val second = DatagramPacket(ByteArray(512), 512)
            val controller = DiagnosticsController(Context())
            val plan = RunConfig(null, null, ProbePolicy(false, false, emptySet(), true, false), 1000,
                RawDnsConfig("127.0.0.1", server.localPort, "retry.test", tcp = false), 2)
            assertTrue(controller.start(plan))
            server.receive(first); server.receive(second)
            val response = second.data.copyOf(second.length)
            response[2] = 0x81.toByte(); response[3] = 0x83.toByte()
            server.send(DatagramPacket(response, response.size, second.socketAddress))
            waitFor("UDP retry did not finish") { !controller.busy }
            val report = controller.report!!
            assertEquals(60000L, report.config.evidenceBudgetMillis)
            assertEquals(Failure.TIMEOUT, report.rawDns.single().failure)
            assertEquals(listOf(ProbeKind.RAW_UDP, ProbeKind.RAW_UDP), report.attempts.map { it.probe })
            assertEquals(3, report.attempts[1].rawDns!!.responseCode)
            assertArrayEquals(first.data.copyOfRange(2, first.length), second.data.copyOfRange(2, second.length))
            server.soTimeout = 150
            try { server.receive(DatagramPacket(ByteArray(512), 512)); fail("Unexpected third query") }
            catch (_: java.net.SocketTimeoutException) {}
        }
    }
}
