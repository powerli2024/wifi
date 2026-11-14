package dev.proxyaudit.android

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** JVM loopback only. No public destination, Android emulator, DNS or proxy configuration is used. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class DeviceSelfTestTest {
    @Test fun bounded_loopback_http_timeout_and_refusal_are_distinct_expected_scenarios() {
        val report = DeviceSelfTest(3000).use { it.execute() }
        assertFalse(report.cancelled)
        assertFalse(report.timedOut)
        assertTrue(report.serverTerminated)
        assertEquals(listOf("LOOPBACK_HTTP", "CONTROLLED_READ_TIMEOUT", "CONTROLLED_REFUSAL"), report.checks.map { it.id })
        assertEquals(report.checks.toString(), listOf(SelfTestStatus.PASS, SelfTestStatus.PASS, SelfTestStatus.PASS), report.checks.map { it.status })
        assertTrue(report.durationMillis < 3500)
        assertTrue(report.summary.contains("不证明外网可达"))
        val json = JSONObject(DeviceSelfTest.toJson(report))
        assertEquals("THIS_PROCESS_LOOPBACK_ONLY", json.getString("scope"))
        assertFalse(json.getBoolean("externalNetworkTested"))
        assertFalse(json.getBoolean("tlsTested"))
        assertFalse(json.getBoolean("vpnPathVerified"))
        assertFalse(json.getBoolean("dnsLeakTested"))
    }

    @Test fun close_before_execute_keeps_every_network_scenario_unstarted() {
        val probe = DeviceSelfTest()
        probe.close()
        val report = probe.execute()
        assertTrue(report.cancelled)
        assertTrue(report.serverTerminated)
        assertTrue(report.checks.all { it.status == SelfTestStatus.NOT_STARTED })
        assertTrue(report.checks.all { it.durationMillis == null })
        assertTrue(report.summary.contains("已取消"))
    }

    @Test fun cancellation_closes_owned_sockets_and_stops_remaining_scenarios() {
        val probe = DeviceSelfTest(3000)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit<DeviceSelfTestReport> { probe.execute() }
            val lock = DeviceSelfTest::class.java.getDeclaredField("lock").apply { isAccessible = true }.get(probe)
            val field = DeviceSelfTest::class.java.getDeclaredField("resources").apply { isAccessible = true }
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
            var found = false
            while (System.nanoTime() < until && !future.isDone) {
                @Suppress("UNCHECKED_CAST")
                val active = synchronized(lock) { (field.get(probe) as Set<Closeable>).isNotEmpty() }
                if (active) { found = true; break }
                Thread.sleep(1)
            }
            assertTrue("Fixture resources must be live before cancellation", found)
            probe.close()
            val report = future.get(2, TimeUnit.SECONDS)
            assertTrue(report.cancelled)
            assertTrue(report.serverTerminated)
            assertTrue(report.checks.any { it.status == SelfTestStatus.NOT_STARTED })
            assertFalse(report.checks.all { it.status == SelfTestStatus.PASS })
            @Suppress("UNCHECKED_CAST")
            assertTrue(synchronized(lock) { (field.get(probe) as Set<Closeable>).isEmpty() })
        } finally { probe.close(); executor.shutdownNow() }
    }

    @Test fun repeated_execution_and_invalid_budgets_are_rejected_before_new_work() {
        for (budget in listOf(0, 499, 10001)) {
            try { DeviceSelfTest(budget); fail("Invalid budget accepted") }
            catch (_: IllegalArgumentException) { }
        }
        val probe = DeviceSelfTest().apply { close() }
        probe.execute()
        try { probe.execute(); fail("A second execution was accepted") }
        catch (_: IllegalStateException) { }
    }

    @Test fun cancellation_wakes_client_waiting_for_server_accept_even_if_server_never_signals_ready() {
        val serverEntered = CountDownLatch(1)
        val releaseAccept = CountDownLatch(1)
        val executionThread = AtomicReference<Thread>()
        // Keep the server before accept/register. The TCP backlog accepts the client connection,
        // so its readiness wait can only finish through cancellation, not a server callback.
        val probe = DeviceSelfTest(10_000) { serverEntered.countDown(); releaseAccept.await() }
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit<DeviceSelfTestReport> {
                executionThread.set(Thread.currentThread())
                probe.execute()
            }
            assertTrue("Controlled server must reach the accept handoff", serverEntered.await(2, TimeUnit.SECONDS))
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
            var waiting = false
            while (System.nanoTime() < until && !future.isDone) {
                val trace = executionThread.get()?.stackTrace.orEmpty()
                if (trace.any { it.className == CountDownLatch::class.java.name && it.methodName == "await" } &&
                    trace.any { it.className.startsWith(DeviceSelfTest::class.java.name) }) {
                    waiting = true; break
                }
                Thread.sleep(1)
            }
            assertTrue("Client must be inside the readiness wait before cancellation", waiting)
            probe.close()
            val report = future.get(2, TimeUnit.SECONDS)
            assertTrue(report.cancelled)
            assertFalse(report.timedOut)
            assertTrue(report.serverTerminated)
            assertEquals(SelfTestStatus.PASS, report.checks.single { it.id == "LOOPBACK_HTTP" }.status)
            assertEquals(SelfTestStatus.CANCELLED, report.checks.single { it.id == "CONTROLLED_READ_TIMEOUT" }.status)
            assertEquals(SelfTestStatus.NOT_STARTED, report.checks.single { it.id == "CONTROLLED_REFUSAL" }.status)
            assertEquals("CANCELLED", report.checks.single { it.id == "CONTROLLED_READ_TIMEOUT" }.errorCode)
        } finally {
            releaseAccept.countDown(); probe.close(); executor.shutdownNow()
        }
    }
}
