package dev.proxyaudit.android

import android.os.Looper
import dev.proxyaudit.core.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Injected local values only. No public HTTP/DNS or real loopback operation is launched here. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class DeepDiagnosticsSessionTest {
    private val sessions = mutableListOf<DeepDiagnosticsSession>()
    private fun session(backend: DeepFakeBackend, budget: Long = 5000, monitor: Long = 10000) =
        DeepDiagnosticsSession(backend, budget, monitor).also { sessions += it }
    @After fun releaseExecutors() { sessions.forEach(DeepFixtures::shutdown) }

    @Test fun construction_and_observation_do_not_collect_or_probe_and_local_plan_stays_local() {
        val backend = DeepFakeBackend()
        val session = session(backend)
        session.observe { }
        assertEquals(0, backend.snapshots.get())
        assertEquals(0, backend.inventories.get())
        assertEquals(0, backend.selfCalls.get())
        assertTrue(session.start(null, "UNKNOWN", null))
        DeepFixtures.await(session)
        assertEquals(1, backend.selfCalls.get())
        assertEquals(0, backend.websiteCalls.get())
        assertEquals(0, backend.rawCalls.get())
        assertNull(session.report!!.stopReason)
        assertTrue(session.report!!.findings.any { it.contains("仅做本机") })
    }

    @Test fun raw_requires_domain_plan_and_numeric_server_before_any_collection() {
        val backend = DeepFakeBackend(); val session = session(backend)
        assertFalse(session.start(null, "UNKNOWN", "192.0.2.53"))
        assertFalse(session.start(WebsitePlan.parse("https://192.0.2.1"), "UNKNOWN", "192.0.2.53"))
        assertFalse(session.start(WebsitePlan.parse("https://[2001:db8::1]"), "UNKNOWN", "192.0.2.53"))
        assertFalse(session.start(DeepFixtures.plan(), "UNKNOWN", "dns.example.test"))
        assertFalse(session.start(DeepFixtures.plan(), "arbitrary-private-context", null))
        assertEquals(0, backend.snapshots.get()); assertFalse(session.busy)
    }

    @Test fun initial_snapshot_exception_is_sanitized_and_does_not_leave_slot_busy() {
        val backend = DeepFakeBackend().apply { snapshotFn = { throw IllegalStateException("private exception.example") } }
        val session = session(backend)
        assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", null))
        DeepFixtures.await(session)
        assertEquals("LOCAL_EXECUTION_ERROR", session.report!!.stopReason)
        assertEquals(0, backend.selfCalls.get()); assertEquals(0, backend.websiteCalls.get())
        assertFalse(session.report!!.toJson(true).contains("private exception.example"))
        backend.snapshotFn = { DeepFixtures.snapshot() }
        assertTrue(session.start(null, "UNKNOWN", null)); DeepFixtures.await(session)
    }

    @Test fun cancellation_during_inventory_stops_before_creating_any_probe() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val backend = DeepFakeBackend().apply {
            inventoryFn = { if (inventories.get() == 1) { entered.countDown(); release.await(3, TimeUnit.SECONDS) }; DeepFixtures.inventory() }
        }
        val session = session(backend)
        try {
            assertTrue(session.start(DeepFixtures.plan(), "ENABLED", "192.0.2.53"))
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            session.cancel()
            assertTrue(session.busy)
            assertFalse(session.start(null, "UNKNOWN", null))
        } finally { release.countDown() }
        DeepFixtures.await(session)
        assertEquals("USER_CANCELLED", session.report!!.stopReason)
        assertEquals(0, backend.selfCalls.get()); assertEquals(0, backend.websiteCalls.get()); assertEquals(0, backend.rawCalls.get())
    }

    @Test fun cancel_initiates_cleanup_without_releasing_slot_or_starting_next_stage() {
        val entered = CountDownLatch(1); val closed = CountDownLatch(1); val release = CountDownLatch(1)
        val backend = DeepFakeBackend().apply {
            selfFn = { object : DeepOperation<DeviceSelfTestReport> {
                override fun execute(): DeviceSelfTestReport { entered.countDown(); release.await(3, TimeUnit.SECONDS); return DeepFixtures.self() }
                override fun close() { closed.countDown() }
            } }
        }
        val session = session(backend)
        try {
            assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", "192.0.2.53"))
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            session.cancel()
            assertTrue(closed.await(1, TimeUnit.SECONDS))
            assertTrue(session.busy); assertFalse(session.start(null, "UNKNOWN", null))
            assertEquals(0, backend.websiteCalls.get())
        } finally { release.countDown() }
        DeepFixtures.await(session)
        assertEquals("USER_CANCELLED", session.report!!.stopReason)
        assertEquals(0, backend.websiteCalls.get()); assertEquals(0, backend.rawCalls.get())
        assertTrue(session.report!!.findings.none { it.contains("四项均取得地址") })
    }

    @Test fun blocked_network_observer_does_not_block_deadline_or_cleanup() {
        val observerEntered = CountDownLatch(1); val releaseObserver = CountDownLatch(1)
        val selfEntered = CountDownLatch(1); val closed = CountDownLatch(1)
        val backend = DeepFakeBackend().apply {
            snapshotFn = {
                if (Thread.currentThread().name == "deep-network-observer") {
                    observerEntered.countDown(); releaseObserver.await(3, TimeUnit.SECONDS)
                }; DeepFixtures.snapshot()
            }
            selfFn = { object : DeepOperation<DeviceSelfTestReport> {
                override fun execute(): DeviceSelfTestReport { selfEntered.countDown(); closed.await(3, TimeUnit.SECONDS); return DeepFixtures.self().copy(cancelled = true) }
                override fun close() { closed.countDown() }
            } }
        }
        val session = session(backend, 350, 10)
        try {
            assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", "192.0.2.53"))
            assertTrue(selfEntered.await(2, TimeUnit.SECONDS)); assertTrue(observerEntered.await(2, TimeUnit.SECONDS))
            assertTrue("deadline cleanup must bypass the blocked observer", closed.await(2, TimeUnit.SECONDS))
            DeepFixtures.await(session)
            assertEquals("TOTAL_DEADLINE", session.report!!.stopReason)
            assertEquals(0, backend.websiteCalls.get()); assertEquals(0, backend.rawCalls.get())
        } finally { releaseObserver.countDown() }
    }

    @Test fun late_observer_from_previous_run_cannot_cancel_a_new_run() {
        val oldObserver = CountDownLatch(1); val releaseObserver = CountDownLatch(1); val observerReturned = CountDownLatch(1)
        val secondSelf = CountDownLatch(1); val releaseSecond = CountDownLatch(1)
        val observerCalls = AtomicInteger()
        val backend = DeepFakeBackend().apply {
            snapshotFn = {
                if (Thread.currentThread().name == "deep-network-observer" && observerCalls.incrementAndGet() == 1) {
                    oldObserver.countDown(); releaseObserver.await(3, TimeUnit.SECONDS)
                    observerReturned.countDown(); DeepFixtures.snapshot().copy(networkId = "obsolete-network")
                } else DeepFixtures.snapshot()
            }
            selfFn = { val n = selfCalls.get(); DeepFixtures.operation {
                if (n == 1) assertTrue(oldObserver.await(2, TimeUnit.SECONDS))
                else { secondSelf.countDown(); releaseSecond.await(3, TimeUnit.SECONDS) }
                DeepFixtures.self()
            } }
        }
        val session = session(backend, monitor = 10)
        try {
            assertTrue(session.start(null, "UNKNOWN", null)); DeepFixtures.await(session)
            assertTrue(session.start(null, "UNKNOWN", null)); assertTrue(secondSelf.await(2, TimeUnit.SECONDS))
            releaseObserver.countDown(); assertTrue(observerReturned.await(2, TimeUnit.SECONDS))
            Thread.sleep(30)
            assertTrue(session.busy); assertFalse(session.status.contains("停止"))
        } finally { releaseObserver.countDown(); releaseSecond.countDown() }
        DeepFixtures.await(session); assertNull(session.report!!.stopReason)
    }

    @Test fun changed_snapshot_after_local_stage_stops_website_and_raw() {
        val backend = DeepFakeBackend().apply {
            selfFn = { DeepFixtures.operation {
                snapshotFn = { DeepFixtures.snapshot().copy(configuredDnsServers = listOf("192.0.2.54")) }
                DeepFixtures.self()
            } }
        }
        val session = session(backend)
        assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", "192.0.2.53")); DeepFixtures.await(session)
        assertEquals("NETWORK_CHANGED", session.report!!.stopReason)
        assertEquals(0, backend.websiteCalls.get()); assertEquals(0, backend.rawCalls.get())
    }

    @Test fun proxy_change_in_final_inventory_invalidates_complete_conclusion() {
        val backend = DeepFakeBackend().apply {
            inventoryFn = { DeepFixtures.inventory().let {
                if (inventories.get() > 1) it.copy(defaultProxy = InventoryProxy("changed.private.test", 8080, false, null, emptyList())) else it
            } }
        }
        val session = session(backend)
        assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", null)); DeepFixtures.await(session)
        assertEquals("NETWORK_CHANGED", session.report!!.stopReason)
        assertTrue(session.report!!.findings.none { it == "fixture website success" })
    }

    @Test fun missing_final_inventory_is_unknown_and_not_claimed_as_observed_network_change() {
        val backend = DeepFakeBackend().apply {
            inventoryFn = { if (inventories.get() > 1) throw IllegalStateException("private failure") else DeepFixtures.inventory() }
        }
        val session = session(backend)
        assertTrue(session.start(null, "UNKNOWN", null)); DeepFixtures.await(session)
        assertEquals("NETWORK_OBSERVATION_UNAVAILABLE", session.report!!.stopReason)
        assertNull(session.report!!.after)
        assertTrue(session.report!!.findings.none { it.contains("网络条件改变") })
        assertFalse(session.report!!.toJson(true).contains("private failure"))
    }

    @Test fun raw_mismatch_names_the_protocol_and_truncated_or_cancelled_never_count_as_usable() {
        val backend = DeepFakeBackend().apply { rawFn = { config, transport ->
            DeepFixtures.raw(transport).let {
                if (config.recordType == DnsRecordType.A && transport == DnsTransport.TCP) it.copy(execution = Execution.ERROR, failure = Failure.TIMEOUT, addresses = emptyList())
                else if (config.recordType == DnsRecordType.AAAA && transport == DnsTransport.UDP) it.copy(truncated = true)
                else it
            }
        } }
        val session = session(backend)
        assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", "192.0.2.53")); DeepFixtures.await(session)
        val findings = session.report!!.findings.joinToString()
        assertTrue(findings.contains("UDP 取得地址，TCP 执行错误 TIMEOUT"))
        assertTrue(findings.contains("响应被截断"))
        assertFalse(findings.contains("四项均取得地址"))
        backend.rawFn = { _, transport -> DeepFixtures.raw(transport).copy(execution = Execution.CANCELLED) }
        assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", "192.0.2.53")); DeepFixtures.await(session)
        assertFalse(session.report!!.findings.any { it.contains("四项均取得地址") || it.contains("端口策略") })
    }

    @Test fun four_usable_raw_results_preserve_website_failure_and_prioritize_its_stage() {
        val backend = DeepFakeBackend().apply { websiteFn = { plan -> DeepFixtures.operation {
            DeepFixtures.website(plan).copy(execution = Execution.ERROR, failure = WebsiteFailure.TLS_PEER_IDENTITY,
                stages = listOf(WebsiteStageResult(WebsiteStage.TLS, WebsiteStageStatus.FAILED, "fixed TLS identity error")))
        } } }
        val session = session(backend)
        assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", "192.0.2.53")); DeepFixtures.await(session)
        assertEquals(4, session.report!!.dns.size)
        assertEquals(Execution.ERROR, session.report!!.website!!.execution)
        assertTrue(session.report!!.findings.any { it.contains("四项均取得地址") })
        assertTrue(session.report!!.findings.any { it.contains("不要关闭证书校验") })
        assertEquals(listOf(DnsRecordType.A, DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.AAAA),
            session.report!!.dns.map { it.recordType })
    }

    @Test fun four_raw_successes_with_mixed_website_attempts_prioritize_stability_instead_of_current_failure() {
        val failedStage = WebsiteStageResult(WebsiteStage.CONNECT, WebsiteStageStatus.FAILED, "fixed timeout")
        val first = WebsiteAttemptResult(number = 1, execution = Execution.ERROR, stages = listOf(failedStage),
            durationMillis = 250, failure = WebsiteFailure.TIMEOUT, statusCode = null, tlsVersion = null,
            cipherSuite = null, certificateNotAfterUtc = null, dns = emptyList(), connections = emptyList(),
            bodyBytesRead = 0, bodyTruncated = false, redirectOrigin = null)
        val second = first.copy(number = 2, execution = Execution.COMPLETED, failure = null, statusCode = 200,
            stages = listOf(WebsiteStageResult(WebsiteStage.CONNECT, WebsiteStageStatus.SUCCEEDED, "fixed completed")))
        val backend = DeepFakeBackend().apply { websiteFn = { plan -> DeepFixtures.operation {
            DeepFixtures.website(plan).copy(execution = Execution.ERROR, failure = WebsiteFailure.TIMEOUT,
                stages = listOf(failedStage), attempts = listOf(first, second), summary = "首次失败，附加复核成功")
        } } }
        val session = session(backend)
        assertTrue(session.start(DeepFixtures.plan(), "UNKNOWN", "192.0.2.53")); DeepFixtures.await(session)
        assertTrue(session.report!!.findings.any { it.contains("网站首次在连接阶段失败，附加复核成功") && it.contains("复测稳定性") })
        assertTrue(session.report!!.findings.none { it.contains("网站连接阶段失败：") || it.contains("优先检查代理节点") })
        assertEquals(Execution.ERROR, session.report!!.website!!.execution)
        assertEquals(2, session.report!!.website!!.attempts.size)
    }

    @Test fun export_freezes_old_report_defaults_to_redaction_and_request_codes_are_not_reused() {
        val backend = DeepFakeBackend(); val session = session(backend)
        assertTrue(session.start(DeepFixtures.plan(), "ENABLED", "192.0.2.53")); DeepFixtures.await(session)
        val oldId = session.report!!.id
        val ticket = session.freezeExport()!!
        assertTrue(ticket.suggestedName.endsWith("-redacted.json"))
        assertNull(session.takeExport("wrong-ticket")); assertTrue(session.exportPending)
        session.clear()
        assertTrue(session.start(null, "UNKNOWN", null)); DeepFixtures.await(session)
        val json = session.takeExport(ticket.id)!!
        assertEquals(oldId, JSONObject(json).getString("runId"))
        assertNotEquals(oldId, session.report!!.id)
        for (secret in listOf("secret.example.test", "private-query", "192.0.2.53", "198.51.100.7", "iface-private"))
            assertFalse(secret, json.contains(secret))
        val next = session.freezeExport()!!
        assertTrue(next.requestCode > ticket.requestCode)
        session.discardExport(next.id)
        session.reserveRestoredExportCode(6400)
        assertTrue(session.freezeExport()!!.requestCode > 6400)
    }
}

internal object DeepFixtures {
    const val TIME = "2026-10-22T01:00:00Z"
    fun plan() = WebsitePlan.parse("https://secret.example.test/private-path?token=private-query")
    fun snapshot() = NetworkSnapshot("test-network", listOf("WIFI"), false, true, true,
        listOf("192.0.2.7"), listOf("192.0.2.53"), true, "dns.private.test", true)
    fun inventory(): NetworkInventoryReport {
        val n = InventoryNetwork("test-network", true, TIME, listOf("WIFI", "VPN"),
            mapOf("VALIDATED" to true, "NOT_METERED" to true, "NOT_RESTRICTED" to true), 1000, 500, -60,
            "iface-private", listOf("192.0.2.7/24", "2001:db8::1/64"),
            listOf(InventoryRoute("0.0.0.0/0", "192.0.2.1", "iface-private", true)), listOf("192.0.2.53"),
            null, 1400, true, "dns.private.test", InventoryProxy("proxy.private.test", 8080, false, null, emptyList()), emptyList())
        return NetworkInventoryReport(TIME, TIME, 2, 35, true, true, "test-network", null, n.httpProxy, listOf(n), emptyList())
    }
    fun self() = DeviceSelfTestReport(TIME, TIME, 1, 3000, false, false, true,
        listOf(SelfTestCheck("FIXTURE", "本机受控样本", SelfTestStatus.PASS, 1, "仅框架测试样本")))
    fun website(plan: WebsitePlan) = WebsiteReport(plan, Execution.COMPLETED, emptyList(), emptyList(),
        200, "TLSv1.3", "TLS_AES_128_GCM_SHA256", 1, "fixture website success", emptyList(), emptyList())
    fun raw(transport: DnsTransport) = RawDnsObservation(transport, Execution.COMPLETED,
        durationMillis = 1, responseCode = 0, addresses = listOf("198.51.100.7"))
    fun <T> operation(action: () -> T) = object : DeepOperation<T> {
        override fun execute() = action()
        override fun close() = Unit
    }
    fun await(session: DeepDiagnosticsSession) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
        while (session.busy && System.nanoTime() < until) Thread.sleep(5)
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse("Deep session worker did not finish", session.busy)
        assertNotNull(session.report)
    }
    fun shutdown(session: DeepDiagnosticsSession) {
        for (name in listOf("worker", "scheduler", "networkMonitor", "cleanup"))
            (DeepDiagnosticsSession::class.java.getDeclaredField(name).apply { isAccessible = true }.get(session) as ExecutorService).shutdownNow()
    }
}
internal class DeepFakeBackend : DeepDiagnosticsBackend {
    val snapshots = AtomicInteger(); val inventories = AtomicInteger()
    val selfCalls = AtomicInteger(); val websiteCalls = AtomicInteger(); val rawCalls = AtomicInteger()
    @Volatile var snapshotFn: () -> NetworkSnapshot = { DeepFixtures.snapshot() }
    @Volatile var inventoryFn: () -> NetworkInventoryReport = { DeepFixtures.inventory() }
    @Volatile var selfFn: () -> DeepOperation<DeviceSelfTestReport> = { DeepFixtures.operation { DeepFixtures.self() } }
    @Volatile var websiteFn: (WebsitePlan) -> DeepOperation<WebsiteReport> = { plan -> DeepFixtures.operation { DeepFixtures.website(plan) } }
    @Volatile var rawFn: (RawDnsConfig, DnsTransport) -> RawDnsObservation = { _, transport -> DeepFixtures.raw(transport) }
    override fun controllerBusy() = false
    override fun websitePending() = false
    override fun snapshot(): NetworkSnapshot { snapshots.incrementAndGet(); return snapshotFn() }
    override fun inventory(): NetworkInventoryReport { inventories.incrementAndGet(); return inventoryFn() }
    override fun selfTest(): DeepOperation<DeviceSelfTestReport> { selfCalls.incrementAndGet(); return selfFn() }
    override fun website(plan: WebsitePlan): DeepOperation<WebsiteReport> { websiteCalls.incrementAndGet(); return websiteFn(plan) }
    override fun raw(config: RawDnsConfig, transport: DnsTransport, timeoutMillis: Int): DeepOperation<RawDnsObservation> {
        rawCalls.incrementAndGet(); require(timeoutMillis in 1..4000)
        return DeepFixtures.operation { rawFn(config, transport) }
    }
}

