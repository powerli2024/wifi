package dev.proxyaudit.android

import dev.proxyaudit.core.*
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class DeepBaselineSessionTest {
    private val sessions = mutableListOf<DeepDiagnosticsSession>()
    private fun session(backend: DeepFakeBackend) = DeepDiagnosticsSession(backend, 5000, 10000).also { sessions += it }
    private fun backend() = DeepFakeBackend().apply {
        websiteFn = { plan -> DeepFixtures.operation { DeepComparisonFixtures.website(plan) } }
    }
    @After fun release() = sessions.forEach(DeepFixtures::shutdown)

    @Test fun baseline_is_process_local_and_plan_does_not_follow_edits_or_new_dns_configuration() {
        val backend = backend(); val session = session(backend)
        assertFalse(session.saveBaseline()); assertNull(session.retestPlan())
        assertTrue(session.start(DeepFixtures.plan(), "ENABLED", "192.0.2.53")); DeepFixtures.await(session)
        val original = session.report!!
        val calls = backend.websiteCalls.get()
        assertEquals(original.id, session.retestPlan()!!.sourceRunId)
        assertFalse(session.retestPlan()!!.usesBaseline)
        assertTrue(session.saveBaseline()); assertNull(session.comparison)
        session.urlDraft = "https://other.example.test/changed"; session.proxyDraft = 2; session.rawDraft = false
        session.clear()
        assertSame(original, session.baseline)
        val plan = session.retestPlan()!!
        assertTrue(plan.usesBaseline); assertEquals(DeepFixtures.plan().url, plan.websitePlan!!.url)
        assertEquals("ENABLED", plan.expectedProxy); assertEquals("192.0.2.53", plan.rawServer)
        assertEquals(calls, backend.websiteCalls.get())
        val inventory = DeepFixtures.inventory().let { it.copy(networks = it.networks.map { n -> n.copy(dnsServers = listOf("192.0.2.54")) }) }
        backend.inventoryFn = { inventory }
        assertTrue(session.start(plan.websitePlan, plan.expectedProxy, plan.rawServer)); DeepFixtures.await(session)
        assertEquals("192.0.2.53", session.report!!.dnsServer)
        assertTrue(session.comparison!!.comparable)
        assertTrue(session.comparison!!.cautions.any { it.contains("配置改变") })
        assertNull(session(backend()).baseline)
    }

    @Test fun comparison_export_is_frozen_before_report_or_baseline_is_replaced() {
        val session = session(backend())
        assertTrue(session.start(DeepFixtures.plan(), "ENABLED", null)); DeepFixtures.await(session)
        assertTrue(session.saveBaseline()); val baselineId = session.baseline!!.id
        val plan = session.retestPlan()!!
        assertTrue(session.start(plan.websitePlan, plan.expectedProxy, plan.rawServer)); DeepFixtures.await(session)
        val currentId = session.report!!.id
        val ticket = session.freezeComparisonExport()!!
        assertNull(session.freezeComparisonExport()); assertNull(session.takeExport("wrong"))
        session.clearBaseline(); session.clear()
        val payload = session.takeExport(ticket.id)!!
        val json = JSONObject(payload)
        assertEquals(baselineId, json.getJSONObject("baseline").getString("runId"))
        assertEquals(currentId, json.getJSONObject("current").getString("runId"))
        for (secret in listOf("secret.example.test", "private-query", "private-path")) assertFalse(payload.contains(secret))
        assertFalse(session.exportPending)
    }

    @Test fun cancelled_run_cannot_replace_good_baseline_and_comparison_stays_blocked() {
        val backend = backend(); val session = session(backend)
        assertTrue(session.start(DeepFixtures.plan(), "ENABLED", null)); DeepFixtures.await(session)
        assertTrue(session.saveBaseline()); val baseline = session.baseline
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        backend.selfFn = { DeepFixtures.operation { entered.countDown(); release.await(3, TimeUnit.SECONDS); DeepFixtures.self() } }
        try {
            assertTrue(session.start(DeepFixtures.plan(), "ENABLED", null))
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertFalse(session.saveBaseline()); assertNull(session.retestPlan())
            session.cancel()
        } finally { release.countDown() }
        DeepFixtures.await(session)
        assertFalse(session.saveBaseline()); assertSame(baseline, session.baseline)
        assertFalse(session.comparison!!.comparable)
        assertTrue(session.comparison!!.changes.isEmpty())
    }
}
