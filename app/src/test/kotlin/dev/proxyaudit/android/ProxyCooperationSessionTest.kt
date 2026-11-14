package dev.proxyaudit.android

import android.os.Looper
import dev.proxyaudit.core.*
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Injected data only: constructing or accepting a plan here never contacts a network. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class ProxyCooperationSessionTest {
    private val sessions = mutableListOf<ProxyCooperationSession>()
    private fun session(backend: ProxyFakeBackend = ProxyFakeBackend()) = ProxyCooperationSession(backend).also { sessions += it }
    @After fun cleanup() { sessions.forEach(ProxyFixtures::shutdown) }

    @Test fun observing_and_export_without_report_do_not_create_operation() {
        val backend = ProxyFakeBackend(); val session = session(backend)
        var notifications = 0
        val observer = { notifications++; Unit }
        session.observe(observer)
        assertEquals(1, notifications); assertEquals(0, backend.operations.get())
        assertFalse(session.busy); assertNull(session.record); assertNull(session.freezeExport())
        session.removeObserver(observer)
    }

    @Test fun unavailable_backend_does_not_create_or_queue_an_operation() {
        val backend = ProxyFakeBackend().apply { unavailableNow = true }; val session = session(backend)
        assertFalse(session.start(ProxyFixtures.plan()))
        assertEquals(0, backend.operations.get()); assertFalse(session.busy); assertNull(session.record)
        backend.unavailableNow = false
        assertTrue(session.start(ProxyFixtures.plan())); ProxyFixtures.await(session)
        assertEquals(1, backend.operations.get())
    }

    @Test fun successful_record_has_common_identity_and_only_redacted_snapshot() {
        val session = session()
        assertTrue(session.start(ProxyFixtures.plan())); ProxyFixtures.await(session)
        val record = session.record!!
        assertEquals(AppIdentity.version, record.appVersion)
        val json = record.toJson(); val parsed = JSONObject(json)
        assertEquals("PROXY_READ_ONLY_COOPERATION", parsed.getString("reportKind"))
        assertEquals(record.id, parsed.getString("runId"))
        assertEquals("NOT_CORRELATED_WITH_THIS_APP", parsed.getJSONObject("apiSnapshot").getString("association"))
        assertFalse(parsed.getJSONObject("apiSnapshot").getBoolean("proxyPathVerified"))
        for (private in ProxyFixtures.PRIVATE_VALUES) assertFalse(private, json.contains(private))
        assertNotNull(parsed.getJSONObject("evidenceEnvelope"))
    }

    @Test fun creation_and_execution_errors_are_sanitized_and_release_session() {
        val backend = ProxyFakeBackend().apply { operationFn = { throw IllegalStateException("fixture-private-token") } }
        val session = session(backend)
        assertFalse(session.start(ProxyFixtures.plan())); assertFalse(session.busy)
        assertFalse(session.status.contains("fixture-private-token"))
        backend.operationFn = { ProxyFixtures.operation { throw IllegalStateException("fixture-private-token") } }
        assertTrue(session.start(ProxyFixtures.plan())); ProxyFixtures.await(session)
        assertNull(session.record); assertFalse(session.status.contains("fixture-private-token"))
        backend.operationFn = { ProxyFixtures.operation { ProxyFixtures.report() } }
        assertTrue(session.start(ProxyFixtures.plan())); ProxyFixtures.await(session)
        assertNotNull(session.record)
    }

    @Test fun cancellation_keeps_slot_until_execution_finishes_and_prevents_export_or_second_start() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val closed = CountDownLatch(1)
        val backend = ProxyFakeBackend().apply { operationFn = {
            object : ProxyCooperationOperation {
                override fun execute(): ProxyCooperationReport {
                    entered.countDown(); release.await(3, TimeUnit.SECONDS)
                    return ProxyFixtures.report().copy(execution = Execution.CANCELLED, failure = ProxyCooperationFailure.CANCELLED)
                }
                override fun close() { closed.countDown() }
            }
        } }
        val session = session(backend)
        try {
            assertTrue(session.start(ProxyFixtures.plan())); assertTrue(entered.await(1, TimeUnit.SECONDS))
            session.cancel(); assertTrue(closed.await(1, TimeUnit.SECONDS))
            assertTrue(session.busy); assertFalse(session.start(ProxyFixtures.plan())); assertNull(session.freezeExport())
            assertFalse(session.clear()); assertEquals(1, backend.operations.get())
        } finally { release.countDown() }
        ProxyFixtures.await(session)
        assertEquals(Execution.CANCELLED, session.record!!.result.execution)
        assertTrue(session.clear()); assertNull(session.record); assertEquals("", session.endpointDraft)
    }

    @Test fun frozen_export_survives_a_new_run_and_wrong_ticket_never_consumes_it() {
        val session = session()
        assertTrue(session.start(ProxyFixtures.plan())); ProxyFixtures.await(session)
        val old = session.record!!.id
        val ticket = session.freezeExport()!!
        assertTrue(ticket.suggestedName.endsWith("-redacted.json"))
        assertNull(session.takeExport("wrong-ticket"))
        assertTrue(session.start(ProxyFixtures.plan())); ProxyFixtures.await(session)
        assertNotEquals(old, session.record!!.id)
        val frozen = session.takeExport(ticket.id)!!
        assertEquals(old, JSONObject(frozen).getString("runId"))
        for (private in ProxyFixtures.PRIVATE_VALUES) assertFalse(private, frozen.contains(private))
        assertNull(session.takeExport(ticket.id))
        val next = session.freezeExport()!!
        assertTrue(next.requestCode > ticket.requestCode)
        session.discardExport("wrong-ticket")
        assertNotNull(session.takeExport(next.id))
    }

    @Test fun clearing_idle_session_discards_report_endpoint_and_pending_export() {
        val session = session(); session.endpointDraft = "https://controller.private.test:9090"
        assertTrue(session.start(ProxyFixtures.plan())); ProxyFixtures.await(session)
        val ticket = session.freezeExport()!!
        assertTrue(session.clear()); assertEquals("", session.endpointDraft)
        assertNull(session.record); assertNull(session.takeExport(ticket.id)); assertNull(session.freezeExport())
    }
}

internal object ProxyFixtures {
    val PRIVATE_VALUES = listOf("controller.private.test", "private-source-ip", "private-destination-ip", "private-host",
        "private-connection", "private-node", "fixture-private-token")
    fun plan() = ProxyCooperationPlan.parse("https://controller.private.test:9090", "fixture-private-token")
    fun report() = ProxyCooperationReport("https://controller.private.test:9090", Execution.COMPLETED, null, 15,
        "fixture-v1", 1, listOf(ProxyConnectionMetadata("private-connection", "tcp", "HTTP", "private-source-ip", 12345,
            "private-destination-ip", 443, "private-host", listOf("private-node"), "Domain")), false,
        listOf(ProxyRequestResult("/version", Execution.COMPLETED, null, 200, 5, 30),
            ProxyRequestResult("/connections", Execution.COMPLETED, null, 200, 10, 100)),
        "只读快照已取得，尚未关联本应用。", listOf("核对同一时间的实验。"), listOf("API 可达不证明代理路径。"))
    fun operation(action: () -> ProxyCooperationReport) = object : ProxyCooperationOperation {
        override fun execute() = action()
        override fun close() = Unit
    }
    fun await(session: ProxyCooperationSession) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
        while (session.busy && System.nanoTime() < until) Thread.sleep(5)
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse("Proxy session did not finish", session.busy)
    }
    fun shutdown(session: ProxyCooperationSession) {
        ProxyCooperationSession::class.java.declaredFields.filter { ExecutorService::class.java.isAssignableFrom(it.type) }
            .forEach { field -> field.isAccessible = true; (field.get(session) as ExecutorService).shutdownNow() }
    }
}

internal class ProxyFakeBackend : ProxyCooperationBackend {
    val operations = AtomicInteger()
    @Volatile var unavailableNow = false
    @Volatile var operationFn: (ProxyCooperationPlan) -> ProxyCooperationOperation = { ProxyFixtures.operation { ProxyFixtures.report() } }
    override fun unavailable() = unavailableNow
    override fun operation(plan: ProxyCooperationPlan): ProxyCooperationOperation { operations.incrementAndGet(); return operationFn(plan) }
}
