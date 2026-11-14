package dev.proxyaudit.qa

import android.content.Context
import dev.proxyaudit.android.DiagnosticsController
import dev.proxyaudit.core.*
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

/** Export retention/identity checks on the real controller with the existing fake platform. */
class ExportRetentionTest {
    @Test fun `export serializes immediately so mutable report members and later report changes cannot alter payload`() {
        val original = DemoFixture.report()
        val ips = mutableSetOf("203.0.113.7")
        val addresses = mutableListOf("192.0.2.123")
        val snapshot = original.copy(config = original.config.copy(policy = original.config.policy.copy(expectedSourceIps = ips)),
            networkBefore = original.networkBefore.copy(localAddresses = addresses))
        val expected = ReportExporter.toJson(snapshot, true)
        val controller = DiagnosticsController(Context())
        val ticket = controller.beginExport(snapshot, true)!!
        ips.clear(); ips.add("192.0.2.222")
        addresses.clear(); addresses.add("192.0.2.223")
        controller.showDemo(); controller.clear()
        assertNull(controller.report)
        assertTrue(controller.exportPending)
        assertEquals(expected, controller.consumeExport(ticket.requestId))
        assertFalse(controller.exportPending)
        assertTrue(ticket.suggestedName.contains("DEMO-"))
        assertTrue(ticket.suggestedName.endsWith("-full.json"))
    }

    @Test fun `pending redacted export cannot be replaced or upgraded to full and consumes once`() {
        val snapshot = DemoFixture.report()
        val controller = DiagnosticsController(Context())
        val ticket = controller.beginExport(snapshot, false)!!
        assertNull(controller.beginExport(snapshot, true))
        assertTrue(controller.exportPending)
        val payload = controller.consumeExport(ticket.requestId)!!
        assertEquals(ReportExporter.toJson(snapshot, false), payload)
        assertFalse(payload.contains("203.0.113.7"))
        assertFalse(payload.contains("echo.example.test"))
        assertNull(controller.consumeExport(ticket.requestId))
        assertTrue(ticket.suggestedName.endsWith("-redacted.json"))
        assertFalse(controller.exportPending)
    }

    @Test fun `wrong identity cannot consume or cancel a pending snapshot`() {
        val controller = DiagnosticsController(Context())
        val ticket = controller.beginExport(DemoFixture.report(), false)!!
        for (wrong in listOf("", "unknown", ticket.requestId.uppercase(), ticket.requestId + "x")) {
            if (wrong == ticket.requestId) continue
            assertNull(controller.consumeExport(wrong))
            controller.cancelExport(wrong)
            assertTrue(controller.exportPending)
        }
        assertNotNull(controller.consumeExport(ticket.requestId))
    }

    @Test fun `cancel discards snapshot and retry gets new identity and nonreused code immune to stale ticket`() {
        val controller = DiagnosticsController(Context())
        val first = controller.beginExport(DemoFixture.report(), false)!!
        controller.cancelExport(first.requestId)
        assertFalse(controller.exportPending)
        assertNull(controller.consumeExport(first.requestId))
        val second = controller.beginExport(DemoFixture.report(), true)!!
        assertNotEquals(first.requestId, second.requestId)
        assertNotEquals(first.requestCode, second.requestCode)
        assertTrue(second.requestCode in 0..65535)
        controller.cancelExport(first.requestId)
        assertNull(controller.consumeExport(first.requestId))
        assertTrue(controller.exportPending)
        assertNotNull(controller.consumeExport(second.requestId))
    }

    @Test fun `concurrent duplicate callbacks receive exactly one frozen payload`() {
        val controller = DiagnosticsController(Context())
        val snapshot = DemoFixture.report()
        val ticket = controller.beginExport(snapshot, false)!!
        val pool = Executors.newFixedThreadPool(8)
        try {
            val calls = (1..64).map { pool.submit<String?> { controller.consumeExport(ticket.requestId) } }
            val obtained = calls.map { it.get(2, TimeUnit.SECONDS) }.filterNotNull()
            assertEquals(listOf(ReportExporter.toJson(snapshot, false)), obtained)
            assertFalse(controller.exportPending)
        } finally { pool.shutdownNow() }
    }

    @Test fun `fresh process controller has no old payload and old UUID cannot consume its new payload`() {
        val oldController = DiagnosticsController(Context())
        val old = oldController.beginExport(DemoFixture.report(), true)!!
        val newController = DiagnosticsController(Context())
        assertFalse(newController.exportPending)
        assertNull(newController.consumeExport(old.requestId))
        val fresh = newController.beginExport(DemoFixture.report(), false)!!
        assertNotEquals(old.requestId, fresh.requestId)
        assertNull(newController.consumeExport(old.requestId))
        assertTrue(newController.exportPending)
        assertEquals(ReportExporter.toJson(DemoFixture.report(), false), newController.consumeExport(fresh.requestId))
    }

    @Test fun `restored code is reserved before a fresh process creates a retry ticket`() {
        val oldController = DiagnosticsController(Context())
        val old = oldController.beginExport(DemoFixture.report(), true)!!
        val freshController = DiagnosticsController(Context())
        freshController.reserveRestoredExportCode(old.requestCode)
        val fresh = freshController.beginExport(DemoFixture.report(), false)!!
        assertTrue(fresh.requestCode > old.requestCode)
        assertNotEquals(old.requestId, fresh.requestId)
        assertNull(freshController.consumeExport(old.requestId))
        freshController.cancelExport(old.requestId)
        assertTrue(freshController.exportPending)
        assertNotNull(freshController.consumeExport(fresh.requestId))
    }

    @Test fun `restoration only advances valid request codes and never wraps or lowers high water mark`() {
        val controller = DiagnosticsController(Context())
        for (invalid in listOf(-1, Int.MIN_VALUE, 65536, Int.MAX_VALUE)) controller.reserveRestoredExportCode(invalid)
        val first = controller.beginExport(DemoFixture.report(), false)!!
        assertEquals(21, first.requestCode)
        controller.cancelExport(first.requestId)
        controller.reserveRestoredExportCode(400)
        controller.reserveRestoredExportCode(21)
        val second = controller.beginExport(DemoFixture.report(), false)!!
        assertEquals(401, second.requestCode)
        controller.cancelExport(second.requestId)
        controller.reserveRestoredExportCode(65535)
        controller.reserveRestoredExportCode(100)
        assertNull(controller.beginExport(DemoFixture.report(), false))
        assertFalse(controller.exportPending)
    }

    @Test fun `sixteen bit request code exhaustion refuses reuse rather than wrap`() {
        val controller = DiagnosticsController(Context())
        val field = DiagnosticsController::class.java.getDeclaredField("nextExportRequestCode")
        field.isAccessible = true
        field.setInt(controller, 65535)
        val last = controller.beginExport(DemoFixture.report(), false)!!
        assertEquals(65535, last.requestCode)
        controller.cancelExport(last.requestId)
        assertNull(controller.beginExport(DemoFixture.report(), false))
        assertFalse(controller.exportPending)
    }
}
