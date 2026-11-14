package dev.proxyaudit.qa

import android.content.Context
import dev.proxyaudit.android.DiagnosticsController
import dev.proxyaudit.core.*
import org.junit.Assert.*
import org.junit.Test

class BaselineRetentionTest {
    private fun setReport(controller: DiagnosticsController, report: RunReport) {
        controller.javaClass.getDeclaredField("report").apply { isAccessible = true }.set(controller, report)
    }
    @Test fun empty_and_demo_cannot_be_saved_as_runtime_baseline() {
        val controller = DiagnosticsController(Context())
        assertFalse(controller.pinBaseline())
        controller.showDemo()
        assertFalse(controller.pinBaseline()); assertNull(controller.baseline)
        assertNull(controller.beginComparisonExport(false))
    }
    @Test fun baseline_survives_new_report_and_comparison_export_is_frozen_and_redacted() {
        val controller = DiagnosticsController(Context())
        val before = DemoFixture.report().copy(evidenceOrigin = EvidenceOrigin.ANDROID_RUNTIME)
        val after = before.copy(runId = "next-runtime")
        setReport(controller, before); assertTrue(controller.pinBaseline())
        setReport(controller, after)
        val ticket = controller.beginComparisonExport(false)!!
        assertNull(controller.beginExport(after, true))
        controller.clear()
        assertNull(controller.baseline); assertNull(controller.report)
        assertEquals(ReportComparison.toJson(before, after, false), controller.consumeExport(ticket.requestId))
        assertNull(controller.consumeExport(ticket.requestId))
    }
}
