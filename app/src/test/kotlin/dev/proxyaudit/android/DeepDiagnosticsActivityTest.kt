package dev.proxyaudit.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import com.google.android.material.textfield.TextInputLayout
import com.google.android.material.appbar.MaterialToolbar
import dev.proxyaudit.core.*
import org.junit.Assert.*
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowDialog
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** UI uses an injected offline backend; accepting a dialog never contacts a public target. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class DeepDiagnosticsActivityTest {
    private lateinit var backend: DeepFakeBackend
    private lateinit var session: DeepDiagnosticsSession
    @Before fun setup() {
        backend = DeepFakeBackend()
        backend.websiteFn = { plan -> DeepFixtures.operation { DeepComparisonFixtures.website(plan) } }
        session = DeepDiagnosticsSession(backend, 5000, 10000)
        val app = RuntimeEnvironment.getApplication() as DiagnosticsApplication
        DiagnosticsApplication::class.java.getDeclaredField("deepDiagnostics\$delegate").apply { isAccessible = true }
            .set(app, lazy { session })
    }
    @After fun shutdown() { DeepFixtures.shutdown(session) }
    private fun children(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { children(view.getChildAt(it)) } else emptyList()
    private fun views(activity: DeepDiagnosticsActivity) = children(activity.findViewById(android.R.id.content))
    private fun button(activity: DeepDiagnosticsActivity, label: String) = views(activity).filterIsInstance<Button>().single { it.text.toString() == label }
    private fun input(activity: DeepDiagnosticsActivity) = views(activity).filterIsInstance<EditText>().single { it.tag == "website-url" }
    private fun raw(activity: DeepDiagnosticsActivity) = views(activity).filterIsInstance<CheckBox>().single { it.tag == "deep-raw" }
    private fun tagged(activity: DeepDiagnosticsActivity, tag: String) = views(activity).single { it.tag == tag }
    private fun visibleText(activity: DeepDiagnosticsActivity) = views(activity).filterIsInstance<TextView>()
        .filter { view -> generateSequence(view as View) { it.parent as? View }.all { it.visibility == View.VISIBLE } }
        .joinToString("\n") { it.text.toString() }
    private fun dialog() = ShadowDialog.getLatestDialog() as AlertDialog
    private fun dialogText() = dialog().findViewById<TextView>(android.R.id.message)!!.text.toString()
    private fun idle() { shadowOf(Looper.getMainLooper()).idle() }
    private fun finishedReport() { assertTrue(session.start(null, "UNKNOWN", null)); DeepFixtures.await(session) }
    private fun beginExport(activity: DeepDiagnosticsActivity) {
        button(activity, "导出深度诊断 JSON").performClick(); idle()
        assertEquals("导出脱敏报告", dialog().getButton(AlertDialog.BUTTON_POSITIVE).text.toString())
        dialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); idle()
    }

    @Test fun opening_and_rotation_preserve_only_memory_draft_and_never_run_a_probe() {
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            assertFalse(raw(activity.get()).isChecked)
            input(activity.get()).setText("https://secret.example.test/private-path?token=private-query")
            val state = Bundle(); activity.saveInstanceState(state)
            assertFalse(state.toString().contains("private-query"))
            assertFalse(input(activity.get()).isSaveEnabled)
            assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO, input(activity.get()).importantForAutofill)
            activity.recreate(); idle()
            assertEquals("https://secret.example.test/private-path?token=private-query", input(activity.get()).text.toString())
            assertEquals(0, backend.snapshots.get()); assertEquals(0, backend.selfCalls.get())
            assertNull(session.report); assertFalse(session.busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun local_only_ignores_invalid_url_and_raw_checkbox_and_requires_explicit_confirmation() {
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            input(activity.get()).setText("not a valid URL")
            raw(activity.get()).isChecked = true
            button(activity.get(), "仅检查本机环境（不访问外网）").performClick(); idle()
            assertFalse(dialogText().contains("网站：")); assertFalse(dialogText().contains("原始 DNS："))
            assertEquals(0, backend.snapshots.get())
            dialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertEquals(0, backend.selfCalls.get())
            button(activity.get(), "仅检查本机环境（不访问外网）").performClick(); idle()
            dialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); DeepFixtures.await(session)
            assertEquals(1, backend.selfCalls.get())
            assertEquals(0, backend.websiteCalls.get()); assertEquals(0, backend.rawCalls.get())
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun numeric_url_with_dns_expansion_shows_inline_correction_before_dialog_or_network() {
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            input(activity.get()).setText("https://192.0.2.1/")
            raw(activity.get()).isChecked = true
            button(activity.get(), "开始自动诊断").performClick(); idle()
            val field = views(activity.get()).filterIsInstance<TextInputLayout>().single()
            assertTrue(field.error.toString().contains("数字 IP"))
            assertTrue(field.error.toString().contains("关闭扩展"))
            assertNull(ShadowDialog.getLatestDialog())
            assertEquals(0, backend.snapshots.get()); assertEquals(0, backend.websiteCalls.get())
            raw(activity.get()).isChecked = false
            button(activity.get(), "开始自动诊断").performClick(); idle()
            assertTrue(dialogText().contains("https://192.0.2.1"))
            dialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun details_start_collapsed_and_expand_locally_without_opening_json_or_new_probe() {
        finishedReport()
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            val before = backend.snapshots.get()
            assertEquals(View.GONE, tagged(activity.get(), "deep-section-network").visibility)
            assertEquals(View.GONE, tagged(activity.get(), "deep-section-self").visibility)
            assertFalse(visibleText(activity.get()).contains("MTU：1400"))
            tagged(activity.get(), "deep-toggle-network").performClick()
            tagged(activity.get(), "deep-toggle-self").performClick(); idle()
            val text = visibleText(activity.get())
            for (fact in listOf("WIFI", "VPN", "系统验证：是", "Private DNS：是", "IPv4 1 / IPv6 1",
                "路由：1 条", "MTU：1400", "存在显式代理配置", "符合本机场景预期"))
                assertTrue(fact, text.contains(fact))
            assertTrue(button(activity.get(), "查看网络画像全部字段").isEnabled)
            assertFalse(text.contains(" · PASS"))
            tagged(activity.get(), "deep-toggle-network").performClick(); idle()
            assertEquals(View.GONE, tagged(activity.get(), "deep-section-network").visibility)
            assertEquals(before, backend.snapshots.get()); assertEquals(1, backend.selfCalls.get())
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun all_five_stages_and_export_are_available_before_collapsed_website_evidence() {
        backend.websiteFn = { plan -> DeepFixtures.operation {
            DeepFixtures.website(plan).copy(stages = listOf(
                WebsiteStageResult(WebsiteStage.DNS, WebsiteStageStatus.NOT_OBSERVED, "proxy supplied resolution"),
                WebsiteStageResult(WebsiteStage.CONNECT, WebsiteStageStatus.SUCCEEDED, "connected", 3),
                WebsiteStageResult(WebsiteStage.TLS, WebsiteStageStatus.SUCCEEDED, "verified", 12),
                WebsiteStageResult(WebsiteStage.HTTP, WebsiteStageStatus.SUCCEEDED, "response received", 4),
                WebsiteStageResult(WebsiteStage.BODY, WebsiteStageStatus.PARTIAL, "bounded body", 1)),
                limitations = listOf("long evidence-only explanation"))
        } }
        assertTrue(session.start(DeepFixtures.plan(), "ENABLED", "192.0.2.53")); DeepFixtures.await(session)
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            val table = children(tagged(activity.get(), "deep-stage-table")).filterIsInstance<TextView>()
                .joinToString("\n") { it.text.toString() }
            for (item in listOf("DNS", "连接", "TLS", "HTTP", "正文", "未观测", "部分完成", "12 ms")) assertTrue(item, table.contains(item))
            assertFalse(visibleText(activity.get()).contains("long evidence-only explanation"))
            val export = tagged(activity.get(), "deep-export")
            val result = tagged(activity.get(), "deep-results")
            val parent = export.parent as ViewGroup
            assertSame(parent, result.parent)
            assertTrue(parent.indexOfChild(export) < parent.indexOfChild(result))
            assertTrue(export.isEnabled)
            val toolbar = views(activity.get()).filterIsInstance<MaterialToolbar>().single()
            assertEquals("导出", toolbar.menu.getItem(0).title.toString())
            assertTrue("The fixed toolbar keeps export accessible at any scroll position", toolbar.menu.getItem(0).isEnabled)
            for (key in listOf("website", "network", "self", "dns")) assertEquals(View.GONE, tagged(activity.get(), "deep-section-$key").visibility)
            tagged(activity.get(), "deep-toggle-website").performClick(); idle()
            assertTrue(visibleText(activity.get()).contains("long evidence-only explanation"))
            assertEquals(1, backend.websiteCalls.get()); assertEquals(4, backend.rawCalls.get())
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun expanded_details_survive_rotation_but_collapse_for_a_new_report() {
        finishedReport()
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            tagged(activity.get(), "deep-toggle-network").performClick(); idle()
            activity.recreate(); idle()
            assertEquals(View.VISIBLE, tagged(activity.get(), "deep-section-network").visibility)
            finishedReport(); idle()
            assertEquals(View.GONE, tagged(activity.get(), "deep-section-network").visibility)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun baseline_and_original_plan_retest_require_confirmation_and_ignore_edited_inputs() {
        val received = mutableListOf<String>()
        backend.websiteFn = { plan -> received += plan.url; DeepFixtures.operation { DeepComparisonFixtures.website(plan) } }
        assertTrue(session.start(DeepFixtures.plan(), "ENABLED", "192.0.2.53")); DeepFixtures.await(session)
        val originalId = session.report!!.id
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            button(activity.get(), "保存本次为基线").performClick(); idle()
            assertNull(session.baseline); assertEquals(1, backend.websiteCalls.get())
            dialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertNull(session.baseline)
            button(activity.get(), "保存本次为基线").performClick(); idle()
            dialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); idle()
            assertEquals(originalId, session.baseline!!.id)
            input(activity.get()).setText("https://other.example.test/changed")
            raw(activity.get()).isChecked = false
            button(activity.get(), "按基线原计划复测").performClick(); idle()
            assertTrue(dialogText().contains("https://secret.example.test"))
            assertTrue(dialogText().contains("明文 DNS：192.0.2.53:53"))
            assertTrue(dialogText().contains("不自动替换"))
            assertFalse(dialogText().contains("other.example.test"))
            assertEquals(1, backend.websiteCalls.get())
            dialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertEquals(1, backend.websiteCalls.get())
            button(activity.get(), "按基线原计划复测").performClick(); idle()
            dialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); DeepFixtures.await(session)
            assertEquals(listOf(DeepFixtures.plan().url, DeepFixtures.plan().url), received)
            assertEquals(8, backend.rawCalls.get())
            assertEquals(originalId, session.baseline!!.id)
            assertNotNull(session.comparison)
            assertTrue(button(activity.get(), "导出基线与本次对照 JSON").isEnabled)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun stopped_report_explains_why_it_cannot_replace_a_baseline() {
        backend.snapshotFn = { throw IllegalStateException("offline injected observation failure") }
        assertTrue(session.start(null, "UNKNOWN", null)); DeepFixtures.await(session)
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            assertFalse(button(activity.get(), "保存本次为基线").isEnabled)
            assertTrue(visibleText(activity.get()).contains("本次不能保存为基线"))
            assertNull(session.baseline)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun comparison_export_freezes_both_reports_before_rotation_and_clearing_baseline() {
        assertTrue(session.start(DeepFixtures.plan(), "ENABLED", "192.0.2.53")); DeepFixtures.await(session)
        assertTrue(session.saveBaseline())
        assertTrue(session.start(DeepFixtures.plan(), "ENABLED", "192.0.2.53")); DeepFixtures.await(session)
        val expected = session.comparisonToJson()!!
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            button(activity.get(), "导出基线与本次对照 JSON").performClick(); idle()
            dialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); idle()
            val request = shadowOf(activity.get()).nextStartedActivityForResult
            activity.recreate(); idle(); session.clearBaseline(); session.clear(); idle()
            val target = Uri.parse("content://test.documents/deep-comparison.json")
            val closed = CountDownLatch(1)
            val out = object : ByteArrayOutputStream() { override fun close() { super.close(); closed.countDown() } }
            shadowOf(activity.get().contentResolver).registerOutputStream(target, out)
            shadowOf(activity.get()).callOnActivityResult(request.requestCode, Activity.RESULT_OK, Intent().setData(target))
            assertTrue(closed.await(3, TimeUnit.SECONDS)); idle()
            assertEquals(expected, out.toString("UTF-8"))
            assertTrue(out.toString("UTF-8").contains("NETWORK_DEEP_COMPARISON"))
            assertFalse(out.toString("UTF-8").contains("private-query"))
            assertFalse(session.exportPending)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun redacted_export_survives_rotation_and_clear_and_duplicate_completion_does_not_write_again() {
        finishedReport()
        val expected = session.report!!.toJson()
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            beginExport(activity.get())
            val request = shadowOf(activity.get()).nextStartedActivityForResult
            assertTrue(request.intent.getStringExtra(Intent.EXTRA_TITLE)!!.endsWith("-redacted.json"))
            val state = Bundle(); activity.saveInstanceState(state)
            assertEquals(request.requestCode, state.getInt("deepExportCode"))
            assertTrue(state.getString("deepExport")!!.matches(Regex("[a-f0-9-]{36}")))
            activity.recreate(); idle()
            session.clear(); idle()
            val target = Uri.parse("content://test.documents/deep-rotation.json")
            val closed = CountDownLatch(1)
            val out = object : ByteArrayOutputStream() { override fun close() { super.close(); closed.countDown() } }
            shadowOf(activity.get().contentResolver).registerOutputStream(target, out)
            shadowOf(activity.get()).callOnActivityResult(request.requestCode, Activity.RESULT_OK, Intent().setData(target))
            assertTrue(closed.await(3, TimeUnit.SECONDS)); idle()
            assertEquals(expected, out.toString("UTF-8")); assertFalse(session.exportPending)
            val bytes = out.size()
            shadowOf(activity.get()).callOnActivityResult(request.requestCode, Activity.RESULT_OK, Intent().setData(target))
            idle(); assertEquals(bytes, out.size())
            assertFalse(out.toString("UTF-8").contains("iface-private"))
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun old_picker_callback_cannot_consume_new_ticket_or_write_to_old_destination() {
        finishedReport()
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).setup()
        try {
            beginExport(activity.get())
            val first = shadowOf(activity.get()).nextStartedActivityForResult
            shadowOf(activity.get()).callOnActivityResult(first.requestCode, Activity.RESULT_CANCELED, null); idle()
            beginExport(activity.get())
            val second = shadowOf(activity.get()).nextStartedActivityForResult
            assertNotEquals(first.requestCode, second.requestCode)
            val target = Uri.parse("content://test.documents/stale.json"); val out = ByteArrayOutputStream()
            shadowOf(activity.get().contentResolver).registerOutputStream(target, out)
            shadowOf(activity.get()).callOnActivityResult(first.requestCode, Activity.RESULT_OK, Intent().setData(target)); idle()
            assertTrue(session.exportPending); assertEquals(0, out.size())
            shadowOf(activity.get()).callOnActivityResult(second.requestCode, Activity.RESULT_CANCELED, null); idle()
            assertFalse(session.exportPending)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun restored_missing_process_payload_reserves_request_code_and_never_exports_new_report_through_old_callback() {
        finishedReport()
        val saved = Bundle().apply { putString("deepExport", "00000000-0000-4000-8000-000000000001"); putInt("deepExportCode", 6500) }
        val activity = Robolectric.buildActivity(DeepDiagnosticsActivity::class.java).create(saved).start().resume().visible()
        try {
            beginExport(activity.get())
            val request = shadowOf(activity.get()).nextStartedActivityForResult
            assertTrue(request.requestCode > 6500)
            shadowOf(activity.get()).callOnActivityResult(6500, Activity.RESULT_OK,
                Intent().setData(Uri.parse("content://test.documents/old-process.json"))); idle()
            assertTrue(session.exportPending)
            shadowOf(activity.get()).callOnActivityResult(request.requestCode, Activity.RESULT_CANCELED, null)
            assertFalse(session.exportPending)
        } finally { activity.pause().stop().destroy() }
    }
}

