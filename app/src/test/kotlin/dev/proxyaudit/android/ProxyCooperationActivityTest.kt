package dev.proxyaudit.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
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

/** The only backend here is a fake; accepting the confirmation never performs real network I/O. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class ProxyCooperationActivityTest {
    private lateinit var backend: ProxyFakeBackend
    private lateinit var session: ProxyCooperationSession
    @Before fun setup() {
        backend = ProxyFakeBackend(); session = ProxyCooperationSession(backend)
        val app = RuntimeEnvironment.getApplication() as DiagnosticsApplication
        DiagnosticsApplication::class.java.getDeclaredField("proxyCooperation\$delegate").apply { isAccessible = true }.set(app, lazy { session })
    }
    @After fun shutdown() { ProxyFixtures.shutdown(session) }
    private fun children(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { children(view.getChildAt(it)) } else emptyList()
    private fun views(activity: ProxyCooperationActivity) = children(activity.findViewById(android.R.id.content))
    private fun button(activity: ProxyCooperationActivity, label: String) = views(activity).filterIsInstance<Button>().single { it.text.toString() == label }
    private fun input(activity: ProxyCooperationActivity, tag: String) = views(activity).filterIsInstance<EditText>().single { it.tag == tag }
    private fun endpoint(activity: ProxyCooperationActivity) = input(activity, "proxy-endpoint")
    private fun secret(activity: ProxyCooperationActivity) = input(activity, "proxy-secret")
    private fun dialog() = ShadowDialog.getLatestDialog() as AlertDialog
    private fun idle() = shadowOf(Looper.getMainLooper()).idle()
    private fun report() { assertTrue(session.start(ProxyFixtures.plan())); ProxyFixtures.await(session) }
    private fun export(activity: ProxyCooperationActivity) { button(activity, "导出脱敏快照").performClick(); idle() }

    @Test fun open_and_rotation_do_not_probe_or_persist_secret_and_keep_only_memory_endpoint() {
        val activity = Robolectric.buildActivity(ProxyCooperationActivity::class.java).setup()
        try {
            assertEquals(0, backend.operations.get()); assertFalse(session.busy)
            endpoint(activity.get()).setText("https://controller.private.test:9090")
            secret(activity.get()).setText("fixture-private-token")
            assertFalse(secret(activity.get()).isSaveEnabled)
            assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, secret(activity.get()).importantForAutofill)
            assertTrue(secret(activity.get()).imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
            val saved = Bundle(); activity.saveInstanceState(saved)
            assertFalse(saved.toString().contains("fixture-private-token"))
            assertFalse(saved.toString().contains("controller.private.test"))
            activity.recreate(); idle()
            assertEquals("", secret(activity.get()).text.toString())
            assertEquals("https://controller.private.test:9090", endpoint(activity.get()).text.toString())
            assertEquals(0, backend.operations.get()); assertNull(session.record)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun checking_valid_input_shows_scope_and_requires_confirmation_before_creating_operation() {
        val activity = Robolectric.buildActivity(ProxyCooperationActivity::class.java).setup()
        try {
            endpoint(activity.get()).setText("https://controller.private.test:9090")
            secret(activity.get()).setText("fixture-private-token")
            button(activity.get(), "确认只读检查").performClick(); idle()
            val text = dialog().findViewById<TextView>(android.R.id.message)!!.text.toString()
            for (clue in listOf("/version", "/connections", "3 秒", "15 秒", "256 KiB", "100 条")) assertTrue(clue, text.contains(clue))
            assertFalse(text.contains("fixture-private-token")); assertEquals("", secret(activity.get()).text.toString())
            assertEquals(0, backend.operations.get())
            dialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertEquals(0, backend.operations.get())
            secret(activity.get()).setText("fixture-private-token")
            button(activity.get(), "确认只读检查").performClick(); idle()
            dialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); ProxyFixtures.await(session)
            assertEquals(1, backend.operations.get()); assertNotNull(session.record)
            assertEquals("", secret(activity.get()).text.toString())
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun invalid_origin_cannot_open_confirmation_or_call_backend() {
        val activity = Robolectric.buildActivity(ProxyCooperationActivity::class.java).setup()
        try {
            endpoint(activity.get()).setText("http://controller.private.test:9090")
            secret(activity.get()).setText("fixture-private-token")
            button(activity.get(), "确认只读检查").performClick(); idle()
            assertNull(ShadowDialog.getLatestDialog()); assertEquals(0, backend.operations.get())
            endpoint(activity.get()).setText("https://controller.private.test/configs")
            button(activity.get(), "确认只读检查").performClick(); idle()
            assertNull(ShadowDialog.getLatestDialog()); assertEquals(0, backend.operations.get())
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun busy_run_disables_new_actions_and_clear_until_cancellation_finishes() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val cancelled = CountDownLatch(1)
        backend.operationFn = { object : ProxyCooperationOperation {
            override fun execute() = ProxyFixtures.report().also { entered.countDown(); release.await(3, TimeUnit.SECONDS) }
            override fun close() { cancelled.countDown() }
        } }
        val activity = Robolectric.buildActivity(ProxyCooperationActivity::class.java).setup()
        try {
            assertTrue(session.start(ProxyFixtures.plan())); assertTrue(entered.await(1, TimeUnit.SECONDS)); idle()
            assertFalse(button(activity.get(), "确认只读检查").isEnabled)
            assertFalse(button(activity.get(), "导出脱敏快照").isEnabled)
            assertFalse("Clearing must not promise removal while a result can still arrive", button(activity.get(), "清除连接信息与报告").isEnabled)
            assertFalse(endpoint(activity.get()).isEnabled); assertFalse(secret(activity.get()).isEnabled)
            assertTrue(button(activity.get(), "取消读取").isEnabled)
            button(activity.get(), "取消读取").performClick(); idle()
            assertTrue(cancelled.await(1, TimeUnit.SECONDS)); assertTrue(session.busy)
        } finally { release.countDown(); ProxyFixtures.await(session); activity.pause().stop().destroy() }
    }

    @Test fun export_retains_frozen_redacted_report_through_rotation_and_new_report() {
        report(); val old = session.record!!.id
        val activity = Robolectric.buildActivity(ProxyCooperationActivity::class.java).setup()
        try {
            export(activity.get())
            val request = shadowOf(activity.get()).nextStartedActivityForResult
            assertEquals(Intent.ACTION_CREATE_DOCUMENT, request.intent.action)
            assertTrue(request.intent.getStringExtra(Intent.EXTRA_TITLE)!!.endsWith("-redacted.json"))
            activity.recreate(); idle(); report()
            assertNotEquals(old, session.record!!.id)
            val uri = Uri.parse("content://proxy.tests/frozen.json"); val output = ByteArrayOutputStream()
            shadowOf(activity.get().contentResolver).registerOutputStream(uri, output)
            shadowOf(activity.get()).callOnActivityResult(request.requestCode, Activity.RESULT_OK, Intent().setData(uri))
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (output.size() == 0 && System.nanoTime() < until) Thread.sleep(5)
            idle()
            val json = output.toString("UTF-8")
            assertEquals(old, JSONObject(json).getString("runId"))
            for (private in ProxyFixtures.PRIVATE_VALUES) assertFalse(private, json.contains(private))
            val bytes = output.size()
            shadowOf(activity.get()).callOnActivityResult(request.requestCode, Activity.RESULT_OK, Intent().setData(uri)); idle()
            assertEquals(bytes, output.size())
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun cancelled_picker_old_callback_cannot_consume_new_export() {
        report()
        val activity = Robolectric.buildActivity(ProxyCooperationActivity::class.java).setup()
        try {
            export(activity.get()); val first = shadowOf(activity.get()).nextStartedActivityForResult
            shadowOf(activity.get()).callOnActivityResult(first.requestCode, Activity.RESULT_CANCELED, null); idle()
            export(activity.get()); val second = shadowOf(activity.get()).nextStartedActivityForResult
            assertNotEquals(first.requestCode, second.requestCode)
            val uri = Uri.parse("content://proxy.tests/stale.json"); val output = ByteArrayOutputStream()
            shadowOf(activity.get().contentResolver).registerOutputStream(uri, output)
            shadowOf(activity.get()).callOnActivityResult(first.requestCode, Activity.RESULT_OK, Intent().setData(uri)); idle()
            assertEquals(0, output.size())
            assertFalse(button(activity.get(), "导出脱敏快照").isEnabled)
            shadowOf(activity.get()).callOnActivityResult(second.requestCode, Activity.RESULT_CANCELED, null); idle()
            assertTrue(button(activity.get(), "导出脱敏快照").isEnabled)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun process_recreated_missing_payload_reserves_old_code_and_allows_safe_new_export() {
        report()
        val saved = Bundle().apply {
            putString("proxyExport", "00000000-0000-4000-8000-000000000001")
            putInt("proxyExportCode", 18000)
        }
        val activity = Robolectric.buildActivity(ProxyCooperationActivity::class.java).create(saved).start().resume().visible()
        try {
            assertTrue("Lost memory payload must not leave export permanently disabled", button(activity.get(), "导出脱敏快照").isEnabled)
            export(activity.get()); val current = shadowOf(activity.get()).nextStartedActivityForResult
            assertTrue(current.requestCode > 18000)
            val uri = Uri.parse("content://proxy.tests/old-process.json"); val output = ByteArrayOutputStream()
            shadowOf(activity.get().contentResolver).registerOutputStream(uri, output)
            shadowOf(activity.get()).callOnActivityResult(18000, Activity.RESULT_OK, Intent().setData(uri)); idle()
            assertEquals(0, output.size())
            assertFalse(button(activity.get(), "导出脱敏快照").isEnabled)
            shadowOf(activity.get()).callOnActivityResult(current.requestCode, Activity.RESULT_CANCELED, null); idle()
            assertTrue(button(activity.get(), "导出脱敏快照").isEnabled)
        } finally { activity.pause().stop().destroy() }
    }
}
