package dev.proxyaudit.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Looper
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import dev.proxyaudit.core.DemoFixture
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowDialog

/** Framework-only UI and local fake-document tests. No device, client import, or network probe. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class RepairActivityTest {
    private val original = Uri.parse("content://test/document/original")
    private val target = Uri.parse("content://test/document/copy")
    private val source = "proxies: []\nrules: [MATCH,DIRECT]\n# credential-secret\ndns:\n  enable: false\n  nameserver: [8.8.8.8]\n"
    private fun all(view: View): List<View> = listOf(view) + if (view is ViewGroup)
        (0 until view.childCount).flatMap { all(view.getChildAt(it)) } else emptyList()
    private fun views(activity: RepairActivity) = all(activity.findViewById(android.R.id.content))
    private fun button(activity: RepairActivity, label: String) = views(activity).filterIsInstance<MaterialButton>().single { it.text.toString() == label }
    private fun text(activity: RepairActivity, tag: String) = views(activity).filterIsInstance<TextView>().single { it.tag == tag }.text.toString()
    private fun provider(activity: RepairActivity) = views(activity).filterIsInstance<Spinner>().single()
    private fun app(activity: RepairActivity) = activity.application as DiagnosticsApplication
    private fun session(activity: RepairActivity) = app(activity).repairSession
    private fun idle() { shadowOf(Looper.getMainLooper()).idle() }
    private fun await(activity: RepairActivity) {
        val until = System.nanoTime() + 5_000_000_000L
        while (session(activity).busy && System.nanoTime() < until) { Thread.sleep(10); idle() }
        idle(); assertFalse(session(activity).busy)
    }
    private fun importSource(activity: RepairActivity) {
        shadowOf(activity.contentResolver).registerInputStream(original, ByteArrayInputStream(source.toByteArray()))
        val ticket = session(activity).beginImport()!!
        assertTrue(session(activity).accept(ticket.id, ticket.code, original)); await(activity)
    }
    private fun preview(activity: RepairActivity) {
        importSource(activity)
        provider(activity).setSelection(1); idle()
        button(activity, "生成 DNS 修改预览").performClick(); await(activity)
        assertNotNull(session(activity).plan)
    }
    private fun launchSave(activity: RepairActivity): Int {
        button(activity, "保存修复副本").performClick(); idle()
        val dialog = ShadowDialog.getLatestDialog() as AlertDialog
        assertTrue(dialog.findViewById<TextView>(android.R.id.message)!!.text.contains("敏感内容"))
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick(); idle()
        val launched = shadowOf(activity).nextStartedActivityForResult
        assertEquals(Intent.ACTION_CREATE_DOCUMENT, launched.intent.action)
        return launched.requestCode
    }
    private fun sendCopy(activity: RepairActivity, code: Int, input: InputStream) {
        shadowOf(activity.contentResolver).registerOutputStream(target, ByteArrayOutputStream())
        shadowOf(activity.contentResolver).registerInputStream(target, input)
        shadowOf(activity).callOnActivityResult(code, Activity.RESULT_OK, Intent().setData(target))
    }

    @Test fun first_visit_requires_explicit_provider_and_uses_material_controls_without_network() {
        val activity = Robolectric.buildActivity(RepairActivity::class.java).setup()
        try {
            idle()
            assertEquals(0, provider(activity.get()).selectedItemPosition)
            assertEquals("请选择 DNS 方案", provider(activity.get()).selectedItem.toString())
            assertFalse(button(activity.get(), "生成 DNS 修改预览").isEnabled)
            assertFalse(button(activity.get(), "复制所选服务的 Private DNS 主机名").isEnabled)
            assertFalse(button(activity.get(), "我已在客户端导入此副本").isEnabled)
            assertEquals(1, views(activity.get()).filterIsInstance<MaterialToolbar>().size)
            assertEquals(1, views(activity.get()).filterIsInstance<MaterialCheckBox>().size)
            importSource(activity.get())
            assertFalse(button(activity.get(), "生成 DNS 修改预览").isEnabled)
            assertFalse(app(activity.get()).controller.busy); assertNull(app(activity.get()).controller.report)
            assertTrue(text(activity.get(), "repairRecovery").contains("应用没有自动备份"))
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun explicit_choice_survives_rotation_without_serializing_config_and_generate_links_baseline() {
        val activity = Robolectric.buildActivity(RepairActivity::class.java).setup()
        try {
            importSource(activity.get())
            val runId = "00000000-0000-4000-8000-000000000010"
            // Synthetic test identity only; no real observation is created by this fixture.
            DiagnosticsController::class.java.getDeclaredField("baseline").apply { isAccessible = true }
                .set(app(activity.get()).controller, DemoFixture.report().copy(runId = runId))
            provider(activity.get()).setSelection(2); idle()
            button(activity.get(), "生成 DNS 修改预览").performClick(); await(activity.get())
            assertEquals(runId, session(activity.get()).baselineRunId)
            val saved = Bundle(); activity.saveInstanceState(saved)
            assertEquals(1, saved.getInt("repairProviderIndex"))
            assertFalse(saved.toString().contains("credential-secret"))
            assertFalse(saved.toString().contains("nameserver"))
            activity.recreate(); idle()
            assertEquals(2, provider(activity.get()).selectedItemPosition)
            assertTrue(text(activity.get(), "repairBaseline").contains(runId))
            assertNull(app(activity.get()).controller.report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun only_verified_copy_enables_user_import_record_and_new_plan_invalidates_it() {
        val activity = Robolectric.buildActivity(RepairActivity::class.java).setup()
        try {
            preview(activity.get())
            val expected = session(activity.get()).plan!!.repairedYaml
            val code = launchSave(activity.get())
            sendCopy(activity.get(), code, ByteArrayInputStream(expected.toByteArray())); await(activity.get())
            assertEquals(CopyExportState.COPY_READBACK_VERIFIED, session(activity.get()).exportState)
            assertTrue(text(activity.get(), "repairCopyResult").contains(session(activity.get()).copyEvidence!!.readbackSha256!!))
            assertFalse(session(activity.get()).userReportedApplied)
            assertTrue(button(activity.get(), "我已在客户端导入此副本").isEnabled)
            button(activity.get(), "我已在客户端导入此副本").performClick(); idle()
            assertTrue(session(activity.get()).userReportedApplied)
            assertTrue(text(activity.get(), "repairCopyResult").contains("客户端生效状态未独立核验"))
            assertFalse(button(activity.get(), "我已在客户端导入此副本").isEnabled)
            assertFalse(app(activity.get()).controller.busy); assertNull(app(activity.get()).controller.report)
            provider(activity.get()).setSelection(2); idle()
            assertFalse(session(activity.get()).userReportedApplied)
            assertFalse(button(activity.get(), "我已在客户端导入此副本").isEnabled)
            assertFalse(text(activity.get(), "repairCopyResult").contains("读回 SHA-256"))
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun unverified_and_mismatched_copies_are_distinct_and_cannot_record_import() {
        val activity = Robolectric.buildActivity(RepairActivity::class.java).setup()
        try {
            preview(activity.get())
            var code = launchSave(activity.get())
            sendCopy(activity.get(), code, object : InputStream() { override fun read(): Int = throw SecurityException("credential-secret") })
            await(activity.get())
            assertTrue(text(activity.get(), "repairCopyResult").contains("内容未核实"))
            assertFalse(button(activity.get(), "我已在客户端导入此副本").isEnabled)
            assertFalse(text(activity.get(), "repairStatus").contains("credential-secret"))
            code = launchSave(activity.get())
            sendCopy(activity.get(), code, ByteArrayInputStream(ByteArray(0))); await(activity.get())
            assertTrue(text(activity.get(), "repairCopyResult").contains("失败，请勿导入"))
            assertFalse(button(activity.get(), "我已在客户端导入此副本").isEnabled)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun picker_rotation_keeps_only_identity_and_cancelled_callback_cannot_write() {
        val activity = Robolectric.buildActivity(RepairActivity::class.java).setup()
        try {
            preview(activity.get())
            val code = launchSave(activity.get())
            val saved = Bundle(); activity.saveInstanceState(saved)
            assertEquals(code, saved.getInt("repairRequestCode"))
            assertTrue(saved.getString("repairRequestId")!!.matches(Regex("[a-f0-9-]{36}")))
            assertFalse(saved.toString().contains("credential-secret"))
            activity.recreate(); idle()
            assertTrue(session(activity.get()).pickerPending)
            shadowOf(activity.get()).callOnActivityResult(code, Activity.RESULT_CANCELED, null); idle()
            assertEquals(CopyExportState.CANCELLED_NO_WRITE, session(activity.get()).exportState)
            val output = ByteArrayOutputStream()
            shadowOf(activity.get().contentResolver).registerOutputStream(target, output)
            shadowOf(activity.get()).callOnActivityResult(code, Activity.RESULT_OK, Intent().setData(target)); idle()
            assertEquals(0, output.size()); assertFalse(session(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun cancel_button_preserves_busy_slot_until_readback_returns() {
        val activity = Robolectric.buildActivity(RepairActivity::class.java).setup()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        try {
            preview(activity.get())
            val bytes = session(activity.get()).plan!!.repairedYaml.toByteArray()
            val code = launchSave(activity.get())
            sendCopy(activity.get(), code, object : ByteArrayInputStream(bytes) {
                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    entered.countDown(); check(release.await(3, TimeUnit.SECONDS))
                    return super.read(buffer, offset, length)
                }
            })
            assertTrue(entered.await(3, TimeUnit.SECONDS)); idle()
            val cancel = button(activity.get(), "取消当前文件操作")
            assertTrue(cancel.isShown); assertTrue(cancel.isEnabled)
            cancel.performClick(); idle()
            assertTrue(session(activity.get()).busy); assertFalse(cancel.isEnabled)
            assertFalse(button(activity.get(), "选择本地 YAML 配置").isEnabled)
            release.countDown(); await(activity.get())
            assertEquals(CopyExportState.COPY_WRITTEN_UNVERIFIED, session(activity.get()).exportState)
            assertFalse(button(activity.get(), "取消当前文件操作").isShown)
            assertFalse(button(activity.get(), "我已在客户端导入此副本").isEnabled)
        } finally { release.countDown(); await(activity.get()); activity.pause().stop().destroy() }
    }

    @Test fun settings_navigation_and_return_never_claim_apply_or_start_retest() {
        val activity = Robolectric.buildActivity(RepairActivity::class.java).setup()
        try {
            button(activity.get(), "打开网络设置，配置 Private DNS").performClick(); idle()
            assertEquals(Settings.ACTION_WIRELESS_SETTINGS, shadowOf(activity.get()).nextStartedActivity.action)
            assertFalse(session(activity.get()).userReportedApplied)
            assertNull(app(activity.get()).controller.report); assertFalse(app(activity.get()).controller.busy)
            button(activity.get(), "返回修复页，核对计划并复测").performClick(); idle()
            assertTrue(activity.get().isFinishing)
        } finally { activity.pause().stop().destroy() }
    }
}

