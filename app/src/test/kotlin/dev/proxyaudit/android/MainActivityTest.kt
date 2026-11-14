package dev.proxyaudit.android

import androidx.appcompat.app.AlertDialog
import android.app.Activity
import android.net.Uri
import android.os.Bundle
import android.content.Intent
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.textfield.TextInputLayout
import dev.proxyaudit.core.*
import java.io.ByteArrayOutputStream
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

/** Local Android-framework simulation only. These tests perform no real DNS/HTTPS/device/VPN probes. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class MainActivityTest {
    private fun children(view: View): List<View> = listOf(view) + if (view is ViewGroup) (0 until view.childCount).flatMap { children(view.getChildAt(it)) } else emptyList()
    private fun views(activity: MainActivity) = children(activity.findViewById(android.R.id.content))
    private fun button(activity: MainActivity, label: String) = views(activity).filterIsInstance<Button>().single { it.text.toString() == label }
    private fun check(activity: MainActivity, label: String) = views(activity).filterIsInstance<CheckBox>().single { it.text.toString() == label }
    private fun input(activity: MainActivity, hint: String) = views(activity).filterIsInstance<EditText>().single { it.tag == hint }
    private fun shownText(activity: MainActivity) = views(activity).filterIsInstance<TextView>().filter { it.isShown }.joinToString("\n") { it.text.toString() }
    private fun latestDialog() = ShadowDialog.getLatestDialog() as AlertDialog
    private fun dialogText() = latestDialog().findViewById<TextView>(android.R.id.message)!!.text.toString()
    private fun field(activity: MainActivity, hint: String) = views(activity).filterIsInstance<TextInputLayout>()
        .single { it.editText === input(activity, hint) }
    private fun navigation(activity: MainActivity) = views(activity).filterIsInstance<BottomNavigationView>().single()
    private fun navigate(activity: MainActivity, id: Int) {
        if (views(activity).single { it.tag == "report-panel" }.isShown) activity.onBackPressedDispatcher.onBackPressed()
        navigation(activity).selectedItemId = id; idle()
    }
    private fun controller(activity: MainActivity) = (activity.application as DiagnosticsApplication).controller
    private fun idle() { shadowOf(Looper.getMainLooper()).idle() }
    private fun openExpert(activity: MainActivity) {
        val panel = views(activity).single { it.tag == "expert-panel" }
        if (panel.visibility != View.VISIBLE) navigate(activity, MainActivity.NAV_TEST)
        assertTrue(panel.isShown)
    }
    private fun quickTarget(activity: MainActivity) = views(activity).filterIsInstance<Spinner>().single { it.tag == "quick-target" }
    private fun openResults(activity: MainActivity, details: Boolean = false) {
        if (!views(activity).single { it.tag == "report-panel" }.isShown) {
            navigate(activity, MainActivity.NAV_REPAIR)
            button(activity, "查看当前报告与基线对照").performClick(); idle()
        }
        if (details && views(activity).single { it.tag == "evidence-details" }.visibility != View.VISIBLE)
            button(activity, "展开详细证据").performClick()
        idle()
    }

    @Test fun navigation_keeps_one_task_visible_and_preserves_fields_without_network() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            assertTrue(views(activity.get()).single { it.tag == "home-panel" }.isShown)
            openExpert(activity.get())
            input(activity.get(), "随机标记.你控制的域名").setText("keep.example.test")
            assertFalse(views(activity.get()).single { it.tag == "home-panel" }.isShown)
            assertFalse(input(activity.get(), "https://你的受控主机:8443").isShown)
            assertFalse(input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").isShown)
            check(activity.get(), "执行 HTTPS 来源地址回显").isChecked = true
            assertTrue(input(activity.get(), "https://你的受控主机:8443").isShown)
            openResults(activity.get())
            assertTrue(shownText(activity.get()).contains("还没有检查结果"))
            assertFalse(views(activity.get()).single { it.tag == "expert-panel" }.isShown)
            openExpert(activity.get())
            assertEquals("keep.example.test", input(activity.get(), "随机标记.你控制的域名").text.toString())
            assertFalse(controller(activity.get()).busy); assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun dns_scenario_fills_same_host_and_protocols_but_requires_separate_run_confirmation() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            button(activity.get(), "DNS 连通对照").performClick(); idle()
            assertNull(ShadowDialog.getLatestDialog())
            assertEquals("example.com", input(activity.get(), "随机标记.你控制的域名").text.toString())
            assertEquals("example.com", input(activity.get(), "原始DNS随机标记.你控制的域名").text.toString())
            assertEquals("53", input(activity.get(), "1–65535").text.toString())
            assertTrue(check(activity.get(), "执行原始 DNS UDP 探测").isChecked)
            assertTrue(check(activity.get(), "执行原始 DNS TCP 探测").isChecked)
            assertFalse(check(activity.get(), "查询 AAAA 记录（未选时查询 A）").isChecked)
            assertFalse(check(activity.get(), "我信任所选回显服务如实报告来源 IP").isChecked)
            assertFalse(controller(activity.get()).busy); assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun https_scenario_never_invents_target_expected_ip_or_trust() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            check(activity.get(), "我信任所选回显服务如实报告来源 IP").isChecked = true
            button(activity.get(), "HTTPS 出口核验").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); idle()
            assertTrue(check(activity.get(), "执行 HTTPS 来源地址回显").isChecked)
            assertFalse(check(activity.get(), "执行系统 DNS 解析").isChecked)
            assertFalse(check(activity.get(), "我信任所选回显服务如实报告来源 IP").isChecked)
            assertEquals("", input(activity.get(), "https://你的受控主机:8443").text.toString())
            assertEquals("", input(activity.get(), "IPv4 / IPv6，以英文逗号分隔").text.toString())
            assertFalse(controller(activity.get()).busy); assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun result_summary_separates_dns_error_response_and_unmeasured_https_before_details() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            injectReport(activity.get(), runtimeFixture(raw = true).copy(dns = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE)))
            activity.recreate(); idle(); openResults(activity.get())
            val text = shownText(activity.get())
            assertTrue(text.contains("系统 DNS 报错"))
            assertTrue(text.contains("UDP DNS · 返回地址"))
            assertTrue(text.contains("TCP DNS · 返回地址"))
            assertTrue(text.contains("HTTPS 出口 · 未测"))
            assertFalse(views(activity.get()).single { it.tag == "evidence-details" }.isShown)
            assertFalse(text.contains("192.0.2.53"))
            openResults(activity.get(), details = true)
            assertTrue(shownText(activity.get()).contains("192.0.2.53"))
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun invalid_field_is_identified_and_guide_contract_matches_parser() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            input(activity.get(), "随机标记.你控制的域名").setText("https://invalid.example")
            button(activity.get(), "开始本次探测").performClick(); idle()
            assertNotNull(field(activity.get(), "随机标记.你控制的域名").error)
            assertNull(ShadowDialog.getLatestDialog())
            check(activity.get(), "执行 HTTPS 来源地址回显").isChecked = true
            button(activity.get(), "回显服务需要满足什么").performClick(); idle()
            assertTrue(dialogText().contains("\"schemaVersion\":1"))
            assertTrue(dialogText().contains("\"observedSourceIp\""))
            assertTrue(dialogText().contains("tools/echo_fixture.py"))
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun launch_shows_quick_check_without_inputs_and_collapses_professional_form_without_network() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            assertTrue(views(activity.get()).filterIsInstance<EditText>().none { it.isShown })
            assertTrue(views(activity.get()).filterIsInstance<EditText>().filter { it.tag !in listOf("1–65535", "随机标记.你控制的域名") }.all { it.text.isEmpty() })
            assertEquals("53", input(activity.get(), "1–65535").text.toString())
            assertEquals("example.com", input(activity.get(), "随机标记.你控制的域名").text.toString())
            assertFalse(check(activity.get(), "执行 HTTPS 来源地址回显").isChecked)
            assertTrue(check(activity.get(), "执行系统 DNS 解析").isChecked)
            assertFalse(check(activity.get(), "同时检查原始 DNS UDP / TCP（明文，需确认）").isChecked)
            assertFalse(quickTarget(activity.get()).isEnabled)
            assertTrue(button(activity.get(), "开始快速检查").isShown)
            assertFalse(check(activity.get(), "执行原始 DNS UDP 探测").isChecked)
            assertFalse(check(activity.get(), "执行原始 DNS TCP 探测").isChecked)
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
            assertFalse(button(activity.get(), "导出本次 JSON 证据").isEnabled)
        } finally { activity.pause().stop().destroy() }
    }
    @Test fun offline_demo_is_labeled_and_survives_activity_recreation() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "查看离线演示（不联网）").performClick(); idle()
            assertEquals(EvidenceOrigin.SYNTHETIC_FIXTURE, controller(activity.get()).report!!.evidenceOrigin)
            assertTrue(controller(activity.get()).isDemo); assertFalse(controller(activity.get()).busy)
            activity.recreate(); idle()
            assertTrue(controller(activity.get()).isDemo)
            assertTrue(button(activity.get(), "导出本次 JSON 证据").isEnabled)
        } finally { activity.pause().stop().destroy() }
    }
    @Test fun empty_target_validation_does_not_start_network() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            input(activity.get(), "随机标记.你控制的域名").setText("")
            button(activity.get(), "开始本次探测").performClick(); idle()
            assertNotNull(field(activity.get(), "随机标记.你控制的域名").error)
            assertNull(ShadowDialog.getLatestDialog())
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }
    @Test fun cancelling_target_confirmation_does_not_start_probe() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            check(activity.get(), "执行 HTTPS 来源地址回显").isChecked = true
            check(activity.get(), "执行系统 DNS 解析").isChecked = false
            input(activity.get(), "https://你的受控主机:8443").setText("https://echo.example.test")
            button(activity.get(), "开始本次探测").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }
    @Test fun redacted_export_uses_system_document_picker_with_demo_filename() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "查看离线演示（不联网）").performClick(); idle()
            button(activity.get(), "导出本次 JSON 证据").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_NEUTRAL).performClick(); idle()
            val intent = shadowOf(activity.get()).nextStartedActivityForResult.intent
            assertEquals(Intent.ACTION_CREATE_DOCUMENT, intent.action)
            assertEquals("application/json", intent.type)
            assertTrue(intent.getStringExtra(Intent.EXTRA_TITLE)!!.contains("DEMO-"))
            assertTrue(intent.getStringExtra(Intent.EXTRA_TITLE)!!.contains("redacted"))
        } finally { activity.pause().stop().destroy() }
    }
    @Test fun clear_removes_report_without_scheduling_network() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "查看离线演示（不联网）").performClick(); idle()
            button(activity.get(), "清除结果与对照基线").performClick(); idle()
            assertNull(controller(activity.get()).report)
            assertFalse(controller(activity.get()).busy)
            assertFalse(button(activity.get(), "导出本次 JSON 证据").isEnabled)
        } finally { activity.pause().stop().destroy() }
    }
    @Test fun export_survives_rotation_and_writes_frozen_redacted_payload_once() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "查看离线演示（不联网）").performClick(); idle()
            val expected = ReportExporter.toJson(controller(activity.get()).report!!, false)
            button(activity.get(), "导出本次 JSON 证据").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_NEUTRAL).performClick(); idle()
            val launched = shadowOf(activity.get()).nextStartedActivityForResult
            val saved = Bundle(); activity.saveInstanceState(saved)
            assertTrue(saved.getString("pending-export-request-id")!!.matches(Regex("[a-f0-9-]{36}")))
            assertEquals(launched.requestCode, saved.getInt("pending-export-request-code"))
            activity.recreate(); idle()
            assertTrue(controller(activity.get()).exportPending)
            assertFalse(button(activity.get(), "导出本次 JSON 证据").isEnabled)
            // Changing the current report does not change the already approved export snapshot.
            controller(activity.get()).clear(); idle()
            val uri = Uri.parse("content://test.documents/export-rotation.json")
            val closed = CountDownLatch(1)
            val output = object : ByteArrayOutputStream() { override fun close() { super.close(); closed.countDown() } }
            shadowOf(activity.get().contentResolver).registerOutputStream(uri, output)
            shadowOf(activity.get()).callOnActivityResult(launched.requestCode, Activity.RESULT_OK, Intent().setData(uri))
            assertTrue(closed.await(3, TimeUnit.SECONDS)); idle()
            assertEquals(expected, output.toString("UTF-8"))
            assertFalse(controller(activity.get()).exportPending)
            val before = output.size()
            shadowOf(activity.get()).callOnActivityResult(launched.requestCode, Activity.RESULT_OK, Intent().setData(uri)); idle()
            assertEquals(before, output.size())
        } finally { activity.pause().stop().destroy() }
    }
    @Test fun cancelled_export_after_rotation_clears_pending_and_allows_retry() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "查看离线演示（不联网）").performClick(); idle()
            button(activity.get(), "导出本次 JSON 证据").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_NEUTRAL).performClick(); idle()
            val first = shadowOf(activity.get()).nextStartedActivityForResult
            activity.recreate(); idle()
            shadowOf(activity.get()).callOnActivityResult(first.requestCode, Activity.RESULT_CANCELED, null); idle()
            assertFalse(controller(activity.get()).exportPending)
            assertTrue(button(activity.get(), "导出本次 JSON 证据").isEnabled)
            button(activity.get(), "导出本次 JSON 证据").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); idle()
            val second = shadowOf(activity.get()).nextStartedActivityForResult
            assertNotEquals(first.requestCode, second.requestCode)
            // A stale completion must not consume the new export ticket or select its destination.
            shadowOf(activity.get()).callOnActivityResult(first.requestCode, Activity.RESULT_OK, Intent().setData(Uri.parse("content://test.documents/old.json"))); idle()
            assertTrue(controller(activity.get()).exportPending)
            shadowOf(activity.get()).callOnActivityResult(second.requestCode, Activity.RESULT_CANCELED, null); idle()
            assertFalse(controller(activity.get()).exportPending)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun restored_picker_identity_is_not_reused_when_process_payload_is_missing() {
        val saved = Bundle().apply {
            putString("pending-export-request-id", "00000000-0000-4000-8000-000000000001")
            putInt("pending-export-request-code", 21)
        }
        val activity = Robolectric.buildActivity(MainActivity::class.java).create(saved).start().resume().visible()
        try {
            assertFalse(controller(activity.get()).exportPending)
            button(activity.get(), "查看离线演示（不联网）").performClick(); idle()
            button(activity.get(), "导出本次 JSON 证据").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_NEUTRAL).performClick(); idle()
            val newRequest = shadowOf(activity.get()).nextStartedActivityForResult
            assertTrue(newRequest.requestCode > 21)
            shadowOf(activity.get()).callOnActivityResult(21, Activity.RESULT_OK, Intent().setData(Uri.parse("content://test.documents/stale-process.json"))); idle()
            assertTrue(controller(activity.get()).exportPending)
            shadowOf(activity.get()).callOnActivityResult(newRequest.requestCode, Activity.RESULT_CANCELED, null); idle()
            assertFalse(controller(activity.get()).exportPending)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun raw_dns_only_ipv4_a_target_can_be_confirmed_without_https_or_system_dns() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            check(activity.get(), "执行 HTTPS 来源地址回显").isChecked = false
            check(activity.get(), "执行系统 DNS 解析").isChecked = false
            check(activity.get(), "执行原始 DNS UDP 探测").isChecked = true
            input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").setText("192.0.2.53")
            input(activity.get(), "原始DNS随机标记.你控制的域名").setText("probe.example.test")
            button(activity.get(), "开始本次探测").performClick(); idle()
            val text = dialogText()
            assertTrue(text.contains("原始 DNS UDP：192.0.2.53:53 · probe.example.test · A"))
            assertFalse(text.contains("原始 DNS TCP："))
            assertFalse(text.contains("HTTPS："))
            assertFalse(text.contains("系统 DNS："))
            assertTrue(text.contains("明文 DNS"))
            assertTrue(text.contains("响应不证明无泄露"))
            assertFalse(controller(activity.get()).busy)
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun raw_dns_ipv6_aaaa_confirmation_lists_each_transport_and_scope() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            check(activity.get(), "执行 HTTPS 来源地址回显").isChecked = false
            check(activity.get(), "执行系统 DNS 解析").isChecked = false
            check(activity.get(), "执行原始 DNS UDP 探测").isChecked = true
            check(activity.get(), "执行原始 DNS TCP 探测").isChecked = true
            check(activity.get(), "查询 AAAA 记录（未选时查询 A）").isChecked = true
            input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").setText("2001:db8::53")
            input(activity.get(), "1–65535").setText("5353")
            input(activity.get(), "原始DNS随机标记.你控制的域名").setText("v6.example.test")
            button(activity.get(), "开始本次探测").performClick(); idle()
            val address = "2001:db8::53"
            val text = dialogText()
            assertTrue(text.contains("原始 DNS UDP：[$address]:5353 · v6.example.test · AAAA"))
            assertTrue(text.contains("原始 DNS TCP：[$address]:5353 · v6.example.test · AAAA"))
            assertTrue(text.contains("数字 IPv6 只代表 socket 目标地址族"))
            assertTrue(text.contains("不证明实际外层路径"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun raw_dns_missing_or_invalid_inputs_are_rejected_before_confirmation() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            check(activity.get(), "执行 HTTPS 来源地址回显").isChecked = false
            check(activity.get(), "执行系统 DNS 解析").isChecked = false
            check(activity.get(), "执行原始 DNS TCP 探测").isChecked = true
            val invalid = listOf(
                Triple("", "53", "probe.example.test"),
                Triple("resolver.example.test", "53", "probe.example.test"),
                Triple("192.0.2.53", "0", "probe.example.test"),
                Triple("192.0.2.53", "53", ""),
                Triple("192.0.2.53", "53", "https://probe.example.test")
            )
            invalid.forEach { (server, port, host) ->
                input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").setText(server)
                input(activity.get(), "1–65535").setText(port)
                input(activity.get(), "原始DNS随机标记.你控制的域名").setText(host)
                button(activity.get(), "开始本次探测").performClick(); idle()
                val errors = views(activity.get()).filterIsInstance<TextInputLayout>().mapNotNull { it.error?.toString() }
                assertEquals(1, errors.size)
                assertTrue(errors.single().startsWith("原始 DNS"))
                assertNull(ShadowDialog.getLatestDialog())
                assertFalse(controller(activity.get()).busy)
                assertNull(controller(activity.get()).report)
            }
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun mapped_ipv6_literal_keeps_the_requested_address_family_in_confirmation() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            check(activity.get(), "执行 HTTPS 来源地址回显").isChecked = false
            check(activity.get(), "执行系统 DNS 解析").isChecked = false
            check(activity.get(), "执行原始 DNS TCP 探测").isChecked = true
            input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").setText("::ffff:192.0.2.53")
            input(activity.get(), "原始DNS随机标记.你控制的域名").setText("mapped.example.test")
            button(activity.get(), "开始本次探测").performClick(); idle()
            assertTrue(dialogText().contains("原始 DNS TCP：[::ffff:192.0.2.53]:53 · mapped.example.test · A"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun raw_dns_results_show_each_protocol_without_claiming_an_outer_ipv6_path() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            controller(activity.get()).showDemo(); idle()
            val base = controller(activity.get()).report!!
            val raw = RawDnsConfig("2001:db8::53", host = "v6.example.test", recordType = DnsRecordType.AAAA, udp = true, tcp = true)
            val report = base.copy(
                config = base.config.copy(endpoint = null, dnsHost = null,
                    policy = base.config.policy.copy(runHttps = false, runDns = false), rawDns = raw),
                dns = DnsObservation(), https = HttpsObservation(),
                rawDns = listOf(
                    RawDnsObservation(transport = DnsTransport.UDP, execution = Execution.COMPLETED,
                        transactionId = 123, durationMillis = 12, responseCode = 0, truncated = true,
                        addresses = listOf("2001:db8::25"), failure = null),
                    RawDnsObservation(transport = DnsTransport.TCP, execution = Execution.ERROR,
                        transactionId = 124, durationMillis = 80, responseCode = null, truncated = false,
                        addresses = emptyList(), failure = Failure.TIMEOUT)
                )
            )
            DiagnosticsController::class.java.getDeclaredField("report").apply { isAccessible = true }
                .set(controller(activity.get()), report)
            activity.recreate(); idle()
            openResults(activity.get(), details = true)
            val text = shownText(activity.get())
            assertTrue(text.contains("离线演示：下列时间、地址和结果均为虚构"))
            assertTrue(text.contains("原始 DNS UDP"))
            assertTrue(text.contains("原始 DNS TCP"))
            assertTrue(text.contains("12 ms"))
            assertTrue(text.contains("80 ms"))
            assertTrue(text.contains("DNS 响应码：0 · 截断标记：是"))
            assertTrue(text.contains("2001:db8::25"))
            assertTrue(text.contains("TIMEOUT"))
            assertTrue(text.contains("v6.example.test · AAAA"))
            assertTrue(text.contains("请求的 socket 目标地址族：IPv6；实际外层路径未证明"))
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun input_draft_survives_rotation_only_in_process_without_saved_state_identifiers() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            input(activity.get(), "https://你的受控主机:8443").setText("https://echo.example.test")
            input(activity.get(), "IPv4 / IPv6，以英文逗号分隔").setText("203.0.113.7")
            input(activity.get(), "随机标记.你控制的域名").setText("system.example.test")
            check(activity.get(), "执行 HTTPS 来源地址回显").isChecked = false
            check(activity.get(), "执行系统 DNS 解析").isChecked = true
            check(activity.get(), "我信任所选回显服务如实报告来源 IP").isChecked = true
            check(activity.get(), "IPv6 专项仍在验收范围内").isChecked = false
            check(activity.get(), "执行原始 DNS UDP 探测").isChecked = true
            check(activity.get(), "执行原始 DNS TCP 探测").isChecked = true
            check(activity.get(), "查询 AAAA 记录（未选时查询 A）").isChecked = true
            input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").setText("2001:db8::53")
            input(activity.get(), "1–65535").setText("5353")
            input(activity.get(), "原始DNS随机标记.你控制的域名").setText("raw.example.test")
            assertTrue(views(activity.get()).filterIsInstance<EditText>().all { !it.isSaveEnabled })
            assertTrue(views(activity.get()).filterIsInstance<CheckBox>().all { !it.isSaveEnabled })
            val saved = Bundle(); activity.saveInstanceState(saved)
            assertFalse(saved.keySet().any { it in setOf("endpoint", "dnsHost", "rawHost", "rawServer", "expectedIps", "inputDraft") })
            activity.recreate(); idle()
            assertEquals("https://echo.example.test", input(activity.get(), "https://你的受控主机:8443").text.toString())
            assertEquals("203.0.113.7", input(activity.get(), "IPv4 / IPv6，以英文逗号分隔").text.toString())
            assertEquals("system.example.test", input(activity.get(), "随机标记.你控制的域名").text.toString())
            assertEquals("2001:db8::53", input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").text.toString())
            assertEquals("5353", input(activity.get(), "1–65535").text.toString())
            assertEquals("raw.example.test", input(activity.get(), "原始DNS随机标记.你控制的域名").text.toString())
            assertFalse(check(activity.get(), "执行 HTTPS 来源地址回显").isChecked)
            assertTrue(check(activity.get(), "执行系统 DNS 解析").isChecked)
            assertTrue(check(activity.get(), "执行原始 DNS UDP 探测").isChecked)
            assertTrue(check(activity.get(), "执行原始 DNS TCP 探测").isChecked)
            assertTrue(check(activity.get(), "查询 AAAA 记录（未选时查询 A）").isChecked)
            assertTrue(check(activity.get(), "我信任所选回显服务如实报告来源 IP").isChecked)
            assertFalse(check(activity.get(), "IPv6 专项仍在验收范围内").isChecked)
            assertTrue(views(activity.get()).single { it.tag == "expert-panel" }.isShown)
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun quick_default_confirms_system_query_without_input_or_implicit_public_target() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "开始快速检查").performClick(); idle()
            assertTrue(dialogText().contains("系统 DNS：example.com"))
            assertTrue(dialogText().contains("由 Android 系统处理"))
            assertFalse(dialogText().contains("原始 DNS UDP："))
            assertFalse(dialogText().contains("HTTPS："))
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertNull(controller(activity.get()).report)
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun quick_public_target_is_only_active_after_explicit_plaintext_opt_in_and_survives_rotation() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            check(activity.get(), "同时检查原始 DNS UDP / TCP（明文，需确认）").isChecked = true
            assertTrue(quickTarget(activity.get()).isEnabled)
            quickTarget(activity.get()).setSelection(2); idle() // Quad9, not a system DNS change.
            val saved = Bundle(); activity.saveInstanceState(saved)
            assertFalse(saved.keySet().any { it in setOf("quickRaw", "quickTarget", "expertExpanded") })
            activity.recreate(); idle()
            assertEquals(2, quickTarget(activity.get()).selectedItemPosition)
            assertFalse(quickTarget(activity.get()).isSaveEnabled)
            assertTrue(check(activity.get(), "同时检查原始 DNS UDP / TCP（明文，需确认）").isChecked)
            button(activity.get(), "开始快速检查").performClick(); idle()
            assertTrue(dialogText().contains("原始 DNS UDP：9.9.9.9:53 · example.com · A"))
            assertTrue(dialogText().contains("原始 DNS TCP：9.9.9.9:53 · example.com · A"))
            assertTrue(dialogText().contains("系统 DNS：example.com"))
            assertTrue(dialogText().contains("明文 DNS"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            check(activity.get(), "同时检查原始 DNS UDP / TCP（明文，需确认）").isChecked = false
            assertFalse(quickTarget(activity.get()).isEnabled)
            button(activity.get(), "开始快速检查").performClick(); idle()
            assertFalse(dialogText().contains("9.9.9.9"))
            assertFalse(dialogText().contains("原始 DNS UDP："))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun private_dns_active_warning_does_not_describe_raw_probe_as_encrypted() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            val plan = QuickCheck.build(runtimeFixture().networkBefore, QuickDnsTarget.CLOUDFLARE, true)
            // Pass a fabricated snapshot flag to the shared confirmation renderer; no sockets are opened.
            MainActivity::class.java.getDeclaredMethod("confirm", RunConfig::class.java,
                Boolean::class.javaObjectType, String::class.java).apply { isAccessible = true }
                .invoke(activity.get(), plan, true, "")
            idle()
            assertTrue(dialogText().contains("Private DNS 已启用"))
            assertTrue(dialogText().contains("仍发送明文 DNS"))
            assertTrue(dialogText().contains("不会自动采用系统的加密解析"))
            assertFalse(controller(activity.get()).busy)
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun professional_form_with_all_probes_disabled_rejects_before_confirmation() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            check(activity.get(), "执行系统 DNS 解析").isChecked = false
            button(activity.get(), "开始本次探测").performClick(); idle()
            assertEquals("请至少选择一项探测", dialogText())
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun repair_entry_opens_activity_without_extra_config_or_starting_a_probe() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "打开修复中心").performClick(); idle()
            assertTrue(views(activity.get()).single { it.tag == "repair-panel" }.isShown)
            assertNull(shadowOf(activity.get()).nextStartedActivity)
            button(activity.get(), "审查配置与保存副本").performClick(); idle()
            val intent = shadowOf(activity.get()).nextStartedActivity
            assertEquals(RepairActivity::class.java.name, intent.component!!.className)
            assertTrue(intent.extras == null || intent.extras!!.isEmpty)
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun demo_advice_cannot_be_saved_as_a_real_baseline() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "查看离线演示（不联网）").performClick(); idle()
            openResults(activity.get(), details = true)
            assertTrue(shownText(activity.get()).contains("演示数据不能诊断当前设备或网络"))
            assertFalse(shownText(activity.get()).contains("系统解析已返回地址"))
            assertFalse(button(activity.get(), "保存当前结果为对照基线").isEnabled)
            assertFalse(button(activity.get(), "按基线相同计划复测").isEnabled)
            assertFalse(button(activity.get(), "导出基线与本次对照").isEnabled)
            assertNull(controller(activity.get()).baseline)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun baseline_rerun_uses_frozen_plan_requires_confirmation_and_clear_removes_it() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            val base = runtimeFixture(raw = true)
            injectReport(activity.get(), base)
            activity.recreate(); idle()
            openResults(activity.get())
            button(activity.get(), "保存当前结果为对照基线").performClick(); idle()
            assertEquals(base.runId, controller(activity.get()).baseline!!.runId)
            openResults(activity.get())
            assertTrue(shownText(activity.get()).contains("当前结果已保存为基线"))
            assertFalse(button(activity.get(), "导出基线与本次对照").isEnabled)
            // Editing the professional form must not silently replace the pinned plan.
            openExpert(activity.get())
            input(activity.get(), "原始DNS随机标记.你控制的域名").setText("different.example.test")
            openResults(activity.get())
            button(activity.get(), "按基线相同计划复测").performClick(); idle()
            assertTrue(dialogText().contains("192.0.2.53:53 · example.com · A"))
            assertFalse(dialogText().contains("different.example.test"))
            assertTrue(dialogText().contains("不会按当前网络重新选择目标"))
            assertFalse(controller(activity.get()).busy)
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertEquals(base.runId, controller(activity.get()).report!!.runId)
            activity.recreate(); idle()
            assertEquals(base.runId, controller(activity.get()).baseline!!.runId)
            button(activity.get(), "清除结果与对照基线").performClick(); idle()
            assertNull(controller(activity.get()).baseline)
            assertFalse(button(activity.get(), "按基线相同计划复测").isEnabled)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun cancelled_result_shows_incomparable_advice_instead_of_improvement() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            val base = runtimeFixture()
            injectReport(activity.get(), base)
            assertTrue(controller(activity.get()).pinBaseline())
            injectReport(activity.get(), base.copy(runId = SECOND_RUN,
                dns = DnsObservation(Execution.CANCELLED, failure = Failure.CANCELLED)))
            activity.recreate(); idle()
            openResults(activity.get(), details = true)
            val text = shownText(activity.get())
            assertTrue(text.contains("系统解析已取消"))
            assertTrue(text.contains("不可比：系统解析未完成或已取消"))
            assertFalse(text.contains("可用性观察改善"))
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun comparison_export_uses_frozen_redacted_pair_across_rotation_and_clear() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            val base = runtimeFixture(raw = true)
            val after = base.copy(runId = SECOND_RUN)
            injectReport(activity.get(), base)
            assertTrue(controller(activity.get()).pinBaseline())
            injectReport(activity.get(), after)
            activity.recreate(); idle()
            openResults(activity.get())
            assertTrue(shownText(activity.get()).contains("可用性观察未变"))
            assertTrue(shownText(activity.get()).contains("不表示已通过隐私验证"))
            button(activity.get(), "导出基线与本次对照").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_NEUTRAL).performClick(); idle()
            val launched = shadowOf(activity.get()).nextStartedActivityForResult
            assertEquals(Intent.ACTION_CREATE_DOCUMENT, launched.intent.action)
            activity.recreate(); idle()
            assertFalse(button(activity.get(), "导出基线与本次对照").isEnabled)
            controller(activity.get()).clear(); idle()
            val output = object : ByteArrayOutputStream() {
                val closed = CountDownLatch(1)
                override fun close() { super.close(); closed.countDown() }
            }
            val uri = Uri.parse("content://test.documents/comparison.json")
            shadowOf(activity.get().contentResolver).registerOutputStream(uri, output)
            shadowOf(activity.get()).callOnActivityResult(launched.requestCode, Activity.RESULT_OK, Intent().setData(uri))
            assertTrue(output.closed.await(3, TimeUnit.SECONDS)); idle()
            val json = output.toString("UTF-8")
            assertEquals(ReportComparison.toJson(base, after, false), json)
            assertFalse(json.contains("192.0.2.53"))
            assertFalse(json.contains("example.com"))
            assertFalse(controller(activity.get()).exportPending)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun material_labels_remain_present_after_entry_and_field_errors_stay_inline() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            val labels = mapOf(
                "随机标记.你控制的域名" to "待解析域名",
                "数字 IPv4 或 IPv6，不带方括号" to "解析器数字 IP",
                "1–65535" to "解析器端口",
                "原始DNS随机标记.你控制的域名" to "原始 DNS 查询域名",
                "https://你的受控主机:8443" to "HTTPS 服务源地址",
                "IPv4 / IPv6，以英文逗号分隔" to "预期服务端来源 IP（可留空）"
            )
            labels.forEach { (hint, label) ->
                assertEquals(label, field(activity.get(), hint).hint.toString())
                assertEquals(hint, field(activity.get(), hint).helperText.toString())
            }
            input(activity.get(), "随机标记.你控制的域名").setText("https://invalid.example")
            button(activity.get(), "开始本次探测").performClick(); idle()
            assertNotNull(field(activity.get(), "随机标记.你控制的域名").error)
            assertEquals("待解析域名", field(activity.get(), "随机标记.你控制的域名").hint.toString())
            assertNull(ShadowDialog.getLatestDialog())
            input(activity.get(), "随机标记.你控制的域名").setText("example.com")
            button(activity.get(), "开始本次探测").performClick(); idle()
            assertNull(field(activity.get(), "随机标记.你控制的域名").error)
            assertTrue(dialogText().contains("系统 DNS：example.com"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun report_is_a_subpage_with_return_to_its_origin_even_after_rotation() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            assertEquals(3, navigation(activity.get()).menu.size())
            assertEquals(MainActivity.NAV_HOME, navigation(activity.get()).selectedItemId)
            navigate(activity.get(), MainActivity.NAV_REPAIR)
            button(activity.get(), "查看当前报告与基线对照").performClick(); idle()
            assertTrue(views(activity.get()).single { it.tag == "report-panel" }.isShown)
            assertFalse(navigation(activity.get()).isShown)
            assertTrue(shownText(activity.get()).contains("还没有检查结果"))
            activity.recreate(); idle()
            activity.get().onBackPressedDispatcher.onBackPressed(); idle()
            assertTrue(views(activity.get()).single { it.tag == "repair-panel" }.isShown)
            assertEquals(MainActivity.NAV_REPAIR, navigation(activity.get()).selectedItemId)
            assertTrue(navigation(activity.get()).isShown)
            activity.get().onBackPressedDispatcher.onBackPressed(); idle()
            assertTrue(views(activity.get()).single { it.tag == "home-panel" }.isShown)
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun customized_scenario_requires_confirmation_and_cancel_preserves_inputs() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            openExpert(activity.get())
            input(activity.get(), "随机标记.你控制的域名").setText("keep.example.test")
            input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").setText("192.0.2.53")
            button(activity.get(), "DNS 连通对照").performClick(); idle()
            assertTrue(dialogText().contains("此操作不联网"))
            assertEquals("keep.example.test", input(activity.get(), "随机标记.你控制的域名").text.toString())
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick(); idle()
            assertEquals("keep.example.test", input(activity.get(), "随机标记.你控制的域名").text.toString())
            assertEquals("192.0.2.53", input(activity.get(), "数字 IPv4 或 IPv6，不带方括号").text.toString())
            button(activity.get(), "DNS 连通对照").performClick(); idle()
            latestDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick(); idle()
            assertEquals("example.com", input(activity.get(), "随机标记.你控制的域名").text.toString())
            assertTrue(check(activity.get(), "执行原始 DNS UDP 探测").isChecked)
            assertFalse(controller(activity.get()).busy)
            assertNull(controller(activity.get()).report)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun retry_defaults_off_and_only_explicit_professional_choice_confirms_two_attempts() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            val label = activity.get().getString(R.string.retry_label)
            assertFalse(check(activity.get(), label).isChecked)
            button(activity.get(), "开始快速检查").performClick(); idle()
            assertTrue(dialogText().contains("每项最多 1 次逻辑尝试，接收结果总时限 20 秒"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
            openExpert(activity.get())
            button(activity.get(), "开始本次探测").performClick(); idle()
            assertTrue(dialogText().contains("每项最多 1 次逻辑尝试"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
            check(activity.get(), label).isChecked = true
            activity.recreate(); idle()
            assertTrue(check(activity.get(), label).isChecked)
            button(activity.get(), "开始本次探测").performClick(); idle()
            val text = dialogText()
            assertTrue(text.contains("每项最多 2 次逻辑尝试，接收结果总时限 20 秒"))
            assertTrue(text.contains("仅超时或明确连接失败"))
            assertTrue(text.contains("保留失败和成功，不切换目标或协议"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
            navigate(activity.get(), MainActivity.NAV_HOME)
            button(activity.get(), "开始快速检查").performClick(); idle()
            assertTrue(dialogText().contains("每项最多 1 次逻辑尝试"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
            assertNull(controller(activity.get()).report)
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun repair_baseline_mismatch_blocks_retest_until_the_link_matches() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            val original = runtimeFixture()
            injectReport(activity.get(), original)
            assertTrue(controller(activity.get()).pinBaseline())
            val session = (activity.get().application as DiagnosticsApplication).repairSession
            assertTrue(session.associateBaseline(original.runId))
            injectReport(activity.get(), original.copy(runId = SECOND_RUN))
            assertTrue(controller(activity.get()).pinBaseline())
            activity.recreate(); idle()
            navigate(activity.get(), MainActivity.NAV_REPAIR)
            assertTrue(shownText(activity.get()).contains("配置关联的基线已被替换或清除"))
            assertFalse(button(activity.get(), "按修复基线计划复测").isEnabled)
            assertTrue(session.associateBaseline(SECOND_RUN))
            // RepairSession changes are refreshed when the screen is recreated, as on return from repair.
            activity.recreate(); idle()
            assertFalse(shownText(activity.get()).contains("配置关联的基线已被替换或清除"))
            assertTrue(button(activity.get(), "按修复基线计划复测").isEnabled)
            button(activity.get(), "按修复基线计划复测").performClick(); idle()
            assertTrue(dialogText().contains("复测不会读取当前表单或自动更换 DNS 目标"))
            latestDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    @Test fun demo_summary_never_describes_fabricated_success_as_a_device_measurement() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup()
        try {
            button(activity.get(), "查看离线演示（不联网）").performClick(); idle()
            val text = shownText(activity.get())
            assertTrue(text.contains("这是演示结果"))
            assertTrue(text.contains("未执行本次设备探测"))
            listOf("系统 DNS", "UDP DNS", "TCP DNS", "HTTPS 出口").forEach {
                assertTrue(text.contains("$it · 演示数据"))
            }
            assertFalse(text.contains("系统 DNS 已返回地址"))
            assertFalse(text.contains("HTTPS 出口 · 来源匹配"))
            assertFalse(button(activity.get(), "保存当前结果为对照基线").isEnabled)
            navigate(activity.get(), MainActivity.NAV_REPAIR)
            assertFalse(button(activity.get(), "使用当前结果建立修复基线").isEnabled)
            assertFalse(button(activity.get(), "按修复基线计划复测").isEnabled)
            assertNull(controller(activity.get()).baseline)
            assertFalse(controller(activity.get()).busy)
        } finally { activity.pause().stop().destroy() }
    }

    // These fabricated runtime-shaped reports only exercise UI logic; they are never device evidence.
    private fun runtimeFixture(raw: Boolean = false): RunReport {
        val network = NetworkSnapshot("test-network", listOf("WIFI"), false, true, true,
            listOf("192.0.2.5"), listOf("192.0.2.53"), false, null, true)
        return RunReport("00000000-0000-4000-8000-000000000001",
            "2026-10-21T00:00:00Z", "2026-10-21T00:00:01Z", 1000, 35, "0.3.0",
            QuickCheck.build(network, includeRaw = raw), network, network, false,
            DnsObservation(Execution.COMPLETED, listOf("192.0.2.8"), 20), HttpsObservation(),
            EvidenceOrigin.ANDROID_RUNTIME,
            if (raw) listOf(
                RawDnsObservation(DnsTransport.UDP, Execution.COMPLETED, 1, 25, 0, false, listOf("192.0.2.8")),
                RawDnsObservation(DnsTransport.TCP, Execution.COMPLETED, 2, 30, 0, false, listOf("192.0.2.8"))
            ) else emptyList())
    }

    private fun injectReport(activity: MainActivity, report: RunReport) {
        DiagnosticsController::class.java.getDeclaredField("report").apply { isAccessible = true }
            .set(controller(activity), report)
        DiagnosticsController::class.java.getDeclaredField("isDemo").apply { isAccessible = true }
            .setBoolean(controller(activity), false)
    }

    companion object { private const val SECOND_RUN = "00000000-0000-4000-8000-000000000002" }
}
