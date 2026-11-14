package dev.proxyaudit.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.InputFilter
import android.text.InputType
import android.view.View
import android.view.MenuItem
import android.view.WindowInsets
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.isVisible
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import dev.proxyaudit.core.NumericIp
import dev.proxyaudit.core.ProxyCooperationProbe
import dev.proxyaudit.core.WebsiteDiagnostics
import dev.proxyaudit.core.WebsitePlan
import dev.proxyaudit.core.WebsiteReport
import dev.proxyaudit.core.WebsiteStage
import dev.proxyaudit.core.WebsiteStageStatus
import dev.proxyaudit.core.isDnsHost
import java.net.URI
import java.util.concurrent.Executors

/** Website diagnostics is separate from the strict /v1/echo policy experiment. */
class DeepDiagnosticsActivity : AppCompatActivity() {
    private val app get() = application as DiagnosticsApplication
    private val session get() = app.deepDiagnostics
    private lateinit var root: LinearLayout
    private lateinit var url: TextInputEditText
    private lateinit var field: TextInputLayout
    private lateinit var proxy: Spinner
    private lateinit var raw: MaterialCheckBox
    private lateinit var start: MaterialButton
    private lateinit var local: MaterialButton
    private lateinit var cancel: MaterialButton
    private lateinit var export: MaterialButton
    private lateinit var toolbarExport: MenuItem
    private lateinit var saveBaseline: MaterialButton
    private lateinit var retest: MaterialButton
    private lateinit var exportComparison: MaterialButton
    private lateinit var clearReport: MaterialButton
    private lateinit var clearSavedBaseline: MaterialButton
    private lateinit var baselineStatus: TextView
    private lateinit var status: TextView
    private lateinit var results: LinearLayout
    private val observer = { render() }
    private val handler = Handler(Looper.getMainLooper())
    private val writer = Executors.newSingleThreadExecutor()
    private var pendingExport: String? = null
    private var pendingExportCode = -1
    private var renderedId: String? = null
    private var renderedKey: String? = null
    private val expanded = mutableSetOf<String>()
    private val refresh = object : Runnable {
        override fun run() { render(); handler.postDelayed(this, 1_000) }
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        pendingExport = state?.getString("deepExport")
        pendingExportCode = state?.getInt("deepExportCode", -1) ?: -1
        session.reserveRestoredExportCode(pendingExportCode)
        if (state?.getString("expandedReportId") == session.report?.id) {
            expanded.addAll(state?.getStringArrayList("expandedSections").orEmpty())
            renderedId = session.report?.id
        }
        val shell = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(getColor(R.color.surface)) }
        shell.addView(MaterialToolbar(this).apply {
            title = "网络深度诊断"; setNavigationIcon(R.drawable.ic_back)
            navigationContentDescription = "返回"; setNavigationOnClickListener { finish() }
            toolbarExport = menu.add("导出").apply {
                setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM); isEnabled = false
                setOnMenuItemClickListener { exportDialog(); true }
            }
        })
        val scroll = ScrollView(this)
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(12), dp(20), dp(24)) }
        scroll.addView(root); shell.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        shell.setOnApplyWindowInsetsListener { view, insets ->
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
            } else {
                @Suppress("DEPRECATION") view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            }; insets
        }
        setContentView(shell)
        status = MaterialUi.card(this, root, "一个网址，逐层定位", "网络画像 → 本机自检 → DNS / 连接 / TLS / HTTP / 正文")
        status.tag = "deep-status"
        field = TextInputLayout(this).apply { hint = "网站地址"; isSaveEnabled = false }
        url = TextInputEditText(field.context).apply {
            tag = "website-url"; isSaveEnabled = false; setSingleLine()
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            filters = arrayOf(InputFilter.LengthFilter(2048)); setText(session.urlDraft)
        }
        field.addView(url); root.addView(field)
        button("填入 ChatGPT") { url.setText(R.string.website_chatgpt_url) }
        text("支持域名或完整 HTTPS 地址；先定位失败阶段，再决定复测和修复。", 13)
        text("你的代理状态（作为排查线索）", 16)
        proxy = Spinner(this).apply {
            tag = "proxy-declaration"; isSaveEnabled = false
            adapter = ArrayAdapter(this@DeepDiagnosticsActivity, android.R.layout.simple_spinner_dropdown_item,
                listOf("不确定", "代理已开启（模式可未知）", "代理未开启"))
            setSelection(session.proxyDraft.coerceIn(0, 2))
        }; root.addView(proxy, LinearLayout.LayoutParams(-1, dp(52)))
        raw = MaterialCheckBox(this).apply {
            setText(R.string.website_raw_dns_option)
            tag = "deep-raw"; isChecked = session.rawDraft; isSaveEnabled = false
        }; root.addView(raw)
        text("选用当前网络 DNS 做 A / AAAA × UDP / TCP 对照，每项最多 4 秒；会发送明文查询。", 13)
        start = button("开始自动诊断", true) { confirm(false) }
        local = button("仅检查本机环境（不访问外网）") { confirm(true) }
        cancel = button("停止本次诊断") { session.cancel() }
        export = button("导出深度诊断 JSON") { exportDialog() }
        export.tag = "deep-export"
        baselineStatus = text("", 13).apply { tag = "deep-baseline-status" }
        saveBaseline = button("保存本次为基线") { confirmBaseline() }
        retest = button("按原计划复测") { confirmRetest() }
        exportComparison = button("导出基线与本次对照 JSON") { exportDialog(true) }
        results = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; tag = "deep-results" }; root.addView(results)
        clearReport = button("清除本次深度报告") { session.clear() }
        clearSavedBaseline = button("清除深度诊断基线") { session.clearBaseline() }
        text("按定位处理", 20)
        button("代理只读协同") { startActivity(Intent(this, ProxyCooperationActivity::class.java)) }
        button("查看系统 VPN 设置") { openSettings(Settings.ACTION_VPN_SETTINGS) }
        button("查看网络与 Private DNS 设置") { openSettings(Settings.ACTION_WIRELESS_SETTINGS) }
        text("系统设置由你确认修改；诊断不会关闭 VPN、修改 DNS 或安装证书。分应用规则通常需在代理客户端内查看。", 13)
        render()
    }

    private fun confirm(localOnly: Boolean) {
        if (cannotStart()) {
            toast("另一项诊断仍在执行或释放资源，请稍后。")
            return
        }
        field.error = null
        val plan = if (localOnly) null else try { WebsitePlan.parse(url.text.toString()) }
        catch (e: IllegalArgumentException) { field.error = e.message ?: "请输入有效 HTTPS 地址"; return }
        if (plan != null && raw.isChecked && !isDnsHost(URI(plan.url).host ?: "")) {
            field.error = "数字 IP 网址不适用域名 DNS 对照，请关闭扩展对照后诊断。"; return
        }
        val server = if (!localOnly && raw.isChecked) app.controller.snapshot().configuredDnsServers.firstOrNull { NumericIp.canonical(it) != null } else null
        if (!localOnly && raw.isChecked && server == null) { field.error = "当前网络未提供可用数字 DNS 地址；可先关闭扩展对照。"; return }
        val expected = listOf("UNKNOWN", "ENABLED", "DISABLED")[proxy.selectedItemPosition.coerceIn(0, 2)]
        MaterialAlertDialogBuilder(this).setTitle(if (localOnly) "运行本机受控自检" else "运行自动分层诊断")
            .setMessage(buildString {
                append("收集 Android 可见接口、路由、MTU、DNS、Private DNS、系统代理与网络能力。\n\n内置回环服务检查正常响应、超时与拒绝连接，结束即关闭。")
                plan?.let { append("\n\n网站：${it.displayTarget}\n使用填写的路径和查询参数发送有界 GET，不携带浏览器登录凭据，不自动跳转；暂时性连接/等待失败自动复核一次。网站总预算 30 秒，整体不超过 60 秒（系统释放可能延迟）。") }
                server?.let { append("\n\n原始 DNS：${dnsEndpoint(it)}，针对网址域名进行 A / AAAA × UDP / TCP 四项明文查询。") }
                if (plan != null) append("\n\n网站和解析器可能记录测试来源、域名及时间。")
            }).setNegativeButton("取消", null).setPositiveButton("开始") { _, _ ->
                saveDraft()
                if (cannotStart() || !session.start(plan, expected, server)) toast("上一项操作仍在执行，请稍后。")
            }.show()
    }
    private fun render() {
        if (!::results.isInitialized) return
        val blocked = cannotStart()
        start.isEnabled = !blocked; local.isEnabled = !blocked
        url.isEnabled = !session.busy; proxy.isEnabled = !session.busy; raw.isEnabled = !session.busy
        cancel.visibility = if (session.busy) View.VISIBLE else View.GONE
        val report = session.report
        val primaryFinding = report?.let {
            if (it.stopReason != null) it.findings.firstOrNull()
            else it.website?.summary ?: it.selfTest?.summary ?: it.findings.firstOrNull()
        }
        status.text = if (!session.busy && report != null && !WebsiteDiagnostics.hasPendingWork())
            getString(R.string.card_content, "本次定位", primaryFinding ?: session.status)
        else getString(R.string.card_content, "诊断状态", if (!session.busy && WebsiteDiagnostics.hasPendingWork()) "报告已冻结，等待系统释放解析资源…" else session.status)
        export.isEnabled = !session.busy && session.report != null && !session.exportPending
        toolbarExport.isEnabled = export.isEnabled
        val baselineBlockers = session.baselineSaveBlockers
        val comparison = session.comparison
        saveBaseline.isEnabled = !blocked && baselineBlockers.isEmpty()
        retest.isEnabled = !blocked && session.retestPlan() != null
        retest.text = if (session.baseline != null) "按基线原计划复测" else "按原计划复测"
        exportComparison.isEnabled = !session.busy && comparison != null && !session.exportPending
        clearReport.isEnabled = !session.busy && report != null
        clearSavedBaseline.isEnabled = !session.busy && session.baseline != null
        baselineStatus.text = session.baseline?.let { "已保存基线 · ${it.startedAt}\n复测沿用基线网址、预算和原始 DNS 目标。基线仅保留在本次应用进程中。" }
            ?: "修复前保存基线，调整后按原计划复测。两份报告可一起导出。"
        if (!session.busy && session.report != null && baselineBlockers.isNotEmpty())
            baselineStatus.append("\n本次不能保存为基线：${baselineBlockers.joinToString(" ")}")
        val key = "${report?.id}:${session.baseline?.id}:${comparison?.summary}"
        if (renderedKey == key) return
        renderedKey = key
        if (renderedId != report?.id) expanded.clear()
        renderedId = report?.id; results.removeAllViews()
        report ?: return
        report.website?.let { stageTable(it) }
        comparison?.let { value ->
            MaterialUi.card(this, results, "与基线比较", value.summary)
            disclosure("comparison", "比较条件与变化") { body ->
                detail(body, buildString {
                    if (value.blockers.isNotEmpty()) appendLine("不可直接归因的原因\n" + value.blockers.joinToString("\n"))
                    if (value.changes.isNotEmpty()) appendLine("观察到的变化\n" + value.changes.joinToString("\n"))
                    if (value.cautions.isNotEmpty()) appendLine("解释说明\n" + value.cautions.joinToString("\n"))
                })
            }
        }
        val explanations = report.findings.filter { it != primaryFinding }
        if (explanations.isNotEmpty()) disclosure("analysis", "定位依据与处理建议") { body -> detail(body, explanations.joinToString("\n\n")) }
        report.website?.let { site -> disclosure("website", "网站完整证据与说明") { body -> detail(body, site.toText()) } }
        report.before?.let {
            disclosure("network", "Android 网络画像") { body ->
                detail(body, inventoryText(it))
                body.addView(MaterialUi.button(this, "查看网络画像全部字段") {
                    MaterialAlertDialogBuilder(this).setTitle("当前设备网络信息（仅本机显示）")
                        .setMessage(NetworkInventory.toJson(it, true)).setPositiveButton("关闭", null).show()
                })
            }
        }
        report.selfTest?.let { value ->
            disclosure("self", "手机内置实验 · ${value.checks.count { it.status == SelfTestStatus.PASS }}/${value.checks.size} 符合预期") { body ->
                detail(body, value.summary + "\n" + value.checks.joinToString("\n") { "${it.title} · ${selfStatus(it.status)}\n${it.detail}" })
            }
        }
        if (report.dns.isNotEmpty()) disclosure("dns", "当前 DNS 交叉验证 · ${report.dns.size} 项") { body ->
            detail(body, report.dns.joinToString("\n\n") {
                val o = it.observation
                "${it.recordType} / ${o.transport} · ${executionLabel(o.execution)}\n${o.durationMillis ?: "—"} ms · rcode ${o.responseCode ?: "—"} · ${o.addresses.size} 个地址 · ${o.failure ?: "无执行错误"}"
            })
        }
    }
    private fun confirmBaseline() {
        val value = session.report ?: return
        MaterialAlertDialogBuilder(this).setTitle(if (session.baseline == null) "保存修复前基线" else "替换现有基线")
            .setMessage("保存本次报告和完整实验计划，供修改设置后复测比较。\n\n${value.website?.plan?.displayTarget ?: "仅本机环境实验"}\n\n基线只保存在本次应用进程中；需要留档时请导出。失败结果也可作为基线，取消或缺测的报告不能保存。")
            .setNegativeButton("取消", null).setPositiveButton("保存基线") { _, _ ->
                if (session.report?.id != value.id || !session.saveBaseline()) toast("当前报告不完整、仍在运行或已改变，未保存基线。")
                else toast("基线已保存；调整后可按基线原计划复测。")
                render()
            }.show()
    }
    private fun confirmRetest() {
        if (cannotStart()) { toast("另一项诊断仍在执行或释放资源，请稍后。"); return }
        val plan = session.retestPlan() ?: return
        MaterialAlertDialogBuilder(this).setTitle(if (plan.usesBaseline) "按基线原计划复测" else "按本次原计划复测")
            .setMessage(buildString {
                append("重新收集网络画像并运行本机自检。")
                plan.websitePlan?.let {
                    append("\n\n网站：${it.displayTarget}\n沿用原完整路径和查询参数，发送有界 GET，不携带浏览器登录凭据或自动跳转。网站预算 ${it.totalTimeoutMillis / 1000} 秒，最多 ${it.maxAttempts} 次尝试。")
                }
                plan.rawServer?.let {
                    append("\n\n明文 DNS：${dnsEndpoint(it)}\n沿用原目标执行 A / AAAA × UDP / TCP；即使当前 DNS 配置已改变也不自动替换，以便对照。")
                }
                append("\n\n代理声明：${when (plan.expectedProxy) { "ENABLED" -> "代理已开启"; "DISABLED" -> "代理未开启"; else -> "不确定" }}（沿用原声明）。")
                if (plan.websitePlan != null) append("\n网站和解析器可能记录测试来源、域名及时间；整体预算最多 60 秒。")
                else append("\n仅运行本机环境实验，不访问外网。")
                append("\n\n当前输入框的修改不会替换原计划。")
            }).setNegativeButton("取消", null).setPositiveButton("开始复测") { _, _ ->
                if (cannotStart() || session.retestPlan()?.sourceRunId != plan.sourceRunId ||
                    !session.start(plan.websitePlan, plan.expectedProxy, plan.rawServer)) toast("原计划已改变或仍有操作运行，请重新确认。")
            }.show()
    }
    private fun cannotStart() = session.busy || app.controller.busy || WebsiteDiagnostics.hasPendingWork() ||
        app.proxyCooperation.busy || ProxyCooperationProbe.hasPendingWork()
    private fun dnsEndpoint(address: String) = if (':' in address) "[$address]:53" else "$address:53"
    private fun stageTable(value: WebsiteReport) {
        val body = evidenceCard("分层结果${if (value.attempts.size > 1) " · 首次尝试" else ""}")
        fun row(label: String, state: String, duration: String, heading: Boolean = false) {
            val line = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; minimumHeight = dp(40) }
            listOf(label to 1f, state to 1.7f, duration to 1f).forEach { (item, weight) ->
                line.addView(TextView(this).apply {
                    text = item; textSize = if (heading) 13f else 15f
                    setTextColor(getColor(if (heading) R.color.on_surface_variant else R.color.on_surface))
                    setPadding(0, dp(8), dp(4), dp(8)); isSaveEnabled = false
                }, LinearLayout.LayoutParams(0, -2, weight))
            }; body.addView(line)
        }
        row("阶段", "观察结果", "耗时", true)
        for (stage in WebsiteStage.entries) {
            val item = value.stages.firstOrNull { it.stage == stage }
            row(when (stage) { WebsiteStage.DNS -> "DNS"; WebsiteStage.CONNECT -> "连接"; WebsiteStage.TLS -> "TLS"; WebsiteStage.HTTP -> "HTTP"; WebsiteStage.BODY -> "正文" },
                when (item?.status ?: WebsiteStageStatus.NOT_RUN) {
                    WebsiteStageStatus.NOT_RUN -> "未执行"; WebsiteStageStatus.SUCCEEDED -> "成功"
                    WebsiteStageStatus.FAILED -> "失败"; WebsiteStageStatus.CANCELLED -> "已取消"
                    WebsiteStageStatus.NOT_OBSERVED -> "未观测"; WebsiteStageStatus.PARTIAL -> "部分完成"
                }, item?.durationMillis?.let { "$it ms" } ?: "—")
        }
        detail(body, buildString {
            value.statusCode?.let { append("HTTP $it · ${value.httpProtocol ?: "协议未观测"}  ") }
            value.tlsVersion?.let { append("$it  ") }
            append("总计 ${value.durationMillis} ms")
            if (value.attempts.size > 1) append("\n共 ${value.attempts.size} 次尝试；首轮结果保留，复核详情见完整证据。")
        })
        body.tag = "deep-stage-table"
    }
    private fun evidenceCard(title: String): LinearLayout {
        val card = MaterialCardView(this).apply {
            radius = dp(12).toFloat(); cardElevation = 0f; strokeWidth = 0
            setCardBackgroundColor(getColor(R.color.surface_container)); isSaveEnabled = false
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, dp(8), 0, dp(8)) }
        }
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(12), dp(16), dp(12))
        }
        detail(body, title, 18); card.addView(body); results.addView(card); return body
    }
    /** Expanding an evidence section only reads the already frozen report. */
    private fun disclosure(key: String, title: String, content: (LinearLayout) -> Unit) {
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; tag = "deep-section-$key"; isSaveEnabled = false
            setPadding(dp(12), 0, dp(12), dp(8))
            isVisible = key in expanded
        }
        val toggle = MaterialUi.button(this, "") { }.apply { tag = "deep-toggle-$key" }
        fun label() {
            toggle.text = getString(R.string.deep_disclosure_label,
                getString(if (body.isVisible) R.string.deep_collapse else R.string.deep_expand), title)
            toggle.contentDescription = toggle.text
            toggle.isSelected = body.isVisible
        }
        toggle.setOnClickListener {
            if (body.isVisible) { body.isVisible = false; expanded.remove(key) }
            else { body.isVisible = true; expanded.add(key) }
            label()
        }
        label(); content(body); results.addView(toggle); results.addView(body)
    }
    private fun detail(parent: LinearLayout, value: String, size: Int = 14) = TextView(this).apply {
        text = value; textSize = size.toFloat(); setTextColor(getColor(R.color.on_surface))
        setPadding(0, dp(6), 0, dp(6)); isSaveEnabled = false; setTextIsSelectable(true)
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        parent.addView(this)
    }
    private fun exportDialog(comparison: Boolean = false) {
        MaterialAlertDialogBuilder(this).setTitle(if (comparison) "导出基线与本次对照" else "选择报告内容")
            .setMessage("默认脱敏网址、IP、代理地址和接口身份，保留阶段与错误。完整报告含设备网络标识，仅在需要本地深入分析时保存。")
            .setNegativeButton("取消", null).setPositiveButton("导出脱敏报告") { _, _ -> export(false, comparison) }
            .setNeutralButton("完整报告") { _, _ -> export(true, comparison) }.show()
    }
    private fun export(full: Boolean, comparison: Boolean = false) {
        val ticket = (if (comparison) session.freezeComparisonExport(full) else session.freezeExport(full)) ?: return
        pendingExport = ticket.id; pendingExportCode = ticket.requestCode
        try {
            @Suppress("DEPRECATION") startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                type = "application/json"; addCategory(Intent.CATEGORY_OPENABLE)
                putExtra(Intent.EXTRA_TITLE, ticket.suggestedName)
            }, ticket.requestCode)
        } catch (_: RuntimeException) { session.discardExport(pendingExport); pendingExport = null; pendingExportCode = -1; toast("无法打开文件选择器。") }
        render()
    }
    @Deprecated("Legacy document result bridge")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pendingExportCode) return
        val id = pendingExport ?: return
        pendingExport = null; pendingExportCode = -1
        if (resultCode != Activity.RESULT_OK || data?.data == null) { session.discardExport(id); render(); return }
        val payload = session.takeExport(id)
        if (payload == null) { toast("进程内原报告已不存在，未写入旧结果，请重新导出。"); render(); return }
        val uri = data.data!!
        writer.execute {
            val ok = runCatching { contentResolver.openOutputStream(uri, "wt")?.use { it.write(payload.toByteArray(Charsets.UTF_8)) } ?: error("No stream") }.isSuccess
            handler.post { toast(if (ok) "报告已保存。" else "保存失败，请更换文件位置后重试。"); render() }
        }
    }
    private fun openSettings(action: String) {
        try { startActivity(Intent(action)) } catch (_: RuntimeException) { toast("此设备未提供该设置入口，请从系统设置进入。") }
    }
    override fun onStart() { super.onStart(); session.observe(observer); handler.postDelayed(refresh, 1_000) }
    override fun onStop() { saveDraft(); session.removeObserver(observer); handler.removeCallbacks(refresh); super.onStop() }
    override fun onSaveInstanceState(out: Bundle) {
        pendingExport?.let { out.putString("deepExport", it); out.putInt("deepExportCode", pendingExportCode) }
        out.putString("expandedReportId", renderedId)
        out.putStringArrayList("expandedSections", ArrayList(expanded))
        super.onSaveInstanceState(out)
    }
    override fun onDestroy() { writer.shutdown(); super.onDestroy() }
    private fun saveDraft() { if (::url.isInitialized) { session.urlDraft = url.text.toString(); session.proxyDraft = proxy.selectedItemPosition; session.rawDraft = raw.isChecked } }
    private fun inventoryText(value: NetworkInventoryReport): String = buildString {
        appendLine(value.summary)
        appendLine("采集时间：${value.capturedAtUtc}；读取耗时 ${value.durationMillis} ms")
        val current = value.networks.singleOrNull { it.isDefault }
        if (current == null) appendLine("默认网络：未取得或无法唯一识别")
        else {
            appendLine("当前传输：${current.transports.joinToString().ifEmpty { "未提供" }}")
            appendLine("VPN 标签：${if ("VPN" in current.transports) "有" else if (current.capabilities == null) "未知" else "未显示"}；系统验证：${yesNo(current.capabilities?.get("VALIDATED"))}")
            appendLine("Private DNS：${yesNo(current.privateDnsActive)}；配置 DNS：${current.dnsServers.size} 个")
            val v4 = current.addresses.count { ':' !in it }
            val v6 = current.addresses.count { ':' in it }
            appendLine("接口地址：${current.addresses.size} 个（IPv4 $v4 / IPv6 $v6）；路由：${current.routes.size} 条；MTU：${current.mtu ?: "未提供"}")
            appendLine("非计费能力：${yesNo(current.capabilities?.get("NOT_METERED"))}；不受限能力：${yesNo(current.capabilities?.get("NOT_RESTRICTED"))}")
            appendLine("系统估计带宽：下行 ${current.downstreamKbps ?: "未知"} / 上行 ${current.upstreamKbps ?: "未知"} Kbps；不是实测速度")
            appendLine("承载相关信号值：${current.signalStrength ?: "未提供"}")
            val proxy = value.defaultProxy ?: current.httpProxy
            appendLine("HTTP 代理配置：${when { proxy == null -> "未取得配置"; proxy.pacPresent -> "存在 PAC（未执行脚本）"; else -> "存在显式代理配置" }}")
            if (current.issues.isNotEmpty()) appendLine("字段缺失或限制：${current.issues.joinToString()}")
        }
        if (value.issues.isNotEmpty()) appendLine("采集限制：${value.issues.joinToString()}")
        append("这些是配置与能力观察，不证明本次流量经过代理；IPv6 地址不证明实际外层 IPv6 路径。")
    }
    private fun yesNo(value: Boolean?) = when (value) { true -> "是"; false -> "否"; null -> "未知" }
    private fun selfStatus(value: SelfTestStatus) = when (value) {
        SelfTestStatus.PASS -> "符合本机场景预期"; SelfTestStatus.FAIL -> "未符合预期"
        SelfTestStatus.CANCELLED -> "已取消"; SelfTestStatus.NOT_STARTED -> "未执行"
    }
    private fun executionLabel(value: dev.proxyaudit.core.Execution) = when (value) {
        dev.proxyaudit.core.Execution.COMPLETED -> "已完成"; dev.proxyaudit.core.Execution.ERROR -> "执行错误"
        dev.proxyaudit.core.Execution.CANCELLED -> "已取消"; dev.proxyaudit.core.Execution.NOT_STARTED -> "未执行"
    }
    private fun button(label: String, primary: Boolean = false, action: () -> Unit): MaterialButton = MaterialUi.button(this, label, primary, action).also { root.addView(it) }
    private fun text(value: String, size: Int) = TextView(this).apply {
        text = value; textSize = size.toFloat(); setTextColor(getColor(R.color.on_surface)); setPadding(0, dp(8), 0, dp(8)); isSaveEnabled = false
        root.addView(this)
    }
    private fun dp(value: Int) = MaterialUi.dp(this, value)
    private fun toast(value: String) { Toast.makeText(this, value, Toast.LENGTH_LONG).show() }
}
