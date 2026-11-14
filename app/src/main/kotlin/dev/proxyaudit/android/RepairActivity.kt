package dev.proxyaudit.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.WindowInsets
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dev.proxyaudit.core.DnsProviders

/** Local config copies and manual recovery guidance; no global settings or client writes. */
class RepairActivity : AppCompatActivity() {
    private val app get() = application as DiagnosticsApplication
    private val session get() = app.repairSession
    private lateinit var root: LinearLayout
    private lateinit var details: LinearLayout
    private lateinit var inspectionDetails: LinearLayout
    private lateinit var status: TextView
    private lateinit var copyResult: TextView
    private lateinit var recovery: TextView
    private lateinit var baseline: TextView
    private lateinit var provider: Spinner
    private lateinit var load: MaterialButton
    private lateinit var preview: MaterialButton
    private lateinit var save: MaterialButton
    private lateinit var clear: MaterialButton
    private lateinit var imported: MaterialButton
    private lateinit var cancel: MaterialButton
    private lateinit var copyHost: MaterialButton
    private lateinit var showInspection: MaterialCheckBox
    private var pendingId: String? = null
    private var pendingCode = -1
    private var selectedProviderIndex = -1
    private var cancelRequested = false
    private var ready = false
    private val observer: () -> Unit = { render() }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        pendingId = state?.getString("repairRequestId")
        pendingCode = state?.getInt("repairRequestCode", -1) ?: -1
        session.reserveCode(pendingCode)
        selectedProviderIndex = (state?.getInt("repairProviderIndex", -1)
            ?: if (session.plan != null) session.providerIndex else -1).takeIf { it in DnsProviders.public.indices } ?: -1
        val shell = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setBackgroundColor(getColor(R.color.surface)); isSaveEnabled = false
        }
        val toolbar = MaterialToolbar(this).apply {
            title = "配置副本与恢复"; setTitleTextColor(getColor(R.color.on_surface))
            setBackgroundColor(getColor(R.color.surface))
            setNavigationIcon(R.drawable.ic_back); setNavigationIconTint(getColor(R.color.on_surface))
            navigationContentDescription = "返回修复页"; setNavigationOnClickListener { finish() }; isSaveEnabled = false
        }
        shell.addView(toolbar, LinearLayout.LayoutParams(-1, -2))
        val scroll = ScrollView(this).apply { isFillViewport = true; isSaveEnabled = false }
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(8), dp(16), dp(24)); isSaveEnabled = false
        }
        scroll.addView(root)
        shell.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        shell.setOnApplyWindowInsetsListener { view, insets ->
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
            } else {
                @Suppress("DEPRECATION") view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            }
            insets
        }
        setContentView(shell)
        MaterialUi.card(this, root, "先审查，再保存副本", "读取配置 → 预览修改 → 保存并读回 → 手动导入 → 同计划复测")
        text("仅处理本地 UTF-8、256 KiB 以内的完整 Mihomo / Clash.Meta YAML。配置仅在进程内处理，不访问其中的订阅地址。", 14)
        load = button("选择本地 YAML 配置", true) { choose(false) }
        val providerLabel = text("选择 DNS 方案", 20)
        provider = Spinner(this).apply {
            id = View.generateViewId(); tag = "repairProvider"; isSaveEnabled = false; minimumHeight = dp(48)
            adapter = object : ArrayAdapter<String>(this@RepairActivity, android.R.layout.simple_spinner_dropdown_item,
                listOf("请选择 DNS 方案") + DnsProviders.public.map { it.label }) {
                override fun isEnabled(position: Int) = position > 0
                override fun areAllItemsEnabled() = false
            }
            setSelection(selectedProviderIndex + 1)
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    if (position > 0) {
                        selectedProviderIndex = position - 1
                        session.selectProvider(selectedProviderIndex)
                        render()
                    }
                }
            }
        }
        providerLabel.labelFor = provider.id
        root.addView(provider, LinearLayout.LayoutParams(-1, -2))
        text("这里没有自动推荐。方案会调整普通查询的 DoH；现有路由仍可能直连，必要引导可能使用明文。企业或局域网解析应先保留原配置并核对影响。", 14)
        baseline = text("", 14).apply { tag = "repairBaseline" }
        preview = button("生成 DNS 修改预览") {
            if (selectedProviderIndex < 0) return@button
            session.selectProvider(selectedProviderIndex)
            session.generate(app.controller.baseline?.runId)
        }
        status = text("", 16).apply { tag = "repairStatus"; accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE }
        cancel = button("取消当前文件操作") {
            if (session.cancelActive()) { cancelRequested = true; render() }
        }
        details = column(root)
        showInspection = MaterialCheckBox(this).apply {
            text = "显示完整审查说明"; textSize = 16f; isSaveEnabled = false; tag = "repairInspectionToggle"
            isChecked = state?.getBoolean("repairShowInspection", false) ?: false
            setOnCheckedChangeListener { _, _ -> render() }
        }
        root.addView(showInspection)
        inspectionDetails = column(root)
        save = button("保存修复副本", true) { confirmSave() }
        copyResult = MaterialUi.card(this, root, "副本状态", "尚未保存副本").apply { tag = "repairCopyResult" }
        imported = button("我已在客户端导入此副本") { session.markUserReportedApplied() }
        recovery = MaterialUi.card(this, root, "恢复准备", "").apply { tag = "repairRecovery" }
        button("返回修复页，核对计划并复测") { finish() }
        clear = button("清除内存中的配置") {
            session.clear(); selectedProviderIndex = -1; provider.setSelection(0); render()
        }
        text("Android 系统 DNS", 20)
        text("这是另一条手动设置路径，不使用上面的“已导入副本”记录。调整前记下原模式和主机名；返回应用不会自动探测，也不代表系统设置已改变。", 14)
        copyHost = button("复制所选服务的 Private DNS 主机名") {
            if (selectedProviderIndex !in DnsProviders.public.indices) return@button
            val host = DnsProviders.public[selectedProviderIndex].privateDnsHost
            (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("Private DNS", host))
            toast("已复制主机名；尚未更改系统设置。")
        }
        button("打开网络设置，配置 Private DNS") { openSettings(Settings.ACTION_WIRELESS_SETTINGS) }
        button("打开 VPN 设置") { openSettings(Settings.ACTION_VPN_SETTINGS) }
        ready = true
        render()
    }

    override fun onStart() { super.onStart(); session.observe(observer) }
    override fun onStop() { session.removeObserver(observer); super.onStop() }
    override fun onSaveInstanceState(outState: Bundle) {
        pendingId?.let { outState.putString("repairRequestId", it); outState.putInt("repairRequestCode", pendingCode) }
        outState.putInt("repairProviderIndex", selectedProviderIndex)
        outState.putBoolean("repairShowInspection", showInspection.isChecked)
        super.onSaveInstanceState(outState)
    }
    private fun render() {
        if (!ready) return
        val idle = !session.busy && !session.pickerPending
        val selected = selectedProviderIndex in DnsProviders.public.indices
        load.isEnabled = idle; provider.isEnabled = idle
        preview.isEnabled = idle && selected && session.hasSource
        save.isEnabled = idle && selected && session.plan?.changes?.isNotEmpty() == true
        clear.isEnabled = !session.busy
        copyHost.isEnabled = idle && selected
        imported.isEnabled = session.canMarkUserReportedApplied
        if (!session.busy) cancelRequested = false
        cancel.visibility = if (session.busy) View.VISIBLE else View.GONE
        cancel.isEnabled = session.busy && !cancelRequested
        status.text = session.status
        baseline.text = session.baselineRunId?.let { "本方案关联基线：$it\n复测前仍需核对原计划；不会自动运行。" }
            ?: if (app.controller.baseline != null) "生成预览时将关联本进程当前基线；生成前请确认它是修改前的检查。"
                else "尚未关联基线。可先返回保存修改前的实际检查，再生成预览。"
        details.removeAllViews()
        session.plan?.let { plan ->
            detail(details, "修改预览 · ${plan.changes.size} 项", 20)
            plan.changes.forEach { detail(details, "${it.path}\n原值：${it.before}\n建议：${it.after}\n${it.reason}") }
            plan.warnings.forEach { detail(details, "• $it") }
        }
        showInspection.isEnabled = session.inspection != null
        inspectionDetails.visibility = if (showInspection.isChecked && session.inspection != null) View.VISIBLE else View.GONE
        inspectionDetails.removeAllViews()
        if (showInspection.isChecked) session.inspection?.let { checked ->
            detail(inspectionDetails, checked.summary, 16)
            checked.findings.forEach { detail(inspectionDetails, "• $it") }
        }
        val stateLabel = when (session.exportState) {
            CopyExportState.NONE -> "尚未保存副本"
            CopyExportState.PLAN_READY -> "方案已生成，尚未写入"
            CopyExportState.WRITING -> "正在写入副本"
            CopyExportState.VERIFYING -> "已写入，正在读回核对"
            CopyExportState.COPY_WRITTEN_UNVERIFIED -> "副本已写入，内容未核实"
            CopyExportState.COPY_READBACK_VERIFIED -> "副本已读回核对"
            CopyExportState.FAILED -> "副本保存或核对失败，请勿导入"
            CopyExportState.CANCELLED_NO_WRITE -> "已取消，未开始写入"
            CopyExportState.CANCELLED_WRITE_UNKNOWN -> "已取消，目标可能是不完整副本"
        }
        val evidence = session.copyEvidence
        copyResult.text = buildString {
            append("副本状态\n$stateLabel")
            evidence?.let {
                append("\n冻结输出 SHA-256：${it.expectedSha256}\n预期字节数：${it.expectedByteCount}")
                it.readbackSha256?.let { hash -> append("\n读回 SHA-256：$hash") }
                it.readbackByteCount?.let { count -> append("\n读回字节数：$count") }
            }
            append(if (session.userReportedApplied) "\n已记录用户手动导入；客户端生效状态未独立核验。"
                else "\n尚未确认客户端导入；副本核对不代表运行效果已验证。")
        }
        recovery.text = buildString {
            append("恢复准备\n")
            session.sourceDocumentUri?.let { append("原文件位置：$it\n") }
            session.plan?.let { append("读取时原文件 SHA-256：${it.sourceSha256}\n") }
            append("请确认原文件仍可找到，并自行保留副本。进程内原文不是备份，应用没有自动备份或控制代理客户端。\n")
            append("导入前记下客户端原配置与 DNS 覆盖选项。若连接异常，手动切回原配置及原覆盖设置，再核对原计划后复测；不要盲目关闭 VPN 或证书验证。")
        }
    }
    private fun confirmSave() {
        val frozen = session.plan ?: return
        if (selectedProviderIndex < 0 || session.busy || session.pickerPending) return
        MaterialAlertDialogBuilder(this).setTitle("保存完整配置副本")
            .setMessage("将保存上方预览的 ${frozen.changes.size} 项修改，并读回核对。原文件保留；目标文件可能含节点凭据、订阅地址等敏感内容，请选择自己控制的位置。\n\n保存不等于客户端已导入，也不证明 DNS 路径安全。")
            .setNegativeButton("取消", null)
            .setPositiveButton("选择保存位置") { _, _ ->
                if (session.plan !== frozen) toast("预览已变化，请重新核对后保存。") else choose(true)
            }.show()
    }
    private fun choose(export: Boolean) {
        val ticket = (if (export) session.beginExport() else session.beginImport()) ?: return
        pendingId = ticket.id; pendingCode = ticket.code
        try {
            @Suppress("DEPRECATION") startActivityForResult(Intent(if (export) Intent.ACTION_CREATE_DOCUMENT else Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = if (export) "application/yaml" else "*/*"
                if (export) putExtra(Intent.EXTRA_TITLE, "mihomo-dns-repaired.yaml")
            }, ticket.code)
        } catch (_: RuntimeException) {
            session.cancel(ticket.id); pendingId = null; pendingCode = -1
            toast("无法打开系统文件窗口，请稍后重试。")
        }
    }
    @Deprecated("Document contents remain in the process, not in saved state.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pendingCode) return
        val id = pendingId ?: return
        pendingId = null; pendingCode = -1
        if (resultCode != RESULT_OK || data?.data == null) { session.cancel(id); return }
        if (!session.accept(id, requestCode, data.data!!)) toast("配置操作已失效或进程已重启，请重新选择。未写入旧配置。")
    }
    private fun openSettings(action: String) {
        try { startActivity(Intent(action)) }
        catch (_: RuntimeException) {
            try { startActivity(Intent(Settings.ACTION_SETTINGS)); toast("请在系统设置中搜索 Private DNS 或 VPN。") }
            catch (_: RuntimeException) { toast("无法打开设置，请手动进入系统网络设置。") }
        }
    }
    private fun column(parent: LinearLayout) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; isSaveEnabled = false; parent.addView(this)
    }
    private fun text(value: String, size: Int = 14) = detail(root, value, size)
    private fun detail(parent: LinearLayout, value: String, size: Int = 14) = TextView(this).apply {
        text = value; textSize = size.toFloat(); setTextColor(getColor(R.color.on_surface))
        setPadding(0, dp(8), 0, dp(8)); isSaveEnabled = false
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (size >= 20) isAccessibilityHeading = true
        parent.addView(this)
    }
    private fun button(label: String, primary: Boolean = false, action: () -> Unit) =
        MaterialUi.button(this, label, primary, action).also { root.addView(it) }
    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    private fun dp(value: Int) = MaterialUi.dp(this, value)
}

