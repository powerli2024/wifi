package dev.proxyaudit.android

import androidx.appcompat.app.AppCompatActivity
import androidx.activity.OnBackPressedCallback
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.navigation.NavigationBarView
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.textfield.TextInputLayout
import com.google.android.material.textfield.TextInputEditText
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.text.InputFilter
import android.view.View
import android.view.WindowInsets
import android.widget.*
import dev.proxyaudit.core.*
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {
    private val controller get() = (application as DiagnosticsApplication).controller
    private lateinit var root: LinearLayout
    private lateinit var scroll: ScrollView
    private lateinit var homePanel: LinearLayout
    private lateinit var reportPanel: LinearLayout
    private lateinit var httpsFields: LinearLayout
    private lateinit var dnsFields: LinearLayout
    private lateinit var rawFields: LinearLayout
    private lateinit var homeSummary: TextView
    private lateinit var deepSummary: TextView
    private lateinit var scenarioHint: TextView
    private lateinit var detailToggle: Button
    private lateinit var evidenceDetails: LinearLayout
    private var resultTarget: LinearLayout? = null
    private lateinit var navigation: BottomNavigationView
    private lateinit var toolbar: MaterialToolbar
    private lateinit var repairPanel: LinearLayout
    private lateinit var repairAdvice: LinearLayout
    private lateinit var repairStatus: TextView
    private lateinit var recoveryCard: TextView
    private lateinit var repairBaseline: Button
    private lateinit var repairRetest: Button
    private lateinit var reportEntry: Button
    private lateinit var retryCheck: CheckBox
    private val fieldContainers = mutableMapOf<EditText, TextInputLayout>()
    private var reportReturnPage = 0
    private val presetButtons = mutableListOf<Button>()
    private var selectedPage = 0
    private var detailsExpanded = false
    private var section: LinearLayout? = null
    private val container get() = section ?: root
    private lateinit var expertPanel: LinearLayout
    private lateinit var expertToggle: Button
    private lateinit var quickRawCheck: CheckBox
    private lateinit var quickTarget: Spinner
    private lateinit var quickOptions: LinearLayout
    private lateinit var quickRun: Button
    private lateinit var repair: Button
    private lateinit var repairFromResults: Button
    private lateinit var pinBaseline: Button
    private lateinit var rerunBaseline: Button
    private lateinit var comparisonExport: Button
    private lateinit var endpoint: EditText
    private lateinit var dnsHost: EditText
    private lateinit var expectedIps: EditText
    private lateinit var httpsCheck: CheckBox
    private lateinit var dnsCheck: CheckBox
    private lateinit var trustCheck: CheckBox
    private lateinit var ipv6Check: CheckBox
    private lateinit var rawUdpCheck: CheckBox
    private lateinit var rawTcpCheck: CheckBox
    private lateinit var rawServer: EditText
    private lateinit var rawPort: EditText
    private lateinit var rawHost: EditText
    private lateinit var rawAaaaCheck: CheckBox
    private lateinit var run: Button
    private lateinit var cancel: Button
    private lateinit var demo: Button
    private lateinit var export: Button
    private lateinit var clear: Button
    private lateinit var status: TextView
    private lateinit var results: LinearLayout
    private val observer: () -> Unit = { render() }
    private var pendingExportId: String? = null
    private var pendingExportCode = -1
    private val writer = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingExportId = savedInstanceState?.getString(EXPORT_ID_STATE)
        pendingExportCode = savedInstanceState?.getInt(EXPORT_CODE_STATE, -1) ?: -1
        controller.reserveRestoredExportCode(pendingExportCode)
        val shell = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(getColor(R.color.surface)) }
        toolbar = MaterialToolbar(this).apply { setBackgroundColor(getColor(R.color.surface)); title = getString(R.string.nav_overview) }
        shell.addView(toolbar, LinearLayout.LayoutParams(-1, -2))
        scroll = ScrollView(this).apply { isFillViewport = true }
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(12), dp(20), dp(24)) }
        scroll.addView(root)
        shell.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        // Android 15 edge-to-edge: ensure inputs/actions are not hidden by bars or the keyboard.
        shell.setOnApplyWindowInsetsListener { view, insets ->
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
            } else {
                @Suppress("DEPRECATION") view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            }
            insets
        }
        navigation = BottomNavigationView(this).apply {
            tag = "primary-navigation"; isSaveEnabled = false
            labelVisibilityMode = NavigationBarView.LABEL_VISIBILITY_LABELED
            menu.add(0, NAV_HOME, 0, R.string.nav_overview).setIcon(R.drawable.ic_overview)
            menu.add(0, NAV_TEST, 1, R.string.nav_tests).setIcon(R.drawable.ic_tests)
            menu.add(0, NAV_REPAIR, 2, R.string.nav_repair).setIcon(R.drawable.ic_repair)
            setOnItemSelectedListener { item ->
                showPage(when (item.itemId) { NAV_TEST -> 1; NAV_REPAIR -> 2; else -> 0 }); true
            }
        }
        shell.addView(navigation, LinearLayout.LayoutParams(-1, -2))
        setContentView(shell)
        homePanel = newPanel(root, "home-panel")
        expertPanel = newPanel(root, "expert-panel")
        reportPanel = newPanel(root, "report-panel")
        repairPanel = newPanel(root, "repair-panel")
        section = homePanel
        body("PROXY / DIAGNOSTICS", 12, getColor(R.color.primary))
        title("代理证据诊断", 28)
        body("定位网站 DNS、连接、TLS 与 HTTP 问题，检查代理环境，修改配置后复测。", 17)
        body("仅测本应用 · 不占用 VPN · 测试前确认目标", 12, getColor(R.color.primary))
        homeSummary = card("从一次检查开始", "尚无结果。先检查 DNS 可用性，再按需要配置出口验证。")
        reportEntry = button("查看最近报告") { showReport() }
        title("网站与网络深度诊断", 20)
        body("输入一个网址，自动收集 Android 网络画像、执行手机内置自检，并逐层定位。支持 ChatGPT 与自定义 HTTPS 网站。", 14)
        deepSummary = card("网站与设备网络", "尚未运行。无需配置服务器，开始后自动收集并定位。")
        button("开始网站与网络诊断", true) { startActivity(Intent(this, DeepDiagnosticsActivity::class.java)) }
        title("01  快速检查 DNS", 20)
        body("不用填写。通过系统解析 example.com；可加测同一域名的 UDP / TCP 响应。", 14)
        quickRawCheck = check("同时检查原始 DNS UDP / TCP（明文，需确认）", false).apply {
            tag = "quick-raw"
        }
        quickOptions = newPanel(homePanel, "quick-options").apply { visibility = View.GONE }
        section = quickOptions
        quickTarget = Spinner(this).apply {
            tag = "quick-target"; isSaveEnabled = false
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_item,
                listOf("当前网络 DNS", "Cloudflare · 1.1.1.1", "Quad9 · 9.9.9.9", "Google · 8.8.8.8"))
                .apply { setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            isEnabled = false
            container.addView(this, LinearLayout.LayoutParams(-1, dp(54)))
        }
        body("目标仅用于原始 DNS，不修改系统设置；当前网络地址可能由 VPN 提供。", 12)
        section = homePanel
        quickRawCheck.setOnCheckedChangeListener { _, checked ->
            quickTarget.isEnabled = checked && !controller.busy
            quickOptions.visibility = if (checked) View.VISIBLE else View.GONE
        }
        quickRun = button("开始快速检查", true) { beginQuick() }
        title("02  专业验证", 20)
        body("按场景填写：DNS 对照、HTTPS 出口。每项都有示例和证据要求。")
        expertToggle = button("进入专业测试") { showPage(1) }
        title("03  修复与复测", 20)
        body("审查 Mihomo / Clash.Meta 配置，生成 DNS 修改副本；导入后用同一计划对照。")
        repair = button("打开修复中心") { showPage(2) }
        button("能力与隐私说明") {
            MaterialAlertDialogBuilder(this).setTitle("本应用能证明什么")
                .setMessage("可自动收集 Android 可见网络、执行手机内置实验，定位网站 DNS、连接、TLS、HTTP 与读取阶段；也可运行严格出口回显及配置副本修复复测。\n\n已完成层、失败层与下一步动作分别显示。DNS 有响应不等于无泄露；全机、其他应用、WebRTC、QUIC 和真实外层路径仍需专项证据。\n\n不申请 root，不安装 CA，不关闭证书验证。用户开始后才主动实验，无遥测或订阅读取。结果仅在进程内保留，导出才写文件，配置副本仍需手动导入。")
                .setPositiveButton("知道了", null).show()
        }
        demo = button("查看离线演示（不联网）") { controller.showDemo(); showReport() }
        section = expertPanel
        title("专业测试", 27)
        button("代理只读协同 · 版本与连接快照") { startActivity(Intent(this, ProxyCooperationActivity::class.java)) }
        button("网站访问 · DNS / 连接 / TLS / HTTP") { startActivity(Intent(this, DeepDiagnosticsActivity::class.java)) }
        body("1  选目的  →  2  检查填写  →  3  确认目标", 14, getColor(R.color.primary))
        body("场景只填入配置，确认后才发送测试流量。", 13)
        ProfessionalScenario.entries.forEach { scenario ->
            presetButtons.add(button(ProfessionalScenarios.guidance(scenario).title) { chooseScenario(scenario) })
        }
        scenarioHint = card("填写建议", "首次可选 DNS 对照，比较系统解析与指定目标的响应。没有受控回显服务时，先不启用 HTTPS。")
        button("查看专业填写指南") { showTestGuide() }
        title("系统 DNS", 20)
        dnsCheck = check("执行系统 DNS 解析", true)
        dnsFields = newPanel(expertPanel, "system-fields"); section = dnsFields
        dnsHost = input("待解析域名", "随机标记.你控制的域名").apply { setText(R.string.default_dns_query) }
        body("连通性可用 example.com。追踪 DNS 路径需你控制的唯一子域名和权威日志；随机前缀本身不保证有有效记录。不要填 URL。", 12)
        section = expertPanel
        title("原始 DNS 对照", 20)
        body("原始查询为明文，可分别检查 UDP / TCP；不受这里的系统 DNS 开关控制。", 13)
        rawUdpCheck = check("执行原始 DNS UDP 探测", false)
        rawTcpCheck = check("执行原始 DNS TCP 探测", false)
        rawFields = newPanel(expertPanel, "raw-fields"); section = rawFields
        rawServer = input("解析器数字 IP", "数字 IPv4 或 IPv6，不带方括号")
        button("填入当前网络 DNS") { fillNetworkDns() }.also { presetButtons.add(it) }
        body("填写客户端 DNS 虚拟地址可观察接管行为；填外部解析器地址可观察对该目标的响应。两者都不能单独确认真实线上路径。", 12)
        rawPort = input("解析器端口", "1–65535").apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            filters = arrayOf(InputFilter.LengthFilter(5))
            setText(R.string.default_dns_port)
        }
        rawHost = input("原始 DNS 查询域名", "原始DNS随机标记.你控制的域名")
        button("与系统查询使用同一域名") { rawHost.setText(dnsHost.text.toString().trim()) }.also { presetButtons.add(it) }
        rawAaaaCheck = check("查询 AAAA 记录（未选时查询 A）", false)
        body("通常端口 53，首次选 A。对照时保持相同域名。AAAA 是记录类型，不表示手机使用了 IPv6 传输。", 12)
        section = expertPanel
        title("HTTPS 代理出口", 20)
        httpsCheck = check("执行 HTTPS 来源地址回显", false)
        httpsFields = newPanel(expertPanel, "https-fields"); section = httpsFields
        endpoint = input("HTTPS 服务源地址", "https://你的受控主机:8443")
        body("填你控制或获准使用的服务源地址，如 https://echo.example.net:8443（格式示例，需替换）。普通网站、订阅链接和通用查 IP 页面不能代替本工具的 /v1/echo 服务。", 12)
        expectedIps = input("预期服务端来源 IP（可留空）", "IPv4 / IPv6，以英文逗号分隔")
        body("填独立确认的预期出口 IP，不要直接拿 DNS 服务器地址或本次结果作答案。公网出口通常不是手机局域网 IP；受控局域网实验允许按独立预期填写私网 IP。留空仅观察。", 14)
        trustCheck = check("我信任所选回显服务如实报告来源 IP", false)
        button("回显服务需要满足什么") {
            MaterialAlertDialogBuilder(this).setTitle("HTTPS 回显契约")
                .setMessage("源地址只包含 https://主机[:端口]，不能带路径、账户、查询参数或片段。应用固定请求 /v1/echo?requestId=本次标记。\n\n需要系统信任的有效 TLS 证书、不重定向，HTTP 200，Content-Type 为 application/json，UTF-8、无压缩，最多 4096 字节，恰好三个键：{\"schemaVersion\":1,\"requestId\":\"原样返回本次标记\",\"observedSourceIp\":\"服务端观察到的数字IP\"}。\n\n源码 tools/echo_fixture.py 仅为电脑回环开发服务，不是可直接从手机访问的公共部署。服务器需另行正确部署与验证。\n\n服务端声明仍需信任；即使 IP 匹配，也不证明整台手机都经过代理。")
                .setPositiveButton("知道了", null).show()
        }
        section = expertPanel
        ipv6Check = check("IPv6 专项仍在验收范围内", true)
        body("保持勾选会诚实记录“观察不足”；取消表示主动排除专项，不代表通过。服务端可能记录来源 IP 与测试域名，请勿填敏感业务数据。", 12)
        retryCheck = check(getString(R.string.retry_label), false)
        body("仅复核超时或明确连接失败；目标、协议和总等待预算不变。附加成功仍保留首次失败，不代表稳定或已修复。", 14)
        run = button("开始本次探测", true) { begin() }
        dnsCheck.setOnCheckedChangeListener { _, _ -> updateFields() }
        httpsCheck.setOnCheckedChangeListener { _, _ -> updateFields() }
        rawUdpCheck.setOnCheckedChangeListener { _, _ -> updateFields() }
        rawTcpCheck.setOnCheckedChangeListener { _, _ -> updateFields() }
        section = reportPanel
        title("检查结果", 27)
        body("先看发现，再看证据。无响应、未执行、证据不足分别显示。", 13)
        status = body("", 15)
        cancel = button("取消正在进行的探测") { controller.cancel() }
        results = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }; reportPanel.addView(results)
        detailToggle = button("展开详细证据") { detailsExpanded = !detailsExpanded; render() }
        evidenceDetails = newPanel(reportPanel, "evidence-details")
        export = button("导出本次 JSON 证据") { exportDialog() }
        title("修复前后对照", 20)
        body("先保存基线 → 调整一个设置 → 按相同计划复测。仅在本进程内保留；退出前可导出。", 13)
        pinBaseline = button("保存当前结果为对照基线") {
            toast(if (controller.pinBaseline()) "基线已保留在当前进程内；可调整一项设置后按相同计划复测。" else "请先完成一次实际检查，再保存基线。")
        }
        rerunBaseline = button("按基线相同计划复测") {
            controller.baseline?.let {
                confirm(it.config, controller.snapshot().privateDnsActive,
                    "沿用基线的查询和原始 DNS 数字目标；不会按当前网络重新选择目标。条件改变时可能不可比。\n\n")
            }
        }
        comparisonExport = button("导出基线与本次对照") { comparisonExportDialog() }
        repairFromResults = button("前往修复中心") { repair.performClick() }
        clear = button("清除结果与对照基线") { controller.clear() }
        section = repairPanel
        title("修复与复测", 27)
        body("先解释异常，再选择动作；保存配置副本后仍需在客户端导入。", 16)
        repairStatus = card("当前阶段", "尚未关联检查结果。可以先诊断，也可以审查你选择的配置。")
        repairAdvice = newPanel(repairPanel, "repair-advice")
        repairBaseline = button("使用当前结果建立修复基线") {
            if (controller.pinBaseline()) {
                val session = (application as DiagnosticsApplication).repairSession
                if (session.plan == null) session.associateBaseline(controller.baseline?.runId)
                toast("基线已保存。已有配置预览仍绑定生成时的基线；更换基线后请重新生成预览。")
            } else toast("请先完成一次实际检查，演示不能用作基线。")
            render()
        }
        button("审查配置与保存副本", true) {
            val session = (application as DiagnosticsApplication).repairSession
            if (!session.hasSource) session.associateBaseline(controller.baseline?.runId)
            startActivity(Intent(this, RepairActivity::class.java))
        }.also { presetButtons.add(it) }
        repairRetest = button("按修复基线计划复测") {
            controller.baseline?.let { confirm(it.config, controller.snapshot().privateDnsActive,
                "复测不会读取当前表单或自动更换 DNS 目标。请先确认客户端已导入副本或完成你计划的设置调整。\n\n") }
        }
        recoveryCard = card("修改前准备恢复方式", "保留原配置；记录原系统 Private DNS 模式和主机名。若修改后无法联网，先恢复这次改动的原值，再复测。不要为取得响应关闭证书验证或取消 VPN 阻断策略。此提示可离线查看，当前会话未自动备份配置。")
        button("查看当前报告与基线对照") { showReport() }
        section = null
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (selectedPage == 3) showPage(reportReturnPage)
                else if (selectedPage != 0) showPage(0)
                else { isEnabled = false; onBackPressedDispatcher.onBackPressed(); isEnabled = true }
            }
        })
        restoreDraft()
    }
    override fun onSaveInstanceState(outState: Bundle) {
        // Only the random request identity is saved. JSON, IPs, domains and policy stay in process memory.
        pendingExportId?.let { outState.putString(EXPORT_ID_STATE, it); outState.putInt(EXPORT_CODE_STATE, pendingExportCode) }
        super.onSaveInstanceState(outState)
    }
    override fun onStart() { super.onStart(); controller.observe(observer) }
    override fun onStop() { saveDraft(); controller.removeObserver(observer); super.onStop() }
    override fun onDestroy() { writer.shutdown(); super.onDestroy() }

    private fun saveDraft() {
        controller.inputDraft = mapOf(
            "endpoint" to endpoint.text.toString(), "dnsHost" to dnsHost.text.toString(),
            "expectedIps" to expectedIps.text.toString(), "https" to httpsCheck.isChecked.toString(),
            "systemDns" to dnsCheck.isChecked.toString(), "trusted" to trustCheck.isChecked.toString(),
            "ipv6Scope" to ipv6Check.isChecked.toString(), "rawUdp" to rawUdpCheck.isChecked.toString(),
            "rawTcp" to rawTcpCheck.isChecked.toString(), "rawServer" to rawServer.text.toString(),
            "rawPort" to rawPort.text.toString(), "rawHost" to rawHost.text.toString(),
            "rawAaaa" to rawAaaaCheck.isChecked.toString(),
            "quickRaw" to quickRawCheck.isChecked.toString(),
            "quickTarget" to quickTarget.selectedItemPosition.toString(),
            "page" to selectedPage.toString(),
            "reportReturnPage" to reportReturnPage.toString(),
            "retry" to retryCheck.isChecked.toString(),
            "detailsExpanded" to detailsExpanded.toString()
        ).toMap()
    }
    private fun restoreDraft() {
        val draft = controller.inputDraft
        listOf("endpoint" to endpoint, "dnsHost" to dnsHost, "expectedIps" to expectedIps,
            "rawServer" to rawServer, "rawPort" to rawPort, "rawHost" to rawHost).forEach { (key, input) ->
            draft[key]?.let { input.setText(it) }
        }
        listOf("https" to httpsCheck, "systemDns" to dnsCheck, "trusted" to trustCheck,
            "ipv6Scope" to ipv6Check, "rawUdp" to rawUdpCheck, "rawTcp" to rawTcpCheck,
            "rawAaaa" to rawAaaaCheck).forEach { (key, check) ->
            draft[key]?.let { check.isChecked = it == "true" }
        }
        quickRawCheck.isChecked = draft["quickRaw"] == "true"
        draft["quickTarget"]?.toIntOrNull()?.takeIf { it in QUICK_TARGETS.indices }?.let { quickTarget.setSelection(it) }
        detailsExpanded = draft["detailsExpanded"] == "true"
        reportReturnPage = draft["reportReturnPage"]?.toIntOrNull()?.takeIf { it in 0..2 } ?: 0
        retryCheck.isChecked = draft["retry"] == "true"
        showPage(draft["page"]?.toIntOrNull()?.takeIf { it in 0..3 } ?: 0)
        updateFields()
    }

    private fun showPage(page: Int) {
        selectedPage = page
        listOf(homePanel, expertPanel, repairPanel, reportPanel).forEachIndexed { index, panel ->
            panel.visibility = if (page == index) View.VISIBLE else View.GONE
        }
        navigation.visibility = if (page == 3) View.GONE else View.VISIBLE
        toolbar.title = getString(when (page) { 1 -> R.string.nav_tests; 2 -> R.string.nav_repair; 3 -> R.string.report_title; else -> R.string.nav_overview })
        if (page == 3) {
            toolbar.setNavigationIcon(R.drawable.ic_back)
            toolbar.navigationContentDescription = getString(R.string.back_to_previous)
            toolbar.setNavigationOnClickListener { showPage(reportReturnPage) }
        } else {
            toolbar.navigationIcon = null
            navigation.menu.findItem(when (page) { 1 -> NAV_TEST; 2 -> NAV_REPAIR; else -> NAV_HOME }).isChecked = true
        }
        currentFocus?.let {
            (getSystemService(INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager).hideSoftInputFromWindow(it.windowToken, 0)
            it.clearFocus()
        }
        scroll.post { scroll.scrollTo(0, 0) }
    }

    private fun showReport() {
        if (selectedPage != 3) reportReturnPage = selectedPage
        showPage(3)
    }

    private fun updateFields() {
        if (!::httpsFields.isInitialized) return
        httpsFields.visibility = if (httpsCheck.isChecked) View.VISIBLE else View.GONE
        dnsFields.visibility = if (dnsCheck.isChecked) View.VISIBLE else View.GONE
        rawFields.visibility = if (rawUdpCheck.isChecked || rawTcpCheck.isChecked) View.VISIBLE else View.GONE
    }

    private fun fillNetworkDns(): Boolean {
        val ip = controller.snapshot().configuredDnsServers.firstOrNull { NumericIp.canonical(it) != null }
        rawServer.setText(ip ?: "")
        toast(if (ip == null) "未取得网络 DNS，请填写你获准测试的解析器数字 IP。" else "已填入网络快照地址，可能是 VPN 虚拟地址；尚未执行。")
        return ip != null
    }

    private fun chooseScenario(scenario: ProfessionalScenario) {
        val guide = ProfessionalScenarios.guidance(scenario)
        val customized = endpoint.text.isNotBlank() || expectedIps.text.isNotBlank() ||
            dnsHost.text.toString() !in listOf("", "example.com") || rawHost.text.isNotBlank() ||
            rawServer.text.isNotBlank() || rawPort.text.toString() !in listOf("", "53") || trustCheck.isChecked
        if (!customized) { applyScenario(scenario); return }
        MaterialAlertDialogBuilder(this).setTitle(guide.title)
            .setMessage("${guide.purpose}\n\n${guide.fieldHints.joinToString("\n\n")}\n\n${guide.boundary}\n\n应用将重设测试开关。DNS 场景填 example.com、A 和端口 53；对照目标取当前网络快照，缺失则留空。HTTPS 场景保留已填地址与预期 IP，但需要重新确认信任。此操作不联网。")
            .setNegativeButton(R.string.cancel, null).setPositiveButton("应用填写建议") { _, _ ->
                applyScenario(scenario)
            }.show()
    }

    private fun applyScenario(scenario: ProfessionalScenario) {
        if (controller.busy) { toast("检查仍在进行，请完成后再调整。"); return }
        val guide = ProfessionalScenarios.guidance(scenario)
        val dns = scenario != ProfessionalScenario.HTTPS_EGRESS
        dnsCheck.isChecked = dns; httpsCheck.isChecked = !dns
        rawUdpCheck.isChecked = scenario == ProfessionalScenario.DNS_COMPARE
        rawTcpCheck.isChecked = rawUdpCheck.isChecked
        trustCheck.isChecked = false; ipv6Check.isChecked = true
        if (dns) {
            dnsHost.setText(R.string.default_dns_query); rawHost.setText(R.string.default_dns_query)
            rawPort.setText(R.string.default_dns_port); rawAaaaCheck.isChecked = false
            if (scenario == ProfessionalScenario.DNS_COMPARE) fillNetworkDns()
        }
        fieldContainers.values.forEach { it.error = null }
        scenarioHint.text = getString(R.string.scenario_content, guide.title, guide.purpose, guide.boundary)
        updateFields()
    }

    private fun showTestGuide() {
        MaterialAlertDialogBuilder(this).setTitle("专业测试怎么填")
            .setMessage("① DNS 异常排查\n系统域名与原始查询域名都填 example.com，原始端口 53，先选 A，同时启用 UDP / TCP。目标取当前网络 DNS 或你获准测试的数字 IP；保持同一目标复测。系统失败、原始成功只说明探测结果不同。\n\n② HTTPS 出口验证\n只填支持 /v1/echo 契约的受控 HTTPS 服务。预期 IP 来自独立确认的代理出口；未知就留空，确认服务可信后再勾选信任。\n\n③ DNS 泄露专项\n用你控制的唯一子域名（先配置有效记录），记录查询时间，并关联权威 DNS、网关或代理日志。随机域名、返回地址或快速响应都不能单独证明路径。\n\n④ 修改后复测\n先在结果页保存基线，只改变一项设置，再按基线计划复测。相同域名可能缓存；新标记适合另开日志实验，不应冒充严格相同计划对照。\n\n未执行 ≠ 失败；有响应 ≠ 无泄露。IPv6 记录与实际外层 IPv6 路径需分开验证。")
            .setPositiveButton("知道了", null).show()
    }

    private fun beginQuick() {
        fieldContainers.values.forEach { it.error = null }
        try {
            val snapshot = controller.snapshot()
            val target = QUICK_TARGETS.getOrElse(quickTarget.selectedItemPosition) { QuickDnsTarget.NETWORK }
            confirm(QuickCheck.build(snapshot, target, quickRawCheck.isChecked), snapshot.privateDnsActive)
        } catch (e: IllegalArgumentException) { validationError(e) }
    }

    private fun begin() {
        try {
            fieldContainers.values.forEach { it.error = null }
            val ep = if (httpsCheck.isChecked) validateField(endpoint) { Endpoint.parse(endpoint.text.toString().trim()) } else null
            val host = if (dnsCheck.isChecked) validateField(dnsHost) { dnsHost.text.toString().trim().also { require(isDnsHost(it)) { "系统 DNS 项需要有效 ASCII 域名，不是 URL 或 IP 地址" } } } else null
            val rawDns = if (rawUdpCheck.isChecked || rawTcpCheck.isChecked) {
                val server = validateField(rawServer) { rawServer.text.toString().trim().also {
                    require(NumericIp.canonical(it) != null) { "原始 DNS 需要数字 IPv4 或 IPv6 解析器地址，不是域名或 URL" }
                } }
                val port = validateField(rawPort) { rawPort.text.toString().toIntOrNull().also {
                    require(it != null && it in 1..65535) { "原始 DNS 端口必须在 1–65535 之间" }
                }!! }
                val rawQuery = validateField(rawHost) { rawHost.text.toString().trim().also {
                    require(isDnsHost(it)) { "原始 DNS 项需要有效 ASCII 查询域名，不是 URL 或 IP 地址" }
                } }
                RawDnsConfig(serverIp = server, port = port, host = rawQuery,
                    recordType = if (rawAaaaCheck.isChecked) DnsRecordType.AAAA else DnsRecordType.A,
                    udp = rawUdpCheck.isChecked, tcp = rawTcpCheck.isChecked)
            } else null
            require(httpsCheck.isChecked || dnsCheck.isChecked || rawDns != null) { "请至少选择一项探测" }
            val ips = if (httpsCheck.isChecked) validateField(expectedIps) { parseExpectedIps(expectedIps.text.toString()) } else emptySet()
            val config = RunConfig(ep, host, ProbePolicy(httpsCheck.isChecked, dnsCheck.isChecked, ips, ipv6Check.isChecked, trustCheck.isChecked), rawDns = rawDns,
                maxAttempts = if (retryCheck.isChecked) 2 else 1)
            confirm(config, controller.snapshot().privateDnsActive)
        } catch (e: IllegalArgumentException) { validationError(e) }
    }

    private fun <T> validateField(field: EditText, validation: () -> T): T = try { validation() }
    catch (error: IllegalArgumentException) {
        fieldContainers[field]?.error = error.message ?: "请检查填写格式"
        field.requestFocus()
        throw error
    }

    private fun validationError(error: IllegalArgumentException) {
        // Only fixed local validation messages are displayed; no raw network exception text.
        // Field errors stay next to the input. Only a plan-level error needs a dialog.
        if (fieldContainers.values.none { it.error != null })
            MaterialAlertDialogBuilder(this).setTitle("请检查配置").setMessage(error.message ?: "配置无效")
                .setPositiveButton("知道了", null).show()
    }

    private fun confirm(config: RunConfig, privateDnsActive: Boolean?, introduction: String = "") {
        if ((application as DiagnosticsApplication).deepDiagnostics.busy || WebsiteDiagnostics.hasPendingWork()) {
            toast("深度诊断仍在执行或释放资源，请先完成或停止该检查。")
            return
        }
        val target = buildString {
                append(introduction)
                append("每项最多 ${config.maxAttempts} 次逻辑尝试，接收结果总时限 ${config.evidenceBudgetMillis / 1000} 秒。系统释放资源可能更久，期间不能开始新检查。\n")
                if (config.maxAttempts > 1) append("仅超时或明确连接失败可附加一次；间隔约 500 ms，保留失败和成功，不切换目标或协议。\n")
                if (config.policy.runHttps) config.endpoint?.let { append("HTTPS：${it.origin}/v1/echo\n") }
                if (config.policy.runDns) config.dnsHost?.let {
                    append("系统 DNS：$it\n由 Android 系统处理；实际解析器、缓存和线上路径未知。\n")
                }
                config.rawDns?.let {
                    val address = if (':' in it.serverIp) "[${it.serverIp}]" else it.serverIp
                    if (it.udp) append("原始 DNS UDP：$address:${it.port} · ${it.host} · ${it.recordType}\n")
                    if (it.tcp) append("原始 DNS TCP：$address:${it.port} · ${it.host} · ${it.recordType}\n")
                    append("\n明文 DNS，VPN 可能接管或改写；响应不证明无泄露。数字 IPv6 只代表 socket 目标地址族，不证明实际外层路径。\n")
                    if (privateDnsActive == true)
                        append("\n注意：系统快照显示 Private DNS 已启用，但这里的原始 UDP/TCP 探针仍发送明文 DNS，不会自动采用系统的加密解析。\n")
                }
                append("\n将发送本应用的测试流量，不会替换或更改现有 VPN 配置。端点和解析器可能记录来源 IP、域名和时间。是否开始？")
        }
        MaterialAlertDialogBuilder(this).setTitle(if (config.rawDns != null && privateDnsActive == true) "确认明文 DNS 测试（Private DNS 已启用）" else "确认本次测试目标").setMessage(target)
                .setNegativeButton(R.string.cancel, null).setPositiveButton("开始") { _, _ ->
                    if ((application as DiagnosticsApplication).deepDiagnostics.busy ||
                        (application as DiagnosticsApplication).proxyCooperation.busy || ProxyCooperationProbe.hasPendingWork() ||
                        WebsiteDiagnostics.hasPendingWork() || !controller.start(config)) toast("上一个操作仍在释放资源，请稍后再试。")
                    else showReport()
                }.show()
    }
    private fun renderRepairHub() {
        val report = controller.report
        val baseline = controller.baseline
        val session = (application as DiagnosticsApplication).repairSession
        val advice = DnsRepairAdvisor.advise(report, baseline)
        val linked = session.baselineRunId
        val mismatch = linked != null && linked != baseline?.runId
        val stage = when {
            session.userReportedApplied -> "已记录手动导入确认；客户端实际生效尚未独立验证。"
            session.exportState == CopyExportState.COPY_READBACK_VERIFIED -> "副本已读回核对；尚未确认客户端导入。"
            session.exportState == CopyExportState.COPY_WRITTEN_UNVERIFIED -> "副本已写入，无法读回核对；不要据此判断修复成功。"
            session.busy -> session.status
            session.exportState == CopyExportState.FAILED || session.exportState == CopyExportState.CANCELLED_WRITE_UNKNOWN -> session.status
            session.plan != null -> "修改预览已生成；尚未取得已核对的配置副本。"
            else -> "等待审查与选择动作。"
        }
        repairStatus.text = getString(R.string.repair_stage_content, stage, advice.sourceLabel, advice.baselineLabel,
            if (mismatch) getString(R.string.repair_baseline_mismatch) else "")
        repairBaseline.isEnabled = !controller.busy && !session.busy && !session.pickerPending &&
            report?.evidenceOrigin == EvidenceOrigin.ANDROID_RUNTIME
        repairRetest.isEnabled = !controller.busy && !session.busy && baseline != null && !mismatch
        recoveryCard.text = getString(R.string.recovery_content,
            session.plan?.sourceSha256?.let { getString(R.string.source_hash_content, it) } ?: "")
        repairAdvice.removeAllViews()
        advice.recommendations.forEach { recommendation ->
            MaterialUi.card(this, repairAdvice, recommendation.title, recommendation.reason)
            repairAdvice.addView(MaterialUi.button(this, "查看建议 · ${recommendation.repairKind.label}") {
                MaterialAlertDialogBuilder(this).setTitle(recommendation.title)
                    .setMessage(recommendation.reason + "\n\n" + recommendation.steps.mapIndexed { index, step -> "${index + 1}. $step" }.joinToString("\n\n") +
                        "\n\n证据局限\n" + recommendation.blindSpots.joinToString("\n") + "\n\n恢复建议\n" + recommendation.recoveryAdvice)
                    .setPositiveButton("知道了", null).show()
            })
        }
    }
    private fun render() {
        if (!::root.isInitialized) return
        val deep = (application as DiagnosticsApplication).deepDiagnostics
        deepSummary.text = when {
            deep.busy -> "网站与设备网络\n${deep.status}\n进入网站诊断可查看进度或停止。"
            deep.report != null -> "最近深度诊断\n${deep.report?.findings?.firstOrNull() ?: "检查完成，进入查看分层证据。"}"
            else -> "网站与设备网络\n尚未运行。无需配置服务器，开始后自动收集并定位。"
        }
        val busy = controller.busy
        val report = controller.report
        val baseline = controller.baseline
        listOf(endpoint, dnsHost, expectedIps, httpsCheck, dnsCheck, trustCheck, ipv6Check,
            rawUdpCheck, rawTcpCheck, rawServer, rawPort, rawHost, rawAaaaCheck, run, demo, clear,
            quickRawCheck, quickRun, repair, repairFromResults, retryCheck).forEach { it.isEnabled = !busy }
        quickTarget.isEnabled = !busy && quickRawCheck.isChecked
        presetButtons.forEach { it.isEnabled = !busy }
        cancel.isEnabled = busy
        cancel.visibility = if (busy) View.VISIBLE else View.GONE
        export.isEnabled = report != null && !controller.exportPending
        pinBaseline.isEnabled = !busy && report?.evidenceOrigin == EvidenceOrigin.ANDROID_RUNTIME
        rerunBaseline.isEnabled = !busy && baseline != null
        comparisonExport.isEnabled = !busy && !controller.exportPending && baseline != null &&
            report != null && report.evidenceOrigin == EvidenceOrigin.ANDROID_RUNTIME && baseline.runId != report.runId
        status.text = controller.status
        reportEntry.isEnabled = report != null || busy
        reportEntry.text = if (busy) "查看检查进度" else "查看最近报告"
        renderRepairHub()
        homeSummary.text = when {
            busy -> "检查进行中\n打开检查进度，可查看状态或取消。"
            report != null -> ReportPresentation.summarize(report).let { "最近一次 · ${if (controller.isDemo) "离线演示" else "本应用"}\n${it.headline}\n查看报告了解发现与下一步。" }
            else -> "从一次检查开始\n尚无结果。先检查 DNS 可用性，再按需要配置出口验证。"
        }
        results.removeAllViews()
        evidenceDetails.removeAllViews()
        resultTarget = null
        detailToggle.isEnabled = report != null
        detailToggle.text = if (detailsExpanded) "收起详细证据" else "展开详细证据"
        evidenceDetails.visibility = if (detailsExpanded && report != null) View.VISIBLE else View.GONE
        if (baseline != null)
            resultText("已保留对照基线 · ${baseline.startedAtUtc}", 12)
        if (report == null) {
            resultText(if (busy) "正在收集证据" else "还没有检查结果", 20)
            resultText(if (busy) "完成后会分别显示系统 DNS、原始 DNS 和 HTTPS 的状态。" else "从首页开始快速检查，或在“测试”页选择专业场景。未执行的项目不会被当作通过。", 14)
            return
        }
        if (controller.isDemo) resultText("离线演示：下列时间、地址和结果均为虚构。", 16, getColor(R.color.attention))
        val summary = ReportPresentation.summarize(report)
        resultText(summary.headline, 22, getColor(R.color.on_surface))
        resultText(summary.detail, 14)
        summary.rows.forEach {
            resultText("${it.title} · ${it.status}", 16, getColor(R.color.primary))
            resultText(it.detail, 13)
        }
        resultText("建议下一步", 18)
        resultText(summary.nextStep, 14)
        if (baseline != null) {
            resultText("与基线对照", 18)
            if (baseline.runId == report.runId) {
                resultText("当前结果已保存为基线。需要手动确认并完成另一次相同计划检查后才能比较。", 13)
            } else {
                val comparison = ReportComparison.compare(baseline, report)
                resultText(comparison.summary, 16)
                resultText(comparison.details.joinToString("\n"), 13)
            }
        }
        resultTarget = evidenceDetails
        if (baseline != null) resultText("对照基线：${baseline.runId} · 仅保留在当前进程内。", 12)
        resultText("逐项诊断建议", 18)
        DiagnosticAdvisor.review(report).forEach {
            resultText(it.title, 16)
            resultText("${it.detail}\n下一步：${it.actionHint}", 13)
        }
        resultText("详细证据", 18)
        report.stopReason?.let { resultText("本次提前停止：$it；未执行的项目不代表通过。", 15, getColor(R.color.attention)) }
        if (report.attempts.isNotEmpty()) {
            resultText("分次尝试记录", 18)
            resultText("每项最多 ${report.config.maxAttempts} 次。汇总保留首次失败；后次成功不能覆盖失败或证明稳定。", 14)
            report.attempts.forEach { attempt ->
                val observation = attempt.dns?.let { "${it.execution} · ${it.failure ?: "无错误"}" }
                    ?: attempt.https?.let { "${it.execution} · ${it.failure ?: "无错误"}" }
                    ?: attempt.rawDns?.let { "${it.execution} · ${it.failure ?: "无错误"} · RCODE ${it.responseCode ?: "未知"}" } ?: "尚无结果"
                resultText("${attempt.probe} · 第 ${attempt.attemptNumber} 次\n$observation\n开始 +${attempt.startedAfterMillis} ms · 结束 ${attempt.finishedAfterMillis?.let { "+$it ms" } ?: "未记录"} · 本次超时上限 ${attempt.timeoutMillis} ms\n标记 ${attempt.attemptId}" +
                    if (attempt.retryScheduled) "\n附加尝试触发：${attempt.retryTrigger} · 已等待 ${attempt.retryDelayMillis} ms（不保证下一次已执行）" else "", 14)
            }
        }
        resultText("运行 ${report.runId}\n${report.startedAtUtc}\n耗时 ${report.durationMillis} ms · 本应用请求范围", 12)
        resultText("实际运行的目标：${report.config.endpoint?.origin ?: "未启用 HTTPS"}\n系统 DNS：${report.config.dnsHost ?: "未启用"}\n预期来源：${report.config.policy.expectedSourceIps.joinToString().ifEmpty { "未设置" }}", 13)
        addResult("HTTPS 来源地址策略", report.egress)
        resultText("执行：${report.https.execution} · HTTP：${report.https.statusCode ?: "未知"}\n服务端报告来源：${report.https.serverReportedSourceIp ?: "未知"}\n正常 TLS 验证：${if (report.https.tlsValidated) "已完成" else "未取得证据"} · 错误：${report.https.failure ?: "无"}", 13)
        addResult("DNS 保密策略", report.dnsPrivacy)
        resultText("系统 DNS 观察", 15)
        resultText("执行：${report.dns.execution}\n返回地址：${report.dns.addresses.joinToString().ifEmpty { "无" }}\n错误：${report.dns.failure ?: "无"}", 13)
        if (report.config.policy.runDns) resultText(SystemDnsDiagnostics.summary(report), 13)
        val raw = report.config.rawDns
        if (raw == null) {
            resultText("原始 DNS UDP / TCP：本次未启用。", 13)
        } else {
            val family = if (':' in raw.serverIp) "IPv6" else "IPv4"
            resultText("原始 DNS 请求目标：${raw.serverIp} · 端口 ${raw.port}\n查询：${raw.host} · ${raw.recordType}\n请求的 socket 目标地址族：$family；实际外层路径未证明。", 13)
            listOf(DnsTransport.UDP to raw.udp, DnsTransport.TCP to raw.tcp).forEach { (transport, enabled) ->
                if (enabled) {
                    val observation = report.rawDns.firstOrNull { it.transport == transport }
                    resultText("原始 DNS $transport", 16)
                    if (observation == null) {
                        resultText("执行：未执行；尚未取得该协议的响应证据。", 13)
                    } else {
                        resultText("执行：${observation.execution} · 耗时：${observation.durationMillis?.let { "$it ms" } ?: "未知"}\nDNS 响应码：${observation.responseCode ?: "未知"} · 截断标记：${if (observation.truncated) "是" else "否"}\n返回地址：${observation.addresses.joinToString().ifEmpty { "无" }}\n错误：${observation.failure ?: "无"}", 13)
                    }
                }
            }
            resultText("明文 DNS 可能被 VPN 接管或改写。响应只证明本应用取得了一份 DNS 响应，不证明无泄露、指定解析器身份或真实物理出口。", 12)
        }
        addResult("IPv6 专项", report.ipv6)
        val n = report.networkBefore
        resultText("运行前网络快照\n传输标签：${n.transports.joinToString().ifEmpty { "未知" }}\nVPN 能力：${yesNo(n.vpnCapability)} · 系统已验证：${yesNo(n.validatedCapability)}\nPrivate DNS：${yesNo(n.privateDnsActive)}\n期间观察到网络变化：${if (report.networkChanged) "是" else "否（不等于证明绝对稳定）"}", 13)
        resultText("证据局限\n" + RunReport.LIMITATIONS.joinToString("\n") { "• $it" }, 12)
        resultTarget = null
    }
    private fun exportDialog() {
        val report = controller.report ?: return
        MaterialAlertDialogBuilder(this).setTitle("选择导出内容")
            .setMessage("脱敏副本会隐藏服务域名、来源 IP、DNS 地址和本地网络标识。完整证据包含这些信息，分享前请检查。演示数据始终标注为演示。")
            .setNegativeButton(R.string.cancel, null)
            .setNeutralButton("脱敏副本") { _, _ -> save(report, false) }
            .setPositiveButton("完整证据") { _, _ -> save(report, true) }.show()
    }
    private fun save(report: RunReport, full: Boolean) {
        saveTicket(controller.beginExport(report, full))
    }
    private fun comparisonExportDialog() {
        val before = controller.baseline ?: return
        val after = controller.report ?: return
        MaterialAlertDialogBuilder(this).setTitle("导出两次检查的对照")
            .setMessage("包含基线、本次报告和比较说明。脱敏副本隐藏两次的域名、地址和网络标识；完整对照包含这些信息。比较只描述观察，不证明已修复或无泄露。")
            .setNegativeButton(R.string.cancel, null)
            .setNeutralButton("脱敏副本") { _, _ -> saveComparison(before.runId, after.runId, false) }
            .setPositiveButton("完整对照") { _, _ -> saveComparison(before.runId, after.runId, true) }.show()
    }
    private fun saveComparison(beforeId: String, afterId: String, full: Boolean) {
        if (controller.baseline?.runId != beforeId || controller.report?.runId != afterId || controller.busy) {
            toast("对照结果已变化，请重新查看后导出。"); return
        }
        saveTicket(controller.beginComparisonExport(full))
    }
    private fun saveTicket(ticket: DiagnosticsController.ExportTicket?) {
        if (ticket == null) { toast("当前没有可导出的结果，或上一次保存尚未结束。"); return }
        pendingExportId = ticket.requestId; pendingExportCode = ticket.requestCode
        try {
            @Suppress("DEPRECATION") startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE); type = "application/json"
                putExtra(Intent.EXTRA_TITLE, ticket.suggestedName)
            }, ticket.requestCode)
        } catch (_: RuntimeException) {
            pendingExportId = null; pendingExportCode = -1; controller.cancelExport(ticket.requestId)
            toast("无法打开系统保存窗口，请稍后重试。")
        }
    }
    @Deprecated("Frozen export request identity is validated before writing the selected document.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pendingExportCode) return
        val requestId = pendingExportId ?: return
        pendingExportId = null; pendingExportCode = -1
        if (resultCode != RESULT_OK || data?.data == null) { controller.cancelExport(requestId); return }
        val uri = data.data!!
        val json = controller.consumeExport(requestId)
        if (json == null) { toast("应用进程已重启，未写入旧结果。请重新导出。"); return }
        writer.execute {
            val success = try { contentResolver.openOutputStream(uri, "wt")?.use { it.write(json.toByteArray(Charsets.UTF_8)) } != null } catch (_: Exception) { false }
            runOnUiThread { toast(if (success) "JSON 已写入你选择的位置。" else "未能写入文件，请重新选择位置。") }
        }
    }
    private fun addResult(label: String, a: Assessment) {
        val color = when (a.verdict) {
            Verdict.MATCH -> getColor(R.color.primary); Verdict.VIOLATE -> getColor(R.color.error)
            Verdict.INSUFFICIENT -> getColor(R.color.attention); else -> getColor(R.color.on_surface_variant)
        }
        resultText("$label · ${a.verdict.label}", 17, color)
        resultText(a.reason, 13)
    }
    private fun resultText(text: String, size: Int, color: Int = getColor(R.color.on_surface_variant)) {
        (resultTarget ?: results).addView(TextView(this).apply { this.text = text; textSize = size.toFloat(); setTextColor(color); setPadding(0, dp(7), 0, dp(7)); setTextIsSelectable(true) })
    }
    private fun title(text: String, size: Int) { body(text, size, getColor(R.color.on_surface)).apply {
        setPadding(0, dp(16), 0, dp(10)); isAccessibilityHeading = true
    } }
    private fun body(text: String, size: Int = 14, color: Int = getColor(R.color.on_surface_variant)): TextView = TextView(this).apply {
        this.text = text; textSize = size.coerceAtLeast(14).toFloat(); setTextColor(color); setPadding(0, dp(5), 0, dp(9)); container.addView(this)
    }
    private fun card(title: String, text: String): TextView =
        MaterialUi.card(this, container, title, text)
    private fun newPanel(parent: LinearLayout, id: String) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; tag = id; isSaveEnabled = false
        parent.addView(this, LinearLayout.LayoutParams(-1, -2))
    }
    private fun check(text: String, checked: Boolean) = MaterialCheckBox(this).apply { this.text = text; minHeight = dp(48); isChecked = checked; isSaveEnabled = false; container.addView(this) }
    private fun input(label: String, hint: String): EditText {
        val layout = TextInputLayout(this).apply {
            this.hint = label; helperText = hint; boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
            isSaveEnabled = false; isHintAnimationEnabled = false
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, dp(8), 0, dp(8)) }
        }
        val edit = TextInputEditText(layout.context).apply {
            id = View.generateViewId(); tag = hint; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            filters = arrayOf(InputFilter.LengthFilter(2048)); setSingleLine(true); textSize = 15f; isSaveEnabled = false; importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            minHeight = dp(56)
        }
        layout.addView(edit, LinearLayout.LayoutParams(-1, -2)); container.addView(layout)
        fieldContainers[edit] = layout
        return edit
    }
    private fun button(label: String, primary: Boolean = false, onClick: () -> Unit) =
        MaterialUi.button(this, label, primary, onClick).also { container.addView(it) }
    private fun yesNo(value: Boolean?) = when (value) { true -> "是"; false -> "否"; null -> "未知" }
    private fun toast(text: String) { Toast.makeText(this, text, Toast.LENGTH_LONG).show() }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    companion object {
        const val NAV_HOME = 1001
        const val NAV_TEST = 1002
        const val NAV_REPAIR = 1003
        private const val EXPORT_ID_STATE = "pending-export-request-id"
        private const val EXPORT_CODE_STATE = "pending-export-request-code"
        private val QUICK_TARGETS = listOf(QuickDnsTarget.NETWORK, QuickDnsTarget.CLOUDFLARE, QuickDnsTarget.QUAD9, QuickDnsTarget.GOOGLE)
    }
}
