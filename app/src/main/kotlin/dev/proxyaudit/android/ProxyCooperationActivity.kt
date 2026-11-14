package dev.proxyaudit.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.WindowInsets
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import dev.proxyaudit.core.ProxyCooperationPlan
import java.util.concurrent.Executors

/** No automatic discovery, polling or connection on screen entry. */
class ProxyCooperationActivity : AppCompatActivity() {
    private val session get() = (application as DiagnosticsApplication).proxyCooperation
    private lateinit var endpoint: EditText
    private lateinit var secret: EditText
    private lateinit var status: TextView
    private lateinit var result: TextView
    private lateinit var start: Button
    private lateinit var cancel: Button
    private lateinit var export: Button
    private lateinit var clear: Button
    private var pendingExport: String? = null
    private var pendingCode = -1
    private val writer = Executors.newSingleThreadExecutor()
    private val observer: () -> Unit = { render() }

    override fun onCreate(saved: Bundle?) {
        super.onCreate(saved)
        pendingExport = saved?.getString("proxyExport"); pendingCode = saved?.getInt("proxyExportCode", -1) ?: -1
        session.reserveRestoredExportCode(pendingCode)
        if (!session.hasExport(pendingExport)) { pendingExport = null; pendingCode = -1 }
        val outer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        outer.setOnApplyWindowInsetsListener { view, insets ->
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
            } else {
                @Suppress("DEPRECATION") view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop,
                    insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            }; insets
        }
        val toolbar = MaterialToolbar(this).apply {
            title = "代理只读协同"
            setNavigationIcon(androidx.appcompat.R.drawable.abc_ic_ab_back_material)
            setNavigationContentDescription("返回"); setNavigationOnClickListener { finish() }
        }
        outer.addView(toolbar)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(8), dp(16), dp(24))
        }
        outer.addView(ScrollView(this).apply { addView(root) }, LinearLayout.LayoutParams(-1, 0, 1f)); setContentView(outer)
        MaterialUi.card(this, root, "取得代理自身的证据", "确认后只读取 GET /version 与 /connections，展示后端版本及当时连接快照。不会改规则、关闭连接或触发测速。")
        MaterialUi.card(this, root, "填写建议", "地址来自代理软件的控制 API 设置，例如 https://controller.example:9090。HTTP 代理入口不是控制 API。仅支持系统信任证书的 HTTPS；没有该接口时，可继续使用网站分层诊断。共享 Secret 可能具备写权限，本应用仅允许上述两项读取。")
        endpoint = input(root, "HTTPS 控制 API 来源地址", "https://controller.example:9090", false).apply {
            tag = "proxy-endpoint"; setText(session.endpointDraft)
        }
        secret = input(root, "Secret（可选，仅本次使用）", "代理未设置认证时留空", true).apply { tag = "proxy-secret" }
        start = MaterialUi.button(this, "确认只读检查", true) { confirm() }.also { root.addView(it) }
        cancel = MaterialUi.button(this, "取消读取") { session.cancel() }.also { root.addView(it) }
        export = MaterialUi.button(this, "导出脱敏快照") { exportReport() }.also { root.addView(it) }
        clear = MaterialUi.button(this, "清除连接信息与报告") {
            if (session.clear()) { secret.text.clear(); endpoint.text.clear() }
            else toast("请等待取消完成后清除。")
        }.also { root.addView(it) }
        status = MaterialUi.card(this, root, "状态", session.status)
        result = TextView(this).apply {
            textSize = 14f; setTextColor(getColor(R.color.on_surface)); setTextIsSelectable(true)
            isSaveEnabled = false; importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }.also { root.addView(it) }
        render()
    }
    private fun input(parent: LinearLayout, label: String, placeholder: String, password: Boolean): EditText {
        val layout = TextInputLayout(this).apply { hint = label; placeholderText = placeholder; isSaveEnabled = false }
        val edit = TextInputEditText(layout.context).apply {
            setSingleLine(); isSaveEnabled = false; importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            inputType = InputType.TYPE_CLASS_TEXT or (if (password) InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_TEXT_VARIATION_URI)
            if (password) imeOptions = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }
        layout.addView(edit); parent.addView(layout); return edit
    }
    private fun confirm() {
        val declaredEndpoint = endpoint.text.toString().trim()
        val plan = try { ProxyCooperationPlan.parse(declaredEndpoint, secret.text.toString()) }
            catch (error: IllegalArgumentException) { toast(error.message ?: "请输入 HTTPS 来源地址"); return }
        secret.text.clear()
        MaterialAlertDialogBuilder(this).setTitle("确认只读 API 目标")
            .setMessage("目标：$declaredEndpoint\n只请求 /version 和 /connections；每项最多 3 秒，总预算 15 秒，每响应最多 256 KiB，最多保留 100 条连接。\n\n使用系统正常网络与证书验证。连接快照可能包含其他应用活动，不能直接归属于本应用。Secret 不写入报告或设置。")
            .setNegativeButton("取消", null).setPositiveButton("开始读取") { _, _ ->
                session.endpointDraft = declaredEndpoint
                if (!session.start(plan)) toast("其他诊断仍在运行或释放资源，请稍后重试。")
            }.show()
    }
    private fun render() {
        if (!::status.isInitialized) return
        start.isEnabled = !session.busy; cancel.isEnabled = session.busy
        clear.isEnabled = !session.busy
        endpoint.isEnabled = !session.busy; secret.isEnabled = !session.busy
        export.isEnabled = !session.busy && session.record != null && pendingExport == null
        status.text = getString(R.string.card_content, "状态", session.status)
        // Readable in-app details; the only export is a redacted frozen snapshot.
        result.text = session.record?.result?.toText(includeIdentifiers = true).orEmpty()
    }
    private fun exportReport() {
        val ticket = session.freezeExport() ?: return
        pendingExport = ticket.id; pendingCode = ticket.requestCode
        try {
            @Suppress("DEPRECATION") startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                type = "application/json"; addCategory(Intent.CATEGORY_OPENABLE); putExtra(Intent.EXTRA_TITLE, ticket.suggestedName)
            }, ticket.requestCode)
        } catch (_: RuntimeException) {
            session.discardExport(pendingExport); pendingExport = null; pendingCode = -1; toast("无法打开文件选择器。")
        }
        render()
    }
    @Deprecated("Legacy document result bridge")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pendingCode) return
        val id = pendingExport ?: return
        pendingExport = null; pendingCode = -1
        if (resultCode != Activity.RESULT_OK || data?.data == null) { session.discardExport(id); render(); return }
        val payload = session.takeExport(id) ?: run { toast("原快照已失效，请重新导出。"); render(); return }
        val uri = data.data!!
        writer.execute {
            val ok = runCatching { contentResolver.openOutputStream(uri, "wt")?.use { it.write(payload.toByteArray(Charsets.UTF_8)) } ?: error("No stream") }.isSuccess
            runOnUiThread { toast(if (ok) "脱敏快照已保存。" else "保存失败，请重试。"); render() }
        }
    }
    override fun onStart() { super.onStart(); session.observe(observer) }
    override fun onStop() { session.endpointDraft = endpoint.text.toString(); secret.text.clear(); session.removeObserver(observer); super.onStop() }
    override fun onSaveInstanceState(outState: Bundle) {
        pendingExport?.let { outState.putString("proxyExport", it); outState.putInt("proxyExportCode", pendingCode) }
        super.onSaveInstanceState(outState)
    }
    override fun onDestroy() { writer.shutdown(); super.onDestroy() }
    private fun dp(value: Int) = MaterialUi.dp(this, value)
    private fun toast(message: String) { Toast.makeText(this, message, Toast.LENGTH_LONG).show() }
}
