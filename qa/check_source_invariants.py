#!/usr/bin/env python3
"""Static guardrails only; never a substitute for device/runtime tests."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
A = "{http://schemas.android.com/apk/res/android}"
T = "{http://schemas.android.com/tools}"
manifest = ET.parse(ROOT / "app/src/main/AndroidManifest.xml").getroot()
permissions = {p.get(A + "name") for p in manifest.findall("uses-permission")}
assert permissions == {"android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"}, permissions
app = manifest.find("application")
assert app is not None
assert app.get(A + "usesCleartextTraffic") == "false"
assert app.get(A + "allowBackup") == "false"
assert not app.findall("service")
removals = app.findall("receiver") + app.findall("provider")
assert {p.get(A + "name") for p in removals} == {
    "androidx.startup.InitializationProvider", "androidx.profileinstaller.ProfileInstallReceiver"}
assert all(p.get(T + "node") == "remove" for p in removals)
# When a build exists, check the effective APK manifest as well as source merge instructions.
merged_path = ROOT / "app/build/intermediates/merged_manifests/debug/processDebugManifest/AndroidManifest.xml"
if merged_path.exists():
    merged = ET.parse(merged_path).getroot()
    signature_permission = "dev.proxyaudit.android.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
    assert {p.get(A + "name") for p in merged.findall("uses-permission")} == permissions | {signature_permission}
    declared = merged.findall("permission")
    assert len(declared) == 1 and declared[0].get(A + "name") == signature_permission
    assert declared[0].get(A + "protectionLevel") == "signature"
    merged_app = merged.find("application")
    assert not any(merged_app.findall(tag) for tag in ("service", "receiver", "provider"))
    assert {a.get(A + "name"): a.get(A + "exported") for a in merged_app.findall("activity")} == {
        "dev.proxyaudit.android.MainActivity": "true", "dev.proxyaudit.android.RepairActivity": "false"}
activities = app.findall("activity")
assert {a.get(A + "name"): a.get(A + "exported") for a in activities} == {
    ".MainActivity": "true", ".RepairActivity": "false"}

controller = (ROOT / "app/src/main/kotlin/dev/proxyaudit/android/DiagnosticsController.kt").read_text()
monitor = (ROOT / "app/src/main/kotlin/dev/proxyaudit/android/NetworkMonitor.kt").read_text()
activity = (ROOT / "app/src/main/kotlin/dev/proxyaudit/android/MainActivity.kt").read_text()
raw_dns = (ROOT / "core/src/main/kotlin/dev/proxyaudit/core/RawDnsProbe.kt").read_text()
repair = (ROOT / "app/src/main/kotlin/dev/proxyaudit/android/RepairActivity.kt").read_text()
session = (ROOT / "app/src/main/kotlin/dev/proxyaudit/android/RepairSession.kt").read_text()
assert "Intent.ACTION_OPEN_DOCUMENT" in repair and "Intent.ACTION_CREATE_DOCUMENT" in repair
assert "sameDocument(uri, item.originalUri)" in session
assert "MAX_BYTES = 256 * 1024" in session
assert "Settings.Global.put" not in repair + session
assert "takePersistableUriPermission" not in repair + session
assert "DnsResolver.getInstance().query(null," in controller
assert "URL(t.config.endpoint!!.requestUrl(requestId)).openConnection()" in controller
assert "connection.instanceFollowRedirects = false" in controller
assert "connection.useCaches = false" in controller
assert 'setRequestProperty("Connection", "close")' in controller
assert "CodingErrorAction.REPORT" in controller
assert "MAX_BODY = 4096" in controller
assert "registerDefaultNetworkCallback(callback)" in monitor
assert "manager.activeNetwork" in monitor
for pattern in (r"\.setHostnameVerifier\(", r"\.setSSLSocketFactory\(", r"\.bindProcessToNetwork\(", r"\.requestNetwork\(", r"VpnService\s*\(", r"\.protect\("):
    assert not re.search(pattern, controller + monitor + raw_dns), pattern
assert "getByName(" not in raw_dns and "getAllByName(" not in raw_dns
assert "getByAddress(" in raw_dns
assert "override fun onStart() { super.onStart(); controller.observe(observer) }" in activity
assert "override fun onStop() { saveDraft(); controller.removeObserver(observer); super.onStop() }" in activity
assert "Intent.ACTION_CREATE_DOCUMENT" in activity
assert "contentResolver.openOutputStream" in activity
assert "isSaveEnabled = false" in activity
assert "controller.reserveRestoredExportCode(pendingExportCode)" in activity
save_state = activity.split("override fun onSaveInstanceState", 1)[1].split("override fun onStart", 1)[0]
assert "outState.putString(EXPORT_ID_STATE, it)" in save_state
assert "outState.putInt(EXPORT_CODE_STATE, pendingExportCode)" in save_state
assert save_state.count(".putString(") == 1 and save_state.count(".putInt(") == 1
assert "ReportExporter" not in save_state
assert "private var pendingExport: PendingExport?" in controller
assert "private data class PendingExport(val ticket: ExportTicket, val json: String)" in controller
assert "if (requestCode != pendingExportCode) return" in activity
print("PASS: static manifest, default-network, numeric raw-DNS targets, TLS/no-bypass, bounded-body, observer and explicit-export guardrails")
print("LIMIT: source inspection only; Android lifecycle and networking are not executed")
