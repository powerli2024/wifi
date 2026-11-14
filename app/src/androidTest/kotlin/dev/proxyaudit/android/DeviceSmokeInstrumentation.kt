package dev.proxyaudit.android

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.view.ViewGroup
import dev.proxyaudit.core.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Dependency-free instrumentation runner. All probe destinations are device loopback.
 * Includes offline application-core/API compatibility checks; never evidence about a user's VPN or DNS path.
 */
class DeviceSmokeInstrumentation : Instrumentation() {
    private val cases = JSONArray()
    private var failed = 0
    private var skipped = 0
    private lateinit var controller: DiagnosticsController
    private var activity: Activity? = null
    private var repairActivity: Activity? = null

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        super.onStart()
        try {
            // Instrumentation.onCreate can run before Application.onCreate has returned.
            waitForIdleSync()
            controller = (targetContext.applicationContext as DiagnosticsApplication).controller
            smoke("launcher_and_offline_demo") {
                val startup = observeOfflineLaunch(MainActivity::class.java) { activity = it }
                runOnMainSync { controller.showDemo() }
                verify(!controller.busy && controller.isDemo, "DEMO_STATE")
                verify(controller.report?.evidenceOrigin == EvidenceOrigin.SYNTHETIC_FIXTURE, "DEMO_ORIGIN")
                runOnMainSync { controller.clear() }
                JSONObject().put("launcherCreated", true).put("startupObservation", startup)
                    .put("demoOrigin", "SYNTHETIC_FIXTURE")
            }
            smoke("repair_activity_offline_launch") {
                val startup = observeOfflineLaunch(RepairActivity::class.java) { repairActivity = it }
                repairActivity?.let { current -> runOnMainSync { current.finish() } }
                waitForIdleSync()
                repairActivity = null
                verify(!controller.busy && controller.report == null, "REPAIR_RETURN_STARTED_PROBE")
                startup.put("returnedWithoutProbeReport", true)
            }
            smoke("offline_quick_advisor_comparison_android_api") {
                offlineDiagnosticsCompatibility()
            }
            smoke("offline_mihomo_repair_android_api") {
                offlineConfigRepairCompatibility()
            }
            smoke("offline_mihomo_rejects_unsafe_yaml") {
                for (source in listOf(
                    "dns:\n  enable: true\ndns:\n  enable: false\n",
                    "dns: !!java.net.URL [\"https://fixture-never-contact.invalid/\"]\n",
                    "dns:\n  enable: true\n---\ndns:\n  enable: false\n"
                )) {
                    expectRejected("CONFIG_UNSAFE_INPUT_ACCEPTED") { MihomoConfigDoctor.inspect(source) }
                }
                JSONObject().put("duplicateKeysRejected", true).put("customTagRejected", true)
                    .put("multipleDocumentsRejected", true).put("networkRequestsIssuedByTest", 0)
            }
            smoke("ipv4_udp_tcp_raw_only") {
                LoopbackDnsServer(ipv4(), DnsRecordType.A).use { server ->
                    successfulRun(server, "127.0.0.1", DnsRecordType.A)
                }
            }
            smoke("ipv6_udp_tcp_raw_only") {
                val server = try { LoopbackDnsServer(ipv6(), DnsRecordType.AAAA) }
                catch (_: SocketException) { throw Skipped("IPV6_LOOPBACK_BIND_UNAVAILABLE") }
                server.use { successfulRun(it, "::1", DnsRecordType.AAAA) }
            }
            smoke("cancel_udp_then_release_slot") {
                val cancelled = LoopbackDnsServer(ipv4(), DnsRecordType.A, reply = false).use { server ->
                    val config = config(server, "127.0.0.1", DnsRecordType.A, 5_000)
                    startRun(config)
                    verify(server.udpReceived.await(2, TimeUnit.SECONDS), "CANCEL_UDP_NOT_RECEIVED")
                    verify(!controller.start(config), "BUSY_SLOT_ACCEPTED_SECOND_RUN")
                    runOnMainSync { controller.cancel() }
                    awaitIdle(4_000)
                    val report = controller.report ?: throw SmokeFailure("CANCEL_REPORT_MISSING")
                    verify(report.rawDns.size == 2, "CANCEL_PROTOCOL_COUNT")
                    val udp = report.rawDns.first { it.transport == DnsTransport.UDP }
                    val tcp = report.rawDns.first { it.transport == DnsTransport.TCP }
                    verify(udp.execution == Execution.CANCELLED && udp.failure == Failure.CANCELLED, "CANCEL_UDP_STATE")
                    verify(tcp.execution == Execution.NOT_STARTED && server.tcpCount.get() == 0, "CANCEL_TCP_STARTED")
                    verify(server.failure.get() == null, "CANCEL_FIXTURE_FAILURE")
                    exportExcerpt(report).put("tcpConnectionsAccepted", server.tcpCount.get())
                }
                // A complete second run verifies that cancellation released the controller slot.
                val recovery = LoopbackDnsServer(ipv4(), DnsRecordType.A).use {
                    successfulRun(it, "127.0.0.1", DnsRecordType.A)
                }
                JSONObject().put("cancelledRun", cancelled).put("recoveryRun", recovery)
            }
        } catch (_: LinkageError) {
            record("runner_setup", "FAIL", "ANDROID_API_LINKAGE_FAILURE")
        } catch (_: Exception) {
            record("runner_setup", "FAIL", "RUNNER_SETUP_FAILURE")
        } finally {
            if (::controller.isInitialized && controller.busy) {
                controller.cancel()
                try { awaitIdle(4_000) } catch (_: Exception) { /* Bounded cleanup only. */ }
            }
            try {
                repairActivity?.let { current -> runOnMainSync { current.finish() } }
                activity?.let { current -> runOnMainSync { current.finish() } }
            } catch (_: Exception) {
                record("launcher_cleanup", "FAIL", "LAUNCHER_CLEANUP_FAILURE")
            }
            val result = JSONObject()
                .put("testMarker", "DEVICE_LOOPBACK_SMOKE")
                .put("testData", "LOCAL_SYNTHETIC_DNS_FIXTURES_ONLY")
                .put("probeDestinations", JSONArray(listOf("127.0.0.1", "::1")))
                .put("offlineCoreAndUiChecksIncluded", true)
                .put("uiNetworkObservationScope", "CONTROLLER_START_AND_RESULT_ONLY_NOT_PACKET_CAPTURE")
                .put("outerNetworkPathVerified", false)
                .put("userVpnEvidence", false)
                .put("limitations", "Offline core/UI checks and device loopback sockets only; no external resolver, system DNS, HTTPS, VPN routing, leak prevention, or other-app traffic tested. Startup checks observe controller activity, not all network packets. Configuration repair is not client import or runtime validation.")
                .put("failed", failed).put("skipped", skipped).put("cases", cases)
            var written = false
            try {
                File(targetContext.filesDir, REPORT_FILE).writeText(result.toString(2) + "\n", Charsets.UTF_8)
                written = true
            } catch (_: Exception) {
                record("write_report", "FAIL", "REPORT_WRITE_FAILED")
            }
            finish(if (failed == 0 && written) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply {
                    putString("stream", "DEVICE_LOOPBACK_SMOKE: failed=$failed skipped=$skipped reportWritten=$written\n")
                    putString("reportFile", REPORT_FILE)
                    putInt("failed", failed)
                    putInt("skipped", skipped)
                    putBoolean("reportWritten", written)
                })
        }
    }

    private fun smoke(name: String, block: () -> JSONObject) {
        try { record(name, "PASS", "LOOPBACK_CHECKS_PASSED", block()) }
        catch (e: Skipped) { record(name, "SKIP", e.code) }
        catch (e: SmokeFailure) { record(name, "FAIL", e.code, e.details) }
        catch (_: LinkageError) { record(name, "FAIL", "ANDROID_API_LINKAGE_FAILURE") }
        catch (_: Exception) { record(name, "FAIL", "UNEXPECTED_TEST_FAILURE") }
        finally {
            if (controller.busy) {
                controller.cancel()
                try { awaitIdle(4_000) } catch (_: Exception) { /* Next test must reject a busy slot. */ }
            }
        }
    }

    private fun record(name: String, status: String, code: String, details: JSONObject? = null) {
        if (status == "FAIL") failed++
        if (status == "SKIP") skipped++
        cases.put(JSONObject().put("name", name).put("status", status).put("summary", code)
            .apply { if (details != null) put("details", details) })
        sendStatus(0, Bundle().apply {
            putString("test", name); putString("status", status); putString("summary", code)
            putString("stream", "$name: $status ($code)\n")
        })
    }

    /** Observes our controller; deliberately does not claim packet capture or all-process network interception. */
    private fun observeOfflineLaunch(type: Class<out Activity>, retain: (Activity) -> Unit): JSONObject {
        verify(!controller.busy, "STARTUP_CONTROLLER_BUSY")
        runOnMainSync { controller.clear() }
        waitForIdleSync()
        val automaticProbeObserved = AtomicInteger()
        val listener: () -> Unit = {
            if (controller.busy || controller.report != null) automaticProbeObserved.incrementAndGet()
        }
        runOnMainSync { controller.observe(listener) }
        try {
            val monitor = addMonitor(type.name, null, false)
            val launched = try {
                targetContext.startActivity(Intent(targetContext, type).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                waitForMonitorWithTimeout(monitor, 8_000)
                    ?: throw IllegalStateException("STARTUP_ACTIVITY_TIMEOUT")
            } finally { removeMonitor(monitor) }
            retain(launched)
            waitForIdleSync()
            var contentVisible = false
            runOnMainSync {
                val content = launched.findViewById<ViewGroup>(android.R.id.content)
                contentVisible = content != null && content.childCount > 0 && launched.window.decorView.isShown
            }
            verify(contentVisible, "STARTUP_CONTENT_NOT_VISIBLE")
            val observationEnd = SystemClock.elapsedRealtime() + 300
            while (SystemClock.elapsedRealtime() < observationEnd) {
                if (controller.busy || controller.report != null) automaticProbeObserved.incrementAndGet()
                Thread.sleep(20)
            }
            waitForIdleSync()
            verify(automaticProbeObserved.get() == 0 && !controller.busy && controller.report == null,
                "STARTUP_AUTOMATIC_PROBE_OBSERVED")
            return JSONObject().put("activityCreated", true).put("contentVisible", true)
                .put("automaticControllerProbeObserved", false).put("observationWindowMillis", 300)
                .put("observationScope", "CONTROLLER_START_AND_RESULT_ONLY_NOT_PACKET_CAPTURE")
        } finally {
            runOnMainSync { controller.removeObserver(listener) }
        }
    }

    private fun offlineDiagnosticsCompatibility(): JSONObject {
        val snapshot = NetworkSnapshot(
            "SYNTHETIC-NETWORK", listOf("WIFI"), false, true, true,
            listOf("192.0.2.201"), listOf("192.0.2.202"), false, null, true
        )
        val plan = QuickCheck.build(snapshot)
        verify(plan.policy.runDns && !plan.policy.runHttps && plan.endpoint == null && plan.rawDns == null,
            "QUICK_DEFAULT_NETWORK_SCOPE")
        val preset = QuickCheck.build(snapshot, QuickDnsTarget.CLOUDFLARE, includeRaw = true)
        verify(preset.rawDns?.serverIp == DnsProviders.get(QuickDnsTarget.CLOUDFLARE).ipv4 &&
            preset.rawDns?.udp == true && preset.rawDns?.tcp == true, "QUICK_PUBLIC_TARGET")
        // Never submit either plan. ANDROID_RUNTIME is intentionally constructed solely to exercise
        // comparison rules; this input is labelled synthetic below and no RunReport is exported as evidence.
        val first = RunReport(
            "00000000-0000-4000-8000-000000000101", "2026-10-21T00:00:00Z", "2026-10-21T00:00:01Z",
            1000, android.os.Build.VERSION.SDK_INT, "DEVICE-SYNTHETIC-ONLY", plan, snapshot, snapshot, false,
            DnsObservation(Execution.ERROR, failure = Failure.TIMEOUT), HttpsObservation()
        )
        val second = first.copy(runId = "00000000-0000-4000-8000-000000000102",
            dns = DnsObservation(Execution.COMPLETED, listOf("192.0.2.203"), 5))
        val comparison = ReportComparison.compare(first, second)
        verify(comparison.comparable && comparison.summary.contains("改善") &&
            comparison.summary.contains("不等于已修复"), "COMPARISON_PRIVACY_BOUNDARY")
        verify(!ReportComparison.compare(first, second.copy(dns = DnsObservation())).comparable,
            "COMPARISON_UNSTARTED_IS_REGRESSION")
        verify(!ReportComparison.compare(first.copy(evidenceOrigin = EvidenceOrigin.SYNTHETIC_FIXTURE), second).comparable,
            "COMPARISON_DEMO_ACCEPTED")
        val json = JSONObject(ReportComparison.toJson(first, second))
        verify(!json.getBoolean("networkIdentifiersIncluded") && json.getJSONObject("comparison").getBoolean("comparable"),
            "COMPARISON_EXPORT_SHAPE")
        for (key in listOf("before", "after")) {
            val child = json.getJSONObject(key)
            verify(!child.getBoolean("networkIdentifiersIncluded") && child.getString("dnsHost") == REDACTED,
                "COMPARISON_CHILD_REDACTION")
            verify(child.getJSONObject("networkBefore").getString("networkId") == REDACTED,
                "COMPARISON_NETWORK_REDACTION")
        }
        val exportedText = json.toString()
        for (secret in listOf("192.0.2.201", "192.0.2.202", "192.0.2.203", "SYNTHETIC-NETWORK", "example.com"))
            verify(!exportedText.contains(secret), "COMPARISON_IDENTIFIER_EXPOSED")
        val findings = DiagnosticAdvisor.review(second)
        verify(findings.any { it.id == "SYSTEM_ADDRESSES" } && findings.any { it.id == "SCOPE_LIMIT" },
            "ADVISOR_EXPECTED_FINDINGS")
        verify(findings.first { it.id == "PRIVATE_DNS_INACTIVE" }.detail.contains("不是 DNS 泄露证据"),
            "ADVISOR_PRIVATE_DNS_FALSE_LEAK")
        verify(DiagnosticAdvisor.review(second.copy(evidenceOrigin = EvidenceOrigin.SYNTHETIC_FIXTURE))
            .map { it.id } == listOf("DEMO_ONLY"), "ADVISOR_DEMO_BOUNDARY")
        verify(!controller.busy && controller.report == null, "OFFLINE_RULES_STARTED_PROBE")
        return JSONObject().put("inputOrigin", "SYNTHETIC_RULE_INPUTS_NOT_NETWORK_OBSERVATIONS")
            .put("quickPlanConstructedOnly", true).put("advisorBoundariesVerified", true)
            .put("comparisonJsonParsedOnAndroid", true).put("comparisonRedactionVerified", true)
            .put("networkRequestsIssuedByTest", 0)
    }

    private fun offlineConfigRepairCompatibility(): JSONObject {
        // Deliberately fake fixture values; never serialize the input, output, credentials or subscription URL.
        val prefix = "# device fixture: retain this comment\r\nmixed-port: 7890\r\nallow-lan: false\r\n"
        val suffix = "proxies:\r\n" +
            "  - name: \"测试节点\"\r\n" +
            "    type: ss\r\n" +
            "    server: fixture-node.invalid\r\n" +
            "    port: 443\r\n" +
            "    cipher: aes-128-gcm\r\n" +
            "    password: \"fixture-only: keep # quoted\"\r\n" +
            "proxy-providers:\r\n" +
            "  fixture-provider:\r\n" +
            "    type: http\r\n" +
            "    url: \"https://fixture-subscription.invalid/data?token=DEVICE-SYNTHETIC\"\r\n" +
            "    path: ./fixture-provider.yaml\r\n" +
            "rules:\r\n" +
            "  - MATCH,DIRECT\r\n"
        val source = prefix + "dns:\r\n  enable: true\r\n  nameserver:\r\n    - 8.8.8.8\r\n" + suffix
        val provider = DnsProviders.get(QuickDnsTarget.CLOUDFLARE)
        val inspection = MihomoConfigDoctor.inspect(source)
        verify(inspection.summary.isNotBlank(), "CONFIG_INSPECTION_SUMMARY_MISSING")
        val first = MihomoConfigDoctor.repair(source, provider)
        verify(first.repairedYaml.startsWith(prefix) && first.repairedYaml.endsWith(suffix),
            "CONFIG_NON_DNS_ORIGINAL_CHANGED")
        verify(first.repairedYaml.contains(provider.dohUrl), "CONFIG_DOH_NOT_WRITTEN")
        verify(first.changes.any { it.path == "dns.nameserver" && it.after.contains(provider.dohUrl) },
            "CONFIG_NAMESERVER_CHANGE_MISSING")
        val expectedHash = MessageDigest.getInstance("SHA-256").digest(source.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        verify(first.sourceSha256 == expectedHash, "CONFIG_SOURCE_HASH")
        val repairedInspection = MihomoConfigDoctor.inspect(first.repairedYaml)
        verify(repairedInspection.summary.isNotBlank(), "CONFIG_REPAIRED_PARSE_FAILED")
        val again = MihomoConfigDoctor.repair(first.repairedYaml, provider)
        verify(again.repairedYaml == first.repairedYaml && again.changes.isEmpty(), "CONFIG_REPAIR_NOT_IDEMPOTENT")
        val diagnostics = inspection.summary + inspection.findings.joinToString() +
            first.warnings.joinToString() + first.changes.joinToString()
        for (credential in listOf("fixture-only", "DEVICE-SYNTHETIC", "fixture-subscription.invalid"))
            verify(!diagnostics.contains(credential), "CONFIG_DIAGNOSTICS_EXPOSE_NON_DNS_SECRET")
        verify(!controller.busy && controller.report == null, "OFFLINE_CONFIG_STARTED_PROBE")
        return JSONObject().put("inputOrigin", "SYNTHETIC_CONFIG_FIXTURE_ONLY")
            .put("inspectionExecutedOnAndroid", true).put("repairExecutedOnAndroid", true)
            .put("nonDnsSourcePreservedExactly", true).put("nameserverDohWritten", true)
            .put("sourceSha256Verified", true).put("repairIdempotent", true)
            .put("diagnosticsOmitNonDnsCredentials", true).put("networkRequestsIssuedByTest", 0)
            .put("clientImportOrRuntimeConfigVerified", false)
    }

    private fun expectRejected(code: String, action: () -> Unit) {
        try { action() } catch (_: IllegalArgumentException) { return }
        throw SmokeFailure(code)
    }

    private fun successfulRun(server: LoopbackDnsServer, ip: String, type: DnsRecordType): JSONObject {
        startRun(config(server, ip, type, 2_000))
        awaitIdle(7_000)
        val report = controller.report ?: throw SmokeFailure("REPORT_MISSING")
        verify(report.evidenceOrigin == EvidenceOrigin.ANDROID_RUNTIME, "RUNTIME_ORIGIN")
        verify(report.dns.execution == Execution.NOT_STARTED && report.https.execution == Execution.NOT_STARTED, "RAW_ONLY_SCOPE")
        verify(report.egress.verdict == Verdict.NOT_RUN && report.dnsPrivacy.verdict == Verdict.NOT_RUN, "UNRUN_ASSESSMENTS")
        verify(report.rawDns.map { it.transport } == listOf(DnsTransport.UDP, DnsTransport.TCP), "PROTOCOLS")
        val expected = if (type == DnsRecordType.A) "192.0.2.123" else "2001:db8::123"
        report.rawDns.forEach {
            verify(it.execution == Execution.COMPLETED && it.failure == null, "RAW_NOT_COMPLETED")
            verify(it.responseCode == 0 && !it.truncated, "RAW_RESPONSE_FLAGS")
            val transactionId = it.transactionId
            val durationMillis = it.durationMillis
            verify(transactionId != null && transactionId in 0..65535, "RAW_TRANSACTION_ID")
            verify(durationMillis != null && durationMillis >= 0, "RAW_DURATION")
            verify(it.addresses.size == 1 && NumericIp.canonical(it.addresses.single()) == NumericIp.canonical(expected), "RAW_ANSWER")
        }
        verify(server.udpCount.get() == 1 && server.tcpCount.get() == 1, "FIXTURE_REQUEST_COUNTS")
        verify(server.failure.get() == null, "FIXTURE_FAILURE")
        return exportExcerpt(report)
            .put("udpRequestsReceived", server.udpCount.get())
            .put("tcpConnectionsAccepted", server.tcpCount.get())
    }

    private fun exportExcerpt(report: RunReport): JSONObject {
        val ticket = controller.beginExport(report, false) ?: throw SmokeFailure("EXPORT_START")
        val text = controller.consumeExport(ticket.requestId) ?: throw SmokeFailure("EXPORT_CONSUME")
        verify(!controller.exportPending, "EXPORT_SLOT_NOT_RELEASED")
        val json = JSONObject(text)
        verify(json.getInt("schemaVersion") == 2 && !json.getBoolean("networkIdentifiersIncluded"), "EXPORT_SCHEMA")
        val config = json.getJSONObject("rawDnsConfig")
        verify(config.getString("serverIp") == REDACTED && config.getString("host") == REDACTED, "EXPORT_TARGET_REDACTION")
        val raw = json.getJSONArray("rawDns")
        for (i in 0 until raw.length()) {
            val item = raw.getJSONObject(i)
            val expected = if (item.getString("execution") == "NOT_STARTED") "NOT_RUN" else "INSUFFICIENT"
            verify(item.getString("privacyVerdict") == expected, "RAW_PRIVACY_BOUNDARY")
            verify(item.getString("wireResolverAndPath") == "UNKNOWN", "RAW_PATH_BOUNDARY")
            val answers = item.getJSONArray("addresses")
            for (j in 0 until answers.length()) verify(answers.getString(j) == REDACTED, "EXPORT_ANSWER_REDACTION")
        }
        for (key in listOf("networkBefore", "networkAfter")) {
            val network = json.getJSONObject(key)
            for (field in listOf("networkId", "privateDnsServerName")) {
                verify(network.isNull(field) || network.getString(field) == REDACTED, "EXPORT_NETWORK_REDACTION")
            }
            for (field in listOf("localAddresses", "configuredDnsServers")) {
                val values = network.getJSONArray(field)
                for (i in 0 until values.length()) verify(values.getString(i) == REDACTED, "EXPORT_NETWORK_REDACTION")
            }
        }
        // Store a labelled excerpt, excluding even redacted incidental device network snapshots.
        return JSONObject().put("kind", "REDACTED_EXPORT_EXCERPT")
            .put("schemaVersion", 2).put("networkIdentifiersIncluded", false)
            .put("rawDnsConfig", config).put("rawDns", raw)
            .put("egressVerdict", json.getJSONObject("https").getJSONObject("egressAssessment").getString("verdict"))
            .put("systemDnsPrivacyVerdict", json.getJSONObject("dns").getJSONObject("privacyAssessment").getString("verdict"))
            .put("networkSnapshotRedactionVerified", true)
    }

    private fun config(server: LoopbackDnsServer, ip: String, type: DnsRecordType, timeout: Int) =
        RunConfig(null, null, ProbePolicy(false, false, emptySet(), false, false), timeout,
            RawDnsConfig(ip, server.port, "device-smoke.invalid", type, udp = true, tcp = true))

    private fun startRun(config: RunConfig) {
        var accepted = false
        runOnMainSync { accepted = controller.start(config) }
        verify(accepted, "RUN_SLOT_NOT_AVAILABLE")
    }

    private fun awaitIdle(timeoutMillis: Long) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (controller.busy && SystemClock.elapsedRealtime() < deadline) Thread.sleep(20)
        if (controller.busy) throw SmokeFailure("CONTROLLER_DID_NOT_RELEASE_SLOT", cancellationDiagnostics(timeoutMillis))
    }

    /** Only code locations and enum state: no thread arguments, exception text, addresses or config. */
    private fun cancellationDiagnostics(waitMillis: Long): JSONObject {
        val threadNames = setOf("main", "probe-worker", "probe-deadline", "probe-cleanup",
            "raw-dns-deadline", "dns-callback")
        val threads = JSONArray()
        try {
            Thread.getAllStackTraces().entries.filter { it.key.name in threadNames }
                .sortedBy { it.key.name }.take(10).forEach { (thread, trace) ->
                    val frames = JSONArray()
                    trace.take(24).forEach {
                        frames.put(JSONObject().put("className", it.className).put("methodName", it.methodName)
                            .put("lineNumber", it.lineNumber).put("nativeMethod", it.isNativeMethod))
                    }
                    threads.put(JSONObject().put("threadName", thread.name).put("state", thread.state.name)
                        .put("frames", frames))
                }
        } catch (_: Exception) { /* Failure details must not hide the original assertion. */ }
        val report = controller.report
        val raw = JSONArray()
        report?.rawDns?.forEach {
            raw.put(JSONObject().put("transport", it.transport.name).put("execution", it.execution.name)
                .put("failure", it.failure?.name ?: JSONObject.NULL))
        }
        return JSONObject().put("kind", "BOUNDED_SLOT_RELEASE_DIAGNOSTIC")
            .put("waitBudgetMillis", waitMillis).put("controllerBusy", controller.busy)
            .put("reportPublished", report != null).put("rawExecutionStates", raw)
            .put("threads", threads)
            .put("scope", "CODE_LOCATIONS_AND_ENUMS_ONLY_NO_NETWORK_IDENTIFIERS_OR_EXCEPTION_TEXT")
    }

    private fun verify(condition: Boolean, code: String) { if (!condition) throw SmokeFailure(code) }
    private class SmokeFailure(val code: String, val details: JSONObject? = null) : Exception()
    private class Skipped(val code: String) : Exception()

    private class LoopbackDnsServer(address: InetAddress, private val type: DnsRecordType, private val reply: Boolean = true) : Closeable {
        private val tcp = ServerSocket()
        private val udp = DatagramSocket(null)
        val port: Int
        val udpCount = AtomicInteger()
        val tcpCount = AtomicInteger()
        val udpReceived = CountDownLatch(1)
        val failure = AtomicReference<String?>(null)
        @Volatile private var running = true
        @Volatile private var acceptedSocket: Socket? = null
        private val udpThread: Thread
        private val tcpThread: Thread

        init {
            try {
                tcp.bind(InetSocketAddress(address, 0))
                port = tcp.localPort
                tcp.soTimeout = 200
                udp.bind(InetSocketAddress(address, port))
                udp.soTimeout = 200
            } catch (e: Exception) {
                tcp.close(); udp.close()
                throw e
            }
            udpThread = Thread({
                while (running) {
                    try {
                        val packet = DatagramPacket(ByteArray(512), 512)
                        udp.receive(packet)
                        udpCount.incrementAndGet()
                        udpReceived.countDown()
                        if (reply) {
                            val response = answer(packet.data.copyOfRange(packet.offset, packet.offset + packet.length))
                            udp.send(DatagramPacket(response, response.size, packet.socketAddress))
                        }
                    } catch (_: SocketTimeoutException) { /* Poll bounded shutdown. */ }
                    catch (_: Exception) { if (running) failure.compareAndSet(null, "UDP_FIXTURE_FAILURE"); break }
                }
            }, "smoke-loopback-udp").apply { isDaemon = true; start() }
            tcpThread = Thread({
                while (running) {
                    try {
                        tcp.accept().use { socket ->
                            acceptedSocket = socket
                            if (!running) return@use
                            tcpCount.incrementAndGet()
                            socket.soTimeout = 1_000
                            val input = DataInputStream(socket.getInputStream())
                            val size = input.readUnsignedShort()
                            require(size in 17..512)
                            val query = ByteArray(size)
                            input.readFully(query)
                            if (reply) {
                                val response = answer(query)
                                DataOutputStream(socket.getOutputStream()).apply {
                                    writeShort(response.size); write(response); flush()
                                }
                            }
                        }
                    } catch (_: SocketTimeoutException) { /* Accept/read operations are bounded. */ }
                    catch (_: Exception) { if (running) failure.compareAndSet(null, "TCP_FIXTURE_FAILURE"); break }
                    finally { acceptedSocket = null }
                }
            }, "smoke-loopback-tcp").apply { isDaemon = true; start() }
        }

        private fun answer(query: ByteArray): ByteArray {
            require(query.size >= 17 && query[4] == 0.toByte() && query[5] == 1.toByte())
            var end = 12
            while (true) {
                require(end < query.size)
                val label = query[end++].toInt() and 255
                if (label == 0) break
                require(label in 1..63 && end + label < query.size)
                end += label
            }
            require(end + 4 == query.size)
            require((query[end].toInt() and 255) == 0 && (query[end + 1].toInt() and 255) == type.wireValue)
            require(query[end + 2] == 0.toByte() && query[end + 3] == 1.toByte())
            val address = if (type == DnsRecordType.A) byteArrayOf(192.toByte(), 0, 2, 123)
                else byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x23)
            val output = java.io.ByteArrayOutputStream()
            DataOutputStream(output).use {
                it.write(query, 0, 2) // Echo transaction ID.
                it.writeShort(0x8180) // Response, recursion available, NOERROR.
                it.writeShort(1); it.writeShort(1); it.writeShort(0); it.writeShort(0)
                it.write(query, 12, query.size - 12) // Echo exact question.
                it.writeShort(0xc00c); it.writeShort(type.wireValue); it.writeShort(1)
                it.writeInt(60); it.writeShort(address.size); it.write(address)
            }
            return output.toByteArray()
        }

        override fun close() {
            running = false
            udp.close()
            tcp.close()
            acceptedSocket?.close()
            udpThread.join(1_500)
            tcpThread.join(1_500)
        }
    }

    companion object {
        private const val REPORT_FILE = "device-smoke-report.json"
        private const val REDACTED = "[REDACTED]"
        private fun ipv4(): InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        private fun ipv6(): InetAddress = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
    }
}
