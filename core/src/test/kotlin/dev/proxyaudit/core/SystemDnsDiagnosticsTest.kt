package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class SystemDnsDiagnosticsTest {
    @Test fun `report overload preserves demonstration and unselected probe provenance`() {
        val demo = SystemDnsDiagnostics.summary(DemoFixture.report())
        assertTrue(demo.contains("虚构"))
        assertTrue(demo.contains("没有执行当前设备查询"))
        assertFalse(demo.contains("已返回地址"))
        val actual = quickReport()
        assertEquals(SystemDnsDiagnostics.summary(actual.dns), SystemDnsDiagnostics.summary(actual))
        val disabled = actual.copy(config = actual.config.copy(policy = actual.config.policy.copy(runDns = false)))
        assertTrue(SystemDnsDiagnostics.summary(disabled).contains("未选择"))
        assertFalse(SystemDnsDiagnostics.summary(disabled).contains("已返回地址"))
    }

    private fun answer(rcode: Int, addresses: List<String> = emptyList()) = DnsObservation(
        if (rcode == 0 && addresses.isNotEmpty()) Execution.COMPLETED else Execution.ERROR,
        addresses, 3, if (rcode == 0 && addresses.isNotEmpty()) null else Failure.DNS_FAILURE,
        SystemDnsStage.ANSWER_CALLBACK, responseCode = rcode)

    @Test fun `legacy quick failure does not invent timeout or resolver cause`() {
        val old = DnsObservation(Execution.ERROR, durationMillis = 3, failure = Failure.DNS_FAILURE)
        val summary = SystemDnsDiagnostics.summary(old)
        assertTrue(summary.contains("未包含"))
        assertTrue(summary.contains("不能从 DNS_FAILURE 或耗时还原根因"))
        assertFalse(summary.contains("ERROR_SYSTEM"))
        assertTrue(SystemDnsDiagnostics.summary(old.copy(failure = Failure.TIMEOUT)).contains("等待预算"))
        assertTrue(SystemDnsDiagnostics.summary(DnsObservation(Execution.COMPLETED, listOf("192.0.2.1"))).contains("已返回地址"))
    }

    @Test fun `answer callback distinguishes negative response empty NOERROR and addresses`() {
        assertTrue(SystemDnsDiagnostics.summary(answer(3)).contains("NXDOMAIN"))
        assertTrue(SystemDnsDiagnostics.summary(answer(3)).contains("不能据此判定污染"))
        assertTrue(SystemDnsDiagnostics.summary(answer(2)).contains("响应码 2"))
        assertTrue(SystemDnsDiagnostics.summary(answer(0)).contains("没有可用地址"))
        val success = SystemDnsDiagnostics.summary(answer(0, listOf("192.0.2.1")))
        assertTrue(success.contains("及地址")); assertTrue(success.contains("路径仍未知"))
    }

    @Test fun `platform codes distinguish response parse system and unknown errors without attribution`() {
        val base = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE,
            diagnosticStage = SystemDnsStage.ERROR_CALLBACK)
        assertTrue(SystemDnsDiagnostics.summary(base.copy(resolverErrorCode = 0)).contains("ERROR_PARSE"))
        val system = SystemDnsDiagnostics.summary(base.copy(resolverErrorCode = 1, systemErrno = 101))
        assertTrue(system.contains("ERROR_SYSTEM")); assertTrue(system.contains("errno=101"))
        assertTrue(system.contains("不能仅凭此归责"))
        assertTrue(SystemDnsDiagnostics.summary(base.copy(resolverErrorCode = 1)).contains("未提供 errno"))
        assertTrue(SystemDnsDiagnostics.summary(base.copy(resolverErrorCode = 73)).contains("code=73"))
    }

    @Test fun `local exception categories are fixed and cancellation takes precedence`() {
        val base = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE,
            diagnosticStage = SystemDnsStage.LOCAL_EXCEPTION)
        val labels = mapOf(SystemDnsExceptionKind.SECURITY to "安全权限异常",
            SystemDnsExceptionKind.INVALID_ARGUMENT to "参数异常", SystemDnsExceptionKind.INTERRUPTED to "线程中断",
            SystemDnsExceptionKind.OTHER to "本地异常")
        for ((kind, label) in labels) assertTrue(SystemDnsDiagnostics.summary(base.copy(exceptionKind = kind)).contains(label))
        val cancelled = base.copy(execution = Execution.CANCELLED, failure = Failure.CANCELLED,
            diagnosticStage = SystemDnsStage.ERROR_CALLBACK, resolverErrorCode = 1, systemErrno = 101)
        assertTrue(SystemDnsDiagnostics.summary(cancelled).contains("已取消"))
        assertFalse(SystemDnsDiagnostics.summary(cancelled).contains("errno="))
    }

    @Test fun `new diagnostic fields export additively while network identifiers stay redacted`() {
        val report = quickReport().copy(dns = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE,
            diagnosticStage = SystemDnsStage.ERROR_CALLBACK, resolverErrorCode = 1, systemErrno = 101))
        for (include in listOf(false, true)) {
            val json = ReportExporter.toJson(report, include)
            for (field in listOf("\"schemaVersion\":2", "\"diagnosticStage\":\"ERROR_CALLBACK\"",
                "\"responseCode\":null", "\"resolverErrorCode\":1", "\"systemErrno\":101", "\"exceptionKind\":null"))
                assertTrue(field, json.contains(field))
            assertFalse(json.contains("exceptionMessage")); assertFalse(json.contains("causeMessage"))
        }
        val redacted = ReportExporter.toJson(report)
        for (value in listOf("example.com", "test-network", "192.0.2.5", "192.0.2.53")) assertFalse(value, redacted.contains(value))
        val legacy = ReportExporter.toJson(quickReport())
        assertTrue(legacy.contains("\"diagnosticStage\":null"))
        assertTrue(legacy.contains("\"resolverErrorCode\":null"))
    }

    @Test fun `inconsistent success with diagnostic error cannot become usable or advisor success`() {
        val success = answer(0, listOf("192.0.2.1"))
        assertTrue(DiagnosticEvidence.systemUsable(success))
        val invalid = listOf(success.copy(responseCode = 3), success.copy(resolverErrorCode = 0),
            success.copy(diagnosticStage = SystemDnsStage.ERROR_CALLBACK),
            success.copy(diagnosticStage = SystemDnsStage.LOCAL_EXCEPTION),
            success.copy(exceptionKind = SystemDnsExceptionKind.OTHER))
        for (observation in invalid) {
            assertFalse(DiagnosticEvidence.systemUsable(observation))
            assertFalse(DiagnosticAdvisor.review(quickReport().copy(dns = observation)).any { it.id == "SYSTEM_ADDRESSES" })
        }
    }

    @Test fun `advisor shows recorded system detail and never upgrades DNS privacy`() {
        val report = quickReport(raw = true).copy(dns = answer(3))
        val findings = DiagnosticAdvisor.review(report).associateBy { it.id }
        assertTrue(findings.getValue("SYSTEM_NO_ADDRESSES").detail.contains("NXDOMAIN"))
        assertTrue(findings.containsKey("SYSTEM_RAW_DIFFERENCE"))
        assertEquals(Verdict.INSUFFICIENT, report.dnsPrivacy.verdict)
    }
}
