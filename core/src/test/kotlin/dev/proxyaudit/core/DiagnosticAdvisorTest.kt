package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class DiagnosticAdvisorTest {
    private fun findings(report: RunReport) = DiagnosticAdvisor.review(report).associateBy { it.id }

    @Test fun `mixed DNS attempts suppress first-only operational advice and retain neutral context`() {
        val base = quickReport(raw = true)
        val failed = DnsObservation(Execution.ERROR, failure = Failure.TIMEOUT)
        val attempts = listOf(
            ProbeAttempt("first", ProbeKind.SYSTEM_DNS, 1, 0, 1000, finishedAfterMillis = 1000, dns = failed),
            ProbeAttempt("second", ProbeKind.SYSTEM_DNS, 2, 1500, 1000, finishedAfterMillis = 1520, dns = base.dns))
        val report = base.copy(config = base.config.copy(maxAttempts = 2), dns = failed, attempts = attempts)
        val results = findings(report)
        assertTrue(results.containsKey("ATTEMPTS_DISAGREE"))
        assertFalse(results.keys.any { it.startsWith("SYSTEM_") || it.startsWith("RAW_") })
        assertTrue(results.containsKey("PRIVATE_DNS_INACTIVE"))
        assertFalse(results.getValue("SCOPE_LIMIT").actionHint.contains("调整一项设置"))
        assertTrue(ReportPresentation.summarize(report).headline.contains("多次尝试结果不一致"))
    }

    @Test fun `mixed raw attempts do not report first protocol failure as a whole-run difference`() {
        val base = quickReport(raw = true)
        val failed = base.rawDns[0].copy(execution = Execution.ERROR, addresses = emptyList(), responseCode = null, failure = Failure.TIMEOUT)
        val report = base.copy(config = base.config.copy(maxAttempts = 2),
            rawDns = listOf(failed, base.rawDns[1]), attempts = listOf(
                ProbeAttempt("first", ProbeKind.RAW_UDP, 1, 0, 1000, finishedAfterMillis = 1000, rawDns = failed),
                ProbeAttempt("second", ProbeKind.RAW_UDP, 2, 1500, 1000, finishedAfterMillis = 1520, rawDns = base.rawDns[0])))
        val results = findings(report)
        assertTrue(results.containsKey("ATTEMPTS_DISAGREE"))
        assertFalse(results.containsKey("RAW_UDP_ERROR"))
        assertFalse(results.containsKey("RAW_PROTOCOL_DIFFERENCE"))
        assertFalse(results.containsKey("SYSTEM_ADDRESSES"))
    }

    @Test fun `run stop and incomplete retry suppress apparently complete first observations`() {
        val base = quickReport(raw = true)
        for ((reason, id) in listOf(Failure.CANCELLED to "RUN_CANCELLED",
            Failure.NETWORK_CHANGED to "RUN_NETWORK_CHANGED", Failure.TIMEOUT to "RUN_BUDGET_EXHAUSTED",
            Failure.INTERNAL_ERROR to "RUN_STOPPED")) {
            val results = findings(base.copy(stopReason = reason))
            assertTrue(reason.name, results.containsKey(id))
            assertFalse(results.keys.any { it.startsWith("SYSTEM_") || it.startsWith("RAW_") })
            assertFalse(results.getValue("SCOPE_LIMIT").actionHint.contains("调整一项设置"))
        }
        for (unfinished in listOf(
            ProbeAttempt("pending", ProbeKind.SYSTEM_DNS, 2, 1500, 1000),
            ProbeAttempt("cancelled", ProbeKind.SYSTEM_DNS, 2, 1500, 1000,
                finishedAfterMillis = 1600, dns = DnsObservation(Execution.CANCELLED, failure = Failure.CANCELLED)))) {
            val results = findings(base.copy(attempts = listOf(unfinished)))
            assertTrue(results.containsKey("ATTEMPT_INCOMPLETE"))
            assertFalse(results.containsKey("SYSTEM_ADDRESSES"))
            assertFalse(results.containsKey("SYSTEM_RAW_DIFFERENCE"))
        }
    }

    @Test fun `consistent finished attempts retain bounded per-probe observations`() {
        val base = quickReport(raw = true)
        val attempts = (1..2).map { number -> ProbeAttempt("attempt-$number", ProbeKind.SYSTEM_DNS, number,
            (number - 1) * 100L, 1000, finishedAfterMillis = number * 100L, dns = base.dns) }
        val results = findings(base.copy(config = base.config.copy(maxAttempts = 2), attempts = attempts))
        assertTrue(results.containsKey("SYSTEM_ADDRESSES"))
        assertFalse(results.containsKey("ATTEMPTS_DISAGREE"))
    }

    @Test fun `system error action hints distinguish API failures negative answers and legacy detail gaps`() {
        val old = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE)
        val cases = listOf(old to "支持错误详情",
            old.copy(diagnosticStage = SystemDnsStage.LOCAL_EXCEPTION, exceptionKind = SystemDnsExceptionKind.SECURITY) to "本地调用问题",
            old.copy(diagnosticStage = SystemDnsStage.ERROR_CALLBACK, resolverErrorCode = 1) to "未知系统错误",
            old.copy(diagnosticStage = SystemDnsStage.ANSWER_CALLBACK, responseCode = 3) to "私有名称",
            old.copy(diagnosticStage = SystemDnsStage.ANSWER_CALLBACK, responseCode = 0) to "所需 A/AAAA")
        for ((observation, expected) in cases) {
            val result = findings(quickReport().copy(dns = observation)).getValue("SYSTEM_NO_ADDRESSES")
            assertTrue(expected, result.actionHint.contains(expected))
        }
    }

    @Test fun `synthetic evidence only gets an explicit demonstration finding`() {
        val results = findings(quickReport(raw = true).copy(evidenceOrigin = EvidenceOrigin.SYNTHETIC_FIXTURE))
        assertEquals(setOf("DEMO_ONLY"), results.keys)
    }

    @Test fun `unstable or unavailable network suppresses operational diagnosis`() {
        val base = quickReport(raw = true)
        for (report in listOf(base.copy(networkChanged = true),
            base.copy(networkAfter = base.networkAfter.copy(configuredDnsServers = listOf("192.0.2.54"))),
            base.copy(networkBefore = base.networkBefore.copy(observationAvailable = false)),
            base.copy(networkBefore = base.networkBefore.copy(networkId = null)))) {
            val results = findings(report)
            assertTrue(results.containsKey("NETWORK_UNSTABLE"))
            assertFalse(results.keys.any { it.endsWith("_ADDRESSES") })
        }
    }

    @Test fun `system success failure not started and cancellation remain distinct`() {
        val base = quickReport()
        assertTrue(findings(base).containsKey("SYSTEM_ADDRESSES"))
        for (failure in listOf(Failure.DNS_FAILURE, Failure.TIMEOUT, Failure.IO_FAILURE)) {
            val results = findings(base.copy(dns = DnsObservation(Execution.ERROR, failure = failure)))
            assertTrue(results.containsKey("SYSTEM_NO_ADDRESSES"))
            assertFalse(results.containsKey("SYSTEM_ADDRESSES"))
        }
        assertTrue(findings(base.copy(dns = DnsObservation())).containsKey("SYSTEM_NOT_RUN"))
        assertTrue(findings(base.copy(dns = DnsObservation(Execution.CANCELLED))).containsKey("SYSTEM_CANCELLED"))
    }

    @Test fun `NXDOMAIN TC empty NOERROR and error response codes never become usable addresses`() {
        val base = quickReport(raw = true)
        val raw = base.rawDns[0]
        val cases = mapOf(
            raw.copy(responseCode = 3) to "RAW_UDP_NXDOMAIN",
            raw.copy(truncated = true) to "RAW_UDP_TRUNCATED",
            raw.copy(addresses = emptyList()) to "RAW_UDP_NO_ADDRESSES",
            raw.copy(responseCode = 2) to "RAW_UDP_RCODE",
            raw.copy(responseCode = 5) to "RAW_UDP_RCODE",
            raw.copy(responseCode = null) to "RAW_UDP_RCODE"
        )
        for ((observation, expectedId) in cases) {
            val results = findings(base.copy(rawDns = listOf(observation, base.rawDns[1])))
            assertTrue(expectedId, results.containsKey(expectedId))
            assertFalse(results.containsKey("RAW_UDP_ADDRESSES"))
        }
    }

    @Test fun `protocol difference is actionable but never attributes blocking or privacy`() {
        val base = quickReport(raw = true)
        val failed = base.rawDns[0].copy(execution = Execution.ERROR, addresses = emptyList(), responseCode = null, failure = Failure.TIMEOUT)
        val results = findings(base.copy(rawDns = listOf(failed, base.rawDns[1])))
        val difference = results.getValue("RAW_PROTOCOL_DIFFERENCE")
        assertTrue(difference.detail.contains("不足以确定"))
        assertTrue(difference.actionHint.contains("不"))
    }

    @Test fun `cancelled or unstarted protocol is not treated as a transport discrepancy`() {
        val base = quickReport(raw = true)
        for (execution in listOf(Execution.CANCELLED, Execution.NOT_STARTED)) {
            val results = findings(base.copy(rawDns = listOf(RawDnsObservation(DnsTransport.UDP, execution), base.rawDns[1])))
            assertFalse(results.containsKey("RAW_PROTOCOL_DIFFERENCE"))
        }
        assertTrue(findings(base.copy(rawDns = listOf(base.rawDns[1]))).containsKey("RAW_INCOMPLETE"))
    }

    @Test fun `different successful answer addresses never create poisoning or a protocol failure`() {
        val base = quickReport(raw = true)
        val results = findings(base.copy(rawDns = listOf(base.rawDns[0].copy(addresses = listOf("192.0.2.21")), base.rawDns[1])))
        assertTrue(results.containsKey("RAW_UDP_ADDRESSES"))
        assertTrue(results.containsKey("RAW_TCP_ADDRESSES"))
        assertFalse(results.containsKey("RAW_PROTOCOL_DIFFERENCE"))
        assertFalse(results.containsKey("SYSTEM_RAW_DIFFERENCE"))
    }

    @Test fun `system and raw discrepancy includes configuration checks without automatic repair`() {
        val base = quickReport(raw = true)
        val results = findings(base.copy(dns = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE)))
        val finding = results.getValue("SYSTEM_RAW_DIFFERENCE")
        assertTrue(finding.detail.contains("查询类型"))
        assertTrue(finding.actionHint.contains("每次只修改一项"))
    }

    @Test fun `different queried hosts never suggest a system resolver problem from raw success`() {
        val base = quickReport(raw = true)
        val report = base.copy(config = base.config.copy(dnsHost = "missing.other.example"),
            dns = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE))
        val results = findings(report)
        assertTrue(results.containsKey("DIFFERENT_QUERY_TARGETS"))
        assertFalse(results.containsKey("SYSTEM_RAW_DIFFERENCE"))
        val canonical = report.copy(config = report.config.copy(dnsHost = "EXAMPLE.COM."))
        assertTrue(findings(canonical).containsKey("SYSTEM_RAW_DIFFERENCE"))
    }

    @Test fun `Private DNS false is not leakage and true does not encrypt the raw probe`() {
        val base = quickReport(raw = true)
        val inactive = findings(base).getValue("PRIVATE_DNS_INACTIVE")
        assertTrue(inactive.detail.contains("不是 DNS 泄露证据"))
        val network = base.networkBefore.copy(privateDnsActive = true, privateDnsServerName = "dns.example")
        val active = findings(base.copy(networkBefore = network, networkAfter = network)).getValue("PRIVATE_DNS_ACTIVE")
        assertTrue(active.detail.contains("明文"))
        assertTrue(active.detail.contains("不证明"))
    }

    @Test fun `VPN virtual resolver context is retained without calling it a broken public resolver`() {
        val base = quickReport(raw = true)
        val network = base.networkBefore.copy(vpnCapability = true, transports = listOf("VPN"))
        val results = findings(base.copy(networkBefore = network, networkAfter = network))
        assertTrue(results.getValue("VPN_DNS_CONTEXT").detail.contains("虚拟地址"))
        assertTrue(results.getValue("SCOPE_LIMIT").detail.contains("只观察本应用"))
    }
}
