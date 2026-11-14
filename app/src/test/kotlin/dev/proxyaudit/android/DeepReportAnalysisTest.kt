package dev.proxyaudit.android

import dev.proxyaudit.core.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class DeepReportAnalysisTest {
    @Test fun http_proxy_without_origin_dns_is_explained_but_direct_does_not_exclude_vpn() {
        val report = DeepComparisonFixtures.report()
        val observations = DeepReportAnalysis.findings(report)
        assertTrue(observations.any { it.contains("HTTP 代理") && it.contains("原始 DNS 对照也不等同") })
        val originSeen = report.website!!.attempts.single().copy(dns = listOf(WebsiteDnsResult("ORIGIN", listOf("192.0.2.9"), 1)))
        assertFalse(DeepReportAnalysis.findings(report.copy(website = report.website.copy(attempts = listOf(originSeen)))).any { it.contains("未观察到本地站点") })
        val direct = originSeen.copy(connections = listOf(WebsiteConnectionResult("DIRECT", "IPv4", "192.0.2.9")))
        assertTrue(DeepReportAnalysis.findings(report.copy(website = report.website.copy(attempts = listOf(direct)))).any { it.contains("VPN 仍可能") })
        val numeric = report.copy(website = report.website.copy(plan = WebsitePlan.parse("https://192.0.2.9")))
        assertTrue(DeepReportAnalysis.findings(numeric).any { it.contains("目标本身是数字 IP") })
        assertFalse(DeepReportAnalysis.findings(numeric).any { it.contains("站点解析可由代理承接") })
    }

    @Test fun fake_ip_range_includes_both_18_and_19_without_claiming_poison_or_leak() {
        for (address in listOf("198.18.0.0", "198.18.255.255", "198.19.0.1", "198.19.255.255")) assertTrue(DeepReportAnalysis.isFakeIpRange(address))
        for (address in listOf("198.17.255.255", "198.20.0.0", "198.18.1.999", "2001:db8::1", "private.host")) assertFalse(DeepReportAnalysis.isFakeIpRange(address))
        val report = DeepComparisonFixtures.report().let { it.copy(dns = it.dns.map { d ->
            if (d.recordType == DnsRecordType.A) d.copy(observation = d.observation.copy(addresses = listOf("198.19.0.2"))) else d
        }) }
        assertTrue(DeepReportAnalysis.findings(report).any { it.contains("fake-IP") && it.contains("不能确认") })
        assertTrue(DeepReportAnalysis.findings(report.copy(stopReason = "NETWORK_CHANGED")).isEmpty())
    }

    @Test fun empty_aaaa_is_a_response_but_timeout_or_truncation_are_not_empty_success() {
        val report = DeepComparisonFixtures.report().let { it.copy(dns = it.dns.map { d ->
            if (d.recordType == DnsRecordType.AAAA) d.copy(observation = d.observation.copy(addresses = emptyList())) else d
        }) }
        assertTrue(DeepReportAnalysis.findings(report).any { it.contains("NOERROR 空地址") && it.contains("与超时或传输失败不同") })
        for (failed in listOf(
            report.copy(dns = report.dns.map { it.copy(observation = it.observation.copy(execution = Execution.ERROR, failure = Failure.TIMEOUT)) }),
            report.copy(dns = report.dns.map { it.copy(observation = it.observation.copy(truncated = true)) }),
            report.copy(stopReason = "USER_CANCELLED")
        )) assertFalse(DeepReportAnalysis.findings(failed).any { it.contains("NOERROR 空地址") })
    }

    @Test fun different_successful_udp_tcp_sets_are_not_attributed_to_pollution() {
        val report = DeepComparisonFixtures.report().let { it.copy(dns = it.dns.map { d ->
            if (d.observation.transport == DnsTransport.TCP) d.copy(observation = d.observation.copy(addresses = listOf("203.0.113.2"))) else d
        }) }
        val findings = DeepReportAnalysis.findings(report)
        assertTrue(findings.any { it.contains("地址集合不同") && it.contains("不能直接判污染") })
    }

    @Test fun later_success_keeps_first_failure_without_requiring_raw_dns() {
        val report = DeepComparisonFixtures.report(failure = WebsiteFailure.TIMEOUT)
        val first = report.website!!.attempts.single()
        val mixed = report.copy(dns = emptyList(), dnsServer = null, website = report.website.copy(
            attempts = listOf(first, DeepComparisonFixtures.attempt().copy(number = 2))))
        assertTrue(DeepReportAnalysis.findings(mixed).any { it.contains("首次网站尝试失败") && it.contains("不能把后续成功解释为自动修复") })
    }

    @Test fun empty_answer_versus_transport_failure_is_a_protocol_difference_without_leak_attribution() {
        val report = DeepComparisonFixtures.report().copy(dns = listOf(
            DeepDnsResult(DnsRecordType.AAAA, RawDnsObservation(DnsTransport.UDP, Execution.COMPLETED, responseCode = 0)),
            DeepDnsResult(DnsRecordType.AAAA, RawDnsObservation(DnsTransport.TCP, Execution.ERROR, failure = Failure.TIMEOUT))))
        assertTrue(DeepReportAnalysis.findings(report).any { it.contains("UDP 收到 NOERROR 空地址响应，TCP 执行错误 TIMEOUT") && it.contains("不将它直接归因") })
    }

    @Test fun successful_answer_versus_transport_error_is_explained_in_either_direction() {
        for (failed in DnsTransport.entries) {
            val report = DeepComparisonFixtures.report().copy(dns = DnsTransport.entries.map { transport ->
                DeepDnsResult(DnsRecordType.A, if (transport == failed)
                    RawDnsObservation(transport, Execution.ERROR, failure = Failure.TIMEOUT)
                else RawDnsObservation(transport, Execution.COMPLETED, responseCode = 0, addresses = listOf("203.0.113.9")))
            })
            val findings = DeepReportAnalysis.findings(report)
            assertTrue(findings.any { it.contains("执行错误 TIMEOUT") && it.contains("取得地址") && it.contains("不将它直接归因") })
            assertFalse(findings.any { it.contains("收到 NOERROR 空地址响应") })
        }
    }

    @Test fun cancelled_attempt_or_cancelled_website_does_not_create_a_completed_proxy_explanation() {
        val normal = DeepComparisonFixtures.report(failure = WebsiteFailure.TIMEOUT)
        val canceledAttempt = normal.website!!.attempts.single().copy(execution = Execution.CANCELLED, failure = WebsiteFailure.CANCELLED)
        val canceled = normal.copy(website = normal.website.copy(attempts = listOf(canceledAttempt)))
        assertFalse(DeepReportAnalysis.findings(canceled).any { it.contains("已观察到 HTTP 代理连接") })
        val stoppedAggregate = normal.copy(website = normal.website.copy(execution = Execution.CANCELLED,
            attempts = listOf(normal.website.attempts.single(), DeepComparisonFixtures.attempt().copy(number = 2))))
        assertFalse(DeepReportAnalysis.findings(stoppedAggregate).any { it.contains("后续复核完成") || it.contains("已观察到 HTTP 代理连接") })
    }
}
