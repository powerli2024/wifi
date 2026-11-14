package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class ReportComparisonTest {
    private val before get() = quickReport()
    private val nextId = "00000000-0000-4000-8000-000000000002"
    private fun next(report: RunReport) = report.copy(runId = nextId)

    @Test fun `success after timeout is bounded availability improvement not a repaired privacy claim`() {
        val failed = before.copy(dns = DnsObservation(Execution.ERROR, failure = Failure.TIMEOUT))
        val result = ReportComparison.compare(failed, next(before))
        assertTrue(result.comparable)
        assertTrue(result.summary.contains("改善"))
        assertTrue(result.summary.contains("不等于已修复"))
        assertTrue(result.details.any { it.contains("不能证明全机无泄露") })
    }

    @Test fun `timeout after successful result is observed regression with unknown cause`() {
        val result = ReportComparison.compare(before, next(before).copy(dns = DnsObservation(Execution.ERROR, failure = Failure.TIMEOUT)))
        assertTrue(result.comparable); assertTrue(result.summary.contains("退化")); assertTrue(result.summary.contains("原因尚未确定"))
    }

    @Test fun `same positive answers with different addresses and timings are not ranked as repaired`() {
        val result = ReportComparison.compare(before, next(before).copy(dns = before.dns.copy(addresses = listOf("192.0.2.22"), durationMillis = 1)))
        assertTrue(result.comparable)
        assertTrue(result.summary.contains("未变"))
        assertFalse(result.summary.contains("改善"))
    }

    @Test fun `demonstrations same report versions and query plan changes are not comparable`() {
        val base = before
        val cases = listOf(
            base, next(base).copy(evidenceOrigin = EvidenceOrigin.SYNTHETIC_FIXTURE),
            next(base).copy(appVersion = "0.4.0"), next(base).copy(androidApi = 34),
            next(base).copy(config = base.config.copy(dnsHost = "different.example")),
            next(base).copy(config = base.config.copy(timeoutMillis = 1000)),
            next(base).copy(config = base.config.copy(policy = base.config.policy.copy(ipv6InScope = false)))
        )
        for (after in cases) assertFalse(ReportComparison.compare(base, after).comparable)
    }

    @Test fun `unstable run unavailable snapshots and changed network or VPN prevent comparison`() {
        val base = before
        val differentNetwork = base.networkBefore.copy(networkId = "other-network")
        val differentVpn = base.networkBefore.copy(vpnCapability = true, transports = listOf("VPN"))
        for (after in listOf(
            next(base).copy(networkChanged = true),
            next(base).copy(networkBefore = base.networkBefore.copy(observationAvailable = false)),
            next(base).copy(networkBefore = differentNetwork, networkAfter = differentNetwork),
            next(base).copy(networkBefore = differentVpn, networkAfter = differentVpn),
            next(base).copy(networkAfter = base.networkAfter.copy(privateDnsActive = true))
        )) assertFalse(ReportComparison.compare(base, after).comparable)
    }

    @Test fun `DNS setting changes between stable runs allow facts but explicitly forbid attribution`() {
        val base = before.copy(dns = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE))
        val changed = before.networkBefore.copy(configuredDnsServers = listOf("192.0.2.54"),
            privateDnsActive = true, privateDnsServerName = "private.example")
        val after = next(before).copy(networkBefore = changed, networkAfter = changed)
        val result = ReportComparison.compare(base, after)
        assertTrue(result.comparable)
        assertTrue(result.summary.contains("改善"))
        assertTrue(result.details.any { it.contains("DNS 配置发生变化") && it.contains("不能据此归因") })
    }

    @Test fun `not started cancelled and internal error are never treated as regression`() {
        for (observation in listOf(DnsObservation(), DnsObservation(Execution.CANCELLED),
            DnsObservation(Execution.ERROR, failure = Failure.CANCELLED),
            DnsObservation(Execution.ERROR, failure = Failure.INTERNAL_ERROR))) {
            val result = ReportComparison.compare(before, next(before).copy(dns = observation))
            assertFalse(result.comparable)
            assertFalse(result.summary.contains("退化"))
        }
    }

    @Test fun `NXDOMAIN truncation and empty NOERROR are not address availability`() {
        val base = quickReport(raw = true)
        val raw = base.rawDns[0]
        for (observation in listOf(raw.copy(responseCode = 3), raw.copy(truncated = true), raw.copy(addresses = emptyList()))) {
            val after = next(base).copy(rawDns = listOf(observation, base.rawDns[1]))
            val result = ReportComparison.compare(base, after)
            assertTrue(result.comparable)
            assertTrue(result.summary.contains("退化"))
        }
    }

    @Test fun `missing cancelled or duplicate raw observations make the comparison inconclusive`() {
        val base = quickReport(raw = true)
        for (raw in listOf(
            emptyList(),
            listOf(base.rawDns[0], base.rawDns[0], base.rawDns[1]),
            listOf(base.rawDns[0].copy(execution = Execution.CANCELLED), base.rawDns[1]),
            listOf(RawDnsObservation(DnsTransport.UDP), base.rawDns[1])
        )) assertFalse(ReportComparison.compare(base, next(base).copy(rawDns = raw)).comparable)
    }

    @Test fun `different raw resolver type transport or socket family is not the same experiment`() {
        val base = quickReport(raw = true)
        val raw = base.config.rawDns!!
        for (changed in listOf(raw.copy(serverIp = "192.0.2.54"), raw.copy(port = 5353),
            raw.copy(recordType = DnsRecordType.AAAA), raw.copy(tcp = false),
            raw.copy(serverIp = "::ffff:" + raw.serverIp))) {
            val after = next(base).copy(config = base.config.copy(rawDns = changed))
            assertFalse(ReportComparison.compare(base, after).comparable)
        }
    }

    @Test fun `one protocol improves and another regresses is reported as mixed evidence`() {
        val base = quickReport(raw = true)
        val failedUdp = base.rawDns[0].copy(execution = Execution.ERROR, responseCode = null, failure = Failure.TIMEOUT)
        val failedTcp = base.rawDns[1].copy(execution = Execution.ERROR, responseCode = null, failure = Failure.TIMEOUT)
        val result = ReportComparison.compare(base.copy(rawDns = listOf(failedUdp, base.rawDns[1])),
            next(base).copy(rawDns = listOf(base.rawDns[0], failedTcp)))
        assertTrue(result.comparable); assertTrue(result.summary.contains("有改善也有退化"))
    }

    @Test fun `canonical endpoint equality does not depend on object identity`() {
        val base = before.copy(config = before.config.copy(endpoint = Endpoint.parse("https://echo.example")))
        val after = next(base).copy(config = base.config.copy(endpoint = Endpoint.parse("https://echo.example:443/")))
        assertTrue(ReportComparison.compare(base, after).comparable)
    }

    @Test fun `export embeds both complete reports and defaults to redacting both sets of identifiers`() {
        val base = quickReport(raw = true)
        val after = next(base).copy(dns = base.dns.copy(addresses = listOf("192.0.2.221")))
        val redacted = ReportComparison.toJson(base, after)
        val full = ReportComparison.toJson(base, after, true)
        for (secret in listOf("192.0.2.53", "192.0.2.5", "192.0.2.8", "192.0.2.221", "example.com", "test-network")) {
            assertFalse(secret, redacted.contains(secret))
            assertTrue(secret, full.contains(secret))
        }
        assertTrue(redacted.contains("\"before\":" + ReportExporter.toJson(base).trimEnd()))
        assertTrue(redacted.contains("\"after\":" + ReportExporter.toJson(after).trimEnd()))
        assertTrue(redacted.contains("\"artifactType\":\"REPORT_COMPARISON\""))
        assertTrue(redacted.contains("\"networkIdentifiersIncluded\":false"))
        assertTrue(full.contains("\"networkIdentifiersIncluded\":true"))
    }
}
