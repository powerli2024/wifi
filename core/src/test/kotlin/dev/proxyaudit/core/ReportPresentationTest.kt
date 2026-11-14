package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class ReportPresentationTest {
    private fun summary(report: RunReport) = ReportPresentation.summarize(report)
    private fun row(report: RunReport, title: String) = summary(report).rows.single { it.title == title }
    private fun systemError() = quickReport(raw = true).copy(
        dns = DnsObservation(Execution.ERROR, durationMillis = 3, failure = Failure.DNS_FAILURE))
    private fun httpsReport(): RunReport {
        val demo = DemoFixture.report()
        return demo.copy(evidenceOrigin = EvidenceOrigin.ANDROID_RUNTIME,
            config = demo.config.copy(dnsHost = null, policy = demo.config.policy.copy(runDns = false)),
            dns = DnsObservation())
    }

    @Test fun `reported system error raw address success and untested HTTPS remain distinct`() {
        // Same execution combination as the supplied redacted report, with independent synthetic
        // non-sensitive targets. The redacted file does not prove that its two hosts are equal.
        val result = summary(systemError())
        assertEquals("系统 DNS 报错，UDP/TCP 已返回地址", result.headline)
        assertEquals(listOf("解析错误", "返回地址", "返回地址", "未测"), result.rows.map { it.status })
        assertTrue(result.detail.contains("HTTPS 出口：未测"))
        assertTrue(result.detail.contains("实际路径仍未知"))
        assertTrue(result.nextStep.contains("每次只改一项"))
        assertTrue(result.nextStep.contains("查询类型"))
        assertFalse(result.toString().contains("已确认泄露"))
        assertFalse(result.toString().contains("1.1.1.1"))
    }

    @Test fun `different or missing queried hosts do not locate a system DNS fault`() {
        val base = systemError()
        for (host in listOf("other.example", null, "[REDACTED]")) {
            val report = base.copy(config = base.config.copy(dnsHost = host))
            val result = summary(report)
            assertTrue(result.headline.contains("暂不对照"))
            assertFalse(result.headline.contains("UDP/TCP 已返回"))
            assertTrue(result.nextStep.contains("同一域名"))
            assertEquals("解析错误", result.rows.first().status)
        }
    }

    @Test fun `same host comparison normalizes only DNS case and terminal dot`() {
        val base = systemError()
        val report = base.copy(config = base.config.copy(dnsHost = "EXAMPLE.COM."))
        assertEquals("系统 DNS 报错，UDP/TCP 已返回地址", summary(report).headline)
    }

    @Test fun `network changes and missing snapshots prevent stable causal hints`() {
        val base = systemError()
        for (report in listOf(base.copy(networkChanged = true),
            base.copy(networkAfter = base.networkAfter.copy(configuredDnsServers = listOf("192.0.2.99"))),
            base.copy(networkBefore = base.networkBefore.copy(observationAvailable = false)),
            base.copy(networkBefore = base.networkBefore.copy(networkId = null)))) {
            val result = summary(report)
            assertEquals("网络条件不稳定或未确认", result.headline)
            assertFalse(result.nextStep.contains("每次只改一项"))
            assertEquals("解析错误", result.rows.first().status)
            assertEquals("返回地址", result.rows[1].status)
        }
    }

    @Test fun `synthetic evidence stays visibly separate from device results`() {
        val result = summary(systemError().copy(evidenceOrigin = EvidenceOrigin.SYNTHETIC_FIXTURE))
        assertEquals("这是演示结果", result.headline)
        assertTrue(result.detail.contains("不是当前设备测量"))
        assertTrue(result.nextStep.contains("实际检查"))
        assertEquals("这是演示结果", summary(DemoFixture.report()).headline)
        for (row in result.rows + summary(DemoFixture.report()).rows) {
            assertEquals("演示数据", row.status)
            assertTrue(row.detail.contains("没有当前设备的诊断"))
            assertFalse(row.detail.contains("取得 2 个地址"))
            assertFalse(row.detail.contains("符合预期"))
        }
    }

    @Test fun `global stopping conditions override complete looking aggregate observations`() {
        val report = quickReport(raw = true)
        val cases = mapOf(Failure.CANCELLED to "检查已取消，结果可能不完整",
            Failure.NETWORK_CHANGED to "网络变化，检查提前停止",
            Failure.TIMEOUT to "总等待预算结束，检查可能不完整",
            Failure.INTERNAL_ERROR to "检查提前停止，结果可能不完整")
        for ((reason, headline) in cases) {
            val result = summary(report.copy(stopReason = reason))
            assertEquals(headline, result.headline)
            assertFalse(result.nextStep.contains("可保存为"))
        }
    }

    @Test fun `retries expose first failure and later success without rewriting aggregate evidence`() {
        val report = systemError()
        val first = report.dns.copy(failure = Failure.TIMEOUT)
        val success = quickReport().dns
        val attempts = listOf(
            ProbeAttempt("first", ProbeKind.SYSTEM_DNS, 1, 0, 1_000, 1_000, dns = first),
            ProbeAttempt("second", ProbeKind.SYSTEM_DNS, 2, 1_300, 1_000, 1_320, dns = success))
        val retried = report.copy(dns = first, attempts = attempts)
        val result = summary(retried)
        assertEquals("多次尝试结果不一致，先观察稳定性", result.headline)
        assertEquals("解析错误", result.rows.first().status)
        assertTrue(result.detail.contains("系统 DNS 首次：未取得有效结果（TIMEOUT）"))
        assertTrue(result.detail.contains("系统 DNS 附加尝试 2：取得地址"))
        assertTrue(result.nextStep.contains("不挑选较好结果"))
        assertEquals(first, retried.dns)
    }

    @Test fun `cancelled or unfinished attempts are not hidden by a successful aggregate`() {
        val base = quickReport()
        val attempt = ProbeAttempt("attempt", ProbeKind.SYSTEM_DNS, 1, 0, 1_000,
            dns = DnsObservation(Execution.CANCELLED))
        for (value in listOf(attempt, attempt.copy(finishedAfterMillis = 200))) {
            val result = summary(base.copy(attempts = listOf(value)))
            assertEquals("部分尝试未完成，暂不作完整对照", result.headline)
            assertTrue(result.detail.contains(if (value.finishedAfterMillis == null) "尚无完成记录" else "已取消"))
        }
    }

    @Test fun `HTTPS attempt success requires its own echoed identifier and is not a policy verdict`() {
        val report = httpsReport()
        val first = HttpsObservation(Execution.ERROR, failure = Failure.IO_FAILURE)
        val second = report.https.copy(echoedRequestId = "second")
        val attempts = listOf(
            ProbeAttempt(report.runId, ProbeKind.HTTPS, 1, 0, 1_000, 200, https = first),
            ProbeAttempt("second", ProbeKind.HTTPS, 2, 500, 1_000, 700, https = second))
        val result = summary(report.copy(https = first, attempts = attempts))
        assertEquals("多次尝试结果不一致，先观察稳定性", result.headline)
        assertTrue(result.detail.contains("符合协议的回显（不代表出口策略符合）"))
        val wrongId = attempts.last().copy(https = second.copy(echoedRequestId = report.runId))
        val invalid = summary(report.copy(https = first, attempts = listOf(attempts.first(), wrongId)))
        assertFalse(invalid.headline.contains("多次尝试结果不一致"))
        assertFalse(invalid.detail.contains("取得符合协议的回显"))
    }

    @Test fun `system error row includes recorded phase rather than generic resolver attribution`() {
        val report = quickReport().copy(dns = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE,
            diagnosticStage = SystemDnsStage.LOCAL_EXCEPTION, exceptionKind = SystemDnsExceptionKind.SECURITY))
        assertTrue(row(report, "系统 DNS").detail.contains("安全权限异常"))
    }

    @Test fun `system untested cancelled failed and empty responses are separate states`() {
        val base = quickReport()
        val cases = listOf(
            DnsObservation() to "未测",
            DnsObservation(Execution.CANCELLED) to "已取消",
            DnsObservation(Execution.ERROR, failure = Failure.CANCELLED) to "已取消",
            DnsObservation(Execution.ERROR, failure = Failure.TIMEOUT) to "解析错误",
            DnsObservation(Execution.COMPLETED) to "未返回可用地址",
            DnsObservation(Execution.COMPLETED, listOf("[REDACTED]")) to "未返回可用地址",
            DnsObservation(Execution.COMPLETED, listOf("192.0.2.9"), failure = Failure.DNS_FAILURE) to "解析错误"
        )
        for ((observation, expected) in cases)
            assertEquals(expected, row(base.copy(dns = observation), "系统 DNS").status)
        assertEquals("本次尚无已执行的检查", summary(base.copy(dns = DnsObservation())).headline)
    }

    @Test fun `raw NXDOMAIN truncation response errors and empty NOERROR are not address success`() {
        val base = quickReport(raw = true)
        val udp = base.rawDns.first()
        val cases = listOf(
            udp.copy(responseCode = 3) to "域名不存在",
            udp.copy(truncated = true) to "响应截断",
            udp.copy(responseCode = 2) to "响应错误",
            udp.copy(responseCode = null) to "响应不完整",
            udp.copy(addresses = emptyList()) to "无所需地址",
            udp.copy(addresses = listOf("[REDACTED]")) to "无所需地址"
        )
        for ((observation, expected) in cases) {
            val report = base.copy(rawDns = listOf(observation, base.rawDns[1]))
            assertEquals(expected, row(report, "UDP DNS").status)
            assertFalse(row(report, "UDP DNS").detail.contains("取得 1 个地址"))
        }
    }

    @Test fun `raw cancellation and nonexecution do not become protocol failures`() {
        val base = quickReport(raw = true)
        for ((execution, status) in listOf(Execution.CANCELLED to "已取消", Execution.NOT_STARTED to "未测")) {
            val report = base.copy(rawDns = listOf(RawDnsObservation(DnsTransport.UDP, execution), base.rawDns[1]))
            assertEquals(status, row(report, "UDP DNS").status)
            assertFalse(summary(report).headline.contains("UDP 与 TCP"))
        }
        val report = base.copy(rawDns = listOf(base.rawDns[0].copy(execution = Execution.ERROR, failure = Failure.TIMEOUT), base.rawDns[1]))
        assertEquals("查询错误", row(report, "UDP DNS").status)
        assertEquals("UDP 与 TCP 的地址结果不同", summary(report).headline)
    }

    @Test fun `missing and duplicate raw observations are explicit rather than guessed`() {
        val base = quickReport(raw = true)
        val missing = base.copy(rawDns = listOf(base.rawDns[1]))
        assertEquals("结果缺失", row(missing, "UDP DNS").status)
        val duplicate = base.copy(rawDns = listOf(base.rawDns[0], base.rawDns[0], base.rawDns[1]))
        assertEquals("结果不唯一", row(duplicate, "UDP DNS").status)
        assertFalse(summary(duplicate).headline.contains("UDP 与 TCP"))
    }

    @Test fun `disabled modules ignore inconsistent leftover observations`() {
        val base = httpsReport()
        val report = base.copy(config = base.config.copy(rawDns = null,
            policy = base.config.policy.copy(runHttps = false, runDns = false)),
            dns = DnsObservation(Execution.COMPLETED, listOf("192.0.2.1")), rawDns = quickReport(raw = true).rawDns)
        val result = summary(report)
        assertEquals(listOf("未测", "未测", "未测", "未测"), result.rows.map { it.status })
        assertEquals("本次尚无已执行的检查", result.headline)
    }

    @Test fun `HTTPS matched and mismatched policies remain limited to this request`() {
        val matched = httpsReport()
        assertEquals("符合预期", row(matched, "HTTPS 出口").status)
        assertEquals("本次 HTTPS 出口符合预期", summary(matched).headline)
        assertTrue(summary(matched).nextStep.contains("本应用"))
        val mismatched = matched.copy(https = matched.https.copy(serverReportedSourceIp = "198.51.100.99"))
        assertEquals("不符合预期", row(mismatched, "HTTPS 出口").status)
        assertEquals("本次 HTTPS 出口不符合预期", summary(mismatched).headline)
        assertTrue(summary(mismatched).nextStep.contains("不是全机泄露判定"))
    }

    @Test fun `missing trust expectation or validated echo cannot produce an egress verdict`() {
        val base = httpsReport()
        val reports = listOf(
            base.copy(config = base.config.copy(endpoint = null)),
            base.copy(config = base.config.copy(policy = base.config.policy.copy(endpointTrustedByUser = false))),
            base.copy(config = base.config.copy(policy = base.config.policy.copy(expectedSourceIps = emptySet()))),
            base.copy(https = base.https.copy(tlsValidated = false)),
            base.copy(https = base.https.copy(echoedRequestId = "wrong-run")),
            base.copy(https = base.https.copy(statusCode = 500)),
            base.copy(https = base.https.copy(serverReportedSourceIp = "not-an-IP"))
        )
        for (report in reports) {
            assertEquals("无法判定", row(report, "HTTPS 出口").status)
            assertEquals("HTTPS 出口暂不能判定", summary(report).headline)
        }
        assertTrue(summary(reports[1]).nextStep.contains("人工"))
        assertTrue(summary(reports[2]).nextStep.contains("独立确认"))
    }

    @Test fun `HTTPS failure cancellation and nonexecution never become source IP mismatch`() {
        val base = httpsReport()
        for ((observation, status) in listOf(
            HttpsObservation() to "未测",
            HttpsObservation(Execution.CANCELLED) to "已取消",
            HttpsObservation(Execution.ERROR, failure = Failure.TLS_FAILURE) to "请求错误",
            HttpsObservation(Execution.ERROR, failure = Failure.TIMEOUT) to "请求错误"
        )) {
            val report = base.copy(https = observation)
            assertEquals(status, row(report, "HTTPS 出口").status)
            assertFalse(summary(report).headline.contains("不符合预期"))
        }
    }

    @Test fun `system DNS success does not hide HTTPS error or missing egress evidence`() {
        val base = httpsReport()
        val dnsSuccess = base.copy(config = base.config.copy(dnsHost = "example.com",
            policy = base.config.policy.copy(runDns = true)),
            dns = DnsObservation(Execution.COMPLETED, listOf("192.0.2.1")))
        val failed = dnsSuccess.copy(https = HttpsObservation(Execution.ERROR, failure = Failure.TLS_FAILURE))
        assertEquals("HTTPS 请求出错，出口尚未判定", summary(failed).headline)
        assertEquals("返回地址", row(failed, "系统 DNS").status)
        val untrusted = dnsSuccess.copy(config = dnsSuccess.config.copy(
            policy = dnsSuccess.config.policy.copy(endpointTrustedByUser = false)))
        assertEquals("HTTPS 出口暂不能判定", summary(untrusted).headline)
        val pending = dnsSuccess.copy(https = HttpsObservation())
        assertEquals("部分检查尚未执行", summary(pending).headline)
        assertEquals("未测", row(pending, "HTTPS 出口").status)
    }

    @Test fun `a successful module does not conceal missing or failed selected modules`() {
        val base = quickReport(raw = true)
        assertEquals("部分检查未取得有效地址结果", summary(base.copy(rawDns = emptyList())).headline)
        val failed = base.copy(rawDns = base.rawDns.map {
            it.copy(execution = Execution.ERROR, failure = Failure.TIMEOUT, addresses = emptyList(), responseCode = null)
        })
        assertEquals("部分检查未取得有效地址结果", summary(failed).headline)
        val https = httpsReport()
        val systemFailed = https.copy(config = https.config.copy(dnsHost = "example.com",
            policy = https.config.policy.copy(runDns = true)),
            dns = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE))
        assertEquals("符合预期", row(systemFailed, "HTTPS 出口").status)
        assertEquals("部分检查未取得有效地址结果", summary(systemFailed).headline)
    }

    @Test fun `different successful DNS addresses are observations rather than poisoning diagnoses`() {
        val base = quickReport(raw = true)
        val report = base.copy(rawDns = listOf(base.rawDns[0].copy(addresses = listOf("192.0.2.99")), base.rawDns[1]))
        val result = summary(report)
        assertEquals(listOf("返回地址", "返回地址", "返回地址", "未测"), result.rows.map { it.status })
        assertFalse(result.headline.contains("不同"))
        assertFalse(result.headline.contains("污染"))
    }

    @Test fun `summary omits raw identifiers credentials and endpoint strings`() {
        val base = httpsReport()
        val report = base.copy(config = base.config.copy(endpoint = Endpoint.parse("https://sensitive.example.test"),
            dnsHost = "secret.example.test", rawDns = RawDnsConfig("192.0.2.53", host = "secret.example.test")),
            rawDns = quickReport(raw = true).rawDns)
        val text = summary(report).toString()
        for (secret in listOf("sensitive.example.test", "secret.example.test", "192.0.2.53", "203.0.113.7", report.runId))
            assertFalse(secret, text.contains(secret))
    }

    @Test fun `presentation leaves config policy and report evidence unchanged`() {
        val report = systemError()
        val before = ReportExporter.toJson(report, true)
        val first = summary(report)
        assertEquals(first, summary(report))
        assertEquals(before, ReportExporter.toJson(report, true))
        assertFalse(report.config.policy.endpointTrustedByUser)
        assertTrue(report.config.policy.expectedSourceIps.isEmpty())
    }
}
