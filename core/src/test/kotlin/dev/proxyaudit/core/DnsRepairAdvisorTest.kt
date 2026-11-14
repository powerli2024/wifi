package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class DnsRepairAdvisorTest {
    private val base get() = quickReport(raw = true)
    private fun advice(report: RunReport?) = DnsRepairAdvisor.advise(report)
    private fun ids(report: RunReport?) = advice(report).recommendations.map { it.id }
    private fun withSystem(result: DnsObservation) = base.copy(dns = result)
    private fun error(stage: SystemDnsStage? = null, code: Int? = null, errno: Int? = null,
                      kind: SystemDnsExceptionKind? = null) =
        DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE, diagnosticStage = stage,
            resolverErrorCode = code, systemErrno = errno, exceptionKind = kind)
    private fun vpn(report: RunReport): RunReport {
        val network = report.networkBefore.copy(vpnCapability = true, transports = listOf("VPN"))
        return report.copy(networkBefore = network, networkAfter = network)
    }
    private fun assertNoSettingAction(report: RunReport) {
        assertFalse(advice(report).recommendations.any { it.repairKind in listOf(
            DnsRepairKind.REVIEW_SYSTEM_SETTINGS, DnsRepairKind.REVIEW_MIHOMO_CONFIG) })
    }
    private fun systemAttempt(number: Int, result: DnsObservation, finished: Long? = 200L) =
        ProbeAttempt("attempt-$number", ProbeKind.SYSTEM_DNS, number, (number - 1) * 300L, 1_000,
            finished, dns = result)

    @Test fun `no evidence and demonstration do not diagnose the current phone`() {
        val none = advice(null)
        assertNull(none.sourceRunId)
        assertEquals(listOf("NO_EVIDENCE"), none.recommendations.map { it.id })
        val demo = advice(DemoFixture.report())
        assertNull(demo.sourceRunId)
        assertTrue(demo.sourceLabel.contains("演示"))
        assertEquals(listOf("DEMO_ONLY"), demo.recommendations.map { it.id })
        assertEquals(DnsRepairKind.COLLECT_EVIDENCE, demo.recommendations.single().repairKind)
        assertTrue(demo.recommendations.single().reason.contains("虚构"))
    }

    @Test fun `source record and baseline provenance do not claim live settings or repair success`() {
        val report = base
        assertEquals(report.runId, advice(report).sourceRunId)
        assertTrue(advice(report).sourceLabel.contains("不是当前网络的实时状态"))
        assertTrue(advice(report).baselineLabel.contains("尚未保存"))
        assertTrue(DnsRepairAdvisor.advise(report, DemoFixture.report()).baselineLabel.contains("演示"))
        assertTrue(DnsRepairAdvisor.advise(report, report).baselineLabel.contains("尚无另一份"))
        assertTrue(DnsRepairAdvisor.advise(null, report).baselineLabel.contains("没有可与之对照"))
        val next = report.copy(runId = "00000000-0000-4000-8000-000000000002")
        assertTrue(DnsRepairAdvisor.advise(next, report).baselineLabel.contains("不表示已通过隐私验证"))
        assertTrue(DnsRepairAdvisor.advise(next.copy(stopReason = Failure.CANCELLED), report)
            .baselineLabel.contains("提前停止"))
    }

    @Test fun `permission and invalid argument require API investigation even when raw DNS succeeds`() {
        val cases = mapOf(SystemDnsExceptionKind.SECURITY to "SYSTEM_PERMISSION",
            SystemDnsExceptionKind.INVALID_ARGUMENT to "SYSTEM_ARGUMENT",
            SystemDnsExceptionKind.INTERRUPTED to "SYSTEM_LOCAL_ERROR",
            SystemDnsExceptionKind.OTHER to "SYSTEM_LOCAL_ERROR")
        for ((kind, id) in cases) {
            val report = vpn(withSystem(error(SystemDnsStage.LOCAL_EXCEPTION, kind = kind)))
            val first = advice(report).recommendations.first()
            assertEquals(id, first.id)
            assertEquals(DnsRepairKind.CHECK_API, first.repairKind)
            assertNoSettingAction(report)
        }
    }

    @Test fun `ERROR_SYSTEM with known unknown or missing errno is not a resolver replacement diagnosis`() {
        for (errno in listOf(101, 13, 9999, null)) {
            val report = vpn(withSystem(error(SystemDnsStage.ERROR_CALLBACK, 1, errno)))
            val first = advice(report).recommendations.first()
            assertEquals("SYSTEM_API_ERROR", first.id)
            assertEquals(DnsRepairKind.CHECK_API, first.repairKind)
            assertTrue(first.reason.contains("ERROR_SYSTEM"))
            assertTrue(first.reason.contains(if (errno == null) "未提供 errno" else "errno=$errno"))
            assertTrue(first.reason.contains("不能仅凭此归责"))
            assertNoSettingAction(report)
        }
    }

    @Test fun `parse and unknown resolver errors retain platform code without claiming poisoning`() {
        for (code in listOf(0, 77, null)) {
            val report = vpn(withSystem(error(SystemDnsStage.ERROR_CALLBACK, code)))
            val first = advice(report).recommendations.first()
            assertEquals(DnsRepairKind.CHECK_API, first.repairKind)
            assertTrue(first.reason.contains(if (code == 0) "ERROR_PARSE" else "code=${code ?: "未记录"}"))
            assertNoSettingAction(report)
        }
    }

    @Test fun `NXDOMAIN checks name and policy without suggesting DNS replacement`() {
        val report = vpn(withSystem(error(SystemDnsStage.ANSWER_CALLBACK).copy(responseCode = 3)))
        val first = advice(report).recommendations.first()
        assertEquals("SYSTEM_NXDOMAIN", first.id)
        assertEquals(DnsRepairKind.KEEP_DNS, first.repairKind)
        assertTrue(first.steps.joinToString().contains("私有名称"))
        assertTrue(ids(report).contains("SYSTEM_RAW_DIFFERENCE"))
        assertNoSettingAction(report)
    }

    @Test fun `empty NOERROR and other response codes ask for bounded evidence`() {
        for (code in listOf(0, 2, 5, null)) {
            val report = vpn(withSystem(error(SystemDnsStage.ANSWER_CALLBACK).copy(responseCode = code)))
            val first = advice(report).recommendations.first()
            assertEquals(DnsRepairKind.COLLECT_EVIDENCE, first.repairKind)
            if (code == 0) {
                assertEquals("SYSTEM_EMPTY_ANSWER", first.id)
                assertTrue(first.steps.joinToString().contains("不要仅因缺少 AAAA 关闭 IPv6"))
            }
            assertNoSettingAction(report)
        }
    }

    @Test fun `legacy DNS_FAILURE and short duration cannot identify root cause`() {
        val report = vpn(withSystem(error().copy(durationMillis = 3)))
        assertEquals("SYSTEM_DETAIL_MISSING", advice(report).recommendations.first().id)
        assertTrue(advice(report).recommendations.first().reason.contains("不能从 DNS_FAILURE 或耗时还原根因"))
        assertNoSettingAction(report)
    }

    @Test fun `same host difference is bounded and normalized but does not prove same lookup type`() {
        val report = withSystem(error()).let { it.copy(config = it.config.copy(dnsHost = "EXAMPLE.COM.")) }
        val difference = advice(report).recommendations.single { it.id == "SYSTEM_RAW_DIFFERENCE" }
        assertEquals(DnsRepairKind.COLLECT_EVIDENCE, difference.repairKind)
        assertTrue(difference.reason.contains("只证明两种方式行为不同"))
        assertTrue(difference.steps.joinToString().contains("A/AAAA"))
        val aaaa = report.copy(config = report.config.copy(rawDns = report.config.rawDns!!.copy(recordType = DnsRecordType.AAAA)))
        assertTrue(ids(aaaa).contains("SYSTEM_RAW_DIFFERENCE"))
        assertNoSettingAction(aaaa)
    }

    @Test fun `different missing invalid and redacted system hosts cannot justify settings advice`() {
        val original = vpn(withSystem(error().copy(failure = Failure.TIMEOUT)))
        for (host in listOf("other.example", null, "[REDACTED]", "not a name")) {
            val report = original.copy(config = original.config.copy(dnsHost = host))
            assertEquals("QUERY_NOT_COMPARABLE", advice(report).recommendations.first().id)
            assertFalse(ids(report).contains("SYSTEM_RAW_DIFFERENCE"))
            assertNoSettingAction(report)
        }
    }

    @Test fun `stable same host timeout offers conditional reversible reviews without choosing a provider`() {
        val report = vpn(withSystem(error().copy(failure = Failure.TIMEOUT)))
        val recommendations = advice(report).recommendations
        val settings = recommendations.single { it.repairKind == DnsRepairKind.REVIEW_SYSTEM_SETTINGS }
        assertTrue(settings.steps.joinToString().contains("原模式"))
        assertTrue(settings.recoveryAdvice.contains("恢复本次确切修改的原值"))
        val config = recommendations.single { it.repairKind == DnsRepairKind.REVIEW_MIHOMO_CONFIG }
        assertTrue(config.title.startsWith("若使用 Mihomo"))
        assertTrue(config.reason.contains("不能识别客户端"))
        assertTrue(config.steps.joinToString().contains("导出不等于导入或生效"))
        assertFalse(recommendations.toString().contains("1.1.1.1"))
        assertFalse(recommendations.toString().contains("8.8.8.8"))
        assertFalse(ids(withSystem(error().copy(failure = Failure.TIMEOUT))).contains("REVIEW_MIHOMO_DNS"))
    }

    @Test fun `network instability missing snapshots and global stops suppress operational settings advice`() {
        val report = vpn(withSystem(error().copy(failure = Failure.TIMEOUT)))
        val variants = listOf(report.copy(networkChanged = true),
            report.copy(networkAfter = report.networkAfter.copy(observationAvailable = false)),
            report.copy(networkAfter = report.networkAfter.copy(networkId = null)),
            report.copy(networkAfter = report.networkAfter.copy(privateDnsActive = true)))
        for (variant in variants) {
            assertEquals(listOf("NETWORK_UNCONFIRMED"), ids(variant))
            assertNoSettingAction(variant)
        }
        for ((stop, id) in mapOf(Failure.CANCELLED to "RUN_CANCELLED", Failure.NETWORK_CHANGED to "NETWORK_CHANGED",
            Failure.TIMEOUT to "RUN_BUDGET_EXHAUSTED", Failure.INTERNAL_ERROR to "RUN_STOPPED")) {
            val variant = report.copy(stopReason = stop)
            assertEquals(listOf(id), ids(variant))
            assertNoSettingAction(variant)
        }
    }

    @Test fun `unstarted cancelled missing and duplicate DNS observations are incomplete rather than failures`() {
        val report = base
        val variants = listOf(report.copy(dns = DnsObservation()),
            report.copy(dns = DnsObservation(Execution.CANCELLED)), report.copy(rawDns = emptyList()),
            report.copy(rawDns = report.rawDns + report.rawDns.first()),
            report.copy(rawDns = listOf(report.rawDns.first().copy(execution = Execution.CANCELLED), report.rawDns.last())))
        for (variant in variants) assertEquals(listOf("DNS_INCOMPLETE"), ids(variant))
    }

    @Test fun `raw truncation negative and protocol difference retain independent observations`() {
        val report = base
        val udp = report.rawDns.first()
        val tcp = report.rawDns.last()
        for ((observation, id) in mapOf(udp.copy(truncated = true) to "RAW_TRUNCATED",
            udp.copy(responseCode = 3, addresses = emptyList()) to "RAW_NXDOMAIN",
            udp.copy(execution = Execution.ERROR, responseCode = null, addresses = emptyList(), failure = Failure.TIMEOUT) to "RAW_PROTOCOL_DIFFERENCE")) {
            val variant = report.copy(rawDns = listOf(observation, tcp))
            val raw = advice(variant).recommendations.single { it.id == id }
            assertTrue(raw.reason.contains("TCP：取得地址"))
            assertTrue(raw.steps.joinToString().contains("TCP 成功不等于加密"))
            assertNoSettingAction(variant)
        }
        val empty = report.copy(rawDns = report.rawDns.map { it.copy(addresses = emptyList()) })
        assertTrue(ids(empty).contains("RAW_NO_USABLE_ANSWER"))
    }

    @Test fun `system timeout with conflicting raw protocol results does not advance to settings review`() {
        val report = vpn(withSystem(error().copy(failure = Failure.TIMEOUT)))
        val negative = report.rawDns.first().copy(responseCode = 3, addresses = emptyList())
        val conflicted = report.copy(rawDns = listOf(negative, report.rawDns.last()))
        assertTrue(ids(conflicted).contains("SYSTEM_RAW_DIFFERENCE"))
        assertTrue(ids(conflicted).contains("RAW_NXDOMAIN"))
        assertNoSettingAction(conflicted)
    }

    @Test fun `successful addresses do not require settings changes or claim HTTPS coverage`() {
        val result = advice(base)
        assertEquals(listOf("SYSTEM_ADDRESSES"), result.recommendations.map { it.id })
        assertEquals(DnsRepairKind.KEEP_DNS, result.recommendations.single().repairKind)
        assertTrue(result.recommendations.single().blindSpots.any { it.contains("HTTPS 出口未测") })
        assertTrue(result.recommendations.single().blindSpots.any { it.contains("DoH/DoT") })
        val rawOnly = base.let { it.copy(config = it.config.copy(policy = it.config.policy.copy(runDns = false))) }
        assertEquals(listOf("RAW_ADDRESSES_ONLY"), ids(rawOnly))
        val disabled = rawOnly.copy(config = rawOnly.config.copy(rawDns = null))
        assertEquals(listOf("DNS_NOT_SELECTED"), ids(disabled))
    }

    @Test fun `HTTPS failure with successful DNS is not a DNS provider recommendation`() {
        val report = base.let { it.copy(config = it.config.copy(policy = it.config.policy.copy(runHttps = true)),
            https = HttpsObservation(Execution.ERROR, failure = Failure.TLS_FAILURE)) }
        val separate = advice(report).recommendations.single { it.id == "HTTPS_SEPARATE" }
        assertEquals(DnsRepairKind.KEEP_DNS, separate.repairKind)
        assertTrue(separate.steps.joinToString().contains("不要关闭证书验证"))
        assertNoSettingAction(report)
    }

    @Test fun `Private DNS active does not block explicit plain protocol diagnostics or recommend disabling it`() {
        val original = withSystem(error().copy(failure = Failure.TIMEOUT))
        val network = original.networkBefore.copy(privateDnsActive = true, privateDnsServerName = "private.example")
        val report = original.copy(networkBefore = network, networkAfter = network)
        val text = advice(report).recommendations.toString()
        assertTrue(text.contains("不必为此关闭 Private DNS"))
        assertFalse(text.contains("POLICY_BLOCKED"))
        assertFalse(text.contains("private.example"))
    }

    @Test fun `mixed retries retain first failure and require more evidence instead of settings changes`() {
        val original = withSystem(error().copy(failure = Failure.TIMEOUT))
        val report = original.copy(attempts = listOf(systemAttempt(1, original.dns), systemAttempt(2, base.dns, 500)))
        assertEquals(listOf("ATTEMPTS_DISAGREE"), ids(report))
        assertTrue(advice(report).recommendations.single().reason.contains("首次失败"))
        assertTrue(DnsRepairAdvisor.advise(report, base.copy(runId = "other")).baselineLabel.contains("不一致"))
        assertNoSettingAction(report)
        assertEquals(Execution.ERROR, report.dns.execution)
    }

    @Test fun `unfinished and cancelled attempt records cannot be hidden by complete aggregate fields`() {
        for (attempt in listOf(systemAttempt(1, base.dns, null), systemAttempt(1, DnsObservation(Execution.CANCELLED)))) {
            val report = base.copy(attempts = listOf(attempt))
            assertEquals(listOf("ATTEMPT_INCOMPLETE"), ids(report))
            assertNoSettingAction(report)
        }
    }

    @Test fun `advice is deterministic preserves evidence and omits query and network identifiers`() {
        val original = base.copy(config = base.config.copy(dnsHost = "secret.example",
            rawDns = base.config.rawDns!!.copy(host = "secret.example")))
        val before = ReportExporter.toJson(original, true)
        assertEquals(advice(original), advice(original))
        assertEquals(before, ReportExporter.toJson(original, true))
        val text = advice(original).recommendations.toString()
        for (secret in listOf("secret.example", "192.0.2.53", "192.0.2.8", "test-network"))
            assertFalse(secret, text.contains(secret))
    }
}
