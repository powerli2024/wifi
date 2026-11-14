package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class AttemptEvidenceTest {
    private val failed = DnsObservation(Execution.ERROR, durationMillis = 1000, failure = Failure.TIMEOUT)
    private fun records() = listOf(
        ProbeAttempt("00000000-0000-4000-8000-000000000011", ProbeKind.SYSTEM_DNS, 1, 0, 1000,
            1000, dns = failed, retryTrigger = RetryTrigger.TIMEOUT, retryScheduled = true, retryDelayMillis = 500),
        ProbeAttempt("00000000-0000-4000-8000-000000000012", ProbeKind.SYSTEM_DNS, 2, 1500, 1000,
            1520, dns = DnsObservation(Execution.COMPLETED, listOf("192.0.2.221"), 20)))
    private fun report() = quickReport().let { it.copy(config = it.config.copy(maxAttempts = 2),
        dns = failed, attempts = records()) }
    private fun next(report: RunReport) = report.copy(runId = "00000000-0000-4000-8000-000000000002")

    @Test fun `retry opt in is bounded and never enlarges original run budget`() {
        val config = quickReport().config
        assertEquals(1, config.maxAttempts)
        assertEquals(20000L, config.copy(maxAttempts = 2).evidenceBudgetMillis)
        assertEquals(60000L, quickReport(raw = true).config.copy(maxAttempts = 2).evidenceBudgetMillis)
        for (attempts in listOf(0, 3, Int.MAX_VALUE)) {
            try { config.copy(maxAttempts = attempts); fail("Invalid retry limit accepted") }
            catch (_: IllegalArgumentException) {}
        }
    }

    @Test fun `attempt records export full details using the same address redaction`() {
        val report = report()
        val redacted = ReportExporter.toJson(report)
        val full = ReportExporter.toJson(report, true)
        assertTrue(redacted.contains("\"schemaVersion\":2"))
        assertTrue(redacted.contains("\"maxAttemptsPerProbe\":2"))
        assertTrue(redacted.contains("\"retryDelayMillis\":500"))
        assertTrue(redacted.contains("\"retryTrigger\":\"TIMEOUT\""))
        assertTrue(redacted.contains("\"attemptNumber\":1")); assertTrue(redacted.contains("\"attemptNumber\":2"))
        assertTrue(redacted.contains("\"errorCode\":\"TIMEOUT\""))
        assertFalse(redacted.contains("192.0.2.221")); assertTrue(full.contains("192.0.2.221"))
        assertFalse(redacted.contains("example.com"))
        for (attempt in report.attempts) assertTrue(redacted.contains(attempt.attemptId))
    }

    @Test fun `all result types in attempt records redact their identifiers`() {
        val report = quickReport(raw = true)
        val attempts = listOf(
            ProbeAttempt("dns-id", ProbeKind.SYSTEM_DNS, 1, 0, 1000, 2, dns = report.dns),
            ProbeAttempt("https-id", ProbeKind.HTTPS, 1, 2, 1000, 4, https = HttpsObservation(
                Execution.COMPLETED, 200, 2, true, "https-id", "203.0.113.221")),
            ProbeAttempt("udp-id", ProbeKind.RAW_UDP, 1, 4, 1000, 5,
                rawDns = report.rawDns[0].copy(addresses = listOf("192.0.2.222"))))
        val output = report.copy(attempts = attempts)
        val redacted = ReportExporter.toJson(output)
        val full = ReportExporter.toJson(output, true)
        for (address in listOf("192.0.2.8", "203.0.113.221", "192.0.2.222")) {
            assertFalse(address, redacted.contains(address)); assertTrue(address, full.contains(address))
        }
    }

    @Test fun `retry policy difference and legacy missing retries prevent comparison`() {
        val one = quickReport()
        assertFalse(ReportComparison.compare(one, next(one).copy(config = one.config.copy(maxAttempts = 2))).comparable)
        val two = report()
        assertFalse(ReportComparison.compare(two.copy(attempts = emptyList()), next(two)).comparable)
        assertTrue(ReportComparison.compare(one, next(one)).comparable) // Compatible legacy records.
    }

    @Test fun `additional success does not turn preserved failure into an improvement`() {
        val before = report()
        val after = next(before)
        val comparison = ReportComparison.compare(before, after)
        assertFalse(comparison.comparable)
        assertTrue(comparison.summary.contains("尝试结果不一致"))
        assertFalse(comparison.summary.contains("未变"))
        assertEquals(Verdict.INSUFFICIENT, after.dnsPrivacy.verdict)
    }

    @Test fun `mixed baseline cannot imply improvement when the later first attempt succeeds`() {
        val before = report()
        val success = before.attempts.last().dns!!
        val after = next(before).copy(dns = success, attempts = listOf(before.attempts.first().copy(
            dns = success, retryTrigger = null, retryScheduled = false, retryDelayMillis = 0)))
        assertTrue(DiagnosticAttemptEvidence.mixed(before))
        assertFalse(DiagnosticAttemptEvidence.mixed(after))
        val comparison = ReportComparison.compare(before, after)
        assertFalse(comparison.comparable)
        assertTrue(comparison.summary.contains("尝试结果不一致"))
        assertFalse(comparison.summary.contains("改善"))
        val json = ReportComparison.toJson(before, after)
        assertTrue(json.contains("\"comparable\":false"))
        assertTrue(json.contains("\"attemptNumber\":2"))
        assertTrue(json.contains("\"errorCode\":\"TIMEOUT\""))
        assertFalse(json.contains("可用性观察改善"))
        assertFalse(json.contains("192.0.2.221"))
    }

    @Test fun `mixed later observations cannot imply regression or unchanged availability`() {
        val mixed = report()
        for (first in listOf(failed, mixed.attempts.last().dns!!)) {
            val before = mixed.copy(dns = first, attempts = listOf(mixed.attempts.first().copy(
                dns = first, retryTrigger = null, retryScheduled = false, retryDelayMillis = 0)))
            assertFalse(DiagnosticAttemptEvidence.mixed(before))
            val comparison = ReportComparison.compare(before, next(mixed))
            assertFalse(comparison.comparable)
            assertTrue(comparison.summary.contains("尝试结果不一致"))
            assertFalse(comparison.summary.contains("退化"))
            assertFalse(comparison.summary.contains("未变"))
        }
    }

    @Test fun `consistent completed retries remain comparable while retaining all attempts`() {
        val before = report().let { mixed -> mixed.copy(attempts = listOf(mixed.attempts.first(),
            mixed.attempts.last().copy(dns = failed))) }
        assertFalse(DiagnosticAttemptEvidence.mixed(before))
        val comparison = ReportComparison.compare(before, next(before))
        assertTrue(comparison.comparable)
        assertTrue(comparison.summary.contains("未变"))
        assertTrue(comparison.details.any { it.contains("首个结果") })
    }

    @Test fun `cancellation during backoff is incomparable despite completed first failure`() {
        val before = report()
        for (stop in listOf(Failure.CANCELLED, Failure.TIMEOUT, Failure.NETWORK_CHANGED)) {
            val after = next(before).copy(attempts = before.attempts.take(1), stopReason = stop)
            val comparison = ReportComparison.compare(before, after)
            assertFalse(comparison.comparable); assertFalse(comparison.summary.contains("退化"))
            assertTrue(ReportExporter.toJson(after).contains("\"stopReason\":\"${stop.name}\""))
        }
    }

    @Test fun `duplicate unfinished reordered or falsely aggregated attempts cannot compare`() {
        val before = report()
        val invalid = listOf(
            before.copy(attempts = listOf(before.attempts[0], before.attempts[1].copy(attemptId = before.attempts[0].attemptId))),
            before.copy(attempts = before.attempts.reversed()),
            before.copy(attempts = listOf(before.attempts[0], before.attempts[1].copy(finishedAfterMillis = null))),
            before.copy(dns = before.attempts[1].dns!!),
            before.copy(attempts = before.attempts + before.attempts[1].copy(attemptId = "third", attemptNumber = 3)))
        for (after in invalid) assertFalse(ReportComparison.compare(before, next(after)).comparable)
    }
}
