package dev.proxyaudit.qa

import dev.proxyaudit.core.*
import java.util.Random
import org.junit.Assert.*
import org.junit.Test

/** Independent QA cases, isolated from the author's CoreTest and production source. */
class IndependentAdversarialTest {
    private val base get() = DemoFixture.report()
    private val nonce = "00000000-0000-4000-8000-000000000001"
    private fun echo(ip: String = "203.0.113.7", id: String = nonce) =
        "{\"schemaVersion\":1,\"requestId\":\"$id\",\"observedSourceIp\":\"$ip\"}"
    private fun reject(label: String, body: () -> Unit) {
        try { body(); fail("Expected rejection: $label") }
        catch (_: IllegalArgumentException) {}
    }

    @Test fun `five verdicts stay distinct and narrowly scoped`() {
        assertEquals(5, Verdict.entries.size)
        assertEquals(setOf(Verdict.MATCH, Verdict.VIOLATE, Verdict.INSUFFICIENT, Verdict.NOT_RUN, Verdict.NOT_APPLICABLE), setOf(
            base.egress.verdict,
            base.copy(https = base.https.copy(serverReportedSourceIp = "192.0.2.1")).egress.verdict,
            base.dnsPrivacy.verdict,
            base.copy(https = HttpsObservation()).egress.verdict,
            Evaluator.ipv6(base.config.policy.copy(ipv6InScope = false)).verdict))
        for (r in listOf(base, base.copy(https = base.https.copy(serverReportedSourceIp = "192.0.2.1")))) {
            assertTrue(r.egress.reason.contains("本次") || r.egress.reason.contains("此项"))
            assertTrue(r.egress.reason.contains("全机"))
            assertEquals("THIS_APP_REQUESTS_ONLY", RunReport.SCOPE)
        }
    }

    @Test fun `exhaustive execution failure tls status matrix never produces false match`() {
        var combinations = 0
        for (execution in Execution.entries) for (failure in listOf<Failure?>(null) + Failure.entries)
            for (tls in listOf(false, true)) for (status in listOf<Int?>(null, 0, 199, 200, 201, 204, 301, 307, 308, 400, 403, 429, 500)) {
                val report = base.copy(https = base.https.copy(execution = execution, failure = failure, tlsValidated = tls, statusCode = status))
                val expected = when {
                    execution == Execution.NOT_STARTED -> Verdict.NOT_RUN
                    execution == Execution.COMPLETED && failure == null && tls && status == 200 -> Verdict.MATCH
                    else -> Verdict.INSUFFICIENT
                }
                assertEquals("$execution/$failure/$tls/$status", expected, report.egress.verdict)
                combinations++
            }
        assertEquals(4 * (Failure.entries.size + 1) * 2 * 13, combinations)
    }

    @Test fun `missing network identifiers unavailable snapshots and any change prevent match`() {
        for (beforeId in listOf<String?>(null, "a", "b")) for (afterId in listOf<String?>(null, "a", "b"))
            for (beforeAvailable in listOf(false, true)) for (afterAvailable in listOf(false, true)) for (changed in listOf(false, true)) {
                val report = base.copy(networkBefore = base.networkBefore.copy(networkId = beforeId, observationAvailable = beforeAvailable),
                    networkAfter = base.networkAfter.copy(networkId = afterId, observationAvailable = afterAvailable), networkChanged = changed)
                val matching = beforeId != null && beforeId == afterId && beforeAvailable && afterAvailable && !changed
                assertEquals("$beforeId/$afterId/$beforeAvailable/$afterAvailable/$changed", if (matching) Verdict.MATCH else Verdict.INSUFFICIENT, report.egress.verdict)
            }
    }

    @Test fun `dns and ipv6 never become privacy pass or failure from incidental results`() {
        for (execution in Execution.entries) for (failure in listOf<Failure?>(null) + Failure.entries)
            for (addresses in listOf(emptyList(), listOf("192.0.2.1"), listOf("2001:db8::1"), listOf("192.0.2.1", "2001:db8::1"))) {
                val result = DnsObservation(execution, addresses, 1, failure)
                assertEquals(if (execution == Execution.NOT_STARTED) Verdict.NOT_RUN else Verdict.INSUFFICIENT,
                    Evaluator.dnsPrivacy(base.config.policy, result).verdict)
                assertEquals(Verdict.NOT_RUN, Evaluator.dnsPrivacy(base.config.policy.copy(runDns = false), result).verdict)
                assertEquals(Verdict.INSUFFICIENT, base.copy(dns = result).ipv6.verdict)
            }
    }

    @Test fun `ip canonicalization covers compression boundaries and embedded ipv4`() {
        val valid = mapOf("::" to "0:0:0:0:0:0:0:0", "::ffff:0:0" to "0.0.0.0", "::ffff:ffff:ffff" to "255.255.255.255",
            "0:0:0:0:0:ffff:c000:0201" to "192.0.2.1", "1:2:3:4:5:6:192.0.2.1" to "1:2:3:4:5:6:c000:201",
            "2001:DB8::192.0.2.1" to "2001:db8:0:0:0:0:c000:201", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" to "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        for ((input, expected) in valid) {
            assertEquals(input, expected, NumericIp.canonical(input))
            assertEquals(input, expected, NumericIp.canonical(expected))
        }
        for (input in listOf("1:2:3:4:5:6:7::8", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "1:2:3:4:5:192.0.2.1",
            "1:2:3:4:5:6::192.0.2.1", "::ffff:256.1.1.1", "::ffff:1.2.3", "1.2.3.4::", "\u0000203.0.113.7", "２０３.0.113.7", "::g", "::00000", "::+1", "::1%1", ":", ":::", "::::")) {
            assertNull(input, NumericIp.canonical(input))
        }
    }

    @Test fun `random numeric parser inputs terminate and canonical output is idempotent`() {
        val random = Random(137)
        val alphabet = "0123456789abcdefABCDEF:.%[]-+ \n\u0000"
        repeat(10_000) {
            val input = buildString { repeat(random.nextInt(90)) { append(alphabet[random.nextInt(alphabet.length)]) } }
            NumericIp.canonical(input)?.let { canonical -> assertEquals("input=$input", canonical, NumericIp.canonical(canonical)) }
        }
    }

    @Test fun `canonical duplicate expected addresses collapse without false disagreement`() {
        assertEquals(setOf("192.0.2.1"), parseExpectedIps("192.0.2.1,::ffff:192.0.2.1,::ffff:c000:201"))
        assertEquals(setOf("2001:db8:0:0:0:0:0:1"), parseExpectedIps("2001:db8::1,2001:DB8:0:0:0:0:0:0001"))
        val report = base.copy(config = base.config.copy(policy = base.config.policy.copy(expectedSourceIps = parseExpectedIps("192.0.2.1,::ffff:192.0.2.1"))),
            https = base.https.copy(serverReportedSourceIp = "::ffff:c000:201"))
        assertEquals(Verdict.MATCH, report.egress.verdict)
    }

    @Test fun `endpoint does not tolerate URL authority ambiguity`() {
        for (input in listOf("https://example.com\\@evil.test", "https://example.com\\evil", "https://example.com/%2e%2e", "https://example.com//", "https://example.com/.",
            "https://example.com?", "https://example.com#", "https://user@example.com", "https://example.com:00000", "https://example.com:-1",
            "https://example.com:99999999999", "https://[::1%25eth0]", "https://example.com\r\nHost:evil", "https://a%2eb.test", "https://例子.test", "https:example.com", "//example.com")) {
            reject(input) { Endpoint.parse(input) }
        }
    }

    @Test fun `request URL nonce format matches the declared UUID wire contract`() {
        val endpoint = Endpoint.parse("https://example.test")
        assertTrue(endpoint.requestUrl(nonce).endsWith("requestId=$nonce"))
        for (invalid in listOf("-".repeat(36), "a".repeat(36), "000000000000400080000000000000000001", "00000000-0000-4000-8000-00000000000A", "$nonce&token=bad", "", nonce + "\n")) {
            reject("invalid UUID shape") { endpoint.requestUrl(invalid) }
        }
    }

    @Test fun `host and expected list length boundaries are enforced`() {
        assertTrue(isDnsHost("a".repeat(63) + ".test"))
        assertFalse(isDnsHost("a".repeat(64) + ".test"))
        val exactly253 = List(3) { "a".repeat(63) }.joinToString(".") + "." + "b".repeat(61)
        assertEquals(253, exactly253.length)
        assertTrue(isDnsHost(exactly253)); assertFalse(isDnsHost(exactly253 + "b"))
        assertEquals(32, parseExpectedIps((0..31).joinToString(",") { "192.0.2.$it" }).size)
        reject("33 IPs") { parseExpectedIps((0..32).joinToString(",") { "192.0.2.$it" }) }
        for (input in listOf("192.0.2.1,,192.0.2.2", ",192.0.2.1", "192.0.2.1;192.0.2.2", "192.0.2.1\n192.0.2.2")) reject(input) { parseExpectedIps(input) }
    }

    @Test fun `echo nonce is exact and replay wrong case and whitespace are refused`() {
        for (id in listOf("", "00000000-0000-4000-8000-000000000002", " $nonce", "$nonce ", nonce.replace("4", "A"))) reject(id) { EchoParser.parse(echo(id = id), nonce) }
        assertEquals(nonce, EchoParser.parse(echo().replace("requestId", "reques\\u0074Id"), nonce).requestId)
        assertEquals(nonce, EchoParser.parse(echo().replace(nonce, nonce.replace("4", "\\u0034")), nonce).requestId)
    }

    @Test fun `strict echo rejects duplicate decoded keys arrays nesting illegal JSON and excessive size`() {
        val malformed = listOf(echo().dropLast(1) + ",\"requestId\":\"$nonce\"}", echo().dropLast(1) + ",\"reques\\u0074Id\":\"$nonce\"}",
            echo().replace("\"observedSourceIp\":\"203.0.113.7\"", "\"observedSourceIp\":{\"ip\":\"203.0.113.7\"}"),
            echo().replace("\"observedSourceIp\":\"203.0.113.7\"", "\"observedSourceIp\":[\"203.0.113.7\"]"),
            echo().replace(":1,", ":+1,"), echo().replace(":1,", ":1.,"), echo().replace(":1,", ":.1,"),
            echo().dropLast(1) + ",}", "\ufeff" + echo(), echo() + "{}", echo() + "\u0000", echo().replace("203.0.113.7", "203.0.113.\\q7"),
            echo().replace("203.0.113.7", "\\ud800"), echo().replace("203.0.113.7", "\\uZZZZ"), echo().replace("203.0.113.7", "a".repeat(513)), " ".repeat(4096) + echo())
        for (text in malformed) reject(text.take(140)) { EchoParser.parse(text, nonce) }
        assertEquals("203.0.113.7", EchoParser.parse(echo() + " ".repeat(4096 - echo().length), nonce).sourceIp)
        reject("4097 chars") { EchoParser.parse(echo() + " ".repeat(4097 - echo().length), nonce) }
    }

    @Test fun `random echo parser input is rejected without unchecked crashes`() {
        val random = Random(273)
        val alphabet = "{}[],:0123456789eE+-.\"\\uabcdefntr \t\r\n\u0000\ud800"
        repeat(5_000) {
            val text = buildString { repeat(random.nextInt(180)) { append(alphabet[random.nextInt(alphabet.length)]) } }
            reject("random text") { EchoParser.parse(text, nonce) }
        }
    }

    @Test fun `minimal export redacts every network identifier location while retaining limitations`() {
        val before = base.networkBefore.copy(networkId = "BEFORE-SECRET", localAddresses = listOf("LOCAL-SECRET-v4", "LOCAL-SECRET-v6"),
            configuredDnsServers = listOf("DNS-SERVER-SECRET"), privateDnsServerName = "PRIVATE-DNS-SECRET")
        val after = before.copy(networkId = "AFTER-SECRET", localAddresses = listOf("AFTER-LOCAL-SECRET"))
        val report = base.copy(networkBefore = before, networkAfter = after,
            config = base.config.copy(endpoint = Endpoint.parse("https://endpoint-secret.example:8443"), dnsHost = "dns-host-secret.example", policy = base.config.policy.copy(expectedSourceIps = setOf("192.0.2.240"))),
            dns = base.dns.copy(addresses = listOf("192.0.2.241", "2001:db8::241")), https = base.https.copy(serverReportedSourceIp = "192.0.2.242"))
        val identifiers = listOf("BEFORE-SECRET", "LOCAL-SECRET-v4", "LOCAL-SECRET-v6", "DNS-SERVER-SECRET", "PRIVATE-DNS-SECRET", "AFTER-SECRET", "AFTER-LOCAL-SECRET",
            "endpoint-secret.example", "dns-host-secret.example", "192.0.2.240", "192.0.2.241", "2001:db8::241", "192.0.2.242")
        val redacted = ReportExporter.toJson(report)
        val full = ReportExporter.toJson(report, true)
        for (value in identifiers) { assertFalse(value, redacted.contains(value)); assertTrue(value, full.contains(value)) }
        for (value in listOf("SYNTHETIC_FIXTURE", "THIS_APP_REQUESTS_ONLY", "UNKNOWN", "limitations", "INSUFFICIENT", "[REDACTED]")) assertTrue(value, redacted.contains(value))
        assertTrue(redacted.contains("\"networkIdentifiersIncluded\":false"))
    }

    @Test fun `untrusted missing policy and unavailable actual data fail closed`() {
        for (actual in listOf<String?>(null, "", "garbage", "203.0.113.07", "203.0.113.7 ", "203.0.113.7\n")) {
            assertEquals(actual, Verdict.INSUFFICIENT, base.copy(https = base.https.copy(serverReportedSourceIp = actual)).egress.verdict)
        }
        for (expected in listOf(emptySet(), setOf("garbage"), setOf("203.0.113.7", "garbage"))) {
            assertEquals(Verdict.INSUFFICIENT, base.copy(config = base.config.copy(policy = base.config.policy.copy(expectedSourceIps = expected))).egress.verdict)
        }
        assertEquals(Verdict.INSUFFICIENT, base.copy(config = base.config.copy(policy = base.config.policy.copy(endpointTrustedByUser = false))).egress.verdict)
        assertEquals(Verdict.INSUFFICIENT, base.copy(https = base.https.copy(echoedRequestId = null)).egress.verdict)
    }
}
