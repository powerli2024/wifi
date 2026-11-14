package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class CoreTest {
    private val demo get() = DemoFixture.report()
    private val nonce = "00000000-0000-4000-8000-000000000001"
    private fun echo(version: String = "1", id: String = "\"$nonce\"", ip: String = "\"203.0.113.7\"") =
        "{\"schemaVersion\":$version,\"requestId\":$id,\"observedSourceIp\":$ip}"
    private fun rejected(block: () -> Unit) { try { block(); fail("Expected rejection") } catch (_: IllegalArgumentException) {} }

    @Test fun `numeric ipv4 strict parsing rejects ambiguous input`() {
        assertEquals("192.0.2.1", NumericIp.canonical("192.0.2.1"))
        for (v in listOf("127.1", "010.0.0.1", "999.0.0.1", "1.2.3.4 ", "1.2.3.-1", "example.com", "0x7f.0.0.1", "")) assertNull(v, NumericIp.canonical(v))
    }
    @Test fun `ipv6 canonicalizes equivalent values and mapped ipv4`() {
        assertEquals(NumericIp.canonical("2001:db8::1"), NumericIp.canonical("2001:0DB8:0:0:0:0:0:0001"))
        assertEquals("192.0.2.1", NumericIp.canonical("::ffff:192.0.2.1"))
        assertEquals("0:0:0:0:0:0:0:1", NumericIp.canonical("::1"))
        for (v in listOf("fe80::1%wlan0", "[::1]", "1::2::3", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "1:2:3:4:5:6:7:8:9", ":::1", "::ffff:192.00.2.1")) assertNull(v, NumericIp.canonical(v))
    }
    @Test fun `dns host validates without regex crashes or implicit network`() {
        assertTrue(isDnsHost("example.com")); assertTrue(isDnsHost("a-b.example.test."))
        for (v in listOf("", "https://example.com", "user@example.com", "example.com/path", "a..b", "-a.com", "a-.com", "a_b.com", "192.0.2.1", "bad host", "例子.com")) assertFalse(v, isDnsHost(v))
    }
    @Test fun `endpoint strips default port and allows explicit origin only`() {
        assertEquals("https://example.com", Endpoint.parse("https://EXAMPLE.com:443/").origin)
        assertEquals("https://[0:0:0:0:0:0:0:1]:8443", Endpoint.parse("https://[::1]:8443").origin)
        assertEquals("https://example.com/v1/echo?requestId=$nonce", Endpoint.parse("https://example.com").requestUrl(nonce))
    }
    @Test fun `endpoint refuses credentials secrets paths and non https`() {
        for (v in listOf("http://example.com", "https://u:p@example.com", "https://example.com?token=secret", "https://example.com/#secret", "https://example.com/token", "https://example.com:0", "https://example.com:65536", "https://[fe80::1%25wlan0]", "https://example.com\n", " https://example.com", "https://example.com/%2f", "https://0177.0.0.1", "https://127.1")) rejected { Endpoint.parse(v) }
    }
    @Test fun `expected ips enforce numeric bounded unambiguous list`() {
        assertEquals(setOf("192.0.2.1", "2001:db8:0:0:0:0:0:1"), parseExpectedIps("192.0.2.1, 2001:db8::1"))
        assertTrue(parseExpectedIps(" ").isEmpty())
        rejected { parseExpectedIps("example.com") }; rejected { parseExpectedIps("192.0.2.1,") }
        rejected { parseExpectedIps(List(33) { "192.0.2.1" }.joinToString(",")) }
    }
    @Test fun `strict echo accepts exact contract and field ordering`() {
        assertEquals("203.0.113.7", EchoParser.parse(echo(), nonce).sourceIp)
        assertEquals(nonce, EchoParser.parse(" { \"observedSourceIp\":\"203.0.113.7\", \"requestId\":\"$nonce\", \"schemaVersion\":1 }\n", nonce).requestId)
    }
    @Test fun `strict echo refuses version coercion`() {
        for (v in listOf("\"1\"", "1.0", "1e0", "01", "2", "null", "true")) rejected { EchoParser.parse(echo(version = v), nonce) }
    }
    @Test fun `strict echo refuses missing mismatched wrong type and extra fields`() {
        for (text in listOf("{}", echo(id = "\"other\""), echo(ip = "null"), echo(ip = "5"), echo(ip = "[]"), echo(ip = "\"example.com\""), echo().dropLast(1) + ",\"extra\":true}", "[]", "<html>login</html>", "")) rejected { EchoParser.parse(text, nonce) }
    }
    @Test fun `strict echo rejects duplicates escaped duplicates malformed and trailing content`() {
        for (text in listOf(echo().dropLast(1) + ",\"observedSourceIp\":\"192.0.2.1\"}", echo().dropLast(1) + ",\"\\u0073chemaVersion\":1}", echo() + "x", echo().replace(",\"requestId\"", ",,\"requestId\""), echo().replace("203.0.113.7", "203.0.113.7\n"), " ".repeat(4097))) rejected { EchoParser.parse(text, nonce) }
    }
    @Test fun `matching echo is scoped match not a global safety score`() {
        assertEquals(Verdict.MATCH, demo.egress.verdict)
        assertTrue(demo.egress.reason.contains("不证明全机"))
        assertEquals(Verdict.INSUFFICIENT, demo.dnsPrivacy.verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.ipv6.verdict)
    }
    @Test fun `vpn presence never overrides mismatching echo`() {
        assertEquals(Verdict.VIOLATE, demo.copy(https = demo.https.copy(serverReportedSourceIp = "192.0.2.99")).egress.verdict)
    }
    @Test fun `vpn absence does not negate narrowly matching source address`() {
        val noVpn = demo.networkBefore.copy(vpnCapability = false, transports = listOf("WIFI"))
        assertEquals(Verdict.MATCH, demo.copy(networkBefore = noVpn, networkAfter = noVpn).egress.verdict)
    }
    @Test fun `empty expectation or untrusted endpoint remains insufficient`() {
        assertEquals(Verdict.INSUFFICIENT, demo.copy(config = demo.config.copy(policy = demo.config.policy.copy(expectedSourceIps = emptySet()))).egress.verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.copy(config = demo.config.copy(policy = demo.config.policy.copy(endpointTrustedByUser = false))).egress.verdict)
    }
    @Test fun `all error categories and cancellations remain insufficient`() {
        for (failure in Failure.entries) assertEquals(failure.name, Verdict.INSUFFICIENT,
            demo.copy(https = demo.https.copy(execution = Execution.ERROR, failure = failure)).egress.verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.copy(https = demo.https.copy(execution = Execution.CANCELLED)).egress.verdict)
    }
    @Test fun `missing tls and unsuccessful http cannot produce pass`() {
        assertEquals(Verdict.INSUFFICIENT, demo.copy(https = demo.https.copy(tlsValidated = false)).egress.verdict)
        for (code in listOf(201, 204, 206, 301, 302, 401, 429, 500)) assertEquals(Verdict.INSUFFICIENT, demo.copy(https = demo.https.copy(statusCode = code)).egress.verdict)
    }
    @Test fun `wrong nonce invalid ip network change missing snapshot cannot produce pass`() {
        assertEquals(Verdict.INSUFFICIENT, demo.copy(https = demo.https.copy(echoedRequestId = "old")).egress.verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.copy(https = demo.https.copy(serverReportedSourceIp = "host.test")).egress.verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.copy(networkChanged = true).egress.verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.copy(networkAfter = demo.networkAfter.copy(observationAvailable = false)).egress.verdict)
    }
    @Test fun `inconsistent network snapshot and missing endpoint cannot pass`() {
        assertEquals(Verdict.INSUFFICIENT, demo.copy(networkBefore = demo.networkBefore.copy(networkId = null)).egress.verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.copy(networkAfter = demo.networkAfter.copy(networkId = "different")).egress.verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.copy(config = demo.config.copy(endpoint = null)).egress.verdict)
    }
    @Test fun `same network id with changed DNS capabilities or links cannot produce a verdict`() {
        val changedSnapshots = listOf(
            demo.networkAfter.copy(configuredDnsServers = listOf("192.0.2.54")),
            demo.networkAfter.copy(localAddresses = listOf("192.0.2.11")),
            demo.networkAfter.copy(privateDnsActive = !(demo.networkAfter.privateDnsActive ?: false)),
            demo.networkAfter.copy(privateDnsServerName = "changed.example.test"),
            demo.networkAfter.copy(vpnCapability = !(demo.networkAfter.vpnCapability ?: false)),
            demo.networkAfter.copy(transports = listOf("CELLULAR"))
        )
        for (snapshot in changedSnapshots) for (actual in listOf("203.0.113.7", "192.0.2.99")) {
            val report = demo.copy(networkAfter = snapshot, https = demo.https.copy(serverReportedSourceIp = actual))
            assertEquals(demo.networkBefore.networkId, snapshot.networkId)
            assertEquals(Verdict.INSUFFICIENT, report.egress.verdict)
        }
    }
    @Test fun `disabled or not started probes remain not run`() {
        assertEquals(Verdict.NOT_RUN, demo.copy(https = HttpsObservation()).egress.verdict)
        assertEquals(Verdict.NOT_RUN, demo.copy(config = demo.config.copy(policy = demo.config.policy.copy(runHttps = false))).egress.verdict)
        assertEquals(Verdict.NOT_RUN, Evaluator.dnsPrivacy(demo.config.policy, DnsObservation()).verdict)
    }
    @Test fun `only explicit ipv6 exclusion produces not applicable`() {
        assertEquals(Verdict.NOT_APPLICABLE, Evaluator.ipv6(demo.config.policy.copy(ipv6InScope = false)).verdict)
        assertEquals(Verdict.INSUFFICIENT, demo.copy(dns = demo.dns.copy(addresses = emptyList())).ipv6.verdict)
    }
    @Test fun `ip equivalence compares canonical addresses`() {
        val run = demo.copy(config = demo.config.copy(policy = demo.config.policy.copy(expectedSourceIps = setOf("2001:db8:0:0:0:0:0:1"))),
            https = demo.https.copy(serverReportedSourceIp = "2001:0DB8::1"))
        assertEquals(Verdict.MATCH, run.egress.verdict)
    }
    @Test fun `minimal export redacts hosts and all addresses`() {
        val json = ReportExporter.toJson(demo)
        for (privateValue in listOf("203.0.113.7", "192.0.2.53", "192.0.2.10", "echo.example.test", "dns.example.test", "DEMO-NETWORK")) assertFalse(privateValue, json.contains(privateValue))
        assertTrue(json.contains("SYNTHETIC_FIXTURE")); assertTrue(json.contains("[REDACTED]")); assertTrue(json.contains("THIS_APP_REQUESTS_ONLY"))
    }
    @Test fun `full export is explicit and structured without raw payload fields`() {
        val json = ReportExporter.toJson(demo, true)
        assertTrue(json.contains("203.0.113.7")); assertTrue(json.contains("\"networkIdentifiersIncluded\":true"))
        for (forbidden in listOf("rawBody", "exceptionMessage", "requestUrl", "Authorization", "Cookie")) assertFalse(forbidden, json.contains(forbidden))
    }
    @Test fun `json encoding escapes control characters and quotes`() {
        assertEquals("\"a\\\"b\\\\c\\n\\u0000\"", Json.write("a\"b\\c\n\u0000"))
    }
    @Test fun `run timeout must be bounded`() { rejected { demo.config.copy(timeoutMillis = 999) }; rejected { demo.config.copy(timeoutMillis = 15001) } }
}
