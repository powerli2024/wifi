package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

/** Provenance is metadata; a completed envelope never supplies a network or privacy verdict. */
class EvidenceEnvelopeTest {
    @Test fun synthetic_demo_origin_is_preserved_in_envelope_and_legacy_fields() {
        val demo = DemoFixture.report()
        assertEquals(EvidenceOrigin.SYNTHETIC_FIXTURE, demo.evidenceOrigin)
        val json = ReportExporter.toJson(demo.copy(appVersion = "test-build-identity"))
        val envelope = envelope(json)
        assertTrue(envelope.contains("\"origin\":\"SYNTHETIC_FIXTURE\""))
        assertFalse(envelope.contains("ANDROID_RUNTIME"))
        assertTrue(json.contains("\"evidenceOrigin\":\"SYNTHETIC_FIXTURE\""))
        assertTrue(envelope.contains("\"appVersion\":\"test-build-identity\""))
        assertTrue(envelope.contains("\"crossSourceCorrelation\":\"NOT_ESTABLISHED\""))
    }

    @Test fun enabled_but_never_started_probes_do_not_appear_as_execution_sources() {
        val report = report().copy(stopReason = Failure.CANCELLED,
            rawDns = listOf(RawDnsObservation(DnsTransport.UDP), RawDnsObservation(DnsTransport.TCP)))
        val json = ReportExporter.toJson(report)
        assertEquals(listOf("NETWORK_SNAPSHOT"), sources(json))
        assertTrue(envelope(json).contains("\"stopped\":true"))
        assertTrue(envelope(json).contains("\"completeness\":\"PARTIAL_OR_INTERRUPTED\""))
        assertTrue(json.contains("\"httpsEnabled\":true"))
        assertTrue(json.contains("\"dnsEnabled\":true"))
        assertTrue(json.contains("\"execution\":\"NOT_STARTED\""))
    }

    @Test fun failure_after_start_is_a_source_even_without_successful_answer() {
        val dns = report().copy(dns = DnsObservation(Execution.ERROR, failure = Failure.DNS_FAILURE,
            diagnosticStage = SystemDnsStage.ERROR_CALLBACK))
        assertEquals(listOf("NETWORK_SNAPSHOT", "SYSTEM_DNS"), sources(ReportExporter.toJson(dns)))
        val https = report().copy(https = HttpsObservation(Execution.ERROR, failure = Failure.TLS_FAILURE))
        assertEquals(listOf("NETWORK_SNAPSHOT", "HTTPS_ECHO"), sources(ReportExporter.toJson(https)))
        val raw = report().copy(rawDns = listOf(
            RawDnsObservation(DnsTransport.UDP, Execution.ERROR, failure = Failure.TIMEOUT),
            RawDnsObservation(DnsTransport.TCP)))
        assertEquals(listOf("NETWORK_SNAPSHOT", "RAW_DNS"), sources(ReportExporter.toJson(raw)))
    }

    @Test fun cancelled_active_probe_is_kept_while_unstarted_following_probes_are_excluded() {
        val report = report().copy(dns = DnsObservation(Execution.CANCELLED, durationMillis = 30,
            failure = Failure.CANCELLED), stopReason = Failure.CANCELLED,
            rawDns = listOf(RawDnsObservation(DnsTransport.UDP), RawDnsObservation(DnsTransport.TCP)))
        val json = ReportExporter.toJson(report)
        assertEquals(listOf("NETWORK_SNAPSHOT", "SYSTEM_DNS"), sources(json))
        assertTrue(envelope(json).contains("\"stopped\":true"))
        assertTrue(json.contains("\"errorCode\":\"CANCELLED\""))
        assertTrue(json.contains("\"execution\":\"NOT_STARTED\""))
    }

    @Test fun stopped_false_does_not_mean_success_complete_probes_or_safety_pass() {
        val failed = report().copy(https = HttpsObservation(Execution.ERROR, failure = Failure.TIMEOUT))
        val json = ReportExporter.toJson(failed)
        val envelope = envelope(json)
        assertTrue(envelope.contains("\"stopped\":false"))
        assertTrue(envelope.contains("\"completeness\":\"SEE_SOURCE_EXECUTION_STATUS\""))
        assertTrue(envelope.contains("\"crossSourceCorrelation\":\"NOT_ESTABLISHED\""))
        assertFalse(envelope.contains("MATCH"))
        assertFalse(envelope.contains("PASS"))
        assertFalse(envelope.contains("SUCCESS"))
        assertTrue(json.contains("\"execution\":\"ERROR\""))
        assertTrue(json.contains("\"errorCode\":\"TIMEOUT\""))
        assertTrue(json.contains("\"verdict\":\"INSUFFICIENT\""))
    }

    @Test fun additive_envelope_keeps_legacy_schema_and_report_fields_in_both_export_modes() {
        val input = report().copy(appVersion = "runtime-identity", dns = DnsObservation(Execution.COMPLETED,
            listOf("198.51.100.11"), 3), https = HttpsObservation(Execution.ERROR, failure = Failure.TLS_FAILURE))
        for (full in listOf(false, true)) {
            val json = ReportExporter.toJson(input, full)
            assertTrue(json.contains("\"schemaVersion\":2"))
            assertTrue(envelope(json).contains("\"version\":1"))
            assertTrue(envelope(json).contains("\"appVersion\":\"runtime-identity\""))
            for (field in listOf("runId", "scope", "startedAtUtc", "finishedAtUtc", "durationMillis", "androidApi",
                "appVersion", "networkBefore", "networkAfter", "policy", "dns", "https", "rawDns", "attempts",
                "stopReason", "ipv6Assessment", "limitations")) assertTrue(field, json.contains("\"$field\":"))
            assertEquals(listOf("NETWORK_SNAPSHOT", "SYSTEM_DNS", "HTTPS_ECHO"), sources(json))
            assertEquals(full, json.contains("198.51.100.11"))
            assertTrue(json.endsWith("\n"))
        }
    }

    @Test fun unavailable_snapshot_remains_a_framework_attempt_without_claiming_network_observed() {
        val unavailable = NetworkSnapshot(null, emptyList(), null, null, null, emptyList(), emptyList(), null, null, false)
        val json = ReportExporter.toJson(report().copy(networkBefore = unavailable, networkAfter = unavailable))
        assertEquals(listOf("NETWORK_SNAPSHOT"), sources(json))
        assertTrue(json.contains("\"observationAvailable\":false"))
        assertTrue(envelope(json).contains("\"completeness\":\"SEE_SOURCE_EXECUTION_STATUS\""))
    }

    @Test fun envelope_deduplicates_source_categories_and_preserves_explicit_origin_without_auto_upgrade() {
        val value = EvidenceEnvelope.toMap("NETWORK_DEEP_DIAGNOSTICS", "test-build", "run", "SYNTHETIC_FIXTURE",
            "THIS_APP_AND_ANDROID_VISIBLE_NETWORKS", listOf("LOCAL_LOOPBACK", "LOCAL_LOOPBACK"), false)
        assertEquals("SYNTHETIC_FIXTURE", value["origin"])
        assertEquals(listOf("LOCAL_LOOPBACK"), value["sources"])
        assertEquals("SEE_SOURCE_EXECUTION_STATUS", value["completeness"])
        assertEquals("NOT_ESTABLISHED", value["crossSourceCorrelation"])
        assertFalse(value.containsKey("verdict"))
        val empty = EvidenceEnvelope.toMap("NETWORK_DEEP_DIAGNOSTICS", "test-build", "run", "ANDROID_RUNTIME",
            "THIS_APP_AND_ANDROID_VISIBLE_NETWORKS", emptyList(), true)
        assertEquals(emptyList<String>(), empty["sources"])
        assertEquals("PARTIAL_OR_INTERRUPTED", empty["completeness"])
    }

    private fun report(): RunReport {
        val network = NetworkSnapshot("private-network", listOf("WIFI"), false, true, true,
            listOf("192.0.2.7"), listOf("192.0.2.53"), false, null, true)
        return RunReport("00000000-0000-4000-8000-000000000001", "2026-10-23T00:00:00Z", "2026-10-23T00:00:01Z",
            1000, 35, "test-build", RunConfig(Endpoint.parse("https://echo.example.test"), "dns.example.test",
                ProbePolicy(true, true, setOf("203.0.113.7"), false, true), rawDns = RawDnsConfig("192.0.2.53", host = "dns.example.test")),
            network, network, false, DnsObservation(), HttpsObservation())
    }

    // The envelope consists only of scalar values and a string array; isolate it from legacy evidence.
    private fun envelope(json: String): String = Regex("\"evidenceEnvelope\":(\\{[^}]*}),\"schemaVersion\"")
        .find(json)?.groupValues?.get(1) ?: error("Missing additive evidence envelope")
    private fun sources(json: String): List<String> {
        val items = Regex("\"sources\":\\[([^]]*)]").find(envelope(json))?.groupValues?.get(1)
            ?: error("Missing sources")
        return Regex("\"([^\"]+)\"").findAll(items).map { it.groupValues[1] }.toList()
    }
}
