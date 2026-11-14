package dev.proxyaudit.android

import dev.proxyaudit.core.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class DeepEvidenceEnvelopeTest {
    @Test fun planned_or_placeholder_operations_are_not_listed_as_executed_sources() {
        val normal = DeepComparisonFixtures.report()
        val unstarted = normal.copy(
            selfTest = normal.selfTest!!.copy(checks = normal.selfTest.checks.map { it.copy(status = SelfTestStatus.NOT_STARTED) }),
            website = normal.website!!.copy(execution = Execution.ERROR, failure = WebsiteFailure.BUSY, attempts = emptyList()),
            dns = normal.dns.map { it.copy(observation = RawDnsObservation(it.observation.transport)) })
        val json = JSONObject(unstarted.toJson())
        assertEquals(listOf("ANDROID_FRAMEWORK"), sources(json))
        assertTrue(json.getJSONObject("frozenPlan").getBoolean("websitePlanned"))
        assertTrue(json.getJSONObject("frozenPlan").getBoolean("rawDnsPlanned"))
        assertEquals("BUSY", json.getJSONObject("website").getString("failure"))
        val none = unstarted.copy(before = null, after = null)
        assertEquals(emptyList<String>(), sources(JSONObject(none.toJson())))
    }

    @Test fun errors_and_cancellation_after_operation_start_remain_evidence_sources() {
        val normal = DeepComparisonFixtures.report(failure = WebsiteFailure.TLS_CERTIFICATE)
        val failed = normal.copy(selfTest = normal.selfTest!!.copy(checks = normal.selfTest.checks.map { it.copy(status = SelfTestStatus.FAIL) }),
            dns = normal.dns.map { it.copy(observation = it.observation.copy(execution = Execution.ERROR,
                failure = Failure.TIMEOUT, addresses = emptyList())) })
        assertEquals(listOf("ANDROID_FRAMEWORK", "LOCAL_LOOPBACK", "WEBSITE_PROBE", "RAW_DNS_PROBE"), sources(JSONObject(failed.toJson())))
        val cancelled = failed.copy(stopReason = "USER_CANCELLED", website = failed.website!!.copy(execution = Execution.CANCELLED,
            failure = WebsiteFailure.CANCELLED, attempts = failed.website.attempts.map { it.copy(execution = Execution.CANCELLED, failure = WebsiteFailure.CANCELLED) }))
        val envelope = JSONObject(cancelled.toJson()).getJSONObject("evidenceEnvelope")
        assertTrue(envelope.getBoolean("stopped"))
        assertEquals("PARTIAL_OR_INTERRUPTED", envelope.getString("completeness"))
        assertTrue(sources(JSONObject(cancelled.toJson())).contains("WEBSITE_PROBE"))
    }

    @Test fun synthetic_origin_and_legacy_schema_are_preserved_and_false_stopped_is_not_success() {
        val failed = DeepComparisonFixtures.report(failure = WebsiteFailure.TLS_CERTIFICATE).copy(origin = "SYNTHETIC_FIXTURE")
        for (full in listOf(false, true)) {
            val json = JSONObject(failed.toJson(full)); val envelope = json.getJSONObject("evidenceEnvelope")
            assertEquals(1, json.getInt("schemaVersion")); assertEquals(1, envelope.getInt("version"))
            assertEquals("SYNTHETIC_FIXTURE", envelope.getString("origin"))
            assertEquals(failed.appVersion, envelope.getString("appVersion"))
            assertFalse(envelope.getBoolean("stopped"))
            assertEquals("SEE_SOURCE_EXECUTION_STATUS", envelope.getString("completeness"))
            assertEquals("NOT_ESTABLISHED", envelope.getString("crossSourceCorrelation"))
            assertFalse(envelope.has("verdict"))
            assertEquals("TLS_CERTIFICATE", json.getJSONObject("website").getString("failure"))
            assertEquals("ERROR", json.getJSONObject("website").getString("execution"))
            for (key in listOf("networkBefore", "networkAfter", "localSelfTest", "website", "rawDns", "findings")) assertTrue(key, json.has(key))
            assertFalse(envelope.toString().contains("secret.example.test"))
        }
    }

    private fun sources(json: JSONObject): List<String> {
        val array = json.getJSONObject("evidenceEnvelope").getJSONArray("sources")
        return (0 until array.length()).map(array::getString)
    }
}
