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
class DeepReportComparisonTest {
    @Test fun complete_failure_can_be_baseline_but_cancelled_missing_or_synthetic_cannot() {
        val failure = DeepComparisonFixtures.report(failure = WebsiteFailure.TLS_CERTIFICATE)
        assertTrue(DeepReportComparisons.baselineBlockers(failure).isEmpty())
        for (bad in listOf(
            failure.copy(stopReason = "USER_CANCELLED"), failure.copy(before = null),
            failure.copy(origin = "SYNTHETIC_FIXTURE"), failure.copy(selfTest = null),
            failure.copy(dns = failure.dns.dropLast(1)),
            failure.copy(before = failure.before!!.copy(issues = listOf("DEFAULT_NETWORK:CHANGED_DURING_COLLECTION"))),
            DeepComparisonFixtures.report(failure = WebsiteFailure.INTERNAL_ERROR),
            failure.copy(website = failure.website!!.copy(attempts = emptyList())),
            failure.copy(website = failure.website!!.copy(execution = Execution.CANCELLED))
        )) assertTrue(DeepReportComparisons.baselineBlockers(bad).isNotEmpty())
    }

    @Test fun exact_url_budgets_proxy_declaration_raw_target_and_version_are_required() {
        val first = DeepComparisonFixtures.report()
        val second = first.copy(id = "next")
        assertTrue(DeepReportComparisons.compare(first, second).comparable)
        val changedPath = WebsitePlan.parse("https://secret.example.test/other?token=private-query")
        val changedBudget = WebsitePlan.parse(first.plannedWebsite!!.url, maxAttempts = 1)
        for (different in listOf(second.copy(appVersion = "future"), second.copy(expectedProxy = "DISABLED"),
            second.copy(dnsServer = "192.0.2.54"),
            second.copy(plannedWebsite = changedPath, website = second.website!!.copy(plan = changedPath)),
            second.copy(plannedWebsite = changedBudget, website = second.website!!.copy(plan = changedBudget)))) {
            val comparison = DeepReportComparisons.compare(first, different)
            assertFalse(comparison.comparable); assertTrue(comparison.changes.isEmpty())
        }
    }

    @Test fun dns_configuration_change_is_descriptive_only_and_preserves_frozen_dns_target() {
        val first = DeepComparisonFixtures.report()
        val network = first.before!!.networks.single().copy(dnsServers = listOf("192.0.2.54"),
            privateDnsActive = false, privateDnsServerName = null)
        val inventory = first.before.copy(networks = listOf(network))
        val second = first.copy(id = "next", before = inventory, after = inventory)
        val comparison = DeepReportComparisons.compare(first, second)
        assertTrue(comparison.comparable)
        assertTrue(comparison.cautions.any { it.contains("配置改变") && it.contains("不能归因") })
        assertEquals(first.dnsServer, second.dnsServer)
        assertTrue(comparison.cautions.any { it.contains("不") && it.contains("安全通过") })
    }

    @Test fun network_vpn_proxy_route_binding_change_or_in_run_change_blocks_comparison() {
        val first = DeepComparisonFixtures.report(); val inventory = first.before!!
        val n = inventory.networks.single()
        val variants = listOf(
            inventory.copy(activeNetworkId = "different", networks = listOf(n.copy(networkId = "different"))),
            inventory.copy(networks = listOf(n.copy(transports = listOf("WIFI")))),
            inventory.copy(defaultProxy = InventoryProxy("other", 9090, false, null, emptyList())),
            inventory.copy(boundNetworkId = "other"),
            inventory.copy(networks = listOf(n.copy(mtu = 1280))),
            inventory.copy(networks = listOf(n.copy(routes = emptyList())))
        )
        for (different in variants) {
            assertFalse(DeepReportComparisons.compare(first, first.copy(id = "next", before = different, after = different)).comparable)
            assertFalse(DeepReportComparisons.compare(first, first.copy(id = "next", after = different)).comparable)
        }
    }

    @Test fun first_failure_is_kept_when_later_attempt_succeeds_and_durations_are_not_repair_verdicts() {
        val first = DeepComparisonFixtures.report(failure = WebsiteFailure.TIMEOUT)
        val failure = first.website!!.attempts.single()
        val success = DeepComparisonFixtures.attempt().copy(number = 2)
        val second = first.copy(id = "next", website = first.website.copy(attempts = listOf(failure, success)))
        val comparison = DeepReportComparisons.compare(first, second)
        assertTrue(comparison.comparable)
        assertTrue(comparison.changes.first().contains("TIMEOUT → ERROR / TIMEOUT"))
        assertTrue(comparison.changes.any { it.contains("#1 ERROR/TIMEOUT") && it.contains("#2 COMPLETED/HTTP200") })
        assertTrue(comparison.cautions.any { it.contains("首次尝试") })
        assertTrue(comparison.changes.any { it.contains("单次耗时变化不等于稳定改善") })
    }

    @Test fun comparison_redacts_identifiers_and_full_export_still_omits_path_and_query() {
        val first = DeepComparisonFixtures.report(); val second = first.copy(id = "next")
        val result = DeepReportComparisons.compare(first, second)
        val redacted = result.toJson(false); val full = result.toJson(true)
        for (secret in listOf("secret.example.test", "192.0.2.53", "iface-private", "proxy.private.test")) assertFalse(redacted.contains(secret))
        for (text in listOf(redacted, full)) for (secret in listOf("private-path", "private-query")) assertFalse(text.contains(secret))
        val json = JSONObject(full)
        assertEquals("NOT_ASSESSED", json.getString("safetyOrPrivacyVerdict"))
        assertEquals(1, json.getJSONObject("baseline").getJSONObject("website").getJSONArray("attempts").length())
        assertEquals(AppIdentity.version, json.getString("appVersion"))
    }
}

internal object DeepComparisonFixtures {
    fun attempt(failure: WebsiteFailure? = null) = WebsiteAttemptResult(1,
        if (failure == null) Execution.COMPLETED else Execution.ERROR,
        listOf(WebsiteStageResult(WebsiteStage.TLS,
            if (failure == null) WebsiteStageStatus.SUCCEEDED else WebsiteStageStatus.FAILED, "controlled observation", 10)),
        15, failure, if (failure == null) 200 else null, if (failure == null) "TLSv1.3" else null,
        null, null, emptyList(), listOf(WebsiteConnectionResult("HTTP", "IPv4", "127.0.0.1")),
        0, false, null)
    fun website(plan: WebsitePlan = DeepFixtures.plan(), failure: WebsiteFailure? = null): WebsiteReport {
        val attempt = attempt(failure)
        return DeepFixtures.website(plan).copy(execution = attempt.execution, stages = attempt.stages,
            attempts = listOf(attempt), failure = failure, statusCode = attempt.statusCode)
    }
    fun report(failure: WebsiteFailure? = null): DeepReport {
        val inventory = DeepFixtures.inventory()
        return DeepReport("first", DeepFixtures.TIME, "ENABLED", inventory, inventory, DeepFixtures.self(),
            website(failure = failure), "192.0.2.53", DnsRecordType.entries.flatMap { type ->
                DnsTransport.entries.map { transport -> DeepDnsResult(type, DeepFixtures.raw(transport)) }
            }, null, emptyList())
    }
}
