package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class QuickCheckTest {
    @Test fun `default quick check is system only with no required endpoint or resolver input`() {
        val unavailable = quickSnapshot().copy(observationAvailable = false, configuredDnsServers = emptyList())
        val plan = QuickCheck.build(unavailable)
        assertEquals("example.com", plan.dnsHost)
        assertTrue(plan.policy.runDns)
        assertFalse(plan.policy.runHttps)
        assertFalse(plan.policy.endpointTrustedByUser)
        assertTrue(plan.policy.expectedSourceIps.isEmpty())
        assertNull(plan.endpoint); assertNull(plan.rawDns)
        assertEquals(20000L, plan.evidenceBudgetMillis)
    }

    @Test fun `choosing a public preset alone does not enable raw probes`() {
        for (target in QuickDnsTarget.entries) {
            assertNull(QuickCheck.build(quickSnapshot(), target).rawDns)
        }
    }

    @Test fun `raw network target uses first strict numeric address without changing IPv6 intent`() {
        val snapshot = quickSnapshot().copy(configuredDnsServers =
            listOf("dns.example", "fe80::1%wlan0", "127.1", "::ffff:192.0.2.53", "192.0.2.54"))
        val raw = QuickCheck.build(snapshot, includeRaw = true).rawDns!!
        assertEquals("::ffff:192.0.2.53", raw.serverIp)
        assertEquals("example.com", raw.host); assertEquals(53, raw.port)
        assertTrue(raw.udp); assertTrue(raw.tcp)
        assertEquals(DnsRecordType.A, raw.recordType)
    }

    @Test fun `raw network plan fails clearly if configured list contains no supported literal`() {
        val snapshot = quickSnapshot().copy(configuredDnsServers = listOf("resolver.example", "fe80::1%wlan0"))
        try { QuickCheck.build(snapshot, includeRaw = true); fail("Expected unavailable configured resolver") }
        catch (error: IllegalArgumentException) { assertTrue(error.message!!.contains("仅检查系统解析")) }
    }

    @Test fun `public catalog contains verified distinct protocol endpoints and explicit raw opt in`() {
        val expected = mapOf(
            QuickDnsTarget.CLOUDFLARE to listOf("1.1.1.1", "https://cloudflare-dns.com/dns-query", "one.one.one.one"),
            QuickDnsTarget.QUAD9 to listOf("9.9.9.9", "https://dns.quad9.net/dns-query", "dns.quad9.net"),
            QuickDnsTarget.GOOGLE to listOf("8.8.8.8", "https://dns.google/dns-query", "dns.google")
        )
        assertEquals(expected.keys, DnsProviders.public.map { it.id }.toSet())
        for ((target, addresses) in expected) {
            val provider = DnsProviders.get(target)
            assertEquals(addresses, listOf(provider.ipv4, provider.dohUrl, provider.privateDnsHost))
            assertEquals(provider.ipv4, QuickCheck.build(quickSnapshot(), target, true).rawDns!!.serverIp)
        }
        try { DnsProviders.get(QuickDnsTarget.NETWORK); fail("NETWORK is not a public provider") }
        catch (_: IllegalArgumentException) {}
    }

    @Test fun `Private DNS active does not silently rewrite an explicitly selected raw plan`() {
        val snapshot = quickSnapshot().copy(privateDnsActive = true, privateDnsServerName = "private.example")
        val default = QuickCheck.build(snapshot)
        assertNull(default.rawDns)
        val optIn = QuickCheck.build(snapshot, QuickDnsTarget.QUAD9, true)
        assertEquals("9.9.9.9", optIn.rawDns!!.serverIp)
        assertEquals(60000L, optIn.evidenceBudgetMillis)
    }
}

/** Independent constructed inputs, not captured runtime evidence or a copy of the demo fixture. */
internal fun quickSnapshot(): NetworkSnapshot = NetworkSnapshot(
    networkId = "test-network", transports = listOf("WIFI"), vpnCapability = false,
    internetCapability = true, validatedCapability = true, localAddresses = listOf("192.0.2.5"),
    configuredDnsServers = listOf("192.0.2.53"), privateDnsActive = false,
    privateDnsServerName = null, observationAvailable = true
)

internal fun quickReport(
    runId: String = "00000000-0000-4000-8000-000000000001",
    raw: Boolean = false
): RunReport {
    val network = quickSnapshot()
    return RunReport(
        runId, "2026-10-21T00:00:00Z", "2026-10-21T00:00:01Z", 1000, 35, "0.3.0",
        QuickCheck.build(network, includeRaw = raw), network, network, false,
        DnsObservation(Execution.COMPLETED, listOf("192.0.2.8"), 20), HttpsObservation(),
        EvidenceOrigin.ANDROID_RUNTIME,
        if (!raw) emptyList() else listOf(
            RawDnsObservation(DnsTransport.UDP, Execution.COMPLETED, 1, 25, 0, false, listOf("192.0.2.8")),
            RawDnsObservation(DnsTransport.TCP, Execution.COMPLETED, 2, 30, 0, false, listOf("192.0.2.8"))
        )
    )
}
