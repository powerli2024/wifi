package dev.proxyaudit.core

/** Deterministic fabricated documentation data. It is never presented as a phone measurement. */
object DemoFixture {
    fun report(): RunReport {
        val network = NetworkSnapshot("DEMO-NETWORK", listOf("WIFI", "VPN"), true, true, true,
            listOf("192.0.2.10"), listOf("192.0.2.53"), null, null, true)
        val policy = ProbePolicy(true, true, setOf("203.0.113.7"), true, true)
        return RunReport("00000000-0000-4000-8000-000000000001", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.250Z",
            250, 35, "DEMO-NOT-A-DEVICE-TEST", RunConfig(Endpoint.parse("https://echo.example.test"), "dns.example.test", policy),
            network, network, false, DnsObservation(Execution.COMPLETED, listOf("192.0.2.25", "2001:db8:0:0:0:0:0:25"), 50),
            HttpsObservation(Execution.COMPLETED, 200, 200, true, "00000000-0000-4000-8000-000000000001", "203.0.113.7"), evidenceOrigin = EvidenceOrigin.SYNTHETIC_FIXTURE)
    }
}
