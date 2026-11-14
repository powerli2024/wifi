package dev.proxyaudit.core

import java.util.Collections

enum class QuickDnsTarget { NETWORK, CLOUDFLARE, QUAD9, GOOGLE }

data class DnsProvider(
    val id: QuickDnsTarget,
    val label: String,
    val ipv4: String,
    val dohUrl: String,
    val privateDnsHost: String
)

/** Provider metadata is informational. Reading this catalog performs no network or settings change. */
object DnsProviders {
    // Official service documentation verified 2026-10-21:
    // https://developers.cloudflare.com/1.1.1.1/ip-addresses/
    // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/
    // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/
    // https://docs.quad9.net/services/
    // https://developers.google.com/speed/public-dns/docs/using
    // https://developers.google.com/speed/public-dns/docs/doh
    val public: List<DnsProvider> = Collections.unmodifiableList(listOf(
        DnsProvider(QuickDnsTarget.CLOUDFLARE, "Cloudflare（标准解析）", "1.1.1.1",
            "https://cloudflare-dns.com/dns-query", "one.one.one.one"),
        DnsProvider(QuickDnsTarget.QUAD9, "Quad9（恶意域名拦截）", "9.9.9.9",
            "https://dns.quad9.net/dns-query", "dns.quad9.net"),
        DnsProvider(QuickDnsTarget.GOOGLE, "Google Public DNS", "8.8.8.8",
            "https://dns.google/dns-query", "dns.google")
    ))

    fun get(target: QuickDnsTarget): DnsProvider =
        public.firstOrNull { it.id == target }
            ?: throw IllegalArgumentException("当前网络 DNS 来自网络快照，不属于公共服务预设")
}

object QuickCheck {
    /** Builds an inert plan. The caller must confirm the concrete plan before starting any probe. */
    fun build(
        snapshot: NetworkSnapshot,
        target: QuickDnsTarget = QuickDnsTarget.NETWORK,
        includeRaw: Boolean = false
    ): RunConfig {
        val raw = if (!includeRaw) null else {
            val server = if (target == QuickDnsTarget.NETWORK) {
                snapshot.configuredDnsServers.firstOrNull { NumericIp.canonical(it) != null }
                    ?: throw IllegalArgumentException("当前网络没有可用的数字 DNS 地址；可仅检查系统解析，或明确选择公共 DNS 对照")
            } else DnsProviders.get(target).ipv4
            // Preserve IPv6 literal intent; mapped IPv6 must not silently become an IPv4 target.
            RawDnsConfig(serverIp = server, host = "example.com")
        }
        return RunConfig(
            endpoint = null,
            dnsHost = "example.com",
            policy = ProbePolicy(runHttps = false, runDns = true, expectedSourceIps = emptySet(),
                ipv6InScope = true, endpointTrustedByUser = false),
            rawDns = raw
        )
    }
}
