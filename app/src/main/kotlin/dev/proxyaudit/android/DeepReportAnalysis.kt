package dev.proxyaudit.android

import dev.proxyaudit.core.*
import java.net.URI

/** Explanations are derived from observed events, never from a guessed proxy route. */
object DeepReportAnalysis {
    fun findings(report: DeepReport): List<String> = buildList {
        if (report.stopReason != null) return@buildList
        val website = report.website
        val numericTarget = website?.plan?.url?.let { URI(it).host?.removeSurrounding("[", "]") }
            ?.let { NumericIp.canonical(it) != null } == true
        val attempts = website?.attempts.orEmpty().takeUnless { website?.execution == Execution.CANCELLED }.orEmpty()
        attempts.forEach { attempt ->
            if (attempt.execution !in setOf(Execution.COMPLETED, Execution.ERROR)) return@forEach
            val prefix = "第 ${attempt.number} 次网站尝试："
            if (attempt.connections.any { it.proxyType == "HTTP" } && attempt.dns.none { it.role == "ORIGIN" }) {
                add(prefix + if (numericTarget) "已观察到 HTTP 代理连接；目标本身是数字 IP，不需要站点域名解析。缺少本地站点 DNS 回调符合该计划。"
                    else "已观察到 HTTP 代理连接，未观察到本地站点 DNS 回调；站点解析可由代理承接。此组合本身不表示 DNS 故障，原始 DNS 对照也不等同于网站请求的解析路径。")
            }
            if (attempt.connections.any { it.proxyType == "DIRECT" }) {
                add(prefix + "DIRECT 表示此连接未选用显式 HTTP/SOCKS 代理；Android VPN 仍可能承载该连接，不能据此认定绕过代理或直连公网。")
            }
        }
        if (attempts.firstOrNull()?.let { it.failure != null || it.execution == Execution.ERROR } == true &&
            attempts.drop(1).any { it.execution == Execution.COMPLETED && it.failure == null }) {
            add("首次网站尝试失败、后续复核完成：保留首次失败和每次阶段证据。优先按同一计划复测稳定性，不能把后续成功解释为自动修复或持续故障已消失。")
        }
        val answers = report.dns.filter { completeAnswer(it.observation) }
        if (answers.any { item -> item.recordType == DnsRecordType.A && item.observation.addresses.any(::isFakeIpRange) }) {
            add("原始 A 查询返回 198.18.0.0/15 范围地址；该范围用于基准测试，也常被代理用作 fake-IP。结合 VPN/代理配置可怀疑 fake-IP 映射，但单次地址特征不能确认实现、污染或泄露；先核对客户端 DNS 模式和同次网站访问结果。")
        }
        val emptyAaaa = answers.filter { it.recordType == DnsRecordType.AAAA && it.observation.addresses.isEmpty() }
        if (emptyAaaa.isNotEmpty()) {
            add("AAAA 的 ${emptyAaaa.joinToString(" / ") { it.observation.transport.name }} 收到 NOERROR 空地址响应；这是已收到 DNS 回答、未提供 IPv6 地址，与超时或传输失败不同。检查目标 AAAA 与客户端 IPv6/DNS 策略；不能单凭此结果判定 IPv6 泄露或公网 IPv6 不可达。")
        }
        for (type in DnsRecordType.entries) {
            val udp = report.dns.singleOrNull { it.recordType == type && it.observation.transport == DnsTransport.UDP }?.observation
            val tcp = report.dns.singleOrNull { it.recordType == type && it.observation.transport == DnsTransport.TCP }?.observation
            if (udp != null && tcp != null && completeAnswer(udp) && completeAnswer(tcp) &&
                udp.addresses.mapNotNull(NumericIp::canonical).toSet() != tcp.addresses.mapNotNull(NumericIp::canonical).toSet()) {
                add("$type：UDP 与 TCP 都收到 NOERROR 回答，但地址集合不同。轮询、缓存、策略或网络处理均可能造成差异；保留两份回答并按原目标复测，不能直接判污染或 DNS 泄露。")
            }
            if (udp != null && tcp != null && terminal(udp) && terminal(tcp) &&
                !(completeAnswer(udp) && completeAnswer(tcp)) && outcome(udp) != outcome(tcp)) {
                add("$type：UDP ${outcome(udp)}，TCP ${outcome(tcp)}。空回答、DNS 响应码与传输错误属于不同结果；按原域名和原解析器复测该差异，不将它直接归因于泄露或污染。")
            }
        }
    }.distinct()

    private fun completeAnswer(o: RawDnsObservation) = o.execution == Execution.COMPLETED &&
        o.failure == null && o.responseCode == 0 && !o.truncated

    private fun terminal(o: RawDnsObservation) = o.execution in setOf(Execution.COMPLETED, Execution.ERROR)
    private fun outcome(o: RawDnsObservation): String = when {
        o.failure != null -> "执行错误 ${o.failure}"
        o.execution == Execution.ERROR -> "执行失败但没有具体错误码"
        o.truncated -> "响应被截断（TC）"
        o.responseCode == 0 && o.addresses.isNotEmpty() -> "取得地址"
        o.responseCode == 0 -> "收到 NOERROR 空地址响应"
        else -> "收到响应码 ${o.responseCode ?: "未知"}"
    }

    internal fun isFakeIpRange(address: String): Boolean {
        val ip = NumericIp.canonical(address) ?: return false
        val parts = ip.split('.')
        return parts.size == 4 && parts[0] == "198" && parts[1] in setOf("18", "19")
    }
}
