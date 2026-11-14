package dev.proxyaudit.core

enum class Verdict(val label: String) {
    MATCH("符合预定策略"), VIOLATE("违反预定策略"), INSUFFICIENT("观察不足"),
    NOT_RUN("未执行"), NOT_APPLICABLE("不适用")
}
enum class EvidenceOrigin { ANDROID_RUNTIME, SYNTHETIC_FIXTURE }
enum class Execution { NOT_STARTED, COMPLETED, ERROR, CANCELLED }
enum class Failure { TIMEOUT, CANCELLED, DNS_FAILURE, TLS_FAILURE, IO_FAILURE, HTTP_STATUS, REDIRECT_REJECTED, RESPONSE_TOO_LARGE, INVALID_ECHO, INVALID_DNS, NETWORK_CHANGED, INTERNAL_ERROR }
data class Assessment(val verdict: Verdict, val reason: String)
data class ProbePolicy(
    val runHttps: Boolean,
    val runDns: Boolean,
    val expectedSourceIps: Set<String>,
    val ipv6InScope: Boolean,
    val endpointTrustedByUser: Boolean
)
data class RunConfig(val endpoint: Endpoint?, val dnsHost: String?, val policy: ProbePolicy, val timeoutMillis: Int = 8_000, val rawDns: RawDnsConfig? = null, val maxAttempts: Int = 1) {
    init { require(timeoutMillis in 1_000..15_000); require(maxAttempts in 1..2) }
    val evidenceBudgetMillis: Long get() = if (rawDns == null) 20_000L else 60_000L
}
enum class DnsTransport { UDP, TCP }
enum class DnsRecordType(val wireValue: Int) { A(1), AAAA(28) }
data class RawDnsConfig(
    val serverIp: String, val port: Int = 53, val host: String,
    val recordType: DnsRecordType = DnsRecordType.A, val udp: Boolean = true, val tcp: Boolean = true
) {
    init {
        require(NumericIp.canonical(serverIp) != null) { "DNS 服务器必须是无作用域的数字 IPv4 或 IPv6 地址" }
        require(port in 1..65535) { "DNS 服务器端口必须为 1..65535" }
        require(isDnsHost(host)) { "查询域名格式不正确" }
        require(udp || tcp) { "至少选择一种 DNS 传输协议" }
    }
}
data class RawDnsObservation(
    val transport: DnsTransport, val execution: Execution = Execution.NOT_STARTED,
    val transactionId: Int? = null, val durationMillis: Long? = null,
    val responseCode: Int? = null, val truncated: Boolean = false,
    val addresses: List<String> = emptyList(), val failure: Failure? = null
)
enum class SystemDnsStage { ANSWER_CALLBACK, ERROR_CALLBACK, LOCAL_EXCEPTION }
enum class SystemDnsExceptionKind { SECURITY, INVALID_ARGUMENT, INTERRUPTED, OTHER }

data class DnsObservation(
    val execution: Execution = Execution.NOT_STARTED,
    val addresses: List<String> = emptyList(),
    val durationMillis: Long? = null,
    val failure: Failure? = null,
    val diagnosticStage: SystemDnsStage? = null,
    val responseCode: Int? = null,
    val resolverErrorCode: Int? = null,
    val systemErrno: Int? = null,
    val exceptionKind: SystemDnsExceptionKind? = null
)
data class HttpsObservation(
    val execution: Execution = Execution.NOT_STARTED,
    val statusCode: Int? = null,
    val durationMillis: Long? = null,
    val tlsValidated: Boolean = false,
    val echoedRequestId: String? = null,
    val serverReportedSourceIp: String? = null,
    val failure: Failure? = null
)

enum class ProbeKind { SYSTEM_DNS, HTTPS, RAW_UDP, RAW_TCP }
enum class RetryTrigger { TIMEOUT, CONNECT_FAILURE }

/** One attempted probe; retryScheduled is intent, not proof that a later attempt started. */
data class ProbeAttempt(
    val attemptId: String, val probe: ProbeKind, val attemptNumber: Int,
    val startedAfterMillis: Long, val timeoutMillis: Int,
    val finishedAfterMillis: Long? = null,
    val dns: DnsObservation? = null, val https: HttpsObservation? = null,
    val rawDns: RawDnsObservation? = null, val retryTrigger: RetryTrigger? = null,
    val retryScheduled: Boolean = false, val retryDelayMillis: Long = 0
)
data class NetworkSnapshot(
    val networkId: String?, val transports: List<String>, val vpnCapability: Boolean?,
    val internetCapability: Boolean?, val validatedCapability: Boolean?,
    val localAddresses: List<String>, val configuredDnsServers: List<String>,
    val privateDnsActive: Boolean?, val privateDnsServerName: String?, val observationAvailable: Boolean
)
data class RunReport(
    val runId: String, val startedAtUtc: String, val finishedAtUtc: String,
    val durationMillis: Long, val androidApi: Int, val appVersion: String,
    val config: RunConfig, val networkBefore: NetworkSnapshot, val networkAfter: NetworkSnapshot,
    val networkChanged: Boolean, val dns: DnsObservation, val https: HttpsObservation,
    val evidenceOrigin: EvidenceOrigin = EvidenceOrigin.ANDROID_RUNTIME,
    val rawDns: List<RawDnsObservation> = emptyList(),
    val attempts: List<ProbeAttempt> = emptyList(),
    val stopReason: Failure? = null
) {
    val egress: Assessment get() = Evaluator.egress(this)
    val dnsPrivacy: Assessment get() = Evaluator.dnsPrivacy(config.policy, dns)
    val ipv6: Assessment get() = Evaluator.ipv6(config.policy)
    companion object {
        const val SCOPE = "THIS_APP_REQUESTS_ONLY"
        val LIMITATIONS = listOf(
            "只观察本应用在本次运行期间的请求，不抓取或证明其他应用、全机或所有协议的行为。",
            "服务端来源 IP 是用户选择端点的声明，不是独立的路由、代理链或网关抓包证据。",
            "系统 DNS 结果不显示实际解析器、传输协议、缓存命中或线上的 DNS 路径。",
            "VPN 能力、系统 Private DNS 与网络验证状态仅为快照，不证明请求经过 VPN。",
            "DNS 返回 AAAA、链路含 IPv6、或服务端报告 IPv6 均不证明手机使用 IPv6 传输。",
            "超时、取消、证书错误和断网只表示探测未取得有效证据，不能证明阻断正确或发生泄露。",
            "每次原始 DNS 尝试只向同一数字服务器发送一次所选协议查询；默认一次，明确启用后仅对限定错误最多尝试两次，不回退协议或使用系统域名解析。",
            "重试保留全部尝试；汇总保留首次失败，不用后次成功覆盖。所有尝试与退避共享原计划总预算，不构成独立路径或无泄露证据。",
            "原始 DNS 的响应码、TC 截断标记和地址不证明解析器身份、加密、线上路径或无泄露；VPN、透明代理或网关仍可能转发或改写。",
            "数字 IPv6 DNS 目标只表示请求的 socket 目标地址族，不证明实际物理链路使用 IPv6。",
            "未测试 QUIC、WebRTC、主动绑定底层网络、故障注入或跨应用流量。"
        )
    }
}
