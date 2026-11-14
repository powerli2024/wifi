package dev.proxyaudit.core

import java.util.Locale

data class DiagnosticFinding(
    val id: String,
    val title: String,
    val detail: String,
    val actionHint: String
)

/** Deterministic observations and next steps; never changes Android, VPN or resolver settings. */
object DiagnosticAdvisor {
    fun review(report: RunReport): List<DiagnosticFinding> {
        if (report.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME) return listOf(DiagnosticFinding(
            "DEMO_ONLY", "这是演示证据", "演示数据不能诊断当前设备或网络。",
            "确认探测目标后运行实际检查，再保存为基线。"
        ))
        val findings = mutableListOf<DiagnosticFinding>()
        // The legacy observations preserve the FIRST attempt. They must not produce operational
        // advice when the whole run is stopped, incomplete, or disagrees with a later attempt.
        val limitation = when {
            report.stopReason == Failure.CANCELLED -> DiagnosticFinding("RUN_CANCELLED", "检查已取消，证据可能不完整",
                "首次与附加尝试的已有观察仍保留；取消后未执行的项目不能由其他成功项补齐。",
                "查看逐次记录；需要完整观察时重新运行相同计划，暂不据此调整 DNS。")
            report.stopReason == Failure.NETWORK_CHANGED -> DiagnosticFinding("RUN_NETWORK_CHANGED", "网络变化，检查提前停止",
                "变化前后的观察不能作为同一稳定条件下的解析差异。",
                "等待网络稳定后重新检查相同计划，不将变化归因于 DNS 设置。")
            report.stopReason == Failure.TIMEOUT -> DiagnosticFinding("RUN_BUDGET_EXHAUSTED", "总等待预算结束，证据可能不完整",
                "总预算结束不等于每项解析都失败；首次聚合结果也不能代表全部尝试已完成。",
                "查看逐次记录和未完成项目；必要时重新检查相同计划，暂不据此调整 DNS。")
            report.stopReason != null -> DiagnosticFinding("RUN_STOPPED", "检查提前停止，证据可能不完整",
                "已有观察不能代表整份计划完整执行，也不足以判断修复效果。",
                "先核对停止状态与逐次记录，解决执行问题后再检查相同计划。")
            !DiagnosticEvidence.stable(report) -> DiagnosticFinding("NETWORK_UNSTABLE", "运行条件不稳定或无法确认",
                "网络变化、快照缺失或同一网络的配置变化会影响本次结果，不能据此定位 DNS 原因。",
                "等待当前网络稳定，使用相同目标和查询重新检查。")
            DiagnosticAttemptEvidence.incomplete(report) -> DiagnosticFinding("ATTEMPT_INCOMPLETE", "部分尝试未完成，暂不作完整对照",
                "聚合结果保留首次观察，不能补足取消、未执行或缺失的附加尝试。",
                "保留逐次记录，需要完整观察时重新运行相同计划；暂不据此调整 DNS。")
            DiagnosticAttemptEvidence.mixed(report) -> DiagnosticFinding("ATTEMPTS_DISAGREE", "多次尝试结果不一致，先观察稳定性",
                "首次失败与附加成功均保留；首次聚合结果不能代表全程，也不能据此定位解析原因。",
                "逐次核对错误、响应码和耗时；必要时复核相同计划，不挑选较好结果或据此调整 DNS。")
            else -> null
        }
        if (limitation != null) {
            findings += limitation
        } else {
            val systemEnabled = report.config.policy.runDns
            val systemUsable = systemEnabled && DiagnosticEvidence.systemUsable(report.dns)
            if (systemEnabled) {
                findings += when {
                    report.dns.execution == Execution.NOT_STARTED -> DiagnosticFinding("SYSTEM_NOT_RUN", "系统解析未执行",
                        "本次没有系统解析结果。", "在网络稳定后重测，不将未执行视为解析失败。")
                    report.dns.execution == Execution.CANCELLED || report.dns.failure == Failure.CANCELLED -> DiagnosticFinding(
                        "SYSTEM_CANCELLED", "系统解析已取消", "取消不说明域名、解析器或网络是否可用。",
                        "需要完整观察时重新执行相同检查。")
                    systemUsable -> DiagnosticFinding("SYSTEM_ADDRESSES", "系统解析已返回地址",
                        "本应用这次取得了地址；系统缓存、实际解析器和线上传输路径仍未知。",
                        "可保存为基线；地址返回不代表全机 DNS 无泄露。")
                    else -> DiagnosticFinding("SYSTEM_NO_ADDRESSES", "系统解析未取得可用地址",
                        SystemDnsDiagnostics.summary(report),
                        systemActionHint(report.dns))
                }
            }

            val raw = report.config.rawDns
            val enabledTransports = DiagnosticEvidence.enabledTransports(raw)
            val observed = enabledTransports.mapNotNull { transport ->
                report.rawDns.singleOrNull { it.transport == transport }
            }
            for (observation in observed) {
                val protocol = observation.transport.name
                val prefix = "RAW_$protocol"
                findings += when {
                    observation.execution == Execution.NOT_STARTED -> DiagnosticFinding("${prefix}_NOT_RUN", "$protocol DNS 未执行",
                        "此协议没有本次查询证据。", "完成相同检查后再比较协议差异。")
                    observation.execution == Execution.CANCELLED || observation.failure == Failure.CANCELLED -> DiagnosticFinding(
                        "${prefix}_CANCELLED", "$protocol DNS 已取消", "取消不是成功阻断或泄露证据。",
                        "需要该协议证据时重新执行。")
                    observation.execution != Execution.COMPLETED || observation.failure != null -> DiagnosticFinding(
                        "${prefix}_ERROR", "$protocol DNS 未取得有效响应",
                        "可能涉及连通性、服务策略、暂时故障或响应格式；本次不能确定原因或实际解析器身份。",
                        "对照同目标的另一协议与系统解析；不要直接关闭安全设置或更换全部 DNS。")
                    observation.truncated -> DiagnosticFinding("${prefix}_TRUNCATED", "$protocol DNS 响应被截断",
                        "已收到 TC 标记，尚不能把返回内容视作完整地址结果。",
                        "查看独立 TCP 检查的结果；本工具不自动回退。")
                    observation.responseCode == 3 -> DiagnosticFinding("${prefix}_NXDOMAIN", "$protocol DNS 返回 NXDOMAIN",
                        "已收到声明域名不存在的响应；收到响应不等于取得查询地址，也不证明所选解析器身份。",
                        "核对域名和服务过滤策略；必要时经确认更换对照目标，不直接判定为污染。")
                    observation.responseCode != 0 -> DiagnosticFinding("${prefix}_RCODE", "$protocol DNS 返回错误状态",
                        "响应码为 ${observation.responseCode?.toString() ?: "未知"}；这不是可用地址结果。",
                        "结合域名、服务器策略和另一协议复核；单次错误不能定位责任方。")
                    DiagnosticEvidence.rawUsable(observation) -> DiagnosticFinding("${prefix}_ADDRESSES", "$protocol DNS 已返回地址",
                        "仅证明本次查询取得地址；指定目标仍可能被 VPN、透明代理或网关接管。",
                        "保存观察；要验证隐私路径还需代理、解析器或网关侧证据。")
                    else -> DiagnosticFinding("${prefix}_NO_ADDRESSES", "$protocol DNS 没有返回所需地址",
                        "NOERROR 但未取得相应地址，可能是无此类型数据、转介或有限解析支持；不能只凭状态码称解析可用。",
                        "核对查询类型；不要把没有 AAAA 地址等同于 IPv6 泄露或已安全阻断。")
                }
            }
            if (raw != null && observed.size != enabledTransports.size) findings += DiagnosticFinding(
                "RAW_INCOMPLETE", "原始 DNS 观察不完整",
                "所选协议缺少唯一结果，不能把缺失记录算作失败或成功。", "完成同一检查后再对照。")

            val udp = observed.singleOrNull { it.transport == DnsTransport.UDP }
            val tcp = observed.singleOrNull { it.transport == DnsTransport.TCP }
            if (udp != null && tcp != null && DiagnosticEvidence.finished(udp.execution, udp.failure) &&
                DiagnosticEvidence.finished(tcp.execution, tcp.failure) &&
                DiagnosticEvidence.rawUsable(udp) != DiagnosticEvidence.rawUsable(tcp)) {
                findings += DiagnosticFinding("RAW_PROTOCOL_DIFFERENCE", "UDP 与 TCP 的地址结果不同",
                    "一个协议取得了地址，另一个没有；这不足以确定过滤、代理兼容或服务器故障。",
                    "保留两项响应码与错误记录，先复测同一目标；不要把切换为 TCP 等同于隐私修复。")
            }
            val rawUsable = observed.any(DiagnosticEvidence::rawUsable)
            val sameHost = raw != null && report.config.dnsHost?.removeSuffix(".")?.lowercase(Locale.ROOT) ==
                raw.host.removeSuffix(".").lowercase(Locale.ROOT)
            if (systemEnabled && raw != null && !sameHost) findings += DiagnosticFinding(
                "DIFFERENT_QUERY_TARGETS", "两种解析方式的查询域名不同",
                "不同域名可能有不同的地址、策略或故障，不能用这一差异定位系统解析问题。",
                "要比较解析方式，请查询同一域名并注意系统与原始探针的查询类型差异。")
            if (systemEnabled && DiagnosticEvidence.finished(report.dns.execution, report.dns.failure) &&
                sameHost && !systemUsable && rawUsable) findings += DiagnosticFinding(
                "SYSTEM_RAW_DIFFERENCE", "指定 DNS 有地址，系统解析未取得",
                "两种解析方式的行为不同；它们可能使用不同缓存、查询类型、解析规则和实际路径。",
                "先看错误阶段与响应码；权限、参数和未知系统错误优先排查调用，NXDOMAIN 先核对名称。确需调整设置时记录原值、每次只修改一项再复测。")
        }

        val network = report.networkAfter
        if (network.privateDnsActive == true) findings += DiagnosticFinding(
            "PRIVATE_DNS_ACTIVE", "系统快照显示 Private DNS 已启用",
            "这不证明所有应用的 DNS 均已加密；主动 UDP/TCP 原始探针仍是明文 DNS 诊断。",
            "保持明文探针为明确选择项；需要核验加密路径时使用相应协议与外部证据。")
        else if (network.privateDnsActive == false) findings += DiagnosticFinding(
            "PRIVATE_DNS_INACTIVE", "系统快照未显示 Private DNS 启用",
            "这本身不是 DNS 泄露证据；VPN 或应用可能自行使用加密解析。",
            if (limitation != null) "此项仅是快照背景；先完成稳定检查，不根据启用状态直接调整 DNS。"
            else "先确认实际 DNS 管理方式，再决定是否配置系统 Private DNS，避免与 VPN 规则冲突。")
        if (network.vpnCapability == true && report.config.rawDns != null) findings += DiagnosticFinding(
            "VPN_DNS_CONTEXT", "VPN 可能接管原始 DNS",
            "配置 DNS 可能是 VPN 虚拟地址；指定数字 IP 不保证请求直接到达该公共解析器。",
            "结合代理核心日志或受控网关证据核验；不要将虚拟地址或端口 53 不可达直接视为故障。")
        findings += DiagnosticFinding("SCOPE_LIMIT", "这些检查不自动修复网络",
            "只观察本应用本次请求；返回地址不证明该地址可连接或网站可用，也不能证明全机无泄露；地址不同不能直接判定污染。",
            if (limitation != null) "先补齐同一计划的稳定观察并保留逐次记录；需要路径判断时补充外部证据。"
            else "保存基线，按证据调整一项设置后复测；需要路径判断时补充外部证据。")
        return findings
    }

    private fun systemActionHint(result: DnsObservation): String = when {
        result.diagnosticStage == SystemDnsStage.LOCAL_EXCEPTION ->
            "先核对输入、应用网络权限、线程状态和 API 兼容性；不要用更换 DNS 掩盖本地调用问题。"
        result.diagnosticStage == SystemDnsStage.ERROR_CALLBACK ->
            "保留解析器错误码与数字 errno，核对默认 DNS 网络及查询提交；未知系统错误不应直接导向更换 DNS。"
        result.diagnosticStage == SystemDnsStage.ANSWER_CALLBACK && result.responseCode == 3 ->
            "核对域名拼写、是否应存在、私有名称与过滤策略；不要盲目替换公共 DNS。"
        result.diagnosticStage == SystemDnsStage.ANSWER_CALLBACK && result.responseCode == 0 ->
            "核对所需 A/AAAA 记录、别名链与工具支持范围；没有地址不等于应关闭 IPv6 或更换 DNS。"
        result.diagnosticStage == null && result.failure != Failure.TIMEOUT ->
            "先用支持错误详情的版本复核；不能从 DNS_FAILURE 或很短的耗时还原根因。"
        else -> "保留目标、错误阶段与响应码，先复核同一计划；不要仅凭单次失败更换全部 DNS。"
    }
}

internal object DiagnosticEvidence {
    fun stable(report: RunReport): Boolean =
        !report.networkChanged && report.networkBefore == report.networkAfter &&
            report.networkBefore.observationAvailable && report.networkAfter.observationAvailable &&
            report.networkBefore.networkId != null && report.networkAfter.networkId != null

    fun systemUsable(observation: DnsObservation): Boolean =
        observation.execution == Execution.COMPLETED && observation.failure == null &&
            (observation.responseCode == null || observation.responseCode == 0) &&
            observation.resolverErrorCode == null && observation.exceptionKind == null &&
            observation.diagnosticStage !in listOf(SystemDnsStage.ERROR_CALLBACK, SystemDnsStage.LOCAL_EXCEPTION) &&
            observation.addresses.isNotEmpty() && observation.addresses.all { NumericIp.canonical(it) != null }

    fun rawUsable(observation: RawDnsObservation): Boolean =
        observation.execution == Execution.COMPLETED && observation.failure == null &&
            observation.responseCode == 0 && !observation.truncated && observation.addresses.isNotEmpty() &&
            observation.addresses.all { NumericIp.canonical(it) != null }

    fun finished(execution: Execution, failure: Failure?): Boolean =
        execution in listOf(Execution.COMPLETED, Execution.ERROR) &&
            failure !in listOf(Failure.CANCELLED, Failure.NETWORK_CHANGED, Failure.INTERNAL_ERROR)

    fun enabledTransports(config: RawDnsConfig?): List<DnsTransport> = buildList {
        if (config?.udp == true) add(DnsTransport.UDP)
        if (config?.tcp == true) add(DnsTransport.TCP)
    }
}
