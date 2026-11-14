package dev.proxyaudit.core

/** Only fixed text, enums and numeric platform codes; never accepts exception text or identifiers. */
object SystemDnsDiagnostics {
    fun summary(report: RunReport): String = if (report.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME)
        "这是虚构的系统 DNS 演示记录；没有执行当前设备查询，不提供当前设备的错误、地址或配置诊断。"
    else if (!report.config.policy.runDns) "本计划未选择系统 DNS 检查，没有本次系统解析详情。"
    else summary(report.dns)

    /** Observation-only compatibility API. Call the report overload for user-facing provenance. */
    fun summary(observation: DnsObservation): String {
        if (observation.execution == Execution.NOT_STARTED) return "系统解析未执行，没有错误详情。"
        if (observation.execution == Execution.CANCELLED || observation.failure == Failure.CANCELLED)
            return "系统解析已取消；取消不表示域名不存在或网络已安全阻断。"
        if (observation.failure == Failure.TIMEOUT)
            return "系统解析在本次等待预算内未完成；这不能定位解析器、VPN 或网络故障。"
        if (observation.failure == Failure.NETWORK_CHANGED)
            return "系统解析期间观察到网络变化；需在网络稳定后复测。"
        return when (observation.diagnosticStage) {
            SystemDnsStage.ANSWER_CALLBACK -> when {
                observation.responseCode == 3 -> "Android 返回 NXDOMAIN（rcode=3，声明域名不存在）；这不是可用地址结果，也不能据此判定污染或责任方。"
                observation.responseCode != null && observation.responseCode != 0 ->
                    "Android 返回 DNS 响应码 ${observation.responseCode}；未取得可用地址，单次状态码不能定位责任方。"
                observation.responseCode == 0 && observation.addresses.isEmpty() ->
                    "Android 返回 NOERROR（rcode=0），但没有可用地址；成功回调不等于解析已取得地址，实际查询类型与缓存仍未知。"
                observation.responseCode == 0 ->
                    "Android 返回 NOERROR（rcode=0）及地址；实际解析器、缓存和线上传输路径仍未知。"
                else -> "收到系统解析回调，但没有记录 DNS 响应码；不能进一步定位原因。"
            }
            SystemDnsStage.ERROR_CALLBACK -> when (observation.resolverErrorCode) {
                // Android DnsResolver public constants: ERROR_PARSE=0 and ERROR_SYSTEM=1 (API 29+).
                0 -> "Android 报告 ERROR_PARSE（code=0）：解析 DNS 响应失败；这不证明响应被污染，也不确定由哪一方造成。"
                1 -> "Android 报告 ERROR_SYSTEM（code=1）：系统解析查询发生错误" +
                    (observation.systemErrno?.let { "，errno=$it" } ?: "，未提供 errno") +
                    "；错误可能发生在取得 DNS 网络或提交查询等环节，不能仅凭此归责 VPN 或服务器。"
                else -> "Android 报告解析器错误，code=${observation.resolverErrorCode?.toString() ?: "未记录"}；当前不能进一步解释该代码。"
            }
            SystemDnsStage.LOCAL_EXCEPTION -> when (observation.exceptionKind) {
                SystemDnsExceptionKind.SECURITY -> "系统 DNS 调用或等待出现安全权限异常；请核对应用权限和系统策略，未保留异常原文。"
                SystemDnsExceptionKind.INVALID_ARGUMENT -> "系统 DNS 调用或等待出现参数异常；请核对查询输入及 API 兼容性，未保留异常原文。"
                SystemDnsExceptionKind.INTERRUPTED -> "系统 DNS 等待被线程中断；这不是 DNS 服务器响应或域名错误的证据。"
                else -> "系统 DNS 调用或等待出现本地异常；未保留异常原文，不能把它当作服务器的 DNS 响应。"
            }
            null -> if (observation.execution == Execution.COMPLETED && observation.failure == null && observation.addresses.isNotEmpty())
                "系统解析已返回地址，但本记录未包含详细响应码；实际解析器、缓存和线上传输路径仍未知。"
            else "本记录未包含系统 DNS 详细响应码或异常类别；不能从 DNS_FAILURE 或耗时还原根因，需用支持详情的版本复测。"
        }
    }
}
