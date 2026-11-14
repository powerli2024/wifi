package dev.proxyaudit.core

object Evaluator {
    fun egress(report: RunReport): Assessment {
        val policy = report.config.policy
        val result = report.https
        if (!policy.runHttps || result.execution == Execution.NOT_STARTED)
            return Assessment(Verdict.NOT_RUN, "HTTPS 出口探测未执行。")
        if (report.config.endpoint == null)
            return Assessment(Verdict.INSUFFICIENT, "缺少本次回显服务来源配置。")
        if (!policy.endpointTrustedByUser)
            return Assessment(Verdict.INSUFFICIENT, "未确认对回显端点及其来源地址声明的信任。")
        if (policy.expectedSourceIps.isEmpty())
            return Assessment(Verdict.INSUFFICIENT, "未填写明确的预期出口 IP，无法对照策略。")
        if (report.networkChanged || report.networkBefore != report.networkAfter || !report.networkBefore.observationAvailable || !report.networkAfter.observationAvailable ||
            report.networkBefore.networkId == null || report.networkAfter.networkId == null || report.networkBefore.networkId != report.networkAfter.networkId)
            return Assessment(Verdict.INSUFFICIENT, "网络变化或快照不可用，本次结果不能用于稳定路径判定。")
        if (result.execution != Execution.COMPLETED || result.failure != null || !result.tlsValidated || result.statusCode != 200)
            return Assessment(Verdict.INSUFFICIENT, "没有取得经过正常 TLS 验证的有效 HTTPS 回显；失败不能证明阻断或泄露。")
        if (result.echoedRequestId != report.runId)
            return Assessment(Verdict.INSUFFICIENT, "请求标识不匹配，响应无法归属于本次运行。")
        val actual = result.serverReportedSourceIp?.let(NumericIp::canonical)
            ?: return Assessment(Verdict.INSUFFICIENT, "服务端未提供有效数字来源 IP。")
        val expected = policy.expectedSourceIps.mapNotNull(NumericIp::canonical).toSet()
        if (expected.size != policy.expectedSourceIps.size)
            return Assessment(Verdict.INSUFFICIENT, "预期出口列表包含无效或未规范化条目。")
        return if (actual in expected) Assessment(Verdict.MATCH, "该 HTTPS 回显的服务端来源 IP 符合预设列表；仅限本应用本次请求，不证明全机无泄露。")
        else Assessment(Verdict.VIOLATE, "该 HTTPS 回显的服务端来源 IP 不在预设列表；这是此项出口策略不匹配，不是独立的全机泄露证明。")
    }
    fun dnsPrivacy(policy: ProbePolicy, result: DnsObservation): Assessment =
        if (!policy.runDns || result.execution == Execution.NOT_STARTED) Assessment(Verdict.NOT_RUN, "系统 DNS 探测未执行。")
        else Assessment(Verdict.INSUFFICIENT, "系统解析只给出地址或错误，不能确定线上解析器、加密或旁路情况；需要网关/解析器证据。")
    fun ipv6(policy: ProbePolicy): Assessment =
        if (!policy.ipv6InScope) Assessment(Verdict.NOT_APPLICABLE, "用户明确将 IPv6 专项验证排除在本次范围之外。")
        else Assessment(Verdict.INSUFFICIENT, "本版本未强制 IPv6 传输并独立核验路径；不能以地址存在或缺失判定 IPv6 无泄露。")
}
