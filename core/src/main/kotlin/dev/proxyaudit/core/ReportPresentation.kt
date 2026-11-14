package dev.proxyaudit.core

import java.util.Locale

data class ProbeSummary(val title: String, val status: String, val detail: String)
data class ReportSummary(
    val headline: String,
    val detail: String,
    val rows: List<ProbeSummary>,
    val nextStep: String
)

/** Display-only interpretation of an in-memory report. Never starts a probe or changes settings. */
object ReportPresentation {
    fun summarize(report: RunReport): ReportSummary {
        if (report.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME) return ReportSummary(
            "这是演示结果", "这些是虚构的演示数据，不是当前设备测量；未执行本次设备探测。",
            listOf("系统 DNS", "UDP DNS", "TCP DNS", "HTTPS 出口").map { title ->
                ProbeSummary(title, "演示数据", "此行只展示 $title 的报告结构；没有当前设备的诊断或策略结论。")
            }, "确认目标后运行实际检查；演示数据不能诊断当前设备或作为实际基线。")
        val rows = listOf(systemRow(report), rawRow(report, DnsTransport.UDP),
            rawRow(report, DnsTransport.TCP), httpsRow(report))
        val findings = DiagnosticAdvisor.review(report).associateBy { it.id }
        val sameHost = sameQueryHost(report)
        val rawResults = DiagnosticEvidence.enabledTransports(report.config.rawDns).mapNotNull { protocol ->
            report.rawDns.singleOrNull { it.transport == protocol }
        }
        val usableProtocols = rawResults.filter(DiagnosticEvidence::rawUsable).map { it.transport.name }
        val systemEnabled = report.config.policy.runDns
        val systemUsable = systemEnabled && DiagnosticEvidence.systemUsable(report.dns)
        val systemFinished = systemEnabled && DiagnosticEvidence.finished(report.dns.execution, report.dns.failure)
        val dnsDifference = sameHost && systemFinished && !systemUsable && usableProtocols.isNotEmpty()
        val cancelled = rows.any { it.status == "已取消" }
        val pending = (systemEnabled && report.dns.execution == Execution.NOT_STARTED) ||
            rawResults.any { it.execution == Execution.NOT_STARTED } ||
            (report.config.policy.runHttps && report.https.execution == Execution.NOT_STARTED)
        val headline: String
        val nextStep: String
        when {
            report.stopReason == Failure.CANCELLED -> {
                headline = "检查已取消，结果可能不完整"
                nextStep = "保留首次与附加尝试的已有记录；需要完整观察时重新运行相同计划，取消不表示安全阻断。"
            }
            report.stopReason == Failure.NETWORK_CHANGED -> {
                headline = "网络变化，检查提前停止"
                nextStep = "本次结果不能用于完整前后对照；等待网络稳定后重建同目标计划，不将网络变化归因于修复。"
            }
            report.stopReason == Failure.TIMEOUT -> {
                headline = "总等待预算结束，检查可能不完整"
                nextStep = "查看各次尝试和未执行项目；其他项目成功不能补齐缺失观察，必要时明确复核相同计划。"
            }
            report.stopReason != null -> {
                headline = "检查提前停止，结果可能不完整"
                nextStep = "先查看停止原因与各项执行状态，不据此判断修复效果。"
            }
            !DiagnosticEvidence.stable(report) -> {
                headline = "网络条件不稳定或未确认"
                nextStep = "等待网络稳定并取得可用快照，保留相同目标与查询重新检查；本次差异不能用于定位原因。"
            }
            cancelled -> {
                headline = "检查已取消，结果可能不完整"
                nextStep = "需要完整对照时重新运行相同方案；取消不表示成功阻断或泄露。"
            }
            DiagnosticAttemptEvidence.incomplete(report) -> {
                headline = "部分尝试未完成，暂不作完整对照"
                nextStep = "查看逐次记录；聚合成功或失败不能补足取消、未执行或缺失的尝试。"
            }
            DiagnosticAttemptEvidence.mixed(report) -> {
                headline = "多次尝试结果不一致，先观察稳定性"
                nextStep = "保留首次失败和附加成功；需要时明确复核同一计划，不挑选较好结果，也不据此归因或自动更改 DNS。"
            }
            rows.all { it.status == "未测" } -> {
                headline = "本次尚无已执行的检查"
                nextStep = "选择一个场景、核对待测试字段，再开始检查。未测不能算作失败。"
            }
            pending -> {
                headline = "部分检查尚未执行"
                nextStep = "保留已完成观察，重新执行需要的项目后再对照；未执行的项目不能视为成功或失败。"
            }
            dnsDifference -> {
                val systemText = if (report.dns.execution == Execution.ERROR || report.dns.failure != null)
                    "系统 DNS 报错" else "系统 DNS 未取得地址"
                headline = "$systemText，${usableProtocols.joinToString("/")} 已返回地址"
                nextStep = "先核对系统错误阶段与响应码；同域也可能有查询类型、缓存和路径差异，不能直接归因。确需调整时记录原值、每次只改一项；权限、参数或未知系统错误先排查调用。"
            }
            systemEnabled && report.config.rawDns != null && !sameHost -> {
                headline = "查询域名不同或未确认，暂不对照"
                nextStep = "将系统 DNS 与原始 DNS 设为同一域名；原始查询先用 A，再重新检查。系统仍自行选择查询地址族。"
            }
            "RAW_PROTOCOL_DIFFERENCE" in findings -> {
                headline = "UDP 与 TCP 的地址结果不同"
                nextStep = findings.getValue("RAW_PROTOCOL_DIFFERENCE").actionHint
            }
            report.egress.verdict == Verdict.VIOLATE -> {
                headline = "本次 HTTPS 出口不符合预期"
                nextStep = "核对预期出口 IP、回显端点的可信性和代理规则，再以相同配置复测；这不是全机泄露判定。"
            }
            rows.last().status == "请求错误" -> {
                headline = "HTTPS 请求出错，出口尚未判定"
                nextStep = "查看 HTTPS 错误和回显格式，再以相同目标复测；DNS 返回地址不代表 HTTPS 可用，失败也不证明代理成功阻断。"
            }
            rows.any { it.status in setOf("解析错误", "查询错误", "结果缺失", "结果不唯一",
                    "响应错误", "响应不完整", "响应截断", "域名不存在", "无所需地址", "未返回可用地址") } -> {
                headline = "部分检查未取得有效地址结果"
                nextStep = "分别查看未完成或异常项目，核对域名、协议和响应码；其他项目成功不能补足这些证据。"
            }
            rows.last().status == "无法判定" -> {
                headline = "HTTPS 出口暂不能判定"
                nextStep = httpsNextStep(report)
            }
            report.egress.verdict == Verdict.MATCH -> {
                headline = "本次 HTTPS 出口符合预期"
                nextStep = "可保存为本应用的基线；验证 DNS、IPv6 或其他应用仍需要各自的探测与外部路径证据。"
            }
            systemUsable -> {
                headline = "系统 DNS 已返回地址"
                nextStep = "可保存为基线；地址返回不证明地址可连接、网站可用或 DNS 路径安全。"
            }
            usableProtocols.isNotEmpty() -> {
                headline = "${usableProtocols.joinToString("/")} DNS 已返回地址"
                nextStep = "保留查询记录；指定目标可能被 VPN 或网关接管，核验路径还需代理日志或外部证据。"
            }
            report.config.policy.runHttps -> {
                headline = "HTTPS 出口暂不能判定"
                nextStep = httpsNextStep(report)
            }
            else -> {
                headline = "本次未取得完整地址结果"
                nextStep = "先核对域名和各项错误，再复测相同方案；不要仅凭失败更换全部 DNS 或关闭安全设置。"
            }
        }
        val observations = rows.joinToString("；") { "${it.title}：${it.status}" }
        val boundary = "只观察本应用本次请求；DNS 实际路径仍未知，不能据此判定全机泄露或安全。"
        return ReportSummary(headline, "$observations。$boundary${DiagnosticAttemptEvidence.detail(report)}", rows, nextStep)
    }

    private fun systemRow(report: RunReport): ProbeSummary {
        val result = report.dns
        return when {
            !report.config.policy.runDns || result.execution == Execution.NOT_STARTED ->
                ProbeSummary("系统 DNS", "未测", "本次没有执行系统解析；不代表解析失败。")
            result.execution == Execution.CANCELLED || result.failure == Failure.CANCELLED ->
                ProbeSummary("系统 DNS", "已取消", "没有完整的系统解析结果；取消不说明域名或网络是否可用。")
            result.execution == Execution.ERROR || result.failure != null ->
                ProbeSummary("系统 DNS", "解析错误", SystemDnsDiagnostics.summary(report))
            DiagnosticEvidence.systemUsable(result) ->
                ProbeSummary("系统 DNS", "返回地址", "取得 ${result.addresses.size} 个地址；缓存、实际解析器和线上传输方式未知。")
            else -> ProbeSummary("系统 DNS", "未返回可用地址", "解析已结束，但没有可用数字地址；不能据此认定污染或泄露。")
        }
    }

    private fun rawRow(report: RunReport, transport: DnsTransport): ProbeSummary {
        val title = "${transport.name} DNS"
        if (transport !in DiagnosticEvidence.enabledTransports(report.config.rawDns))
            return ProbeSummary(title, "未测", "本次未启用此协议的原始 DNS 查询。")
        val matches = report.rawDns.filter { it.transport == transport }
        if (matches.size != 1) return ProbeSummary(title,
            if (matches.isEmpty()) "结果缺失" else "结果不唯一", "缺少唯一的本次观察；不能计为成功或失败。")
        val result = matches.single()
        return when {
            result.execution == Execution.NOT_STARTED -> ProbeSummary(title, "未测", "已选择此协议，但本次查询尚未执行。")
            result.execution == Execution.CANCELLED || result.failure == Failure.CANCELLED ->
                ProbeSummary(title, "已取消", "没有完整查询结果；取消不是成功阻断或泄露证据。")
            result.execution != Execution.COMPLETED || result.failure != null ->
                ProbeSummary(title, "查询错误", "${failureLabel(result.failure)}；没有有效响应，不能确定实际解析器或故障原因。")
            result.truncated -> ProbeSummary(title, "响应截断", "收到 TC 标记，不能视为完整地址结果；不会自动回退或重试。")
            result.responseCode == 3 -> ProbeSummary(title, "域名不存在", "收到 NXDOMAIN 声明；这不是返回地址，也不证明解析器身份或 DNS 污染。")
            result.responseCode == null -> ProbeSummary(title, "响应不完整", "缺少 DNS 响应码，不能认定查询成功。")
            result.responseCode != 0 -> ProbeSummary(title, "响应错误", "响应码为 ${result.responseCode}；需要结合域名和服务策略复核。")
            DiagnosticEvidence.rawUsable(result) -> ProbeSummary(title, "返回地址", "取得 ${result.addresses.size} 个地址；这是明文 DNS 探针，VPN 或网关仍可能接管目标。")
            else -> ProbeSummary(title, "无所需地址", "NOERROR 但没有可用的所需类型地址；不能仅凭响应码称解析可用。")
        }
    }

    private fun httpsRow(report: RunReport): ProbeSummary {
        val result = report.https
        if (!report.config.policy.runHttps || result.execution == Execution.NOT_STARTED)
            return ProbeSummary("HTTPS 出口", "未测", "没有执行 HTTPS 回显，无法推断本次出口是否符合预期。")
        if (result.execution == Execution.CANCELLED || result.failure == Failure.CANCELLED)
            return ProbeSummary("HTTPS 出口", "已取消", "未取得完整回显；取消不能证明阻断或泄露。")
        if (result.execution != Execution.COMPLETED || result.failure != null)
            return ProbeSummary("HTTPS 出口", "请求错误", "${failureLabel(result.failure)}；失败不等于出口不匹配。")
        val assessment = report.egress
        val status = when (assessment.verdict) {
            Verdict.MATCH -> "符合预期"
            Verdict.VIOLATE -> "不符合预期"
            else -> "无法判定"
        }
        return ProbeSummary("HTTPS 出口", status, assessment.reason)
    }

    private fun sameQueryHost(report: RunReport): Boolean {
        val system = report.config.dnsHost ?: return false
        val raw = report.config.rawDns?.host ?: return false
        return isDnsHost(system) && system.removeSuffix(".").lowercase(Locale.ROOT) == raw.removeSuffix(".").lowercase(Locale.ROOT)
    }

    private fun httpsNextStep(report: RunReport): String = when {
        report.config.endpoint == null -> "填写人工核验的 HTTPS 回显端点，再核对协议格式与预期出口 IP。"
        !report.config.policy.endpointTrustedByUser -> "人工核实并确认回显端点的可信性；不会根据一次响应自动信任端点。"
        report.config.policy.expectedSourceIps.isEmpty() -> "填写你独立确认的预期出口 IP；不要直接将本次观察值当作正确答案。"
        else -> "检查 HTTPS 错误和回显格式，以相同目标复测；失败不能证明代理成功阻断或发生泄露。"
    }

    private fun failureLabel(failure: Failure?): String = when (failure) {
        Failure.TIMEOUT -> "等待超时"
        Failure.CANCELLED -> "操作取消"
        Failure.DNS_FAILURE -> "系统解析失败"
        Failure.TLS_FAILURE -> "TLS 验证失败"
        Failure.IO_FAILURE -> "连接或读写失败"
        Failure.HTTP_STATUS -> "HTTP 状态不符合要求"
        Failure.REDIRECT_REJECTED -> "重定向已拒绝"
        Failure.RESPONSE_TOO_LARGE -> "响应超过限制"
        Failure.INVALID_ECHO -> "回显格式无效"
        Failure.INVALID_DNS -> "DNS 响应无效"
        Failure.NETWORK_CHANGED -> "网络条件改变"
        Failure.INTERNAL_ERROR -> "本次探测内部错误"
        null -> "未取得有效结果"
    }
}
