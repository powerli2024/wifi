package dev.proxyaudit.core

import java.util.Locale

enum class DnsRepairKind(val label: String) {
    COLLECT_EVIDENCE("补充观察"), CHECK_API("排查应用与系统调用"),
    REVIEW_SYSTEM_SETTINGS("手动核对系统设置"), REVIEW_MIHOMO_CONFIG("审查 Mihomo 配置"),
    KEEP_DNS("暂不修改 DNS")
}

data class DnsRepairRecommendation(
    val id: String,
    val title: String,
    val reason: String,
    val steps: List<String>,
    val repairKind: DnsRepairKind,
    val blindSpots: List<String>,
    val recoveryAdvice: String
)

data class DnsRepairAdvice(
    val sourceLabel: String,
    val sourceRunId: String?,
    val baselineLabel: String,
    val recommendations: List<DnsRepairRecommendation>
)

/** Fixed, local advice only: no probes, platform calls, provider selection or configuration changes. */
object DnsRepairAdvisor {
    fun advise(report: RunReport?, baseline: RunReport? = null): DnsRepairAdvice {
        val source = when (report?.evidenceOrigin) {
            EvidenceOrigin.ANDROID_RUNTIME -> "依据所选实际检查记录；仅限本应用，不是当前网络的实时状态。"
            EvidenceOrigin.SYNTHETIC_FIXTURE -> "依据演示示例；不是当前设备测量，不能用于修复诊断。"
            null -> "尚无检查记录；当前没有可以定位 DNS 问题的证据。"
        }
        return DnsRepairAdvice(source,
            report?.takeIf { it.evidenceOrigin == EvidenceOrigin.ANDROID_RUNTIME }?.runId,
            baselineLabel(report, baseline), recommendations(report))
    }

    private fun baselineLabel(report: RunReport?, baseline: RunReport?): String = when {
        baseline == null -> "尚未保存实际检查基线；没有修复前后对照。"
        baseline.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME -> "所选基线是演示数据，不能用于实际对照。"
        report == null || report.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME ->
            "已有实际检查基线，但当前没有可与之对照的实际记录。"
        baseline.runId == report.runId -> "当前实际记录已保存为基线；尚无另一份独立复测记录。"
        baseline.stopReason != null || report.stopReason != null -> "至少一份记录提前停止，暂不能形成完整前后对照。"
        DiagnosticAttemptEvidence.mixed(baseline) || DiagnosticAttemptEvidence.mixed(report) ->
            "至少一份记录的多次尝试结果不一致；暂不能据此判定修复效果。"
        else -> ReportComparison.compare(baseline, report).summary
    }

    private fun recommendations(report: RunReport?): List<DnsRepairRecommendation> {
        fun single(id: String, title: String, reason: String, kind: DnsRepairKind,
                   vararg steps: String) = listOf(action(report, id, title, reason, kind, steps.toList()))
        if (report == null) return single("NO_EVIDENCE", "先取得实际检查记录",
            "没有运行结果时不能选择 DNS 修复方案。", DnsRepairKind.COLLECT_EVIDENCE,
            "先使用系统 DNS 检查，核对待查询域名后运行。", "需要协议对照时再明确选择原始 DNS；不会自动增加网络请求。")
        if (report.evidenceOrigin != EvidenceOrigin.ANDROID_RUNTIME) return single("DEMO_ONLY", "先运行实际检查",
            "这是一组虚构示例；示例错误或成功均不表示当前手机的状态。", DnsRepairKind.COLLECT_EVIDENCE,
            "离开演示，核对实际测试目标后运行。", "实际记录才可作为排查与基线的来源；不要按演示修改设置。")
        when (report.stopReason) {
            Failure.CANCELLED -> return single("RUN_CANCELLED", "保留已取消记录，暂不改 DNS",
                "运行已停止，部分探针或附加尝试可能未执行；已有成功项不能补齐缺失证据。",
                DnsRepairKind.COLLECT_EVIDENCE, "需要完整观察时，明确重新运行相同计划；保留取消记录。")
            Failure.NETWORK_CHANGED -> return single("NETWORK_CHANGED", "等网络稳定后重建对照",
                "运行因网络变化停止，不能把变化前后的观察归因于 DNS 设置。",
                DnsRepairKind.COLLECT_EVIDENCE, "保持目标与协议不变，在稳定网络下重新检查；环境改变的记录分别保存。")
            Failure.TIMEOUT -> return single("RUN_BUDGET_EXHAUSTED", "区分总预算结束与解析失败",
                "本次总等待预算已结束，不能据聚合结果声称所有计划项目都完成。",
                DnsRepairKind.COLLECT_EVIDENCE, "查看每次尝试和未完成项目；保留失败记录，必要时明确复核相同计划。")
            null -> Unit
            else -> return single("RUN_STOPPED", "先核对运行提前停止的原因",
                "本次运行提前停止，现有记录不支持完整的修复前后对照。",
                DnsRepairKind.COLLECT_EVIDENCE, "查看停止状态和各探针记录，解决执行问题后再检查相同计划。")
        }
        if (!DiagnosticEvidence.stable(report)) return single("NETWORK_UNCONFIRMED", "先确认稳定的网络条件",
            "网络变化、配置变化或快照缺失会影响观察，当前不能定位 DNS 原因。",
            DnsRepairKind.COLLECT_EVIDENCE, "等待网络稳定，并取得完整前后快照。", "保留相同目标和查询复测；更换目标属于新的实验。")
        if (DiagnosticAttemptEvidence.incomplete(report)) return single("ATTEMPT_INCOMPLETE", "先核对未完成的尝试",
            "尝试记录包含未完成或取消项；聚合结果不能代表整份计划完整执行。",
            DnsRepairKind.COLLECT_EVIDENCE, "保留各次记录，需要完整观察时明确重跑相同计划。")
        if (DiagnosticAttemptEvidence.mixed(report)) return single("ATTEMPTS_DISAGREE", "保留失败与成功，先观察稳定性",
            "同一探针的不同尝试出现不同可用性结果；附加尝试成功不删除首次失败，也不足以归因于某项修复。",
            DnsRepairKind.COLLECT_EVIDENCE, "逐次核对错误、响应码和耗时；不要挑选较好的结果代表全程。",
            "必要时明确复核相同计划并保留所有尝试，不自动换目标或更改 DNS。")

        val system = report.dns
        val systemEnabled = report.config.policy.runDns
        val raw = report.config.rawDns
        val enabled = DiagnosticEvidence.enabledTransports(raw)
        val observations = enabled.mapNotNull { protocol -> report.rawDns.singleOrNull { it.transport == protocol } }
        if (!systemEnabled && raw == null) return single("DNS_NOT_SELECTED", "需要 DNS 诊断时补测系统解析",
            "本计划未选择 DNS 检查；HTTPS 结果不能定位 DNS 配置问题。", DnsRepairKind.COLLECT_EVIDENCE,
            "先选择系统 DNS 检查并确认域名；现有 HTTPS 记录单独保留。")
        if ((systemEnabled && system.execution in listOf(Execution.NOT_STARTED, Execution.CANCELLED)) ||
            (systemEnabled && system.failure in listOf(Failure.CANCELLED, Failure.NETWORK_CHANGED, Failure.INTERNAL_ERROR)) ||
            observations.size != enabled.size || observations.any {
                it.execution in listOf(Execution.NOT_STARTED, Execution.CANCELLED) ||
                    it.failure in listOf(Failure.CANCELLED, Failure.NETWORK_CHANGED, Failure.INTERNAL_ERROR)
            }) return single("DNS_INCOMPLETE", "先补齐未执行或缺失的 DNS 观察",
            "所选 DNS 项目没有完整、唯一的结果；不能把缺失或取消当作解析失败。",
            DnsRepairKind.COLLECT_EVIDENCE, "查看执行状态与内部错误，需要时完成相同计划；保留原记录。")

        val result = mutableListOf<DnsRepairRecommendation>()
        if (systemEnabled) result += systemAction(report)
        if (systemEnabled && raw != null && !sameHost(report)) {
            result.add(0, action(report, "QUERY_NOT_COMPARABLE", "先确认两种查询使用同一域名",
                "系统查询域名缺失、不可验证或与原始查询不同，不能用原始查询成功定位系统解析问题。",
                DnsRepairKind.COLLECT_EVIDENCE, listOf("在本地核对两个域名；脱敏记录不能补出原始域名。",
                    "新对照先使用同一域名与原始 A 查询；系统仍自行选择查询地址族。")))
        }
        val systemDifference = systemEnabled && sameHost(report) &&
            !DiagnosticEvidence.systemUsable(system) && observations.any(DiagnosticEvidence::rawUsable)
        if (systemDifference) {
            result += action(report, "SYSTEM_RAW_DIFFERENCE", "把同域结果差异作为排查线索",
                "原始查询取得地址而系统解析没有；这只证明两种方式行为不同，不确定责任方或实际解析器。",
                DnsRepairKind.COLLECT_EVIDENCE, listOf("对照系统错误阶段、响应码及原始查询类型；缓存、A/AAAA 选择和规则仍可能不同。",
                    "保留相同域名、服务器和协议复核；更换目标或记录类型应另建实验。"))
            // Review settings only after a complete, stable same-host comparison with a timeout.
            // API errors, negative answers and legacy unknown failures must not route to DNS replacement.
            if (system.failure == Failure.TIMEOUT && system.diagnosticStage == null &&
                observations.all(DiagnosticEvidence::rawUsable)) {
                result += action(report, "REVIEW_SYSTEM_DNS", "手动核对系统与 VPN 的 DNS 设置",
                    "相同域名原始查询有地址、系统查询超时，适合检查设置之间是否存在冲突；仍未确定根因。",
                    DnsRepairKind.REVIEW_SYSTEM_SETTINGS, listOf("先记录 Private DNS 原模式、提供商主机名和当前 VPN 的 DNS 设置。",
                        "核对当前网络是否依赖局域网或企业解析；不要将私有名称统一交给公共 DNS。",
                        "只有确认一项具体设置与目标不符时才手动调整；每次只改一项，再复测同一计划。"))
                if (report.networkAfter.vpnCapability == true) result += action(report, "REVIEW_MIHOMO_DNS", "若使用 Mihomo，审查实际生效配置",
                    "快照显示 VPN 能力，但不能识别客户端或证明配置已加载；配置审查只是候选行动。",
                    DnsRepairKind.REVIEW_MIHOMO_CONFIG, listOf("先确认当前客户端、核心版本与真正生效的配置来源。",
                        "选取本人授权的 YAML，检查 DNS 启用、引导、节点解析、规则与客户端覆盖；先看逐项变更预览。",
                        "保留原配置，只导出新副本；导出不等于导入或生效，DoH 也不保证经过代理或无泄露。"))
            }
        }
        val rawProblem = observations.any { !DiagnosticEvidence.rawUsable(it) }
        if (rawProblem) result += rawAction(report, observations)
        if (!systemEnabled && !rawProblem) result += action(report, "RAW_ADDRESSES_ONLY", "暂不因原始查询成功修改 DNS",
            "所选原始查询取得地址，但系统解析未测；响应不能证明解析器身份、加密或路径。",
            DnsRepairKind.KEEP_DNS, listOf("若目标是系统解析可用性，再明确选择同域系统解析进行对照。"))
        if (report.config.policy.runHttps &&
            (report.https.execution == Execution.ERROR || report.https.failure != null || report.egress.verdict == Verdict.VIOLATE)) {
            result += action(report, "HTTPS_SEPARATE", "单独核对 HTTPS 与出口要求",
                "HTTPS 错误或出口不符合预期，不能仅靠更换 DNS 修复或解释。",
                DnsRepairKind.KEEP_DNS, listOf("查看证书、连接、状态码、回显格式及端点可信性；不要关闭证书验证。",
                    "预期出口 IP 应来自独立确认，不把观察值直接设为正确答案。"))
        }
        return result
    }

    private fun systemAction(report: RunReport): DnsRepairRecommendation {
        val result = report.dns
        fun item(id: String, title: String, kind: DnsRepairKind, vararg steps: String) =
            action(report, id, title, SystemDnsDiagnostics.summary(report), kind, steps.toList())
        if (DiagnosticEvidence.systemUsable(result)) return item("SYSTEM_ADDRESSES", "已有系统地址结果，暂不改 DNS",
            DnsRepairKind.KEEP_DNS, "保留当前观察或保存为基线；地址返回不保证网站可用，也不是隐私路径验证。")
        if (result.failure == Failure.TIMEOUT) return item("SYSTEM_TIMEOUT", "先复核系统解析超时",
            DnsRepairKind.COLLECT_EVIDENCE, "保持域名、协议与等待预算不变，必要时明确复核一次并保留首次失败。",
            "若选择明文 UDP/TCP 对照，它不继承系统 Private DNS；不必为此关闭 Private DNS。")
        return when (result.diagnosticStage) {
            SystemDnsStage.LOCAL_EXCEPTION -> when (result.exceptionKind) {
                SystemDnsExceptionKind.SECURITY -> item("SYSTEM_PERMISSION", "先核对应用权限与系统策略", DnsRepairKind.CHECK_API,
                    "核对应用的网络权限声明、系统或设备管理策略与 Android 版本；不要索取无关高权限。",
                    "保存安全异常类别；先解决调用限制，不用替换 DNS 掩盖权限问题。")
                SystemDnsExceptionKind.INVALID_ARGUMENT -> item("SYSTEM_ARGUMENT", "先核对查询输入与 API 参数", DnsRepairKind.CHECK_API,
                    "核对域名格式、查询参数和 Android API 兼容性。", "修正输入或调用问题后重建计划；不要先改解析器。")
                else -> item("SYSTEM_LOCAL_ERROR", "先排查本地调用与执行状态", DnsRepairKind.CHECK_API,
                    "核对线程中断、取消与 API 兼容性；本地异常不是服务器的 DNS 响应。")
            }
            SystemDnsStage.ERROR_CALLBACK -> item(
                if (result.resolverErrorCode == 0) "SYSTEM_PARSE_ERROR" else "SYSTEM_API_ERROR",
                "保留解析器错误码，先排查系统调用", DnsRepairKind.CHECK_API,
                "保留 ERROR_CALLBACK、解析器错误码和已记录的数字 errno；无 errno 时明确未知。",
                "结合 Android 版本核对默认 DNS 网络、查询提交与响应处理；不要仅凭错误码归责 VPN、运营商或服务器。")
            SystemDnsStage.ANSWER_CALLBACK -> when (result.responseCode) {
                3 -> item("SYSTEM_NXDOMAIN", "先核对域名与名称过滤策略", DnsRepairKind.KEEP_DNS,
                    "核对拼写、是否应存在及是否属于企业或局域网私有名称。",
                    "核对当前服务的过滤策略；负响应不是自动替换公共 DNS 的理由。")
                0 -> item("SYSTEM_EMPTY_ANSWER", "先核对查询类型与记录是否存在", DnsRepairKind.COLLECT_EVIDENCE,
                    "核对所需 A/AAAA 记录、别名链和工具支持范围；NOERROR 不保证有地址。",
                    "不要仅因缺少 AAAA 关闭 IPv6，或认定 IPv6 被安全阻断。")
                null -> item("SYSTEM_DETAIL_MISSING", "先补充系统响应详情", DnsRepairKind.COLLECT_EVIDENCE,
                    "保留本记录，使用能记录响应码的检查复核同一计划。")
                else -> item("SYSTEM_NEGATIVE_RESPONSE", "结合响应码核对域名与服务策略", DnsRepairKind.COLLECT_EVIDENCE,
                    "保留响应码，核对域名、服务器策略与同目标对照；单次错误不能定位责任方。")
            }
            null -> item("SYSTEM_DETAIL_MISSING", "先补充系统错误阶段与响应详情", DnsRepairKind.COLLECT_EVIDENCE,
                "旧记录只有失败状态时，用支持详情的版本复核相同计划。",
                "不要从很短的耗时或 DNS_FAILURE 推断污染、封锁或需要更换 DNS。")
        }
    }

    private fun rawAction(report: RunReport, observations: List<RawDnsObservation>): DnsRepairRecommendation {
        val negative = observations.filter { it.execution == Execution.COMPLETED && it.failure == null }
        val truncated = negative.any { it.truncated }
        val nxdomain = negative.any { !it.truncated && it.responseCode == 3 }
        val difference = observations.size == 2 && observations.any(DiagnosticEvidence::rawUsable) &&
            observations.any { !DiagnosticEvidence.rawUsable(it) }
        val id = when { truncated -> "RAW_TRUNCATED"; nxdomain -> "RAW_NXDOMAIN";
            difference -> "RAW_PROTOCOL_DIFFERENCE"; else -> "RAW_NO_USABLE_ANSWER" }
        val reason = observations.joinToString("；") { result ->
            val state = when {
                DiagnosticEvidence.rawUsable(result) -> "取得地址"
                result.failure != null -> "未取得有效响应（${result.failure.name}）"
                result.truncated -> "TC 截断"
                result.responseCode == 3 -> "NXDOMAIN（rcode=3）"
                result.responseCode != null -> "rcode=${result.responseCode}，未取得所需地址"
                else -> "响应码未知，未取得有效地址"
            }
            "${result.transport.name}：$state"
        } + "。这是协议观察，不确定实际解析器身份或路径。"
        return action(report, id, if (difference) "保留 UDP/TCP 差异，先复核同一目标" else "先核对原始 DNS 响应与查询条件",
            reason, if (nxdomain && !truncated) DnsRepairKind.KEEP_DNS else DnsRepairKind.COLLECT_EVIDENCE,
            listOf(when { truncated -> "TC 表示响应不完整；查看独立 TCP 结果，需要时另选 TCP 检查，不自动回退。"
                nxdomain -> "核对域名是否存在、私有域名及过滤策略；不要直接判定污染或统一换 DNS。"
                else -> "核对目标、端口、查询类型和错误；保留固定目标复核，不因单次失败更换全部 DNS。" },
                "TCP 成功不等于加密；明文原始探针不继承 Private DNS，也不要求关闭 Private DNS。"))
    }

    private fun sameHost(report: RunReport): Boolean {
        val system = report.config.dnsHost ?: return false
        val raw = report.config.rawDns?.host ?: return false
        return isDnsHost(system) && system.removeSuffix(".").lowercase(Locale.ROOT) == raw.removeSuffix(".").lowercase(Locale.ROOT)
    }

    private fun action(report: RunReport?, id: String, title: String, reason: String, kind: DnsRepairKind,
                       steps: List<String>): DnsRepairRecommendation {
        val synthetic = report?.evidenceOrigin == EvidenceOrigin.SYNTHETIC_FIXTURE
        val blindSpots = if (synthetic) listOf("演示数据不能诊断当前设备、验证网络或作为实际基线。") else buildList {
            add("仅限所选记录中本应用的请求；实际解析器、缓存、代理路径和其他应用行为仍未知。")
            if (report == null || !report.config.policy.runHttps || report.https.execution == Execution.NOT_STARTED)
                add("HTTPS 出口未测；DNS 有地址不证明网站可用或出口符合预期。")
            add("尚无 DoH/DoT 与独立网关路径验证；没有据此证明全机无泄露。")
        }
        val recovery = when (kind) {
            DnsRepairKind.REVIEW_SYSTEM_SETTINGS -> "本建议未改变任何设置。调整前离线记下原模式与主机名；若退化，仅恢复本次确切修改的原值，再复测。不要自动关闭 VPN、始终开启/阻断设置或证书验证。"
            DnsRepairKind.REVIEW_MIHOMO_CONFIG -> "本建议未修改或导入配置。保留可读原配置与客户端原选择；新副本不适用时重新选择原配置。导出、导入、生效与网络恢复需分别确认。"
            else -> "本建议未更改 DNS 或网络设置，无需撤销。保留当前记录；若此前另行改过设置，先核对并恢复确切原值，不猜测默认值。"
        }
        return DnsRepairRecommendation(id, title, reason, steps, kind, blindSpots, recovery)
    }
}

/** Availability per attempt, deliberately separate from egress policy and privacy verdicts. */
internal object DiagnosticAttemptEvidence {
    fun mixed(report: RunReport): Boolean = report.attempts.groupBy { it.probe }.values.any { attempts ->
        attempts.size > 1 && attempts.mapNotNull(::usable).toSet().size > 1
    }

    fun incomplete(report: RunReport): Boolean = report.attempts.any { attempt ->
        attempt.finishedAfterMillis == null || when (attempt.probe) {
            ProbeKind.SYSTEM_DNS -> attempt.dns?.let { it.execution in listOf(Execution.NOT_STARTED, Execution.CANCELLED) || it.failure == Failure.CANCELLED } ?: true
            ProbeKind.HTTPS -> attempt.https?.let { it.execution in listOf(Execution.NOT_STARTED, Execution.CANCELLED) || it.failure == Failure.CANCELLED } ?: true
            ProbeKind.RAW_UDP, ProbeKind.RAW_TCP -> attempt.rawDns?.let { it.execution in listOf(Execution.NOT_STARTED, Execution.CANCELLED) || it.failure == Failure.CANCELLED } ?: true
        }
    }

    fun detail(report: RunReport): String = if (report.attempts.isEmpty()) "" else
        "逐次观察：" + report.attempts.joinToString("；") { attempt ->
            val label = when (attempt.probe) { ProbeKind.SYSTEM_DNS -> "系统 DNS"; ProbeKind.HTTPS -> "HTTPS";
                ProbeKind.RAW_UDP -> "UDP DNS"; ProbeKind.RAW_TCP -> "TCP DNS" }
            val order = if (attempt.attemptNumber == 1) "首次" else "附加尝试 ${attempt.attemptNumber}"
            val state = when {
                attempt.finishedAfterMillis == null -> "尚无完成记录"
                execution(attempt) == Execution.CANCELLED || failure(attempt) == Failure.CANCELLED -> "已取消"
                execution(attempt) == Execution.NOT_STARTED -> "未执行"
                usable(attempt) == true -> if (attempt.probe == ProbeKind.HTTPS) "取得符合协议的回显（不代表出口策略符合）" else "取得地址"
                failure(attempt) != null -> "未取得有效结果（${failure(attempt)?.name}）"
                else -> "未取得有效地址或回显"
            }
            "$label $order：$state"
        } + "。若首次失败，聚合结果保留该失败，不以附加成功覆盖。"

    private fun usable(attempt: ProbeAttempt): Boolean? = when (attempt.probe) {
        ProbeKind.SYSTEM_DNS -> attempt.dns?.let(DiagnosticEvidence::systemUsable)
        ProbeKind.RAW_UDP, ProbeKind.RAW_TCP -> attempt.rawDns?.let(DiagnosticEvidence::rawUsable)
        ProbeKind.HTTPS -> attempt.https?.let { it.execution == Execution.COMPLETED && it.failure == null &&
            it.statusCode == 200 && it.tlsValidated && it.echoedRequestId == attempt.attemptId &&
            it.serverReportedSourceIp?.let(NumericIp::canonical) != null }
    }

    private fun execution(attempt: ProbeAttempt): Execution? = when (attempt.probe) {
        ProbeKind.SYSTEM_DNS -> attempt.dns?.execution
        ProbeKind.HTTPS -> attempt.https?.execution
        ProbeKind.RAW_UDP, ProbeKind.RAW_TCP -> attempt.rawDns?.execution
    }

    private fun failure(attempt: ProbeAttempt): Failure? = when (attempt.probe) {
        ProbeKind.SYSTEM_DNS -> attempt.dns?.failure
        ProbeKind.HTTPS -> attempt.https?.failure
        ProbeKind.RAW_UDP, ProbeKind.RAW_TCP -> attempt.rawDns?.failure
    }
}
