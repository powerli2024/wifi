package dev.proxyaudit.core

enum class ProfessionalScenario { DNS_SYSTEM, DNS_COMPARE, HTTPS_EGRESS }

data class ScenarioGuidance(
    val title: String,
    val purpose: String,
    val fieldHints: List<String>,
    val boundary: String
)

/** Inert field guidance. Selecting a scenario neither runs probes nor grants endpoint trust. */
object ProfessionalScenarios {
    fun guidance(scenario: ProfessionalScenario): ScenarioGuidance = when (scenario) {
        ProfessionalScenario.DNS_SYSTEM -> ScenarioGuidance(
            "系统 DNS 检查",
            "先看本应用能否通过系统解析取得地址。",
            listOf("启用系统 DNS，查询域名默认 example.com，也可填写你要排查的域名。",
                "本场景不启用原始 UDP/TCP 或 HTTPS；不需要填写出口 IP。"),
            "系统自行管理查询地址族和缓存；返回地址不能显示实际解析器或线上路径。"
        )
        ProfessionalScenario.DNS_COMPARE -> ScenarioGuidance(
            "DNS 连通对照",
            "对照系统解析与指定目标的 UDP/TCP 地址结果。",
            listOf("系统 DNS 与原始 DNS 使用同一域名，默认 example.com；原始记录类型先用 A。",
                "指定数字 DNS 地址与端口，默认端口 53；同时启用 UDP 和 TCP。核对当前网络 DNS 或明确选择对照目标。",
                "本场景不启用 HTTPS；先保持同一目标、同一查询，完成后再单独改变一个条件。"),
            "UDP/TCP 原始查询是明文；系统仍可能查询不同地址族或使用缓存。指定数字 IP 不证明绕过 VPN，也不证明实际解析器身份。"
        )
        ProfessionalScenario.HTTPS_EGRESS -> ScenarioGuidance(
            "HTTPS 出口核验",
            "用可信回显端点对照你独立确认的预期出口 IP。",
            listOf("人工填写兼容本工具回显格式的 HTTPS 服务源地址，不附路径；工具使用固定 /v1/echo，本场景不自动填写公共回显服务。",
                "人工核实端点可信性，再明确确认信任；选择场景或收到响应都不会自动授予信任。",
                "人工填写预期出口 IP，不从本次观察结果自动填入。",
                "先只启用 HTTPS；若需要 DNS 对照，请单独选择对应场景。"),
            "只核验本应用本次 HTTPS 回显；TLS 使用平台正常验证，不允许明文替代。这不是全机、DNS 或 IPv6 无泄露证明。"
        )
    }
}
