package dev.proxyaudit.core

import org.junit.Assert.*
import org.junit.Test

class ProfessionalScenariosTest {
    @Test fun `each supported scenario has complete independent field guidance`() {
        val guidance = ProfessionalScenario.values().map(ProfessionalScenarios::guidance)
        assertEquals(3, guidance.size)
        assertEquals(3, guidance.map { it.title }.toSet().size)
        assertTrue(guidance.all { it.title.isNotBlank() && it.purpose.isNotBlank() &&
            it.fieldHints.isNotEmpty() && it.fieldHints.all(String::isNotBlank) && it.boundary.isNotBlank() })
    }

    @Test fun `DNS comparison defaults describe same host A and deliberate plaintext transports`() {
        val guidance = ProfessionalScenarios.guidance(ProfessionalScenario.DNS_COMPARE)
        val fields = guidance.fieldHints.joinToString(" ")
        assertTrue(fields.contains("同一域名"))
        assertTrue(fields.contains("example.com"))
        assertTrue(fields.contains("类型先用 A"))
        assertTrue(fields.contains("UDP 和 TCP"))
        assertTrue(fields.contains("不启用 HTTPS"))
        assertTrue(guidance.boundary.contains("明文"))
        assertTrue(guidance.boundary.contains("不证明绕过 VPN"))
    }

    @Test fun `HTTPS guidance requires independent manual trust and expected IP decisions`() {
        val guidance = ProfessionalScenarios.guidance(ProfessionalScenario.HTTPS_EGRESS)
        val fields = guidance.fieldHints.joinToString(" ")
        assertTrue(fields.contains("人工填写"))
        assertTrue(fields.contains("不会自动授予信任"))
        assertTrue(fields.contains("不从本次观察结果自动填入"))
        assertTrue(guidance.boundary.contains("平台正常验证"))
        assertTrue(guidance.boundary.contains("不允许明文替代"))
        assertTrue(guidance.boundary.contains("不是全机"))
        val system = ProfessionalScenarios.guidance(ProfessionalScenario.DNS_SYSTEM)
        assertTrue(system.fieldHints.any { "不启用原始 UDP/TCP 或 HTTPS" in it })
    }
}
