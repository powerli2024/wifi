package dev.proxyaudit.core

import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test

class MihomoConfigDoctorTest {
    private val provider = DnsProviders.get(QuickDnsTarget.CLOUDFLARE)

    @Test fun `missing dns gets concrete five field preview and leaves full original prefix`() {
        val source = "# local profile\nmixed-port: 7890\nrules:\n  - MATCH,DIRECT\n"
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertTrue(plan.repairedYaml.startsWith(source))
        assertEquals(setOf("dns.enable", "dns.nameserver", "dns.default-nameserver",
            "dns.proxy-server-nameserver", "dns.respect-rules"), plan.changes.map { it.path }.toSet())
        assertTrue(plan.repairedYaml.contains("nameserver: ['https://cloudflare-dns.com/dns-query']"))
        assertTrue(plan.warnings.any { "明文" in it })
        val hash = MessageDigest.getInstance("SHA-256").digest(source.toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        assertEquals(hash, plan.sourceSha256)
    }

    @Test fun `keeps valid bootstrap node resolvers and all non target original text`() {
        val source = """
            # 😀 节点注释
            proxies:
              - {name: '节点😀', type: ss, password: 'secret-on', server: 192.0.2.1, port: 443}
            dns:
              enable: false # keep comment
              nameserver:
                - 192.0.2.53
              default-nameserver: ['tls://9.9.9.9:853']
              proxy-server-nameserver: ['https://node-dns.example/query?token=secret']
              nameserver-policy:
                '+.lan': '192.0.2.54'
              fallback: [8.8.8.8]
              direct-nameserver: [system]
              ipv6: true
            tun:
              enable: true
              dns-hijack: ['any:53']
            rules: [MATCH,DIRECT]
        """.trimIndent() + "\n"
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertEquals(setOf("dns.enable", "dns.nameserver", "dns.respect-rules"),
            plan.changes.map { it.path }.toSet())
        assertTrue(plan.repairedYaml.startsWith(source.substringBefore("dns:")))
        assertTrue(plan.repairedYaml.endsWith(source.substringAfter("tun:").let { "tun:$it" }))
        assertTrue(plan.repairedYaml.contains("default-nameserver: ['tls://9.9.9.9:853']"))
        assertTrue(plan.repairedYaml.contains("proxy-server-nameserver: ['https://node-dns.example/query?token=secret']"))
        assertTrue(plan.repairedYaml.contains("nameserver-policy:\n    '+.lan': '192.0.2.54'"))
        assertTrue(plan.repairedYaml.contains("enable: true # keep comment"))
        assertTrue(plan.warnings.any { "dns.nameserver-policy" in it })
        assertTrue(plan.warnings.any { "引导解析" in it })
        assertFalse(plan.changes.toString().contains("secret"))
    }

    @Test fun `repair is byte idempotent and second preview empty`() {
        val once = MihomoConfigDoctor.repair("mixed-port: 7890", provider)
        val twice = MihomoConfigDoctor.repair(once.repairedYaml, provider)
        assertEquals(once.repairedYaml, twice.repairedYaml)
        assertTrue(twice.changes.isEmpty())
    }

    @Test fun `flow field values and CRLF and supplementary characters retain boundaries`() {
        val source = "# 🚀\r\nname: '保留😀'\r\ndns:\r\n  enable: false\r\n  nameserver: [1.1.1.1, 8.8.8.8]\r\n  ipv6: false\r\nrules: ['MATCH,DIRECT']"
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertTrue(plan.repairedYaml.startsWith("# 🚀\r\nname: '保留😀'\r\n"))
        assertTrue(plan.repairedYaml.endsWith("rules: ['MATCH,DIRECT']"))
        assertTrue(plan.repairedYaml.contains("  ipv6: false\r\n"))
        assertFalse(plan.repairedYaml.replace("\r\n", "").contains('\n'))
    }

    @Test fun `inserts before explicit document end`() {
        val plan = MihomoConfigDoctor.repair("---\nmixed-port: 7890\n...\n", provider)
        assertTrue(plan.repairedYaml.endsWith("...\n"))
        assertTrue(plan.repairedYaml.indexOf("dns:") < plan.repairedYaml.indexOf("..."))
        assertTrue(MihomoConfigDoctor.repair(plan.repairedYaml, provider).changes.isEmpty())
    }

    @Test fun `empty scalar enable and explicit empty resolver lists can be fixed`() {
        val source = "dns:\n  enable:\n  nameserver: []\n  default-nameserver: []\n  proxy-server-nameserver: []\n"
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertTrue(plan.repairedYaml.contains("enable: true"))
        assertEquals(5, plan.changes.size)
    }

    @Test fun `all previews hide upstream credentials and parameters`() {
        val source = "dns:\n  nameserver: ['https://user:password@resolver.example/path?token=TOPSECRET#DIRECT']\n"
        val inspection = MihomoConfigDoctor.inspect(source)
        val plan = MihomoConfigDoctor.repair(source, provider)
        val display = inspection.toString() + plan.changes + plan.warnings
        for (secret in listOf("user:", "password", "TOPSECRET", "resolver.example"))
            assertFalse(display.contains(secret))
        assertTrue(plan.changes.first { it.path == "dns.nameserver" }.before.contains("隐藏"))
    }

    @Test fun `missing fields do not assert core configuration is invalid or leakage proven`() {
        val result = MihomoConfigDoctor.inspect("dns:\n  enable: true\n")
        assertTrue(result.findings.any { "省略与显式空列表不同" in it })
        assertTrue(result.findings.any { "尚未验证" in it })
        assertFalse(result.summary.contains("无泄露"))
    }

    @Test fun `h3 conflicts refuse even when old respect rules false`() {
        for (source in listOf(
            "dns:\n  respect-rules: true\n  prefer-h3: true\n",
            "dns:\n  respect-rules: false\n  prefer-h3: true\n",
            "dns:\n  nameserver: ['https://resolver.example/dns-query#h3=true']\n",
            "dns:\n  fallback: ['https://resolver.example/dns-query#%68%33=true']\n",
            "dns:\n  fallback: ['https://resolver.example/dns-query#h3']\n"
        )) assertRejected(source, "H3")
    }

    @Test fun `URL decoded DNS parameters match core behavior without form decoding`() {
        assertRejected("dns:\n  proxy-server-nameserver: ['https://dns.quad9.net/dns-query#%68%33=true']\n", "H3")
        val inspection = MihomoConfigDoctor.inspect(
            "dns:\n  nameserver: ['https://resolver.example/query#skip%2Dcert%2Dverify=true']\n")
        assertTrue(inspection.findings.any { "跳过" in it && "证书" in it })
        val source = "dns:\n  proxy-server-nameserver: ['https://dns.quad9.net/dns-query#h3=%66alse&proxy+group']\n"
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertTrue(plan.repairedYaml.contains("#h3=%66alse&proxy+group"))
        assertTrue(MihomoConfigDoctor.repair(plan.repairedYaml, provider).changes.isEmpty())
    }

    @Test fun `malformed fragment encodings refuse with safe public exception`() {
        for (fragment in listOf("%", "%ZZ", "%FF", "%C3%28")) {
            val source = "dns:\n  nameserver: ['https://resolver.example/query#$fragment']\n"
            assertRejected(source, "参数")
            try { MihomoConfigDoctor.inspect(source); fail("Expected rejection") }
            catch (error: ConfigRejectedException) {
                assertFalse(error.message.orEmpty().contains("resolver.example"))
                assertFalse(error.message.orEmpty().contains(fragment))
                assertNull(error.cause)
            }
        }
    }

    @Test fun `foreign profiles and unidentified YAML cannot become Mihomo copies`() {
        for (source in listOf(
            "services:\n  web:\n    image: nginx\n",
            "inbounds: []\noutbounds: []\ndns:\n  servers: []\n",
            "outbounds: []\ndns:\n  enable: true\n",
            "mixed-port: 7890\ndns:\n  servers: []\n",
            "route:\n  rules: []\nmixed-port: 7890\n",
            "apiVersion: v1\nkind: ConfigMap\n",
            "custom:\n  token: secret\n",
            "dns:\n  servers: []\n",
            "dns:\n  ipv6: true\n"
        )) {
            assertRejected(source)
            val inspection = MihomoConfigDoctor.inspect(source)
            assertTrue(inspection.summary.contains("未确认"))
            assertFalse(inspection.toString().contains("secret"))
        }
        assertTrue(MihomoConfigDoctor.repair("custom: kept\nrules: []\n", provider)
            .repairedYaml.startsWith("custom: kept\nrules: []\n"))
    }

    @Test fun `unsupported existing bootstrap or node list refuses instead of overwriting`() {
        for (source in listOf(
            "dns:\n  default-nameserver: ['https://resolver.example/dns-query']\n",
            "dns:\n  proxy-server-nameserver: ['custom-resolver://opaque-secret']\n",
            "dns:\n  proxy-server-nameserver: invalid-secret\n"
        )) assertRejected(source)
    }

    @Test fun `system bootstrap remains explicitly preserved and uncertain`() {
        val plan = MihomoConfigDoctor.repair("dns:\n  default-nameserver: [system]\n", provider)
        assertTrue(plan.repairedYaml.contains("default-nameserver: [system]"))
        assertFalse(plan.changes.any { it.path == "dns.default-nameserver" })
        assertTrue(plan.warnings.any { "保留了已有引导" in it })
    }

    @Test fun `adding fields after final preserved mapping does not consume that mapping`() {
        val source = "dns:\n  nameserver-policy:\n    '+.lan': ['192.0.2.53']\nrules: ['MATCH,DIRECT']\n"
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertTrue(plan.repairedYaml.contains("  nameserver-policy:\n    '+.lan': ['192.0.2.53']\n"))
        assertTrue(plan.repairedYaml.endsWith("rules: ['MATCH,DIRECT']\n"))
        assertTrue(MihomoConfigDoctor.repair(plan.repairedYaml, provider).changes.isEmpty())
    }

    @Test fun `block list patch keeps following external comments and section together`() {
        val suffix = "\n# rules comment with secret placeholder\nrules: ['MATCH,DIRECT']\n"
        val source = "dns:\n  nameserver:\n    - 8.8.8.8" + suffix
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertTrue(plan.repairedYaml.endsWith(suffix))
        assertTrue(MihomoConfigDoctor.repair(plan.repairedYaml, provider).changes.isEmpty())
    }

    @Test fun `insertion preserves inline comment on last non target field`() {
        val source = "dns:\n  ipv6: true # untouched comment\nrules: ['MATCH,DIRECT']\n"
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertTrue(plan.repairedYaml.contains("  ipv6: true # untouched comment\n"))
        assertTrue(plan.repairedYaml.endsWith("rules: ['MATCH,DIRECT']\n"))
    }

    @Test fun `all ambiguous yaml structures are rejected with sanitized errors`() {
        val cases = listOf(
            "{\"dns\":{\"enable\":true}}",
            "{dns: {enable: true}}",
            "- secret",
            "dns: {enable: true}",
            "dns: secret",
            "dns:\n  nameserver: [1.1.1.1]\n  nameserver: [8.8.8.8]\n",
            "dns:\n  enable: false\n'dns':\n  enable: true\n",
            "dns:\n  enable: true\n---\nsecret: true\n",
            "base: &value [1.1.1.1]\ndns:\n  nameserver: *value\n",
            "base: &value {enable: true}\ndns:\n  <<: *value\n",
            "dns:\n  <<: {enable: true}\n",
            "secret: !!java.net.URL ['https://secret.example']\n",
            "secret: !untrusted value\n",
            "? [secret, complex]\n: value\n",
            "secret: [unterminated\n"
        )
        for (source in cases) assertRejected(source)
    }

    @Test fun `size unicode depth and node limits are enforced`() {
        assertRejected("#" + "a".repeat(256 * 1024))
        assertRejected("name: '" + "汉".repeat(90_000) + "'")
        assertRejected("name: '\uD800'")
        assertRejected("data: " + "[".repeat(45) + "0" + "]".repeat(45))
        assertRejected("data: [" + List(20_001) { "x" }.joinToString(",") + "]")
    }

    @Test fun `invalid selected provider cannot inject credentials routing or yaml`() {
        for (bad in listOf(
            provider.copy(ipv4 = "resolver.example"),
            provider.copy(dohUrl = "https://user:secret@resolver.example/query"),
            provider.copy(dohUrl = "https://resolver.example/query?token=secret"),
            provider.copy(dohUrl = "https://resolver.example/query#DIRECT"),
            provider.copy(dohUrl = "http://resolver.example/query")
        )) {
            try { MihomoConfigDoctor.repair("mixed-port: 7890\n", bad); fail("Expected refusal") }
            catch (error: IllegalArgumentException) { assertFalse(error.message.orEmpty().contains("secret")) }
        }
    }

    @Test fun `keeps plaintext scalar spellings dates and unknown fields outside dns byte for byte`() {
        val source = "custom:\n  switch: on\n  date: 2026-10-21\n  password: 012345\n  text: |\n    dns: fake\n    keep this\nrules: [MATCH,DIRECT]\n"
        val plan = MihomoConfigDoctor.repair(source, provider)
        assertTrue(plan.repairedYaml.startsWith(source))
        assertTrue(MihomoConfigDoctor.repair(plan.repairedYaml, provider).changes.isEmpty())
    }

    private fun assertRejected(source: String, expected: String? = null) {
        try { MihomoConfigDoctor.repair(source, provider); fail("Expected fixed, safe rejection") }
        catch (error: IllegalArgumentException) {
            assertTrue(error is ConfigRejectedException)
            assertFalse(error.message.orEmpty().contains("secret", true))
            assertFalse(error.message.orEmpty().contains("opaque"))
            assertFalse(error.message.orEmpty().contains("resolver.example"))
            if (expected != null) assertTrue(error.message.orEmpty().contains(expected))
            assertNull(error.cause)
        }
    }
}
