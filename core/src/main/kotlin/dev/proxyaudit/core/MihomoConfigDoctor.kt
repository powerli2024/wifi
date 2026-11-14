package dev.proxyaudit.core

import java.io.StringReader
import java.net.URI
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import org.yaml.snakeyaml.events.AliasEvent
import org.yaml.snakeyaml.events.CollectionEndEvent
import org.yaml.snakeyaml.events.CollectionStartEvent
import org.yaml.snakeyaml.events.DocumentStartEvent
import org.yaml.snakeyaml.events.NodeEvent
import org.yaml.snakeyaml.events.ScalarEvent
import org.yaml.snakeyaml.nodes.MappingNode
import org.yaml.snakeyaml.nodes.Node
import org.yaml.snakeyaml.nodes.NodeTuple
import org.yaml.snakeyaml.nodes.ScalarNode
import org.yaml.snakeyaml.nodes.SequenceNode
import org.yaml.snakeyaml.nodes.Tag

data class ConfigInspection(val summary: String, val findings: List<String>)
data class ConfigChange(val path: String, val before: String, val after: String, val reason: String)
/** Only fixed, credential-free messages from this validator may be shown in the UI. */
class ConfigRejectedException internal constructor(message: String) : IllegalArgumentException(message)
data class ConfigRepairPlan(
    val repairedYaml: String,
    val changes: List<ConfigChange>,
    val warnings: List<String>,
    val sourceSha256: String
)

/** Offline file advice only. No provider fetch, DNS query, client control, or disk write. */
object MihomoConfigDoctor {
    private const val MAX_BYTES = 256 * 1024
    private const val MAX_DEPTH = 40
    private const val MAX_NODES = 20_000
    private val allowed = linkedSetOf(
        "enable", "nameserver", "default-nameserver", "proxy-server-nameserver", "respect-rules"
    )
    private val preserved = listOf(
        "nameserver-policy", "fallback", "fallback-filter", "direct-nameserver",
        "direct-nameserver-follow-policy", "proxy-server-nameserver-policy", "ipv6",
        "enhanced-mode", "fake-ip-filter", "listen"
    )
    private val mihomoRootKeys = setOf(
        "mixed-port", "port", "socks-port", "redir-port", "tproxy-port",
        "proxies", "proxy-groups", "proxy-providers", "rules", "rule-providers"
    )
    private val mihomoDnsKeys = allowed + setOf(
        "nameserver-policy", "fallback", "fallback-filter", "direct-nameserver",
        "direct-nameserver-follow-policy", "proxy-server-nameserver-policy",
        "enhanced-mode", "fake-ip-range", "fake-ip-filter", "prefer-h3"
    )
    private val foreignRootKeys = setOf(
        "inbounds", "outbounds", "inbound", "outbound", "route", "routing",
        "services", "apiVersion"
    )
    private val tags = setOf(Tag.STR.value, Tag.BOOL.value, Tag.INT.value, Tag.FLOAT.value,
        Tag.NULL.value, Tag.SEQ.value, Tag.MAP.value, Tag.TIMESTAMP.value, Tag.BINARY.value)

    fun inspect(source: String): ConfigInspection {
        val document = parse(source)
        profileRejection(document)?.let { message ->
            return ConfigInspection("已读取 YAML，但未确认它属于可自动修复的 Mihomo 配置。",
                listOf(message, "这里只判断文件结构；没有验证其他应用或核心配置，也没有修改文件。"))
        }
        val fields = document.dns?.let(::entries).orEmpty()
        val findings = mutableListOf(
            "这里只审查所选文件；客户端覆盖、核心版本、运行时路由和实际 DNS 路径尚未验证。"
        )
        if (document.dns == null) {
            findings += "未声明 dns 块；实际行为可能来自内核或客户端默认值，不能据此断定泄露。"
        } else {
            if (truth(fields["enable"]?.valueNode) != true)
                findings += "文件未明确启用内置 DNS；Android 客户端仍可能覆盖该设置。"
            inspectList(fields, "nameserver", findings)
            inspectList(fields, "default-nameserver", findings)
            inspectList(fields, "proxy-server-nameserver", findings)
            if (truth(fields["respect-rules"]?.valueNode) == true &&
                strings(fields["proxy-server-nameserver"]?.valueNode).isNullOrEmpty())
                findings += "respect-rules 已开启，但没有明确的非空节点解析器列表；当前 Mihomo 要求配置该依赖。"
            if (hasH3(document.dns))
                findings += "检测到 H3 设置；自动方案需要 respect-rules，必须先人工处理 H3 冲突。"
            if (hasParameter(document.dns, "skip-cert-verify"))
                findings += "检测到跳过 DNS 上游证书验证的参数；本次窄范围修复不会处理其他上游中的该参数。"
            for (key in preserved.filter(fields::containsKey))
                findings += "保留 dns.$key；它可能影响查询或路径，不属于本次自动覆盖范围。"
        }
        findings += "DoH 加密、来源 IP 相同或规则匹配均不证明全部 DNS 经过代理，也不证明全机无泄露。"
        return ConfigInspection("已完成有限的 Mihomo YAML 文件审查；尚未验证实际生效配置。", findings)
    }

    fun repair(source: String, provider: DnsProvider): ConfigRepairPlan {
        validateProvider(provider)
        val document = parse(source)
        profileRejection(document)?.let(::reject)
        val dns = document.dns
        val fields = dns?.let(::entries).orEmpty()
        if (dns != null && hasH3(dns))
            reject("检测到 DNS H3 设置，与本方案的 respect-rules 存在冲突；请先人工处理，原文件未修改。")

        val bootstrap = retainedList(fields["default-nameserver"]?.valueNode, true)
            ?: listOf(provider.ipv4)
        val proxy = retainedList(fields["proxy-server-nameserver"]?.valueNode, false)
            ?: listOf(provider.dohUrl)
        val desired = linkedMapOf(
            "enable" to Value.BooleanValue(true),
            "nameserver" to Value.StringList(listOf(provider.dohUrl)),
            "default-nameserver" to Value.StringList(bootstrap),
            "proxy-server-nameserver" to Value.StringList(proxy),
            "respect-rules" to Value.BooleanValue(true)
        )
        val changes = mutableListOf<ConfigChange>()
        val patches = mutableListOf<Patch>()
        val additions = mutableListOf<Pair<String, Value>>()
        for ((key, value) in desired) {
            val old = fields[key]?.valueNode
            if (value.matches(old)) continue
            changes += ConfigChange("dns.$key", before(old), value.render(), reason(key))
            if (old == null) additions += key to value
            else {
                val start = document.position(old.startMark.index)
                val end = document.position(contentEnd(old))
                val original = source.substring(start, end)
                val tail = original.substring(original.trimEnd(' ', '\t', '\r', '\n').length)
                val separator = if (start > 0 && source[start - 1] == ':') " " else ""
                patches += Patch(start, end, separator + value.render() + tail)
            }
        }
        val newline = if ("\r\n" in source) "\r\n" else "\n"
        if (additions.isNotEmpty()) {
            val at = if (dns == null) document.position(document.root.endMark.index)
                else insertionOffset(document, dns)
            val indent = dns?.value?.firstOrNull()?.keyNode?.startMark?.column ?: 2
            val prefix = if (at > 0 && source[at - 1] != '\n' && source[at - 1] != '\r') newline else ""
            val block = buildString {
                append(prefix)
                if (dns == null) append("dns:").append(newline)
                for ((key, value) in additions)
                    append(" ".repeat(indent)).append(key).append(": ").append(value.render()).append(newline)
            }
            patches += Patch(at, at, block)
        }
        val ordered = patches.sortedWith(compareBy<Patch> { it.start }.thenBy { it.end })
        for (index in 1 until ordered.size)
            if (ordered[index - 1].end > ordered[index].start)
                reject("无法确定互不重叠的安全修改区间；请人工处理，原文件未修改。")
        val repaired = StringBuilder(source).apply {
            for (patch in ordered.asReversed()) replace(patch.start, patch.end, patch.replacement)
        }.toString()
        val checked = parse(repaired)
        verifyUnchanged(document, checked)
        val repairedFields = entries(checked.dns ?: reject("修复副本校验失败；原文件未修改。"))
        if (desired.any { (key, value) -> !value.matches(repairedFields[key]?.valueNode) })
            reject("修复副本未满足预览的 DNS 变更；原文件未修改。")

        val warnings = mutableListOf(
            "副本尚未导入客户端；订阅更新、全局覆盖和追加系统 DNS 设置可能覆盖这些值。",
            "respect-rules 仅遵守已有路由规则；规则可能选择直连。本方案没有指定代理组或证明无泄露。",
            "仅更改预览列出的五类 DNS 字段；保留所有其他配置，包括节点、规则、TUN 和 IPv6。",
            "完整副本保留原配置凭据；请选择可信的保存位置，不要直接公开。"
        )
        if (bootstrap == listOf(provider.ipv4) &&
            strings(fields["default-nameserver"]?.valueNode).isNullOrEmpty())
            warnings += "新增的数字 IP 引导解析器使用普通明文 DNS；它用于解析 DNS 服务域名，未强制通过代理。"
        else warnings += "保留了已有引导解析器；其加密、出口和可达性未验证。"
        if (proxy.any { upstreamHost(it)?.let { host -> NumericIp.canonical(host) == null } == true })
            warnings += "节点解析器含域名，需要引导解析；节点解析本身不自动继承 respect-rules，且仍可能存在额外依赖。"
        if (proxy.any { '#' in it })
            warnings += "保留的节点解析器含显式出口或附加参数；需人工核对，避免代理节点解析循环。"
        for (key in preserved.filter(fields::containsKey))
            warnings += "dns.$key 保持原文；这条配置分支可能继续采用其他解析器或路径。"
        return ConfigRepairPlan(repaired, changes, warnings.distinct(), sha256(document.bytes))
    }

    private fun inspectList(fields: Map<String, NodeTuple>, key: String, findings: MutableList<String>) {
        val node = fields[key]?.valueNode
        if (node == null) {
            findings += "未声明 dns.$key；省略与显式空列表不同，实际值取决于内核和客户端。"
            return
        }
        val values = strings(node)
        if (values.isNullOrEmpty()) findings += "dns.$key 不是明确的非空字符串列表，需检查。"
        else if (values.any { !validUpstream(it, key == "default-nameserver") })
            findings += "dns.$key 含本工具无法安全验证的上游格式；自动修复不会猜测该配置的含义。"
        if (values?.any { it == "system" || it == "system://" ||
                NumericIp.canonical(it) != null || it.startsWith("udp://") ||
                it.startsWith("tcp://") || it.startsWith("http://") } == true)
            findings += "dns.$key 含系统解析或明文上游；这是配置观察，不是已确认的泄露。"
    }

    private fun retainedList(node: Node?, bootstrap: Boolean): List<String>? {
        if (node == null || node.tag == Tag.NULL) return null
        val values = strings(node)
            ?: reject("已有引导或节点 DNS 不是受支持的字符串列表；请人工处理，原文件未修改。")
        if (values.isEmpty()) return null
        if (values.any { !validUpstream(it, bootstrap) })
            reject("已有引导或节点 DNS 含无法安全确认的上游格式；请人工处理，原文件未修改。")
        return values
    }

    private fun validUpstream(value: String, bootstrap: Boolean): Boolean {
        if (value.isEmpty() || value != value.trim() || value.length > 2048 ||
            value.any { it.code < 32 || it.code == 127 }) return false
        if (value == "system" || value == "system://" || NumericIp.canonical(value) != null) return true
        return try {
            val uri = URI(if ("://" in value) value else "udp://$value")
            val host = uri.host?.removeSurrounding("[", "]") ?: return false
            if (uri.scheme !in setOf("udp", "tcp", "tls", "https", "http", "quic") ||
                uri.port !in -1..65535 || uri.port == 0 || uri.rawUserInfo != null) return false
            if (bootstrap) NumericIp.canonical(host) != null
            else NumericIp.canonical(host) != null || isDnsHost(host)
        } catch (_: Exception) { false }
    }

    private fun upstreamHost(value: String): String? = try {
        URI(if ("://" in value) value else "udp://$value").host?.removeSurrounding("[", "]")
    } catch (_: Exception) { null }

    private fun validateProvider(provider: DnsProvider) {
        if (NumericIp.canonical(provider.ipv4) == null || ':' in provider.ipv4)
            reject("所选 DNS 服务的数字 IPv4 地址无效。")
        val uri = try { URI(provider.dohUrl) } catch (_: Exception) { reject("所选 DNS 服务的 HTTPS 地址无效。") }
        if (uri.scheme != "https" || uri.host == null ||
            !(isDnsHost(uri.host) || NumericIp.canonical(uri.host.removeSurrounding("[", "]")) != null) ||
            uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null ||
            uri.port !in -1..65535 || uri.port == 0 || uri.rawPath.isNullOrEmpty() ||
            provider.dohUrl.any { it.code < 32 } || provider.dohUrl.length > 2048)
            reject("所选 DNS 服务的 HTTPS 地址无效，不能包含账号、查询参数或出口指令。")
    }

    private fun hasH3(dns: MappingNode): Boolean =
        truth(entries(dns)["prefer-h3"]?.valueNode) == true || hasParameter(dns, "h3")

    private fun hasParameter(node: Node, name: String): Boolean = when (node) {
        is ScalarNode -> {
            // Mihomo parses the decoded URL fragment, not a form query: '+' stays '+'.
            val fragment = if ('#' !in node.value) "" else try {
                URI(node.value).fragment.orEmpty().also {
                    if ('\uFFFD' in it)
                        reject("DNS 地址的附加参数包含无法安全解析的编码；请人工处理，原文件未修改。")
                }
            } catch (error: ConfigRejectedException) { throw error }
            catch (_: Exception) {
                reject("DNS 地址的附加参数无法安全解析；请人工处理，原文件未修改。")
            }
            fragment.split('&').any {
                val parts = it.split('=', limit = 2)
                parts[0].equals(name, true) && (parts.size == 1 || !parts[1].equals("false", true))
            }
        }
        is SequenceNode -> node.value.any { hasParameter(it, name) }
        is MappingNode -> node.value.any { hasParameter(it.valueNode, name) }
        else -> false
    }

    private fun truth(node: Node?): Boolean? {
        if (node !is ScalarNode || node.tag != Tag.BOOL) return null
        return when (node.value.lowercase()) {
            "true", "yes", "on" -> true
            "false", "no", "off" -> false
            else -> null
        }
    }

    private fun strings(node: Node?): List<String>? {
        if (node !is SequenceNode || node.value.any { it !is ScalarNode || it.tag != Tag.STR }) return null
        return node.value.map { (it as ScalarNode).value }
    }

    private fun before(node: Node?): String = when {
        node == null -> "未声明（可能使用默认值）"
        truth(node) != null -> truth(node).toString()
        node is SequenceNode -> "原列表（${node.value.size} 项，内容已隐藏）"
        node is MappingNode -> "原映射（内容已隐藏）"
        else -> "原标量（内容已隐藏）"
    }

    private fun reason(key: String): String = when (key) {
        "enable" -> "在文件中明确启用内置 DNS；客户端仍可能覆盖。"
        "nameserver" -> "普通默认上游改用所选服务的 DoH；既有策略分支保持不变。"
        "default-nameserver" -> "为 DNS 服务域名提供明确的数字 IP 引导；该新增路径为明文 DNS。"
        "proxy-server-nameserver" -> "单独声明节点域名解析器，满足 respect-rules 的配置依赖。"
        else -> "让普通 DNS 连接遵守现有路由规则；并不等于强制代理。"
    }

    private sealed class Value {
        abstract fun render(): String
        abstract fun matches(node: Node?): Boolean
        data class BooleanValue(val value: Boolean) : Value() {
            override fun render() = value.toString()
            override fun matches(node: Node?) = truth(node) == value
        }
        data class StringList(val values: List<String>) : Value() {
            override fun render() = values.joinToString(", ", "[", "]") { "'" + it.replace("'", "''") + "'" }
            override fun matches(node: Node?) = strings(node) == values
        }
    }

    private data class Patch(val start: Int, val end: Int, val replacement: String)
    // Block collection end marks can extend across comments belonging to the following section.
    private fun contentEnd(node: Node): Int = when {
        node is MappingNode && node.flowStyle == DumperOptions.FlowStyle.BLOCK && node.value.isNotEmpty() ->
            contentEnd(node.value.last().valueNode)
        node is SequenceNode && node.flowStyle == DumperOptions.FlowStyle.BLOCK && node.value.isNotEmpty() ->
            contentEnd(node.value.last())
        else -> node.endMark.index
    }

    private fun insertionOffset(document: Document, dns: MappingNode): Int {
        val at = document.position(contentEnd(dns))
        if (at == 0 || document.source[at - 1] == '\n') return at
        val newline = document.source.indexOf('\n', at)
        val lineEnd = if (newline < 0) document.source.length else newline
        val remainder = document.source.substring(at, lineEnd).trim()
        if (remainder.isNotEmpty() && !remainder.startsWith('#'))
            reject("DNS 块的末尾结构无法安全定位；请人工处理，原文件未修改。")
        return if (newline < 0) lineEnd else newline + 1
    }

    private data class Document(
        val source: String, val bytes: ByteArray, val positions: IntArray,
        val root: MappingNode, val dns: MappingNode?
    ) {
        fun position(codePoint: Int): Int =
            positions.getOrNull(codePoint) ?: reject("配置位置校验失败；无法安全生成副本。")
        fun text(tuple: NodeTuple) =
            source.substring(position(tuple.keyNode.startMark.index), position(tuple.valueNode.endMark.index))
    }

    private fun parse(source: String): Document {
        if (source.length > MAX_BYTES) reject("配置超过 256 KiB，暂不支持自动处理。")
        val bytes = try {
            val buffer = Charsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(source))
            ByteArray(buffer.remaining()).also { buffer.get(it) }
        } catch (_: Exception) { reject("配置包含无效 Unicode 字符，暂不支持自动处理。") }
        if (bytes.size > MAX_BYTES) reject("配置超过 256 KiB，暂不支持自动处理。")
        val options = LoaderOptions().apply {
            isAllowDuplicateKeys = false
            maxAliasesForCollections = 0
            allowRecursiveKeys = false
            nestingDepthLimit = MAX_DEPTH
            codePointLimit = MAX_BYTES
            tagInspector = org.yaml.snakeyaml.inspector.TagInspector { false }
        }
        val root = try {
            val parser = Yaml(SafeConstructor(options))
            var documents = 0
            var depth = 0
            var count = 0
            for (event in parser.parse(StringReader(source))) {
                if (event is DocumentStartEvent && ++documents > 1)
                    reject("只支持单份 YAML 文档；原文件未修改。")
                if (event is AliasEvent || event is NodeEvent && event.anchor != null)
                    reject("配置含锚点或别名，暂不支持自动修复；原文件未修改。")
                if (event is NodeEvent && ++count > MAX_NODES)
                    reject("配置节点过多，暂不支持自动处理。")
                if (event is CollectionStartEvent) {
                    if (++depth > MAX_DEPTH) reject("配置嵌套超过 40 层，暂不支持自动处理。")
                    if (event.tag != null && event.tag !in tags)
                        reject("配置含自定义 YAML 标签，暂不支持自动处理。")
                }
                if (event is CollectionEndEvent) depth--
                if (event is ScalarEvent && event.tag != null && event.tag !in tags)
                    reject("配置含自定义 YAML 标签，暂不支持自动处理。")
            }
            parser.compose(StringReader(source))
        } catch (error: ConfigRejectedException) { throw error }
        catch (_: Exception) { reject("YAML 格式无效或超出安全解析范围；原文件未修改。") }
        if (root !is MappingNode || root.flowStyle != DumperOptions.FlowStyle.BLOCK)
            reject("只支持块式 YAML 根映射，不支持 JSON、列表或行内根映射。")
        validateTree(root)
        if (root.value.any { it.keyNode.startMark.column != 0 })
            reject("根配置字段必须从行首开始，暂不支持自动处理该缩进。")
        val dnsNode = entries(root)["dns"]?.valueNode
        if (dnsNode != null && (dnsNode !is MappingNode || dnsNode.flowStyle != DumperOptions.FlowStyle.BLOCK))
            reject("dns 必须为块式映射，暂不支持自动处理行内或其他结构。")
        val positions = IntArray(source.codePointCount(0, source.length) + 1)
        var offset = 0
        for (index in 0 until positions.lastIndex) {
            positions[index] = offset
            offset += Character.charCount(source.codePointAt(offset))
        }
        positions[positions.lastIndex] = source.length
        return Document(source, bytes, positions, root, dnsNode as MappingNode?)
    }

    private fun validateTree(node: Node) {
        when (node) {
            is MappingNode -> {
                val keys = mutableSetOf<String>()
                for (tuple in node.value) {
                    val key = tuple.keyNode
                    if (key !is ScalarNode || key.tag != Tag.STR || key.startMark.line != key.endMark.line)
                        reject("只支持单行字符串映射键，暂不支持自动处理。")
                    if (key.value == "<<") reject("配置含 YAML 合并键，暂不支持自动修复。")
                    if (!keys.add(key.value)) reject("配置含重复字段，无法安全确定生效值；原文件未修改。")
                    validateTree(tuple.valueNode)
                }
            }
            is SequenceNode -> node.value.forEach(::validateTree)
            is ScalarNode -> Unit
            else -> reject("配置包含不支持的 YAML 节点。")
        }
    }

    private fun entries(node: MappingNode): Map<String, NodeTuple> =
        node.value.associateBy { (it.keyNode as ScalarNode).value }

    private fun profileRejection(document: Document): String? {
        val rootKeys = entries(document.root).keys
        val dnsKeys = document.dns?.let(::entries)?.keys.orEmpty()
        if (rootKeys.any { it in foreignRootKeys } || "servers" in dnsKeys)
            return "检测到其他应用或代理核心的配置标志；本功能仅生成 Mihomo DNS 副本，请选择对应配置文件。"
        if (rootKeys.none { it in mihomoRootKeys } && dnsKeys.none { it in mihomoDnsKeys })
            return "未找到可识别的 Mihomo 配置字段；无法确认文件用途，请选择含节点、规则或 Mihomo DNS 设置的配置。"
        return null
    }

    private fun verifyUnchanged(before: Document, after: Document) {
        fun unchanged(a: Map<String, NodeTuple>, b: Map<String, NodeTuple>, excluded: Set<String>) {
            val aKeys = a.keys - excluded
            val bKeys = b.keys - excluded
            if (aKeys != bKeys) reject("非目标字段发生变化，已停止导出；原文件未修改。")
            for (key in aKeys) {
                val left = a.getValue(key)
                val right = b.getValue(key)
                // Collection end marks may include the indentation of a newly inserted sibling.
                if (!equivalent(left.valueNode, right.valueNode) ||
                    before.text(left).trimEnd() != after.text(right).trimEnd())
                    reject("非目标字段的语义或原文发生变化，已停止导出；原文件未修改。")
            }
        }
        unchanged(entries(before.root), entries(after.root), setOf("dns"))
        unchanged(before.dns?.let(::entries).orEmpty(), after.dns?.let(::entries).orEmpty(), allowed)
    }

    private fun equivalent(a: Node, b: Node): Boolean {
        if (a.tag != b.tag || a.nodeId != b.nodeId) return false
        return when {
            a is ScalarNode && b is ScalarNode -> a.value == b.value
            a is SequenceNode && b is SequenceNode ->
                a.value.size == b.value.size && a.value.zip(b.value).all { equivalent(it.first, it.second) }
            a is MappingNode && b is MappingNode ->
                a.value.size == b.value.size && a.value.zip(b.value).all {
                    equivalent(it.first.keyNode, it.second.keyNode) && equivalent(it.first.valueNode, it.second.valueNode)
                }
            else -> false
        }
    }

    private fun sha256(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun reject(message: String): Nothing = throw ConfigRejectedException(message)
}
