package dev.proxyaudit.core

import java.net.URI

/** Never resolves names. Canonical values are used only for equality, not route inference. */
object NumericIp {
    fun canonical(input: String): String? {
        if (input.isEmpty() || input != input.trim() || '%' in input || '[' in input || ']' in input) return null
        if (':' !in input) return ipv4(input)?.joinToString(".")
        if (input.any { it !in "0123456789abcdefABCDEF:." }) return null
        var value = input.lowercase()
        if ('.' in value) {
            val split = value.lastIndexOf(':')
            if (split < 0) return null
            val tail = ipv4(value.substring(split + 1)) ?: return null
            value = value.substring(0, split + 1) + ((tail[0] shl 8) or tail[1]).toString(16) + ":" + ((tail[2] shl 8) or tail[3]).toString(16)
        }
        val pieces = value.split("::")
        if (pieces.size > 2) return null
        fun groups(s: String): List<Int>? {
            if (s.isEmpty()) return emptyList()
            val gs = s.split(':')
            if (gs.any { it.isEmpty() || it.length > 4 }) return null
            return gs.map { it.toIntOrNull(16) ?: return null }
        }
        val left = groups(pieces[0]) ?: return null
        val right = if (pieces.size == 2) groups(pieces[1]) ?: return null else emptyList()
        val all = if (pieces.size == 1) { if (left.size != 8) return null; left }
                  else { val omitted = 8 - left.size - right.size; if (omitted < 1) return null; left + List(omitted) { 0 } + right }
        if (all.take(5).all { it == 0 } && all[5] == 0xffff) return listOf(all[6] shr 8, all[6] and 255, all[7] shr 8, all[7] and 255).joinToString(".")
        return all.joinToString(":") { it.toString(16) }
    }
    private fun ipv4(value: String): List<Int>? {
        val groups = value.split('.')
        if (groups.size != 4) return null
        return groups.map {
            if (it.isEmpty() || it.length > 3 || it.any { c -> c !in '0'..'9' } || (it.length > 1 && it[0] == '0')) return null
            val n = it.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            n
        }
    }
}

class Endpoint private constructor(val origin: String) {
    fun requestUrl(requestId: String): String {
        require(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}").matches(requestId))
        return "$origin/v1/echo?requestId=$requestId"
    }
    companion object {
        fun parse(value: String): Endpoint {
            require(value.length <= 300 && value == value.trim()) { "服务源地址格式不正确" }
            val uri = try { URI(value) } catch (_: Exception) { throw IllegalArgumentException("服务源地址格式不正确") }
            require(uri.scheme == "https" && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) { "仅允许 HTTPS；禁止凭据、查询参数和片段" }
            require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") { "只填服务源地址，不能附带路径；使用固定 /v1/echo" }
            val host = uri.host ?: throw IllegalArgumentException("请填写有效主机名或 IP 地址")
            require(uri.port == -1 || uri.port in 1..65535) { "端口无效" }
            require('%' !in host) { "不支持带作用域的 IPv6 地址" }
            val plainHost = host.removePrefix("[").removeSuffix("]")
            val canonical = NumericIp.canonical(plainHost)
            val safeHost = if (canonical != null) {
                if (':' in canonical) "[$canonical]" else canonical
            } else {
                require(':' !in plainHost && !plainHost.all { it.isDigit() || it == '.' } && isDnsHost(plainHost)) { "主机名无效" }
                plainHost.lowercase()
            }
            val port = if (uri.port == -1 || uri.port == 443) "" else ":${uri.port}"
            return Endpoint("https://$safeHost$port")
        }
    }
}

fun isDnsHost(value: String): Boolean {
    if (value.isEmpty() || value.length > 253 || value != value.trim() || NumericIp.canonical(value) != null || value.all { it.isDigit() || it == '.' }) return false
    if (value.any { it.code > 127 || it.isWhitespace() || it in "/@:?#[]\\" }) return false
    val host = value.removeSuffix(".")
    return host.split('.').all { it.isNotEmpty() && it.length <= 63 && it.first().isLetterOrDigit() && it.last().isLetterOrDigit() && it.all { c -> c.isLetterOrDigit() || c == '-' } }
}

fun parseExpectedIps(value: String): Set<String> {
    if (value.isBlank()) return emptySet()
    val parts = value.split(',').map { it.trim() }
    require(parts.size <= 32 && parts.none { it.isEmpty() }) { "最多填写 32 个以英文逗号分隔的 IP" }
    return parts.map { NumericIp.canonical(it) ?: throw IllegalArgumentException("预期出口必须是数字 IPv4 或 IPv6 地址") }.toSet()
}
