package dev.proxyaudit.core

/** A deliberately tiny strict parser for the flat v1 echo contract, not a general JSON parser. */
object EchoParser {
    data class Echo(val requestId: String, val sourceIp: String)
    fun parse(text: String, expectedRequestId: String): Echo {
        require(text.length <= 4096) { "INVALID_ECHO" }
        val fields = FlatObjectReader(text).read()
        require(fields.keys == setOf("schemaVersion", "requestId", "observedSourceIp")) { "INVALID_ECHO" }
        require(fields["schemaVersion"] == NumberToken("1")) { "INVALID_ECHO" }
        val requestId = fields["requestId"] as? String ?: throw IllegalArgumentException("INVALID_ECHO")
        require(requestId == expectedRequestId) { "INVALID_ECHO" }
        val source = fields["observedSourceIp"] as? String ?: throw IllegalArgumentException("INVALID_ECHO")
        val canonical = NumericIp.canonical(source) ?: throw IllegalArgumentException("INVALID_ECHO")
        return Echo(requestId, canonical)
    }
    private data class NumberToken(val raw: String)
    private class FlatObjectReader(private val input: String) {
        private var pos = 0
        fun read(): Map<String, Any?> {
            val result = linkedMapOf<String, Any?>()
            space(); expect('{'); space()
            if (take('}')) { space(); require(pos == input.length); return result }
            while (true) {
                space(); val key = string(); require(!result.containsKey(key))
                space(); expect(':'); space()
                val value: Any? = when (peek()) {
                    '"' -> string()
                    'n' -> { literal("null"); null }
                    't' -> { literal("true"); true }
                    'f' -> { literal("false"); false }
                    else -> number()
                }
                result[key] = value; require(result.size <= 3); space()
                if (take('}')) break
                expect(',')
            }
            space(); require(pos == input.length)
            return result
        }
        private fun string(): String {
            expect('"'); val result = StringBuilder()
            while (true) {
                require(pos < input.length)
                val c = input[pos++]
                if (c == '"') return result.toString()
                require(c.code >= 32)
                if (c != '\\') result.append(c) else {
                    require(pos < input.length)
                    when (val e = input[pos++]) {
                        '"', '\\', '/' -> result.append(e)
                        'b' -> result.append('\b'); 'f' -> result.append('\u000c')
                        'n' -> result.append('\n'); 'r' -> result.append('\r'); 't' -> result.append('\t')
                        'u' -> {
                            require(pos + 4 <= input.length)
                            val digits = input.substring(pos, pos + 4)
                            require(digits.all { it in "0123456789abcdefABCDEF" })
                            result.append(digits.toInt(16).toChar()); pos += 4
                        }
                        else -> throw IllegalArgumentException("INVALID_ECHO")
                    }
                }
                require(result.length <= 512)
            }
        }
        private fun number(): NumberToken {
            val start = pos
            while (pos < input.length && input[pos] in "0123456789+-.eE") pos++
            require(pos > start)
            val raw = input.substring(start, pos)
            require(Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?").matches(raw))
            return NumberToken(raw)
        }
        private fun literal(value: String) { require(input.startsWith(value, pos)); pos += value.length }
        private fun peek(): Char { require(pos < input.length); return input[pos] }
        private fun space() { while (pos < input.length && input[pos] in " \n\r\t") pos++ }
        private fun take(c: Char): Boolean { if (pos < input.length && input[pos] == c) { pos++; return true }; return false }
        private fun expect(c: Char) { require(take(c)) { "INVALID_ECHO" } }
    }
}
