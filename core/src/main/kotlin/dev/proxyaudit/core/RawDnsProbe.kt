package dev.proxyaudit.core

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Single use, no retries, no TCP fallback and no name resolution. Uses the process's default network.
 * A response authenticates neither the resolver nor the physical route. close() cancels socket I/O.
 */
class RawDnsProbe(
    private val config: RawDnsConfig,
    private val transport: DnsTransport,
    private val timeoutMillis: Int
) : AutoCloseable {
    init {
        require(timeoutMillis in 1..15_000)
        require(if (transport == DnsTransport.UDP) config.udp else config.tcp)
    }
    private val lock = Any()
    private val started = AtomicBoolean(false)
    private var cancelled = false
    private var expired = false
    private var resource: Closeable? = null

    override fun close() {
        synchronized(lock) {
            cancelled = true
            resource?.closeQuietly()
            resource = null
        }
    }

    fun execute(): RawDnsObservation {
        check(started.compareAndSet(false, true)) { "DNS probe is single use" }
        val start = System.nanoTime()
        synchronized(lock) {
            if (cancelled) return RawDnsObservation(transport, Execution.CANCELLED, durationMillis = 0, failure = Failure.CANCELLED)
        }
        val transactionId = random.nextInt(65_536)
        val deadline = start + TimeUnit.MILLISECONDS.toNanos(timeoutMillis.toLong())
        val alarm = deadlines.schedule({
            synchronized(lock) {
                expired = true
                resource?.closeQuietly()
                resource = null
            }
        }, timeoutMillis.toLong(), TimeUnit.MILLISECONDS)
        val result = try {
            val query = DnsWire.query(config, transactionId)
            val target = InetSocketAddress(numericAddress(config.serverIp), config.port)
            val bytes = when (transport) {
                DnsTransport.UDP -> udp(query, target, deadline)
                DnsTransport.TCP -> tcp(query, target, deadline)
            }
            val answer = DnsWire.parse(bytes, config, transactionId)
            RawDnsObservation(transport, Execution.COMPLETED, transactionId, responseCode = answer.responseCode,
                truncated = answer.truncated, addresses = answer.addresses)
        } catch (_: TooLarge) {
            RawDnsObservation(transport, Execution.ERROR, transactionId, failure = Failure.RESPONSE_TOO_LARGE)
        } catch (_: IllegalArgumentException) {
            RawDnsObservation(transport, Execution.ERROR, transactionId, failure = Failure.INVALID_DNS)
        } catch (_: SocketTimeoutException) {
            RawDnsObservation(transport, Execution.ERROR, transactionId, failure = Failure.TIMEOUT)
        } catch (_: EOFException) {
            RawDnsObservation(transport, Execution.ERROR, transactionId, failure = Failure.INVALID_DNS)
        } catch (_: IOException) {
            RawDnsObservation(transport, Execution.ERROR, transactionId, failure = Failure.IO_FAILURE)
        } catch (_: SecurityException) {
            RawDnsObservation(transport, Execution.ERROR, transactionId, failure = Failure.IO_FAILURE)
        } finally {
            alarm.cancel(false)
            synchronized(lock) {
                resource?.closeQuietly()
                resource = null
            }
        }
        return synchronized(lock) {
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
            when {
                cancelled -> RawDnsObservation(transport, Execution.CANCELLED, transactionId, elapsed, failure = Failure.CANCELLED)
                expired || System.nanoTime() - deadline >= 0 -> RawDnsObservation(transport, Execution.ERROR, transactionId, elapsed, failure = Failure.TIMEOUT)
                else -> result.copy(durationMillis = elapsed)
            }
        }
    }

    private fun register(socket: Closeable) {
        synchronized(lock) {
            if (cancelled || expired) {
                socket.closeQuietly()
                throw IOException("Probe stopped")
            }
            resource = socket
        }
    }

    private fun remaining(deadline: Long): Int {
        val nanos = deadline - System.nanoTime()
        if (nanos <= 0) throw SocketTimeoutException()
        return ((nanos + 999_999L) / 1_000_000L).coerceAtMost(timeoutMillis.toLong()).toInt()
    }

    private fun udp(query: ByteArray, target: InetSocketAddress, deadline: Long): ByteArray {
        val socket = DatagramSocket(null)
        register(socket)
        socket.bind(InetSocketAddress(0))
        socket.connect(target) // Connected UDP accepts replies only from the specified peer.
        socket.soTimeout = remaining(deadline).coerceAtMost(250)
        socket.send(DatagramPacket(query, query.size))
        val packet = DatagramPacket(ByteArray(DnsWire.MAX_MESSAGE + 1), DnsWire.MAX_MESSAGE + 1)
        while (true) {
            synchronized(lock) {
                if (cancelled) throw IOException("Probe stopped")
                if (expired) throw SocketTimeoutException()
            }
            // Some Android socket implementations do not wake receive immediately on close.
            // Short waits only check cancellation; they never retransmit or extend the deadline.
            socket.soTimeout = remaining(deadline).coerceAtMost(250)
            try {
                socket.receive(packet)
                break
            } catch (_: SocketTimeoutException) {
                // Recheck both stop flags and the original absolute deadline on the next pass.
            }
        }
        if (packet.length > DnsWire.MAX_MESSAGE) throw TooLarge()
        return packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
    }

    private fun tcp(query: ByteArray, target: InetSocketAddress, deadline: Long): ByteArray {
        val socket = Socket()
        register(socket)
        socket.connect(target, remaining(deadline))
        val output = socket.getOutputStream()
        output.write(byteArrayOf((query.size shr 8).toByte(), query.size.toByte()) + query)
        output.flush()
        val input = socket.getInputStream()
        fun readExactly(size: Int): ByteArray {
            val bytes = ByteArray(size)
            var offset = 0
            while (offset < size) {
                socket.soTimeout = remaining(deadline)
                val count = input.read(bytes, offset, size - offset)
                if (count < 0) throw EOFException()
                if (count == 0) continue
                offset += count
            }
            return bytes
        }
        val prefix = readExactly(2)
        val size = ((prefix[0].toInt() and 255) shl 8) or (prefix[1].toInt() and 255)
        if (size > DnsWire.MAX_MESSAGE) throw TooLarge()
        require(size >= 12)
        return readExactly(size)
    }

    private class TooLarge : IOException()
    private fun Closeable.closeQuietly() { try { close() } catch (_: IOException) {} }

    companion object {
        private val random = SecureRandom()
        private val deadlines = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "raw-dns-deadline").apply { isDaemon = true }
        }

        /** getByAddress never performs DNS. Preserve IPv6 literal intent even for mapped literals. */
        internal fun numericAddress(value: String): InetAddress {
            val canonical = requireNotNull(NumericIp.canonical(value))
            if (':' !in canonical) {
                val bytes = canonical.split('.').map { it.toInt().toByte() }.toByteArray()
                if (':' !in value) return InetAddress.getByAddress(bytes)
                return Inet6Address.getByAddress(null, ByteArray(10) + byteArrayOf(-1, -1) + bytes, -1)
            }
            val bytes = canonical.split(':').flatMap {
                val word = it.toInt(16)
                listOf((word shr 8).toByte(), word.toByte())
            }.toByteArray()
            return Inet6Address.getByAddress(null, bytes, -1)
        }
    }
}

/** Bounded DNS wire reader. Unsupported record payloads are skipped, never interpreted as addresses. */
internal object DnsWire {
    const val MAX_MESSAGE = 4096
    data class Answer(val responseCode: Int, val truncated: Boolean, val addresses: List<String>)

    fun query(config: RawDnsConfig, transactionId: Int): ByteArray {
        require(transactionId in 0..65535)
        val out = ByteArrayOutputStream()
        fun word(value: Int) { out.write(value shr 8); out.write(value) }
        word(transactionId); word(0x0100); word(1); word(0); word(0); word(0)
        for (label in config.host.removeSuffix(".").split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size); out.write(bytes)
        }
        out.write(0); word(config.recordType.wireValue); word(1)
        return out.toByteArray()
    }

    fun parse(bytes: ByteArray, config: RawDnsConfig, transactionId: Int): Answer {
        require(bytes.size in 12..MAX_MESSAGE)
        val reader = Reader(bytes)
        require(reader.word() == transactionId)
        val flags = reader.word()
        require(flags and 0x8000 != 0 && flags and 0x7800 == 0 && flags and 0x0040 == 0)
        val questions = reader.word()
        val answers = reader.word()
        val authorities = reader.word()
        val additional = reader.word()
        require(questions == 1)
        val expectedName = config.host.removeSuffix(".").lowercase(Locale.ROOT)
        require(reader.name() == expectedName)
        require(reader.word() == config.recordType.wireValue && reader.word() == 1)
        val aliases = linkedMapOf<String, String>()
        val addresses = mutableListOf<Pair<String, String>>()
        var extendedCode = 0
        var hasOpt = false
        repeat(answers + authorities + additional) { index ->
            val owner = reader.name()
            val type = reader.word()
            val recordClass = reader.word()
            val ttlHigh = reader.word()
            reader.word() // Ordinary TTLs are not used as privacy evidence.
            val length = reader.word()
            val end = reader.position + length
            require(end <= bytes.size)
            when (type) {
                1, 28 -> {
                    require(length == if (type == 1) 4 else 16)
                    if (index < answers && recordClass == 1 && type == config.recordType.wireValue) {
                        val address = if (type == 1) bytes.copyOfRange(reader.position, end).joinToString(".") { (it.toInt() and 255).toString() }
                        else (reader.position until end step 2).joinToString(":") {
                            (((bytes[it].toInt() and 255) shl 8) or (bytes[it + 1].toInt() and 255)).toString(16)
                        }
                        addresses += owner to address
                    }
                    reader.skip(length)
                }
                2, 5, 12, 39 -> {
                    val name = reader.name()
                    if (type == 5 && index < answers && recordClass == 1) {
                        require(aliases[owner] == null || aliases[owner] == name)
                        aliases[owner] = name
                    }
                }
                6 -> { reader.name(); reader.name(); reader.skip(20) }
                15 -> { reader.skip(2); reader.name() }
                33 -> { reader.skip(6); reader.name() }
                41 -> {
                    // OPT carries the high eight RCODE bits, not an address or resolver identity.
                    require(index >= answers + authorities && owner.isEmpty() && !hasOpt)
                    hasOpt = true
                    extendedCode = ttlHigh shr 8
                    while (reader.position < end) {
                        require(end - reader.position >= 4)
                        reader.word()
                        val optionLength = reader.word()
                        require(reader.position + optionLength <= end)
                        reader.skip(optionLength)
                    }
                }
                else -> reader.skip(length)
            }
            require(reader.position == end)
        }
        require(reader.position == bytes.size)
        val allowedNames = linkedSetOf(expectedName)
        var current = expectedName
        while (aliases.containsKey(current)) {
            current = aliases.getValue(current)
            require(allowedNames.add(current))
        }
        val code = (extendedCode shl 4) or (flags and 15)
        val truncated = flags and 0x0200 != 0
        // TC and error responses are observations, not complete sets of successful answers.
        return Answer(code, truncated, if (code != 0 || truncated) emptyList() else addresses.filter { it.first in allowedNames }.map { it.second }.distinct())
    }

    private class Reader(private val bytes: ByteArray) {
        var position = 0
            private set
        private val nameBoundaries = mutableSetOf<Int>()
        fun word(): Int {
            require(position + 2 <= bytes.size)
            val value = ((bytes[position].toInt() and 255) shl 8) or (bytes[position + 1].toInt() and 255)
            position += 2
            return value
        }
        fun skip(count: Int) { require(count >= 0 && position + count <= bytes.size); position += count }
        fun name(): String {
            var offset = position
            var next = -1
            var wireLength = 1
            val visited = mutableSetOf<Int>()
            val labels = mutableListOf<String>()
            while (true) {
                require(offset < bytes.size && visited.add(offset))
                nameBoundaries += offset
                val length = bytes[offset].toInt() and 255
                if (length and 0xc0 == 0xc0) {
                    require(offset + 1 < bytes.size)
                    val target = ((length and 63) shl 8) or (bytes[offset + 1].toInt() and 255)
                    require(target < offset && target in nameBoundaries)
                    if (next < 0) next = offset + 2
                    offset = target
                } else {
                    require(length and 0xc0 == 0)
                    offset++
                    if (length == 0) {
                        if (next < 0) next = offset
                        break
                    }
                    require(offset + length <= bytes.size)
                    wireLength += length + 1
                    require(wireLength <= 255)
                    // Preserve each wire label, including dots within labels, without name ambiguity.
                    val label = bytes.copyOfRange(offset, offset + length)
                    require(label.all { (it.toInt() and 255) in 33..126 && it.toInt() != '.'.code })
                    labels += String(label, Charsets.US_ASCII).lowercase(Locale.ROOT)
                    offset += length
                }
            }
            position = next
            return labels.joinToString(".")
        }
    }
}
