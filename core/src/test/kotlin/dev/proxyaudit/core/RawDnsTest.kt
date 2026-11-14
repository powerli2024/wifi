package dev.proxyaudit.core

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** All socket tests use IPv4 loopback; these are not Android, VPN or public DNS tests. */
class RawDnsTest {
    private val config = RawDnsConfig("127.0.0.1", host = "probe.example.test")
    private val id = 0x5a93
    private val query get() = DnsWire.query(config, id)
    private fun rejected(block: () -> Unit) {
        try { block(); fail("Expected rejection") } catch (_: IllegalArgumentException) {}
    }
    private fun word(value: Int) = byteArrayOf((value shr 8).toByte(), value.toByte())
    private fun name(value: String): ByteArray {
        val output = ByteArrayOutputStream()
        for (part in value.split('.')) { output.write(part.length); output.write(part.toByteArray(Charsets.US_ASCII)) }
        output.write(0)
        return output.toByteArray()
    }
    private fun record(type: Int, data: ByteArray, owner: ByteArray = byteArrayOf(0xc0.toByte(), 12), clazz: Int = 1): ByteArray =
        owner + word(type) + word(clazz) + byteArrayOf(0, 0, 0, 60) + word(data.size) + data
    private fun response(request: ByteArray = query, flags: Int = 0x8180, vararg records: ByteArray): ByteArray {
        val header = request.copyOf()
        header[2] = (flags shr 8).toByte(); header[3] = flags.toByte()
        header[6] = (records.size shr 8).toByte(); header[7] = records.size.toByte()
        return header + records.fold(ByteArray(0)) { accumulated, bytes -> accumulated + bytes }
    }
    private fun ipv4(last: Int = 7) = byteArrayOf(192.toByte(), 0, 2, last.toByte())

    @Test fun `configuration rejects ambiguous targets bad hosts ports and disabled protocols`() {
        for (ip in listOf("resolver.example", "127.1", "010.0.0.1", "[::1]", "fe80::1%wlan0", "127.0.0.1 ", "")) rejected { config.copy(serverIp = ip) }
        for (host in listOf("", "127.0.0.1", "a..test", "host with space", "a".repeat(64) + ".test")) rejected { config.copy(host = host) }
        for (port in listOf(0, -1, 65536)) rejected { config.copy(port = port) }
        rejected { config.copy(udp = false, tcp = false) }
        rejected { RawDnsProbe(config.copy(udp = false), DnsTransport.UDP, 100) }
        rejected { RawDnsProbe(config, DnsTransport.UDP, 0) }
        rejected { RawDnsProbe(config, DnsTransport.UDP, 15001) }
    }

    @Test fun `numeric sockets use address bytes with explicit IPv6 literal family`() {
        assertArrayEquals(byteArrayOf(127, 0, 0, 1), RawDnsProbe.numericAddress("127.0.0.1").address)
        assertTrue(RawDnsProbe.numericAddress("::1") is Inet6Address)
        assertTrue(RawDnsProbe.numericAddress("::ffff:192.0.2.1") is Inet6Address)
        assertEquals(16, RawDnsProbe.numericAddress("2001:db8::1").address.size)
        rejected { RawDnsProbe.numericAddress("resolver.example") }
    }

    @Test fun `query is one standard recursive question without EDNS or hidden followup`() {
        assertArrayEquals(byteArrayOf(0x5a, 0x93.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0), query.copyOfRange(0, 12))
        assertArrayEquals(name(config.host) + byteArrayOf(0, 1, 0, 1), query.copyOfRange(12, query.size))
        val aaaa = DnsWire.query(config.copy(host = "PROBE.example.test.", recordType = DnsRecordType.AAAA), id)
        assertArrayEquals(byteArrayOf(0, 28, 0, 1), aaaa.takeLast(4).toByteArray())
        assertTrue(DnsWire.query(config.copy(host = List(3) { "a".repeat(63) }.joinToString(".") + "." + "b".repeat(61)), id).size <= 512)
    }

    @Test fun `matching A AAAA and case insensitive question responses are observed`() {
        assertEquals(listOf("192.0.2.7"), DnsWire.parse(response(query, 0x8180, record(1, ipv4())), config, id).addresses)
        val upperQuery = DnsWire.query(config.copy(host = "PROBE.EXAMPLE.TEST"), id)
        assertEquals(0, DnsWire.parse(response(upperQuery), config, id).responseCode)
        val six = config.copy(recordType = DnsRecordType.AAAA)
        val bytes = RawDnsProbe.numericAddress("2001:db8::7").address
        val answer = DnsWire.parse(response(DnsWire.query(six, id), 0x8180, record(28, bytes)), six, id)
        assertEquals(listOf("2001:db8:0:0:0:0:0:7"), answer.addresses)
    }

    @Test fun `answer extraction follows CNAME and excludes unrelated and wrong class records`() {
        val alias = "alias.example.test"
        val answer = DnsWire.parse(response(query, 0x8180,
            record(5, name(alias)), record(1, ipv4(9), name(alias)),
            record(1, ipv4(99), name("unrelated.example.test")), record(1, ipv4(88), clazz = 3)), config, id)
        assertEquals(listOf("192.0.2.9"), answer.addresses)
    }

    @Test fun `NXDOMAIN and truncated answers remain explicit observations without address success`() {
        val nx = DnsWire.parse(response(query, 0x8183), config, id)
        assertEquals(3, nx.responseCode); assertFalse(nx.truncated); assertTrue(nx.addresses.isEmpty())
        val tc = DnsWire.parse(response(query, 0x8380, record(1, ipv4())), config, id)
        assertEquals(0, tc.responseCode); assertTrue(tc.truncated); assertTrue(tc.addresses.isEmpty())
    }

    @Test fun `transaction question type class QR opcode and reserved flag must match`() {
        rejected { DnsWire.parse(response(), config, id + 1) }
        for (flags in listOf(0x0180, 0x8980, 0x81c0)) rejected { DnsWire.parse(response(query, flags), config, id) }
        for (wrong in listOf(config.copy(host = "other.example.test"), config.copy(recordType = DnsRecordType.AAAA))) {
            rejected { DnsWire.parse(response(DnsWire.query(wrong, id)), config, id) }
        }
        val badClass = response().apply { this[lastIndex] = 3 }
        rejected { DnsWire.parse(badClass, config, id) }
        for (count in listOf(0, 2)) rejected { DnsWire.parse(response().apply { this[5] = count.toByte() }, config, id) }
    }

    @Test fun `compressed names reject out of range forward interior and cyclic pointers`() {
        for (owner in listOf(
            byteArrayOf(0xff.toByte(), 0xff.toByte()),
            byteArrayOf(0xc0.toByte(), query.size.toByte()), // self pointer
            byteArrayOf(0xc0.toByte(), (query.size + 2).toByte()), // forward pointer
            byteArrayOf(0xc0.toByte(), 13), // inside the first label
            byteArrayOf(0xc0.toByte(), 0), // DNS header is not a name boundary
            byteArrayOf(0x40, 0), byteArrayOf(0x80.toByte(), 0)
        )) rejected { DnsWire.parse(response(query, 0x8180, record(1, ipv4(), owner)), config, id) }
        val cnameCycle = response(query, 0x8180, record(5, name("alias.example.test")),
            record(5, name(config.host), name("alias.example.test")))
        rejected { DnsWire.parse(cnameCycle, config, id) }
    }

    @Test fun `message and resource length bounds reject truncation trailing garbage and invalid addresses`() {
        for (bytes in listOf(ByteArray(11), ByteArray(4097), response() + byteArrayOf(0),
            response(query, 0x8180, record(1, ipv4())).dropLast(1).toByteArray(),
            response(query, 0x8180, record(1, byteArrayOf(1, 2, 3))),
            response(query, 0x8180, record(28, ByteArray(15))),
            response(query, 0x8180, record(5, name("alias.test") + byteArrayOf(0))),
            response(query, 0x8180, record(5, byteArrayOf(0xc0.toByte()))))) {
            rejected { DnsWire.parse(bytes, config, id) }
        }
    }

    @Test fun `authority and additional records cannot masquerade as answer addresses`() {
        val bytes = response(query, 0x8180, record(1, ipv4())).apply { this[7] = 0; this[11] = 1 }
        assertTrue(DnsWire.parse(bytes, config, id).addresses.isEmpty())
    }

    @Test fun `OPT extended response code is not misreported as NOERROR`() {
        val opt = record(41, ByteArray(0), owner = byteArrayOf(0), clazz = 512).apply { this[5] = 1 }
        val bytes = response(query, 0x8180, opt).apply { this[7] = 0; this[11] = 1 }
        assertEquals(16, DnsWire.parse(bytes, config, id).responseCode)
        val duplicate = response(query, 0x8180, opt, opt).apply { this[7] = 0; this[11] = 2 }
        rejected { DnsWire.parse(duplicate, config, id) }
        rejected { DnsWire.parse(response(query, 0x8180, opt), config, id) }
    }

    @Test fun `bounded random malformed packet inputs terminate without unchecked parser crashes`() {
        val random = java.util.Random(481)
        repeat(3000) {
            val bytes = ByteArray(random.nextInt(500))
            random.nextBytes(bytes)
            try { DnsWire.parse(bytes, config, id) } catch (_: IllegalArgumentException) {}
        }
    }

    private class UdpFixture(private val answer: (ByteArray) -> ByteArray?) : AutoCloseable {
        val server = DatagramSocket(0, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
        val received = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        private val thread = Thread {
            try {
                server.soTimeout = 2000
                val packet = DatagramPacket(ByteArray(4096), 4096)
                server.receive(packet)
                received.countDown()
                answer(packet.data.copyOfRange(packet.offset, packet.offset + packet.length))?.let {
                    server.send(DatagramPacket(it, it.size, packet.socketAddress))
                }
            } catch (error: Throwable) {
                if (!server.isClosed && error !is SocketTimeoutException) failure.set(error)
            }
        }.apply { isDaemon = true; start() }
        override fun close() { server.close(); thread.join(2500); failure.get()?.let { throw AssertionError(it) } }
    }

    private class TcpFixture(private val answer: (Socket, ByteArray) -> Unit) : AutoCloseable {
        val server = ServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
        val received = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        private val connection = AtomicReference<Socket?>()
        private val thread = Thread {
            try {
                server.soTimeout = 2000
                server.accept().use { socket ->
                    connection.set(socket)
                    socket.soTimeout = 2000
                    val input = java.io.DataInputStream(socket.getInputStream())
                    val bytes = ByteArray(input.readUnsignedShort())
                    input.readFully(bytes)
                    received.countDown()
                    answer(socket, bytes)
                }
            } catch (error: Throwable) {
                if (!server.isClosed && error !is java.io.IOException) failure.set(error)
            }
        }.apply { isDaemon = true; start() }
        override fun close() {
            server.close(); connection.get()?.close(); thread.join(2500)
            failure.get()?.let { throw AssertionError(it) }
        }
    }

    @Test(timeout = 5000) fun `UDP loopback sends one query and validates the actual response`() {
        UdpFixture { request -> response(request, 0x8180, record(1, ipv4())) }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.UDP, 1000).use {
                val observed = it.execute()
                assertEquals(Execution.COMPLETED, observed.execution)
                assertEquals(listOf("192.0.2.7"), observed.addresses)
                assertNotNull(observed.transactionId); assertNotNull(observed.durationMillis); assertNull(observed.failure)
            }
        }
    }

    @Test(timeout = 5000) fun `UDP delayed response survives multiple receive polls without resending`() {
        UdpFixture { request ->
            Thread.sleep(650)
            response(request, 0x8180, record(1, ipv4()))
        }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.UDP, 2000).use {
                val observed = it.execute()
                assertEquals(Execution.COMPLETED, observed.execution)
                assertEquals(listOf("192.0.2.7"), observed.addresses)
                assertTrue("elapsed=${observed.durationMillis}", observed.durationMillis!! >= 500)
                fixture.server.soTimeout = 150
                try { fixture.server.receive(DatagramPacket(ByteArray(512), 512)); fail("Poll resent the query") }
                catch (_: SocketTimeoutException) {}
            }
        }
    }

    @Test(timeout = 5000) fun `TCP loopback handles split length prefix and fragmented response`() {
        TcpFixture { socket, request ->
            val bytes = response(request, 0x8180, record(1, ipv4()))
            val output = socket.getOutputStream()
            output.write(word(bytes.size).copyOfRange(0, 1)); output.flush()
            Thread.sleep(10)
            output.write(word(bytes.size).copyOfRange(1, 2))
            output.write(bytes.copyOfRange(0, 7)); output.flush()
            Thread.sleep(10)
            output.write(bytes.copyOfRange(7, bytes.size)); output.flush()
        }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.TCP, 1000).use {
                assertEquals(listOf("192.0.2.7"), it.execute().addresses)
            }
        }
    }

    @Test(timeout = 5000) fun `UDP truncation preserves TC and does not open a TCP fallback`() {
        UdpFixture { request -> response(request, 0x8380) }.use { fixture ->
            ServerSocket(fixture.server.localPort, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { tcp ->
                RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.UDP, 1000).use {
                    val observed = it.execute()
                    assertEquals(Execution.COMPLETED, observed.execution)
                    assertTrue(observed.truncated); assertTrue(observed.addresses.isEmpty())
                }
                tcp.soTimeout = 100
                try { tcp.accept().use { fail("Unexpected TCP fallback") } } catch (_: SocketTimeoutException) {}
            }
        }
    }

    @Test(timeout = 5000) fun `oversized UDP payload and TCP length are bounded before parsing`() {
        UdpFixture { ByteArray(4097) }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.UDP, 1000).use {
                assertEquals(Failure.RESPONSE_TOO_LARGE, it.execute().failure)
            }
        }
        TcpFixture { socket, _ -> socket.getOutputStream().write(word(4097)) }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.TCP, 1000).use {
                assertEquals(Failure.RESPONSE_TOO_LARGE, it.execute().failure)
            }
        }
    }

    @Test(timeout = 5000) fun `invalid UDP reply and premature TCP EOF cannot complete`() {
        UdpFixture { request -> response(request).apply { this[0] = (this[0].toInt() xor 1).toByte() } }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.UDP, 1000).use {
                assertEquals(Failure.INVALID_DNS, it.execute().failure)
            }
        }
        TcpFixture { socket, _ -> socket.getOutputStream().write(word(12) + byteArrayOf(0)) }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.TCP, 1000).use {
                assertEquals(Failure.INVALID_DNS, it.execute().failure)
            }
        }
    }

    @Test(timeout = 5000) fun `UDP timeout returns no claim and no retry`() {
        UdpFixture { null }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.UDP, 120).use {
                val observation = it.execute()
                assertEquals(Execution.ERROR, observation.execution); assertEquals(Failure.TIMEOUT, observation.failure)
                assertNull(observation.responseCode); assertTrue(observation.addresses.isEmpty())
                fixture.server.soTimeout = 100
                try { fixture.server.receive(DatagramPacket(ByteArray(512), 512)); fail("Unexpected retry") }
                catch (_: SocketTimeoutException) {}
            }
        }
    }

    @Test(timeout = 5000) fun `UDP polling keeps the original total timeout budget`() {
        UdpFixture { null }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.UDP, 620).use {
                val observed = it.execute()
                assertEquals(Execution.ERROR, observed.execution)
                assertEquals(Failure.TIMEOUT, observed.failure)
                assertTrue("elapsed=${observed.durationMillis}", observed.durationMillis!! in 500..1500)
                fixture.server.soTimeout = 100
                try { fixture.server.receive(DatagramPacket(ByteArray(512), 512)); fail("Poll resent the query") }
                catch (_: SocketTimeoutException) {}
            }
        }
    }

    @Test(timeout = 5000) fun `TCP slow drip is limited by total deadline rather than per read timeout`() {
        TcpFixture { socket, request ->
            val bytes = response(request)
            socket.getOutputStream().write(word(bytes.size))
            for (byte in bytes) {
                socket.getOutputStream().write(byte.toInt()); socket.getOutputStream().flush()
                Thread.sleep(40)
            }
        }.use { fixture ->
            RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.TCP, 180).use {
                val observed = it.execute()
                assertEquals(Failure.TIMEOUT, observed.failure)
                assertTrue("elapsed=${observed.durationMillis}", observed.durationMillis!! < 1500)
            }
        }
    }

    @Test(timeout = 5000) fun `close before execute sends no packet and one instance cannot run twice`() {
        DatagramSocket(0, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { server ->
            val probe = RawDnsProbe(config.copy(port = server.localPort), DnsTransport.UDP, 100)
            probe.close()
            val observed = probe.execute()
            assertEquals(Execution.CANCELLED, observed.execution); assertNull(observed.transactionId)
            server.soTimeout = 100
            try { server.receive(DatagramPacket(ByteArray(512), 512)); fail("Cancelled probe sent data") }
            catch (_: SocketTimeoutException) {}
            try { probe.execute(); fail("Repeated execute allowed") } catch (_: IllegalStateException) {}
        }
    }

    @Test(timeout = 5000) fun `close before TCP execute does not connect`() {
        ServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { server ->
            val probe = RawDnsProbe(config.copy(port = server.localPort), DnsTransport.TCP, 100)
            probe.close()
            assertEquals(Execution.CANCELLED, probe.execute().execution)
            server.soTimeout = 100
            try { server.accept().use { fail("Cancelled probe connected") } } catch (_: SocketTimeoutException) {}
        }
    }

    @Test(timeout = 5000) fun `close cancels a ten second UDP receive within one second`() {
        UdpFixture { null }.use { fixture ->
            val pool = Executors.newSingleThreadExecutor()
            val probe = RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.UDP, 10000)
            try {
                val task = pool.submit<RawDnsObservation> { probe.execute() }
                assertTrue(fixture.received.await(1, TimeUnit.SECONDS))
                Thread.sleep(350) // Cancel while waiting for a reply, after a receive polling interval.
                val startCancel = System.nanoTime()
                probe.close()
                val observed = task.get(1, TimeUnit.SECONDS)
                assertEquals(Execution.CANCELLED, observed.execution)
                assertEquals(Failure.CANCELLED, observed.failure)
                val cancellationMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startCancel)
                assertTrue("cancel elapsed=$cancellationMillis", cancellationMillis < 1000)
            } finally { probe.close(); pool.shutdownNow() }
        }
    }

    @Test(timeout = 5000) fun `close cancels an active TCP read`() {
        val release = CountDownLatch(1)
        TcpFixture { _, _ -> release.await(2, TimeUnit.SECONDS) }.use { fixture ->
            val pool = Executors.newSingleThreadExecutor()
            val probe = RawDnsProbe(config.copy(port = fixture.server.localPort), DnsTransport.TCP, 15000)
            try {
                val task = pool.submit<RawDnsObservation> { probe.execute() }
                assertTrue(fixture.received.await(1, TimeUnit.SECONDS))
                probe.close()
                val observed = task.get(1, TimeUnit.SECONDS)
                assertEquals(Execution.CANCELLED, observed.execution); assertEquals(Failure.CANCELLED, observed.failure)
            } finally { release.countDown(); probe.close(); pool.shutdownNow() }
        }
    }

    @Test fun `schema two redacts raw DNS identifiers and keeps error and coverage evidence`() {
        val base = DemoFixture.report()
        val report = base.copy(config = base.config.copy(rawDns = config.copy(serverIp = "192.0.2.249", host = "raw-secret.example")),
            rawDns = listOf(RawDnsObservation(DnsTransport.UDP, Execution.COMPLETED, 123, 5, 3, true, listOf("192.0.2.248"))))
        val redacted = ReportExporter.toJson(report)
        val full = ReportExporter.toJson(report, true)
        for (secret in listOf("192.0.2.249", "raw-secret.example", "192.0.2.248")) {
            assertFalse(redacted.contains(secret)); assertTrue(full.contains(secret))
        }
        for (field in listOf("\"schemaVersion\":2", "\"responseCode\":3", "\"truncated\":true",
            "\"privacyVerdict\":\"INSUFFICIENT\"", "\"evidenceBudgetMillis\":60000", "\"wireResolverAndPath\":\"UNKNOWN\"")) assertTrue(field, redacted.contains(field))
        assertEquals(20000L, base.config.evidenceBudgetMillis)
        assertEquals(60000L, report.config.evidenceBudgetMillis)
        assertEquals(Verdict.INSUFFICIENT, report.dnsPrivacy.verdict)
        assertEquals(Verdict.INSUFFICIENT, report.ipv6.verdict)
    }
}
