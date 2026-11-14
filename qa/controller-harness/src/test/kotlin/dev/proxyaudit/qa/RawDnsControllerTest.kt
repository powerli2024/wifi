package dev.proxyaudit.qa

import android.content.Context
import dev.proxyaudit.android.DiagnosticsController
import dev.proxyaudit.android.NetworkMonitor
import dev.proxyaudit.core.*
import java.net.BindException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

/** Real loopback DNS sockets plus fake Android APIs; never device/VPN evidence. */
class RawDnsControllerTest {
    private class LoopbackPair(val udp: DatagramSocket, val tcp: ServerSocket) : AutoCloseable {
        override fun close() { try { udp.close() } finally { tcp.close() } }
    }
    /** Reserve BOTH protocols before running a probe. An ephemeral port is only free for the
     * protocol that allocated it, so retry fixture allocation alone after a cross-protocol clash. */
    private fun openLoopbackPair(): LoopbackPair {
        val address = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        var lastCollision: BindException? = null
        repeat(16) {
            val tcp = ServerSocket()
            val udp = DatagramSocket(null)
            try {
                tcp.reuseAddress = false
                udp.reuseAddress = false
                tcp.bind(InetSocketAddress(address, 0))
                udp.bind(InetSocketAddress(address, tcp.localPort))
                return LoopbackPair(udp, tcp)
            } catch (collision: BindException) {
                lastCollision = collision
                try { udp.close() } finally { tcp.close() }
            } catch (error: Exception) {
                try { udp.close() } finally { tcp.close() }
                throw error
            }
        }
        throw AssertionError("Could not reserve one loopback port for both UDP and TCP after 16 fixture allocations", lastCollision)
    }
    private fun config(port: Int, tcp: Boolean = false) = RunConfig(
        null, null, ProbePolicy(false, false, emptySet(), true, false), timeoutMillis = 1000,
        rawDns = RawDnsConfig("127.0.0.1", port, "controller.test", udp = true, tcp = tcp)
    )
    private fun waitFor(block: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
        while (!block() && System.nanoTime() < end) Thread.sleep(5)
        assertTrue("Controller did not finish in time", block())
    }
    @Test fun `raw only starts and reports UDP response without HTTPS or system DNS`() {
        DatagramSocket(0, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { server ->
            server.soTimeout = 3000
            val task = Thread {
                val request = DatagramPacket(ByteArray(512), 512)
                server.receive(request)
                val response = request.data.copyOf(request.length)
                response[2] = 0x81.toByte()
                response[3] = 0x83.toByte() // NXDOMAIN is an observed answer, never privacy success.
                server.send(DatagramPacket(response, response.size, request.socketAddress))
            }.apply { isDaemon = true; start() }
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config(server.localPort)))
            waitFor { !controller.busy }
            task.join(3000)
            val report = controller.report!!
            assertEquals(Execution.NOT_STARTED, report.https.execution)
            assertEquals(Execution.NOT_STARTED, report.dns.execution)
            assertEquals(Execution.COMPLETED, report.rawDns.single().execution)
            assertEquals(3, report.rawDns.single().responseCode)
            assertEquals(Verdict.NOT_RUN, report.egress.verdict)
            assertEquals(Verdict.INSUFFICIENT, report.ipv6.verdict)
        }
    }
    @Test fun `cancel raw UDP preserves cancelled evidence and never begins configured TCP`() {
        DatagramSocket(0, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { server ->
            server.soTimeout = 3000
            val received = CountDownLatch(1)
            val task = Thread {
                server.receive(DatagramPacket(ByteArray(512), 512))
                received.countDown()
                // No response: cancellation must close the waiting UDP socket.
            }.apply { isDaemon = true; start() }
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config(server.localPort, tcp = true)))
            assertTrue(received.await(3, TimeUnit.SECONDS))
            controller.cancel()
            waitFor { !controller.busy }
            task.join(3000)
            val report = controller.report!!
            assertEquals(Execution.CANCELLED, report.rawDns[0].execution)
            assertEquals(Failure.CANCELLED, report.rawDns[0].failure)
            assertEquals(Execution.NOT_STARTED, report.rawDns[1].execution)
            Thread.sleep(30)
            assertSame(report, controller.report)
        }
    }

    @Test(timeout = 8000) fun `blocked snapshot cannot delay UDP close or replace cancelled phase with completed worker state`() {
        openLoopbackPair().use { fixture ->
            val server = fixture.udp
            val tcp = fixture.tcp
            tcp.soTimeout = 150
            server.soTimeout = 2000
            val controller = DiagnosticsController(Context())
            val snapshot = NetworkMonitor.SnapshotGate()
            try {
                assertTrue(controller.start(config(server.localPort, tcp = true).copy(timeoutMillis = 15000)))
                server.receive(DatagramPacket(ByteArray(512), 512))
                val token = DiagnosticsController::class.java.getDeclaredField("token")
                    .apply { isAccessible = true }.get(controller)
                val rawProbe = token.javaClass.getDeclaredField("rawProbe").apply { isAccessible = true }
                val phase = token.javaClass.getDeclaredField("phase").apply { isAccessible = true }
                val activeAttempt = token.javaClass.getDeclaredField("activeAttemptId").apply { isAccessible = true }
                NetworkMonitor.snapshotGate = snapshot
                controller.cancel()
                assertTrue(snapshot.entered.await(1, TimeUnit.SECONDS))
                // Internal lifecycle evidence is needed because the public slot deliberately also
                // waits for publication. Both fields are volatile; never acquire the controller
                // lock in this wait, so a blocked implementation cannot stall the test itself.
                // rawProbe is cleared only after close; NONE demonstrates the phase advanced.
                waitFor {
                    rawProbe.get(token) == null && phase.get(token) == "NONE"
                }
                // Reading volatile NONE above observes the preceding lifecycle clear, while the
                // immutable terminal evidence must still retain the stopped attempt for publication.
                assertNull("completed I/O must not leave an active attempt", activeAttempt.get(token))
                assertNull("snapshot has not returned", controller.report)
                assertTrue("unpublished terminal result must retain the slot", controller.busy)
                assertFalse(controller.start(config(server.localPort)))
                try {
                    tcp.accept().close()
                    fail("TCP must not start after UDP cancellation")
                } catch (_: SocketTimeoutException) { /* No later protocol was started. */ }
                snapshot.release.countDown()
                waitFor { !controller.busy }
                val report = controller.report!!
                assertEquals(Execution.CANCELLED, report.rawDns[0].execution)
                assertEquals(Failure.CANCELLED, report.rawDns[0].failure)
                assertEquals(Execution.NOT_STARTED, report.rawDns[1].execution)
                assertEquals(report.rawDns[0], report.attempts.single().rawDns)
                assertEquals(Failure.CANCELLED, report.stopReason)
                assertEquals(1, snapshot.calls.get())
            } finally {
                snapshot.release.countDown()
                NetworkMonitor.snapshotGate = null
                controller.cancel()
            }
        }
    }
}
