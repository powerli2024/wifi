package dev.proxyaudit.qa

import android.content.Context
import android.net.DnsResolver
import android.system.ErrnoException
import dev.proxyaudit.android.DiagnosticsController
import dev.proxyaudit.core.*
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/** Production controller with API-shaped fakes; no resolver or network request is made. */
class SystemDnsDiagnosticsTest {
    private val config get() = RunConfig(null, "controlled.test", ProbePolicy(false, true, emptySet(), true, false))
    private val address get() = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 5))
    private fun waitFor(label: String, predicate: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!predicate() && System.nanoTime() < deadline) Thread.sleep(5)
        assertTrue(label, predicate())
    }
    private fun runCallback(answer: (DnsResolver.Callback<List<InetAddress>>) -> Unit): RunReport {
        DnsResolver.reset()
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(config))
        waitFor("DNS query was not submitted") { DnsResolver.lastCall != null }
        val call = DnsResolver.lastCall!!
        call.executor.execute { answer(call.callback) }
        waitFor("DNS query did not finish") { !controller.busy }
        assertTrue(call.signal.isCanceled)
        return controller.report!!
    }
    @Before fun reset() { DnsResolver.reset() }

    @Test fun `successful callback retains response code and default resolver API semantics`() {
        val report = runCallback { it.onAnswer(listOf(address), 0) }
        assertEquals(dev.proxyaudit.android.AppIdentity.version, report.appVersion)
        assertEquals(Execution.COMPLETED, report.dns.execution)
        assertEquals(listOf("192.0.2.5"), report.dns.addresses)
        assertEquals(SystemDnsStage.ANSWER_CALLBACK, report.dns.diagnosticStage)
        assertEquals(0, report.dns.responseCode)
        assertNull(report.dns.resolverErrorCode); assertNull(report.dns.systemErrno); assertNull(report.dns.exceptionKind)
        assertEquals(Verdict.INSUFFICIENT, report.dnsPrivacy.verdict)
    }

    @Test fun `NXDOMAIN refusal failure and empty NOERROR retain response code but no usable address`() {
        for (rcode in listOf(3, 5, 2, 0)) {
            val report = runCallback { it.onAnswer(if (rcode == 0) emptyList() else listOf(address), rcode) }
            assertEquals(Execution.ERROR, report.dns.execution)
            assertEquals(Failure.DNS_FAILURE, report.dns.failure)
            assertTrue(report.dns.addresses.isEmpty())
            assertEquals(SystemDnsStage.ANSWER_CALLBACK, report.dns.diagnosticStage)
            assertEquals(rcode, report.dns.responseCode)
            assertNull(report.dns.resolverErrorCode)
        }
    }

    @Test fun `system callback keeps safe errno only and no exception original text in any export`() {
        val report = runCallback { it.onError(DnsResolver.DnsException(DnsResolver.ERROR_SYSTEM,
            ErrnoException("PRIVATE-QUERY-HOST-AND-SECRET", 101))) }
        assertEquals(Execution.ERROR, report.dns.execution)
        assertEquals(Failure.DNS_FAILURE, report.dns.failure)
        assertEquals(SystemDnsStage.ERROR_CALLBACK, report.dns.diagnosticStage)
        assertEquals(1, report.dns.resolverErrorCode); assertEquals(101, report.dns.systemErrno)
        assertNull(report.dns.responseCode); assertNull(report.dns.exceptionKind)
        for (full in listOf(false, true)) {
            val json = ReportExporter.toJson(report, full)
            assertTrue(json.contains("\"systemErrno\":101"))
            assertFalse(json.contains("PRIVATE-QUERY-HOST-AND-SECRET"))
        }
        assertFalse(SystemDnsDiagnostics.summary(report.dns).contains("PRIVATE-QUERY-HOST-AND-SECRET"))
    }

    @Test fun `parse and unknown callback codes retain codes without inventing errno or DNS rcode`() {
        for (code in listOf(DnsResolver.ERROR_PARSE, 73)) {
            val report = runCallback { it.onError(DnsResolver.DnsException(code,
                IllegalArgumentException("PRIVATE-RESPONSE-TEXT"))) }
            assertEquals(code, report.dns.resolverErrorCode)
            assertNull(report.dns.systemErrno); assertNull(report.dns.responseCode)
            assertEquals(SystemDnsStage.ERROR_CALLBACK, report.dns.diagnosticStage)
            assertFalse(ReportExporter.toJson(report, true).contains("PRIVATE-RESPONSE-TEXT"))
        }
    }

    @Test fun `synchronous API exceptions are classified without serializing messages`() {
        val cases = listOf(SecurityException("PRIVATE-EXCEPTION-TEXT") to SystemDnsExceptionKind.SECURITY,
            IllegalArgumentException("PRIVATE-EXCEPTION-TEXT") to SystemDnsExceptionKind.INVALID_ARGUMENT,
            InterruptedException("PRIVATE-EXCEPTION-TEXT") to SystemDnsExceptionKind.INTERRUPTED,
            IllegalStateException("PRIVATE-EXCEPTION-TEXT") to SystemDnsExceptionKind.OTHER)
        for ((exception, expected) in cases) {
            DnsResolver.reset(); DnsResolver.queryException = exception
            val controller = DiagnosticsController(Context())
            assertTrue(controller.start(config))
            waitFor("synchronous exception did not finish") { !controller.busy }
            val observation = controller.report!!.dns
            assertEquals(Failure.DNS_FAILURE, observation.failure)
            assertEquals(SystemDnsStage.LOCAL_EXCEPTION, observation.diagnosticStage)
            assertEquals(expected, observation.exceptionKind)
            assertNull(observation.responseCode); assertNull(observation.resolverErrorCode); assertNull(observation.systemErrno)
            for (full in listOf(false, true)) assertFalse(ReportExporter.toJson(controller.report!!, full).contains("PRIVATE-EXCEPTION-TEXT"))
            assertFalse(controller.status.contains("PRIVATE-EXCEPTION-TEXT"))
        }
    }

    @Test fun `late platform error cannot attach diagnostics to frozen cancelled evidence`() {
        val controller = DiagnosticsController(Context())
        assertTrue(controller.start(config))
        waitFor("DNS query was not submitted") { DnsResolver.lastCall != null }
        val call = DnsResolver.lastCall!!
        controller.cancel()
        waitFor("cancellation did not finish") { !controller.busy }
        val stopped = controller.report!!
        val callbackFinished = CountDownLatch(1)
        call.executor.execute {
            call.callback.onError(DnsResolver.DnsException(DnsResolver.ERROR_SYSTEM, ErrnoException("PRIVATE-LATE-ERROR", 101)))
            callbackFinished.countDown()
        }
        assertTrue(callbackFinished.await(1, TimeUnit.SECONDS))
        assertSame(stopped, controller.report)
        assertEquals(Execution.CANCELLED, stopped.dns.execution)
        assertEquals(Failure.CANCELLED, stopped.dns.failure)
        assertNull(stopped.dns.diagnosticStage); assertNull(stopped.dns.responseCode)
        assertNull(stopped.dns.resolverErrorCode); assertNull(stopped.dns.systemErrno); assertNull(stopped.dns.exceptionKind)
    }
}
