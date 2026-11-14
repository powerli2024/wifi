package dev.proxyaudit.core

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.ServerSocket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Loopback HTTPS only. Test CA trust is injected into an internal constructor, never installed. */
class WebsiteDiagnosticsTest {
    private fun testDns(lookup: (String) -> List<InetAddress>): Dns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> = lookup.invoke(hostname)
    }
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val certificate = HeldCertificate.Builder().commonName("private-certificate-subject")
        .addSubjectAlternativeName("site.test").build()
    private val serverTls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
    private val trustedTls = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    private val noExplicitProxy = object : ProxySelector() {
        override fun select(uri: URI): List<Proxy> = listOf(Proxy.NO_PROXY)
        override fun connectFailed(uri: URI, sa: SocketAddress, ioe: IOException) = Unit
    }
    private fun client(dns: Dns = testDns { listOf(loopback) }): OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(trustedTls.sslSocketFactory(), trustedTls.trustManager)
        .proxySelector(noExplicitProxy).dns(dns).build()
    private fun server(): MockWebServer = MockWebServer().also {
        it.useHttps(serverTls.sslSocketFactory(), false)
        it.start(loopback, 0)
    }
    private fun plan(server: MockWebServer, path: String = "/", timeout: Int = 2000, total: Int = 4000, attempts: Int = 1) =
        WebsitePlan.parse("https://site.test:${server.port}$path", timeout, total, attempts)
    private fun stage(report: WebsiteReport, stage: WebsiteStage) = report.stages.first { it.stage == stage }
    private fun waitIdle() {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
        while (WebsiteDiagnostics.hasPendingWork() && System.nanoTime() < deadline) Thread.sleep(10)
        assertFalse("The bounded worker must eventually exit", WebsiteDiagnostics.hasPendingWork())
    }
    @After fun cleanup() = waitIdle()

    @Test fun `plan defaults bare domain to https but rejects ambiguous or credentialed URLs`() {
        val plan = WebsitePlan.parse("chatgpt.com/help?q=private")
        assertEquals("https://chatgpt.com/help?q=private", plan.url)
        assertEquals("https://chatgpt.com", plan.displayTarget)
        assertFalse(plan.toString().contains("private"))
        for (input in listOf("http://site.test", "https://user:password@site.test/", "https://site.test/#private",
            "https://site.test/a b", "https://site.test\\other", "https://site.test:", "https://site.test:0/", "https://site.test:99999/")) {
            try { WebsitePlan.parse(input); fail("Expected invalid URL") }
            catch (error: IllegalArgumentException) { assertFalse(error.message.orEmpty().contains("password")) }
        }
    }

    @Test fun `local validated HTTPS GET records every layer without saving the body`() {
        server().use { server ->
            server.enqueue(MockResponse().setBody("private-response-body"))
            val report = WebsiteDiagnostics(plan(server, "/secret-path?token=secret-token"), client()).execute()
            assertEquals(report.toText(), Execution.COMPLETED, report.execution)
            WebsiteStage.entries.forEach { assertEquals(it.name, WebsiteStageStatus.SUCCEEDED, stage(report, it).status) }
            assertEquals(200, report.statusCode)
            assertTrue(report.toText(), report.httpProtocol in setOf("http/1.1", "h2"))
            assertNotNull(report.tlsVersion)
            assertNotNull(report.certificateNotAfterUtc)
            assertEquals("GET", server.takeRequest(1, TimeUnit.SECONDS)!!.method)
            assertEquals(21L, report.bodyBytesRead)
            assertFalse(report.bodyTruncated)
            for (full in listOf(false, true)) {
                val output = report.toJson(full) + report.toText(full)
                for (secret in listOf("secret-path", "secret-token", "private-response-body", "private-certificate-subject"))
                    assertFalse("Must not export request/body/certificate identifiers", output.contains(secret))
            }
            assertFalse(report.toJson().contains("site.test"))
            assertFalse(report.toJson().contains("127.0.0.1"))
            assertTrue(report.toJson(true).contains("site.test"))
        }
    }

    @Test fun `HTTP forbidden is response evidence and never triggers automatic retry`() {
        server().use { server ->
            server.enqueue(MockResponse().setResponseCode(403).setBody("Access denied"))
            val report = WebsiteDiagnostics(plan(server, attempts = 2), client()).execute()
            assertEquals(Execution.COMPLETED, report.execution)
            assertEquals(403, report.statusCode)
            assertEquals(WebsiteStageStatus.SUCCEEDED, stage(report, WebsiteStage.TLS).status)
            assertEquals(WebsiteStageStatus.SUCCEEDED, stage(report, WebsiteStage.HTTP).status)
            assertEquals(1, report.attempts.size)
            assertEquals(1, server.requestCount)
            assertTrue(report.summary.contains("访问限制"))
            assertTrue(report.nextSteps.any { it.contains("不是 DNS 失败") })
        }
    }

    @Test fun `redirect is not followed and exports only its origin when explicitly requested`() {
        server().use { first -> server().use { second ->
            first.enqueue(MockResponse().setResponseCode(302)
                .setHeader("Location", "https://site.test:${second.port}/private-next?key=secret").setBody(""))
            val report = WebsiteDiagnostics(plan(first), client()).execute()
            assertEquals(302, report.statusCode)
            assertEquals(0, second.requestCount)
            assertEquals("https://site.test:${second.port}", report.redirectOrigin)
            assertFalse(report.toJson(true).contains("private-next"))
            assertFalse(report.toJson(true).contains("key=secret"))
            assertFalse(report.toJson().contains("site.test"))
        } }
    }

    @Test fun `body ceiling is partial evidence not website failure`() {
        server().use { server ->
            server.enqueue(MockResponse().setBody("x".repeat(WebsiteDiagnostics.BODY_LIMIT_BYTES * 2)))
            val report = WebsiteDiagnostics(plan(server), client()).execute()
            assertEquals(Execution.COMPLETED, report.execution)
            assertEquals(WebsiteDiagnostics.BODY_LIMIT_BYTES.toLong(), report.bodyBytesRead)
            assertTrue(report.bodyTruncated)
            assertEquals(WebsiteStageStatus.PARTIAL, stage(report, WebsiteStage.BODY).status)
            assertEquals(WebsiteStageStatus.SUCCEEDED, stage(report, WebsiteStage.HTTP).status)
            assertNull(report.failure)
        }
    }

    @Test fun `untrusted certificate fails TLS while preserving established connection`() {
        server().use { server ->
            server.enqueue(MockResponse().setBody("must not be read"))
            val untrusted = OkHttpClient.Builder().proxySelector(noExplicitProxy).dns(testDns { listOf(loopback) }).build()
            val report = WebsiteDiagnostics(plan(server, attempts = 2), untrusted).execute()
            assertEquals(Execution.ERROR, report.execution)
            assertEquals(WebsiteStageStatus.SUCCEEDED, stage(report, WebsiteStage.CONNECT).status)
            assertEquals(WebsiteStageStatus.FAILED, stage(report, WebsiteStage.TLS).status)
            assertEquals(WebsiteStageStatus.NOT_RUN, stage(report, WebsiteStage.HTTP).status)
            assertNull(report.certificateNotAfterUtc)
            assertEquals(1, report.attempts.size)
            assertEquals(0, server.requestCount)
        }
    }

    @Test fun `trusted but wrong hostname is rejected with no insecure fallback`() {
        server().use { server ->
            val wrong = WebsitePlan.parse("https://wrong.test:${server.port}/", 2000, 4000, 2)
            val report = WebsiteDiagnostics(wrong, client()).execute()
            assertEquals(WebsiteFailure.TLS_PEER_IDENTITY, report.failure)
            assertEquals(1, report.attempts.size)
            assertEquals(WebsiteStageStatus.FAILED, stage(report, WebsiteStage.TLS).status)
            assertEquals(0, server.requestCount)
            assertFalse(report.toJson(true).contains("private-certificate-subject"))
        }
    }

    private fun invalidCertificateTime(startOffset: Long, endOffset: Long): WebsiteReport {
        val ca = HeldCertificate.Builder().certificateAuthority(0).build()
        val now = System.currentTimeMillis()
        val leaf = HeldCertificate.Builder().addSubjectAlternativeName("site.test").signedBy(ca)
            .validityInterval(now + startOffset, now + endOffset).build()
        val serving = HandshakeCertificates.Builder().heldCertificate(leaf, ca.certificate).build()
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(ca.certificate).build()
        MockWebServer().use { server ->
            server.useHttps(serving.sslSocketFactory(), false)
            server.start(loopback, 0)
            val client = client().newBuilder().sslSocketFactory(trust.sslSocketFactory(), trust.trustManager).build()
            val report = WebsiteDiagnostics(plan(server, attempts = 2), client).execute()
            assertEquals(1, report.attempts.size)
            assertEquals(WebsiteStageStatus.SUCCEEDED, stage(report, WebsiteStage.CONNECT).status)
            assertEquals(WebsiteStageStatus.FAILED, stage(report, WebsiteStage.TLS).status)
            assertNull(report.certificateNotAfterUtc)
            assertEquals(0, server.requestCount)
            return report
        }
    }

    @Test fun `trusted expired leaf is classified without bypassing certificate validation`() {
        assertEquals(WebsiteFailure.TLS_CERTIFICATE_EXPIRED, invalidCertificateTime(-172_800_000, -86_400_000).failure)
    }

    @Test fun `trusted not yet valid leaf suggests clock or certificate investigation`() {
        assertEquals(WebsiteFailure.TLS_CERTIFICATE_NOT_YET_VALID, invalidCertificateTime(86_400_000, 172_800_000).failure)
    }

    @Test fun `same plan temporary failure is preserved when one automatic recheck responds`() {
        server().use { server ->
            server.enqueue(MockResponse().setBody("ok"))
            val lookups = AtomicInteger()
            val dns = testDns {
                if (lookups.incrementAndGet() == 1) throw SocketTimeoutException("private-error-contents")
                listOf(loopback)
            }
            val report = WebsiteDiagnostics(plan(server, attempts = 2), client(dns)).execute()
            assertEquals(2, report.attempts.size)
            assertEquals(WebsiteFailure.TIMEOUT, report.attempts[0].failure)
            assertEquals(Execution.COMPLETED, report.attempts[1].execution)
            assertEquals(Execution.ERROR, report.execution)
            assertEquals(WebsiteStageStatus.FAILED, stage(report, WebsiteStage.DNS).status)
            assertNull(report.statusCode)
            assertEquals(200, report.attempts[1].statusCode)
            assertTrue(report.summary.contains("首次尝试失败"))
            assertEquals(1, server.requestCount)
            assertFalse(report.toJson(true).contains("private-error-contents"))
        }
    }

    @Test fun `full attempt deadline can recheck once within the unchanged total budget`() {
        server().use { server ->
            server.enqueue(MockResponse().setBody("slow-body").setBodyDelay(2, TimeUnit.SECONDS))
            server.enqueue(MockResponse().setBody("second-response"))
            val report = WebsiteDiagnostics(plan(server, timeout = 800, total = 3500, attempts = 2), client()).execute()
            assertEquals(2, report.attempts.size)
            assertEquals(WebsiteFailure.TIMEOUT, report.attempts[0].failure)
            assertEquals(WebsiteStageStatus.SUCCEEDED, report.attempts[0].stages.first { it.stage == WebsiteStage.HTTP }.status)
            assertEquals(Execution.COMPLETED, report.attempts[1].execution)
            assertEquals(2, server.requestCount)
            assertEquals(Execution.ERROR, report.execution)
            assertTrue(report.summary.contains("首次尝试失败"))
        }
    }

    @Test fun `HTTP send failure after verified TLS cannot erase the TLS success`() {
        server().use { server ->
            val failing = client().newBuilder().addNetworkInterceptor { throw IOException("private-send-error") }.build()
            val report = WebsiteDiagnostics(plan(server), failing).execute()
            assertEquals(WebsiteStageStatus.SUCCEEDED, stage(report, WebsiteStage.TLS).status)
            assertEquals(WebsiteStageStatus.FAILED, stage(report, WebsiteStage.HTTP).status)
            assertNotNull(report.certificateNotAfterUtc)
            assertNotNull(report.tlsVersion)
            assertEquals(0, server.requestCount)
            assertFalse(report.toJson(true).contains("private-send-error"))
        }
    }

    @Test fun `DNS failure does not blindly retry or expose exception text`() {
        val calls = AtomicInteger()
        val client = client(testDns { calls.incrementAndGet(); throw UnknownHostException("secret-host-and-token") })
        val report = WebsiteDiagnostics(WebsitePlan.parse("site.test"), client).execute()
        assertEquals(WebsiteFailure.DNS_FAILURE, report.failure)
        assertEquals(1, calls.get())
        assertFalse(report.toJson(true).contains("secret-host-and-token"))
        assertEquals(WebsiteStageStatus.NOT_RUN, stage(report, WebsiteStage.TLS).status)
    }

    @Test fun `system proxy selection is respected without silently connecting to target`() {
        val port = ServerSocket(0, 1, loopback).use { it.localPort }
        val selections = AtomicInteger()
        val originDns = AtomicInteger()
        val selector = object : ProxySelector() {
            override fun select(uri: URI): List<Proxy> {
                selections.incrementAndGet()
                return listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress(loopback, port)))
            }
            override fun connectFailed(uri: URI, sa: SocketAddress, ioe: IOException) = Unit
        }
        val proxied = client(testDns { originDns.incrementAndGet(); throw UnknownHostException() })
            .newBuilder().proxySelector(selector).build()
        val report = WebsiteDiagnostics(WebsitePlan.parse("https://unresolved.test/", 1000, 1500, 1), proxied).execute()
        assertTrue(selections.get() > 0)
        assertEquals(0, originDns.get())
        assertEquals(WebsiteFailure.CONNECT_FAILURE, report.failure)
        assertEquals("HTTP", report.attempts.single().connections.single().proxyType)
        assertEquals(WebsiteStageStatus.NOT_OBSERVED, stage(report, WebsiteStage.DNS).status)
        assertTrue(report.limitations.any { it.contains("不证明流量未经过 VPN") })
    }

    @Test fun `slow response body respects absolute budget and preserves successful headers`() {
        server().use { server ->
            server.enqueue(MockResponse().setBody("delayed").setBodyDelay(2, TimeUnit.SECONDS))
            val started = System.nanoTime()
            val report = WebsiteDiagnostics(plan(server, timeout = 700, total = 700), client()).execute()
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue("Absolute budget must not become a per-read budget: $elapsed", elapsed < 1500)
            assertEquals(Execution.ERROR, report.execution)
            assertEquals(WebsiteStageStatus.SUCCEEDED, stage(report, WebsiteStage.TLS).status)
            assertEquals(WebsiteStageStatus.SUCCEEDED, stage(report, WebsiteStage.HTTP).status)
            assertEquals(WebsiteStageStatus.FAILED, stage(report, WebsiteStage.BODY).status)
            assertEquals(200, report.statusCode)
        }
    }

    @Test fun `cancellation returns promptly but blocked DNS keeps the single work slot until actual exit`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val lookupCount = AtomicInteger()
        val blocker = client(testDns { lookupCount.incrementAndGet(); entered.countDown(); release.await(); listOf(loopback) })
        val engine = WebsiteDiagnostics(WebsitePlan.parse("https://site.test:1/", 3000, 4000, 2), blocker)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit<WebsiteReport> { engine.execute() }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            engine.close()
            val report = future.get(1, TimeUnit.SECONDS)
            assertEquals(Execution.CANCELLED, report.execution)
            assertTrue(WebsiteDiagnostics.hasPendingWork())
            val blocked = WebsiteDiagnostics(WebsitePlan.parse("https://site.test:1/"), blocker).execute()
            assertEquals(WebsiteFailure.BUSY, blocked.failure)
            assertTrue(blocked.attempts.isEmpty())
            assertEquals(1, lookupCount.get())
            val frozen = report.toJson(true)
            release.countDown()
            waitIdle()
            assertEquals(frozen, report.toJson(true))
            assertTrue(report.attempts.single().connections.isEmpty())
        } finally { release.countDown(); engine.close(); executor.shutdownNow() }
    }

    @Test fun `absolute DNS deadline returns without starting replacement worker`() {
        val release = CountDownLatch(1)
        val blocker = client(testDns { release.await(); listOf(loopback) })
        val engine = WebsiteDiagnostics(WebsitePlan.parse("https://site.test:1/", 300, 600, 2), blocker)
        try {
            val start = System.nanoTime()
            val report = engine.execute()
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1000)
            assertEquals(WebsiteFailure.TIMEOUT, report.failure)
            assertEquals(1, report.attempts.size)
            assertTrue(WebsiteDiagnostics.hasPendingWork())
            assertTrue(report.attempts.single().connections.isEmpty())
        } finally { release.countDown(); engine.close() }
    }

    @Test fun `close before execution never starts network work`() {
        val calls = AtomicInteger()
        val engine = WebsiteDiagnostics(WebsitePlan.parse("site.test"), client(testDns { calls.incrementAndGet(); listOf(loopback) }))
        engine.close()
        val report = engine.execute()
        assertEquals(Execution.CANCELLED, report.execution)
        assertEquals(0, calls.get())
        assertTrue(report.attempts.isEmpty())
    }

    @Test fun `advertised idle permits consecutive admissions without spurious busy rejection`() {
        val calls = AtomicInteger()
        val fastFailure = client(testDns { calls.incrementAndGet(); throw UnknownHostException() })
        val plan = WebsitePlan.parse("site.test", 1000, 1000, 1)
        repeat(500) { index ->
            val idleDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
            while (WebsiteDiagnostics.hasPendingWork() && System.nanoTime() < idleDeadline) Thread.yield()
            assertFalse("Previous task must actually release its admission", WebsiteDiagnostics.hasPendingWork())
            val report = WebsiteDiagnostics(plan, fastFailure).execute()
            assertEquals("Admission $index\n${report.toText()}", WebsiteFailure.DNS_FAILURE, report.failure)
        }
        assertEquals(500, calls.get())
    }
}
