package dev.proxyaudit.core

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Loopback only; private test trust is injected through an internal constructor. */
class ProxyCooperationTest {
    private fun dns(lookup: () -> List<InetAddress>): Dns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> = lookup()
    }
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val certificate = HeldCertificate.Builder().commonName("private-test-subject")
        .addSubjectAlternativeName("controller.test").build()
    private val serverTls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
    private val trustedTls = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    private val noProxy = object : ProxySelector() {
        override fun select(uri: URI): List<Proxy> = listOf(Proxy.NO_PROXY)
        override fun connectFailed(uri: URI, sa: SocketAddress, ioe: IOException) = Unit
    }
    private fun client(dns: Dns = dns { listOf(loopback) }): OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(trustedTls.sslSocketFactory(), trustedTls.trustManager)
        .proxySelector(noProxy).dns(dns).build()
    private fun server() = MockWebServer().also { it.useHttps(serverTls.sslSocketFactory(), false); it.start(loopback, 0) }
    private fun plan(server: MockWebServer, secret: String = "") = ProxyCooperationPlan.parse("https://controller.test:${server.port}", secret)
    private fun json(text: String) = MockResponse().setHeader("Content-Type", "application/json").setBody(text)
    private fun version() = json("""{"version":"v1.19.0","meta":true}""")
    private fun connections() = json("""{"connections":[{"id":"connection-private","metadata":{"network":"tcp","type":"HTTP","sourceIP":"127.0.0.1","sourcePort":"45678","destinationIP":"198.18.0.42","destinationPort":443,"host":"site.private"},"chains":["private-node","Auto"],"rule":"DomainSuffix","rulePayload":"never-save-this-payload"}],"downloadTotal":1234}""")
    private fun waitIdle() {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (ProxyCooperationProbe.hasPendingWork() && System.nanoTime() < until) Thread.sleep(10)
        assertFalse("Bounded worker must exit after test", ProxyCooperationProbe.hasPendingWork())
    }
    @After fun cleanup() = waitIdle()

    @Test fun `origin input requires explicit https and rejects credentials path query fragment and invalid ports`() {
        assertNotNull(ProxyCooperationPlan.parse("https://controller.test:8443/"))
        assertNotNull(ProxyCooperationPlan.parse("https://[::1]:8443"))
        for (input in listOf("controller.test", "http://controller.test", "https://user:password@controller.test",
            "https://controller.test/path", "https://controller.test/%2f", "https://controller.test?token=private",
            "https://controller.test#private", "https://controller.test:", "https://controller.test:0", "https://controller.test:65536",
            "https://controller.test\\other", " https://controller.test", "https://controller.test\n")) {
            try { ProxyCooperationPlan.parse(input); fail("Must reject unsafe origin") }
            catch (e: IllegalArgumentException) { assertFalse(e.message.orEmpty().contains("password")); assertFalse(e.message.orEmpty().contains("private")) }
        }
    }

    @Test fun `credentials validation and plan tostring do not expose inputs`() {
        assertFalse(ProxyCooperationPlan.parse("https://controller.test", "private-token").toString().contains("private-token"))
        assertFalse(ProxyCooperationPlan.parse("https://controller.test").toString().contains("controller.test"))
        for (secret in listOf("private\r\nheader", "private token", "x".repeat(4097), "凭据")) {
            try { ProxyCooperationPlan.parse("https://controller.test", secret); fail("Must reject invalid header") }
            catch (e: IllegalArgumentException) { assertFalse(e.message.orEmpty().contains(secret)) }
        }
    }

    @Test fun `only two permitted GET endpoints send authorization and preserve field compatibility`() {
        server().use { server ->
            server.enqueue(version()); server.enqueue(connections())
            val report = ProxyCooperationProbe(plan(server, "private-token"), client()).execute()
            assertEquals(report.toText(), Execution.COMPLETED, report.execution)
            assertNull(report.failure); assertEquals("v1.19.0", report.backendVersion)
            assertEquals(1, report.connectionCount); assertFalse(report.sampleIncomplete)
            assertEquals(45678, report.connections.single().sourcePort)
            assertEquals(443, report.connections.single().destinationPort)
            assertEquals("site.private", report.connections.single().host)
            assertEquals(listOf("/version", "/connections"), report.requests.map { it.path })
            for (path in listOf("/version", "/connections")) {
                val request = server.takeRequest(1, TimeUnit.SECONDS)!!
                assertEquals("GET", request.method); assertEquals(path, request.path)
                assertEquals("Bearer private-token", request.getHeader("Authorization"))
                assertEquals("no-store", request.getHeader("Cache-Control")); assertEquals("identity", request.getHeader("Accept-Encoding"))
                assertEquals(0L, request.bodySize)
            }
            assertEquals(2, server.requestCount)
            assertTrue(report.toJson().contains("NOT_CORRELATED_WITH_THIS_APP"))
            assertTrue(report.toJson().contains("\"proxyPathVerified\":false"))
            val redacted = report.toJson() + report.toText() + report.toString() + report.connections.single().toString()
            for (value in listOf("controller.test", "private-token", "site.private", "connection-private", "127.0.0.1", "private-node"))
                assertFalse(value, redacted.contains(value))
            val full = report.toJson(true) + report.toText(true)
            assertTrue(full.contains("site.private")); assertTrue(full.contains("controller.test"))
            assertFalse(full.contains("private-token")); assertFalse(full.contains("never-save-this-payload"))
            assertFalse(full.contains("private-test-subject"))
        }
    }

    @Test fun `absent secret never sends authorization header`() {
        server().use { server ->
            server.enqueue(version()); server.enqueue(json("{\"connections\":[]}"))
            assertEquals(Execution.COMPLETED, ProxyCooperationProbe(plan(server), client()).execute().execution)
            repeat(2) { assertNull(server.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("Authorization")) }
        }
    }

    @Test fun `version failure stops before connections and 401 403 404 have separate classifications`() {
        for ((status, expected) in listOf(401 to ProxyCooperationFailure.UNAUTHORIZED, 403 to ProxyCooperationFailure.FORBIDDEN,
            404 to ProxyCooperationFailure.NOT_FOUND, 500 to ProxyCooperationFailure.HTTP_ERROR)) {
            server().use { server ->
                server.enqueue(MockResponse().setResponseCode(status).setBody("private-error-body"))
                val report = ProxyCooperationProbe(plan(server), client()).execute()
                assertEquals(expected, report.failure); assertEquals(1, server.requestCount)
                assertEquals(status, report.requests.single().statusCode)
                assertFalse(report.toJson(true).contains("private-error-body"))
            }
        }
    }

    @Test fun `redirect cannot contact another endpoint or disclose credential there`() {
        server().use { first -> server().use { second ->
            first.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "https://controller.test:${second.port}/configs"))
            val report = ProxyCooperationProbe(plan(first, "private-token"), client()).execute()
            assertEquals(ProxyCooperationFailure.HTTP_ERROR, report.failure)
            assertEquals(1, first.requestCount); assertEquals(0, second.requestCount)
            assertFalse(report.toJson(true).contains("configs"))
        } }
    }

    @Test fun `non-json media type and malformed json are distinguished without raw body`() {
        for ((response, expected) in listOf(
            MockResponse().setHeader("Content-Type", "text/html").setBody("<html>private</html>") to ProxyCooperationFailure.NON_JSON,
            json("{\"version\": \"private\",}") to ProxyCooperationFailure.INVALID_JSON,
            json("{\"version\":\"one\",\"version\":\"two\"}") to ProxyCooperationFailure.INVALID_JSON,
            json("[]") to ProxyCooperationFailure.NON_JSON,
            json("{\"meta\":true}") to ProxyCooperationFailure.MISSING_FIELD)) {
            server().use { server ->
                server.enqueue(response)
                val report = ProxyCooperationProbe(plan(server), client()).execute()
                assertEquals(expected, report.failure); assertFalse(report.toJson(true).contains("private"))
                assertEquals(1, server.requestCount)
            }
        }
    }

    @Test fun `response byte ceiling rejects declared and chunked oversized payloads`() {
        val body = " ".repeat(ProxyCooperationProbe.RESPONSE_LIMIT_BYTES + 1)
        for (response in listOf(json(body), MockResponse().setHeader("Content-Type", "application/json").setChunkedBody(body, 4096))) {
            server().use { server ->
                server.enqueue(response)
                val report = ProxyCooperationProbe(plan(server), client()).execute()
                assertEquals(ProxyCooperationFailure.RESPONSE_TOO_LARGE, report.failure)
                assertTrue(report.requests.single().bodyBytesRead <= ProxyCooperationProbe.RESPONSE_LIMIT_BYTES)
                assertEquals(1, server.requestCount)
            }
        }
    }

    @Test fun `503 retry-after zero does not trigger library protocol retry`() {
        server().use { server ->
            server.enqueue(MockResponse().setResponseCode(503).setHeader("Retry-After", "0"))
            server.enqueue(version())
            val report = ProxyCooperationProbe(plan(server), client()).execute()
            assertEquals(ProxyCooperationFailure.HTTP_ERROR, report.failure)
            assertEquals(503, report.requests.single().statusCode)
            assertEquals(1, server.requestCount)
        }
    }

    @Test fun `missing connections and invalid entries retain version but do not invent a count`() {
        for ((body, expected) in listOf("{}" to ProxyCooperationFailure.MISSING_FIELD,
            "{\"connections\":{}}" to ProxyCooperationFailure.INVALID_JSON,
            "{\"connections\":[{}]}" to ProxyCooperationFailure.MISSING_FIELD,
            "{\"connections\":[null]}" to ProxyCooperationFailure.INVALID_JSON)) {
            server().use { server ->
                server.enqueue(version()); server.enqueue(json(body))
                val report = ProxyCooperationProbe(plan(server), client()).execute()
                assertEquals(body, expected, report.failure); assertEquals("v1.19.0", report.backendVersion)
                assertNull(report.connectionCount); assertEquals(0, report.connections.size)
                assertEquals(Execution.COMPLETED, report.requests.first().execution)
                assertEquals(Execution.ERROR, report.requests.last().execution)
            }
        }
    }

    @Test fun `empty and null connections are compatible successful zero snapshots`() {
        for (body in listOf("{\"connections\":[]}", "{\"connections\":null}")) server().use { server ->
            server.enqueue(version()); server.enqueue(json(body))
            val report = ProxyCooperationProbe(plan(server), client()).execute()
            assertEquals(Execution.COMPLETED, report.execution); assertEquals(0, report.connectionCount)
            assertFalse(report.sampleIncomplete)
        }
    }

    @Test fun `alternative IP casing and typed ports are accepted and malformed optional ports omitted`() {
        server().use { server ->
            server.enqueue(version()); server.enqueue(json("""{"connections":[{"id":"x","metadata":{"sourceIp":"::1","destinationIp":"2001:db8::1","sourcePort":53,"destinationPort":"443"}},{"id":"y","metadata":{"sourcePort":"bad","destinationPort":70000}}]}"""))
            val report = ProxyCooperationProbe(plan(server), client()).execute()
            assertEquals(Execution.COMPLETED, report.execution)
            assertEquals("::1", report.connections[0].sourceIp); assertEquals("2001:db8::1", report.connections[0].destinationIp)
            assertEquals(53, report.connections[0].sourcePort); assertEquals(443, report.connections[0].destinationPort)
            assertNull(report.connections[1].sourcePort); assertNull(report.connections[1].destinationPort)
        }
    }

    @Test fun `duplicate IDs invalidate snapshot including duplicates outside retained sample`() {
        val entries = (0..100).map { "{\"id\":\"id$it\"}" } + "{\"id\":\"id100\"}"
        server().use { server ->
            server.enqueue(version()); server.enqueue(json("{\"connections\":[${entries.joinToString()}]}"))
            val report = ProxyCooperationProbe(plan(server), client()).execute()
            assertEquals(ProxyCooperationFailure.DUPLICATE_CONNECTION_ID, report.failure)
            assertNull(report.connectionCount); assertTrue(report.connections.isEmpty())
        }
    }

    @Test fun `snapshot count is complete but exported metadata sample is capped at 100`() {
        val entries = (0..125).map { "{\"id\":\"id$it\"}" }
        server().use { server ->
            server.enqueue(version()); server.enqueue(json("{\"connections\":[${entries.joinToString()}]}"))
            val report = ProxyCooperationProbe(plan(server), client()).execute()
            assertEquals(Execution.COMPLETED, report.execution); assertEquals(126, report.connectionCount)
            assertEquals(100, report.connections.size); assertTrue(report.sampleIncomplete)
            assertFalse(report.toJson(true).contains("id100"))
        }
    }

    @Test fun `response echo of secret is scrubbed in version id host chain rule and every report format`() {
        server().use { server ->
            server.enqueue(json("{\"version\":\"private-token-version\"}"))
            server.enqueue(json("""{"connections":[{"id":"private-token-id","metadata":{"host":"private-token-host","sourceIP":"private-token-ip","network":"private-token-network","type":"private-token-type"},"chains":["private-token-chain","https://user:password@host"],"rule":"private-token-rule","rulePayload":"other-secret"}],"secret":"private-token"}"""))
            val report = ProxyCooperationProbe(plan(server, "private-token"), client()).execute()
            assertEquals(Execution.COMPLETED, report.execution)
            for (full in listOf(false, true)) {
                val output = report.toJson(full) + report.toText(full) + report.toString()
                for (private in listOf("private-token", "password", "other-secret")) assertFalse(output, output.contains(private))
            }
            assertTrue(report.connections.single().chains[1].contains("REDACTED"))
        }
    }

    @Test fun `deep json and long strings fail bounded parser instead of escaping budget`() {
        val depth = "[".repeat(24) + "0" + "]".repeat(24)
        for (body in listOf("{\"version\":\"ok\",\"extra\":$depth}", "{\"version\":\"${"a".repeat(32770)}\"}")) {
            server().use { server ->
                server.enqueue(json(body))
                assertEquals(ProxyCooperationFailure.INVALID_JSON, ProxyCooperationProbe(plan(server), client()).execute().failure)
            }
        }
    }

    @Test fun `untrusted certificate fails without retry or certificate data export`() {
        server().use { server ->
            val platformClient = OkHttpClient.Builder().proxySelector(noProxy).dns(dns { listOf(loopback) }).build()
            val report = ProxyCooperationProbe(plan(server), platformClient).execute()
            assertEquals(ProxyCooperationFailure.TLS_CERTIFICATE, report.failure)
            assertEquals(1, report.requests.size)
            assertFalse(report.toJson(true).contains("private-test-subject"))
        }
    }

    @Test fun `trusted certificate with wrong host fails hostname verification`() {
        server().use { server ->
            val wrong = ProxyCooperationPlan.parse("https://wrong.test:${server.port}")
            val report = ProxyCooperationProbe(wrong, client()).execute()
            assertEquals(ProxyCooperationFailure.TLS_PEER_IDENTITY, report.failure)
        }
    }

    @Test fun `cancel active call returns promptly retains completed version and omits later results`() {
        server().use { server ->
            server.enqueue(version()); server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
            val probe = ProxyCooperationProbe(plan(server), client())
            val executor = Executors.newSingleThreadExecutor()
            try {
                val future = executor.submit<ProxyCooperationReport> { probe.execute() }
                assertNotNull(server.takeRequest(2, TimeUnit.SECONDS)); assertNotNull(server.takeRequest(2, TimeUnit.SECONDS))
                val start = System.nanoTime(); probe.close()
                val report = future.get(1, TimeUnit.SECONDS)
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1000)
                assertEquals(Execution.CANCELLED, report.execution); assertEquals(ProxyCooperationFailure.CANCELLED, report.failure)
                assertEquals("v1.19.0", report.backendVersion); assertNull(report.connectionCount)
                assertEquals(2, report.requests.size); assertEquals(2, server.requestCount)
            } finally { probe.close(); executor.shutdownNow() }
        }
    }

    @Test fun `uninterruptible DNS does not spawn workers and retains global admission until release`() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val lookups = AtomicInteger()
        val resolver = dns { lookups.incrementAndGet(); entered.countDown(); release.await(5, TimeUnit.SECONDS); listOf(loopback) }
        val probe = ProxyCooperationProbe(ProxyCooperationPlan.parse("https://controller.test:9"), client(resolver))
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit<ProxyCooperationReport> { probe.execute() }
            assertTrue(entered.await(1, TimeUnit.SECONDS)); probe.close()
            assertEquals(ProxyCooperationFailure.CANCELLED, future.get(1, TimeUnit.SECONDS).failure)
            assertTrue(ProxyCooperationProbe.hasPendingWork())
            val second = ProxyCooperationProbe(ProxyCooperationPlan.parse("https://controller.test:9"), client(resolver)).execute()
            assertEquals(ProxyCooperationFailure.BUSY, second.failure); assertEquals(1, lookups.get())
        } finally { release.countDown(); probe.close(); executor.shutdownNow() }
    }

    @Test fun `per request timeout is three seconds even when system DNS ignores interruption`() {
        val release = CountDownLatch(1)
        val resolver = dns { release.await(6, TimeUnit.SECONDS); listOf(loopback) }
        val probe = ProxyCooperationProbe(ProxyCooperationPlan.parse("https://controller.test:9"), client(resolver))
        try {
            val start = System.nanoTime()
            val report = probe.execute()
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
            assertEquals(ProxyCooperationFailure.TIMEOUT, report.failure)
            assertTrue("Elapsed: $elapsed", elapsed in 2800..4200)
            assertEquals(listOf("/version"), report.requests.map { it.path })
        } finally { release.countDown(); probe.close() }
    }

    @Test fun `close before execution starts no request and plan can execute only once`() {
        val probe = ProxyCooperationProbe(ProxyCooperationPlan.parse("https://controller.test:9"), client())
        probe.close()
        val report = probe.execute()
        assertEquals(ProxyCooperationFailure.CANCELLED, report.failure); assertTrue(report.requests.isEmpty())
        try { probe.execute(); fail("Expected one-shot plan") } catch (_: IllegalStateException) { }
    }
}
