#!/usr/bin/env python3
"""Loopback TLS fixture tests, not Android/device/VPN or global CA tests."""
from datetime import datetime, timedelta, timezone
from http.client import HTTPSConnection
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from echo_fixture import create_server


class EchoFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="echo-tls-test-")
        cls.cert = Path(cls.temp.name) / "certificate.pem"
        cls.key = Path(cls.temp.name) / "private-key.pem"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "loopback fixture test")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(key, hashes.SHA256()))
        cls.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        cls.key.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        # Trust is scoped to this test client's context. No CA is installed.
        cls.client_context = ssl.create_default_context(cafile=str(cls.cert))

    def setUp(self):
        self.server = create_server(self.cert, self.key, 0, max_workers=2,
                                    handshake_timeout=0.6, request_timeout=0.8)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def request(self, target, headers=None):
        conn = HTTPSConnection("127.0.0.1", self.server.server_port, timeout=2,
                               context=self.client_context)
        try:
            conn.request("GET", target, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read())
        finally:
            conn.close()

    def wait_for_active(self, count):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.server.active_connection_count == count:
                return
            time.sleep(0.005)
        self.fail(f"active connections did not become {count}")

    def connect_raw(self):
        return socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2)

    def connect_tls(self):
        return self.client_context.wrap_socket(self.connect_raw(), server_hostname="127.0.0.1")

    def assert_closed(self, connection):
        try:
            self.assertEqual(b"", connection.recv(1))
        except (ConnectionResetError, ConnectionAbortedError, ssl.SSLError):
            pass

    def test_valid_nonce_and_source(self):
        nonce = "00000000-0000-4000-8000-000000000001"
        status, headers, body = self.request("/v1/echo?requestId=" + nonce)
        self.assertEqual(200, status)
        self.assertEqual({"schemaVersion": 1, "requestId": nonce, "observedSourceIp": "127.0.0.1"}, body)
        self.assertEqual("no-store", headers["Cache-Control"])
        self.assertEqual("close", headers["Connection"])

    def test_forwarded_headers_do_not_override_socket_peer(self):
        _, _, body = self.request("/v1/echo?requestId=00000000-0000-4000-8000-000000000001", {"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual("127.0.0.1", body["observedSourceIp"])

    def test_missing_wrong_path_and_duplicate_id_fail(self):
        for path in ["/", "/v1/echo", "/v1/echo?requestId=bad", "/v1/echo?requestId=x&requestId=y", "/v1/echo?requestId=00000000-0000-4000-8000-000000000001&token=x"]:
            with self.subTest(path=path):
                self.assertEqual(400, self.request(path)[0])

    def test_silent_clienthello_does_not_block_another_tls_client(self):
        with self.connect_raw() as silent:
            self.wait_for_active(1)
            status, _, _ = self.request("/v1/echo?requestId=00000000-0000-4000-8000-000000000001")
            self.assertEqual(200, status)
            self.assert_closed(silent)
        self.wait_for_active(0)

    def test_worker_limit_rejects_excess_and_recovers_after_handshake_timeout(self):
        with self.connect_raw() as first, self.connect_raw() as second:
            self.wait_for_active(2)
            with self.connect_raw() as excess:
                self.assert_closed(excess)
            self.assertEqual(2, self.server.active_connection_count)
            self.assert_closed(first)
            self.assert_closed(second)
        self.wait_for_active(0)
        self.assertEqual(200, self.request(
            "/v1/echo?requestId=00000000-0000-4000-8000-000000000001")[0])

    def test_completed_tls_with_incomplete_http_headers_expires(self):
        with self.connect_tls() as connection:
            connection.sendall(b"GET /v1/echo HTTP/1.1\r\nHost:")
            self.assert_closed(connection)
        self.wait_for_active(0)

    def test_trickled_http_headers_cannot_extend_absolute_deadline(self):
        with self.connect_tls() as connection:
            connection.sendall(b"GET /v1/echo HTTP/1.1\r\nX-Slow: ")
            self.wait_for_active(1)
            end = time.monotonic() + 1.3
            while time.monotonic() < end:
                try:
                    connection.sendall(b"a")
                except OSError:
                    break
                time.sleep(0.1)
            self.assert_closed(connection)
        self.wait_for_active(0)

    def test_certificate_is_rejected_without_test_scoped_trust(self):
        context = ssl.create_default_context()
        with self.connect_raw() as connection:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(connection, server_hostname="127.0.0.1")
        self.wait_for_active(0)

    def test_server_is_loopback_only_and_tls_12_or_newer(self):
        self.assertEqual("127.0.0.1", self.server.server_address[0])
        self.assertEqual(ssl.TLSVersion.TLSv1_2, self.server.tls_context.minimum_version)

    def test_cli_launch_uses_nonblocking_tls_accept_path(self):
        # Exercise main(), not only EchoHandler on an unrelated HTTP server.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).with_name("echo_fixture.py")),
             "--cert", str(self.cert), "--key", str(self.key), "--port", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            end = time.monotonic() + 4
            while True:
                if process.poll() is not None:
                    self.fail("fixture exited before accepting connections")
                try:
                    silent = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                    break
                except (ConnectionRefusedError, TimeoutError):
                    if time.monotonic() >= end:
                        self.fail("fixture did not start")
                    time.sleep(0.01)
            with silent:
                # Old wrap_socket(listening_socket) blocks here on silent's handshake.
                conn = HTTPSConnection("127.0.0.1", port, timeout=1,
                                       context=self.client_context)
                try:
                    conn.request("GET", "/v1/echo?requestId=00000000-0000-4000-8000-000000000001")
                    response = conn.getresponse()
                    self.assertEqual(200, response.status)
                    self.assertEqual("127.0.0.1", json.loads(response.read())["observedSourceIp"])
                finally:
                    conn.close()
        finally:
            process.terminate()
            process.communicate(timeout=4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
