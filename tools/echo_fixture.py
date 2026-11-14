#!/usr/bin/env python3
"""Loopback-only development fixture. No URL logging; no forwarded-header trust."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import re
import socket
import ssl
import threading
from urllib.parse import parse_qs, urlsplit


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ProxyDiagnosticsFixture/1"
    sys_version = ""

    def do_GET(self):
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        ids = params.get("requestId", [])
        if (parsed.path != "/v1/echo" or set(params) != {"requestId"} or len(ids) != 1
                or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", ids[0])):
            self._send(400, {"error": "INVALID_REQUEST"})
            return
        source = str(ipaddress.ip_address(self.client_address[0]))
        self._send(200, {"schemaVersion": 1, "requestId": ids[0], "observedSourceIp": source})

    def _send(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format, *args):
        pass  # Do not persist target, nonce, headers, or client information.


class BoundedTLSEchoServer(HTTPServer):
    """Accept plain sockets, then perform TLS in a bounded set of workers."""

    request_queue_size = 8

    def __init__(self, port, tls_context, *, max_workers=8,
                 handshake_timeout=3.0, request_timeout=5.0):
        if max_workers < 1 or handshake_timeout <= 0 or request_timeout <= 0:
            raise ValueError("worker count and timeouts must be positive")
        super().__init__(("127.0.0.1", port), EchoHandler)
        self.tls_context = tls_context
        self.handshake_timeout = handshake_timeout
        self.request_timeout = request_timeout
        self._slots = threading.BoundedSemaphore(max_workers)
        self._workers = ThreadPoolExecutor(max_workers=max_workers,
                                           thread_name_prefix="echo-tls")
        self._active_lock = threading.Lock()
        self._active_count = 0

    @property
    def active_connection_count(self):
        with self._active_lock:
            return self._active_count

    def process_request(self, request, client_address):
        # Do not queue arbitrary sockets or create a thread per connection.
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._active_lock:
            self._active_count += 1
        try:
            self._workers.submit(self._serve_tls, request, client_address)
        except Exception:
            self.shutdown_request(request)
            self._release_slot()
            raise

    def _release_slot(self):
        with self._active_lock:
            self._active_count -= 1
        self._slots.release()

    @staticmethod
    def _abort_connection(connection):
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()

    def _serve_tls(self, request, client_address):
        connection = request
        deadline = None
        try:
            request.settimeout(self.handshake_timeout)
            connection = self.tls_context.wrap_socket(
                request, server_side=True, do_handshake_on_connect=False)
            connection.do_handshake()
            connection.settimeout(self.request_timeout)
            # A socket read timeout alone can be kept alive by trickling bytes.
            # Bound the entire HTTP handler, including headers and writes.
            deadline = threading.Timer(self.request_timeout,
                                       self._abort_connection, (connection,))
            deadline.daemon = True
            deadline.start()
            self.finish_request(connection, client_address)
        except (OSError, ssl.SSLError):
            pass  # Malformed, disconnected, and timed-out peers are expected.
        except Exception:
            self.handle_error(connection, client_address)
        finally:
            if deadline is not None:
                deadline.cancel()
                if deadline.ident is not None:
                    deadline.join()  # Release the slot only after its timer exits.
            self.shutdown_request(connection)
            self._release_slot()

    def handle_error(self, request, client_address):
        pass  # Do not log client addresses, request data, or nonces.

    def server_close(self):
        super().server_close()
        # Accepted work is bounded by the handshake and absolute HTTP deadlines.
        self._workers.shutdown(wait=True)


def create_server(cert, key, port, **limits):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(cert, key)
    return BoundedTLSEchoServer(port, tls, **limits)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    server = create_server(args.cert, args.key, args.port)
    print(f"Local development fixture listening on https://127.0.0.1:{args.port}; Ctrl+C to stop.",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
