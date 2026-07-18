#!/usr/bin/env python3
"""Unit tests for the api-server mihomo (Clash API) integration."""
import http.client
import importlib.util
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_api():
    spec = importlib.util.spec_from_file_location("apiserver", os.path.join(ROOT, "lib", "api-server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class FakeClash(BaseHTTPRequestHandler):
    last_auth = None
    last_body = None
    def log_message(self, *a): pass
    def _j(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        FakeClash.last_auth = self.headers.get("Authorization")
        path = urllib.parse.unquote(self.path.split("?", 1)[0])
        if path == "/version": return self._j({"version": "1.19.28"})
        if path == "/memory": return self._j({"inuse": 123456, "oslimit": 0})
        if path == "/connections":
            return self._j({"downloadTotal": 1000, "uploadTotal": 500, "connections": [
                {"id": "1", "rule": "DomainSuffix", "chains": ["jp"]},
                {"id": "2", "rule": "DomainSuffix", "chains": ["jp"]},
                {"id": "3", "rule": "GeoIP", "chains": ["direct"]}]})
        if path == "/configs": return self._j({"mode": "rule"})
        if path == "/proxies/日本/delay": return self._j({"delay": 42})
        self.send_response(404); self.end_headers()
    def do_PUT(self):
        FakeClash.last_auth = self.headers.get("Authorization")
        n = int(self.headers.get("Content-Length", "0") or 0)
        FakeClash.last_body = self.rfile.read(n)
        self.send_response(204); self.end_headers()
    def do_DELETE(self):
        FakeClash.last_auth = self.headers.get("Authorization")
        self.send_response(204); self.end_headers()

class MihomoApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()
        cls.secret = tempfile.NamedTemporaryFile(delete=False)
        cls.secret.write(b"s3cr3t-test-token"); cls.secret.close()
        cls.api.CLASH_SECRET_FILE = cls.secret.name
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeClash)
        cls.api.CLASH_ADDR = "127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); os.unlink(cls.secret.name)

    def test_clash_request_injects_secret(self):
        status, _, data = self.api.clash_request("GET", "configs")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["mode"], "rule")
        self.assertEqual(FakeClash.last_auth, "Bearer s3cr3t-test-token")

    def test_clash_request_rejects_bad_path(self):
        status, _, _ = self.api.clash_request("GET", "../etc/passwd")
        self.assertEqual(status, 400)
        status, _, _ = self.api.clash_request("GET", "a b")
        self.assertEqual(status, 400)

    def test_clash_request_missing_secret_returns_503(self):
        self.api.CLASH_SECRET_FILE = "/nonexistent/nope"
        status, _, _ = self.api.clash_request("GET", "configs")
        self.assertEqual(status, 503)
        self.api.CLASH_SECRET_FILE = self.secret.name

    def test_overview_aggregates(self):
        data, err = self.api.mihomo_overview()
        self.assertIsNone(err)
        self.assertEqual(data["connections"], 3)
        self.assertEqual(data["download"], 1000)
        self.assertEqual(data["memory"], 123456)
        self.assertEqual(data["version"], "1.19.28")
        self.assertEqual(data["top_rules"][0], {"rule": "DomainSuffix", "count": 2})

    def test_ws_whitelist(self):
        self.assertTrue(self.api.ws_allowed("traffic"))
        self.assertTrue(self.api.ws_allowed("logs?level=info"))
        self.assertTrue(self.api.ws_allowed("connections"))
        self.assertTrue(self.api.ws_allowed("memory"))
        self.assertFalse(self.api.ws_allowed("configs"))
        self.assertFalse(self.api.ws_allowed("proxies"))

    def test_proxy_forwards_query_with_allowlist(self):
        # timeout 超界被夹紧、url 非 http(s) 被丢弃、level 合法值保留
        status, _, data = self.api.clash_request("GET", "configs?timeout=99999&url=file:///etc/passwd&level=debug&bogus=1")
        self.assertEqual(status, 200)

    def test_normalize_sub(self):
        self.assertEqual(self.api.normalize_sub("configs"), "configs")
        self.assertEqual(self.api.normalize_sub("proxies/%E6%97%A5%E6%9C%AC/delay"),
                         "proxies/日本/delay")
        self.assertIsNone(self.api.normalize_sub("../etc/passwd"))
        self.assertIsNone(self.api.normalize_sub("a b"))
        self.assertIsNone(self.api.normalize_sub("configs%2e%2e/x"))
        self.assertEqual(self.api.normalize_sub("logs?level=info&bogus=1"), "logs?level=info")
        self.assertEqual(self.api.normalize_sub("proxies/jp/delay?timeout=99999&url=https://cp.cloudflare.com/"),
                         "proxies/jp/delay?timeout=10000&url=https%3A%2F%2Fcp.cloudflare.com%2F")
        self.assertEqual(self.api.normalize_sub("configs?force=true"), "configs?force=true")
        self.assertEqual(self.api.normalize_sub("configs?force=yes"), "configs")

    def test_build_ws_request(self):
        headers = {"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                   "Sec-WebSocket-Version": "13",
                   "Sec-WebSocket-Protocol": "chat"}
        req = self.api.build_ws_request("logs?level=info", headers).decode()
        self.assertIn("GET /logs?level=info HTTP/1.1", req)
        self.assertIn("Upgrade: websocket", req)
        self.assertIn("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", req)
        self.assertIn("Authorization: Bearer s3cr3t-test-token", req)
        self.assertTrue(req.endswith("\r\n\r\n"))

    def test_delete_and_cjk_proxy_name(self):
        status, _, _ = self.api.clash_request("DELETE", "connections")
        self.assertEqual(status, 204)
        status, _, data = self.api.clash_request("GET", "proxies/%E6%97%A5%E6%9C%AC/delay?timeout=1000&url=https://cp.cloudflare.com/")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["delay"], 42)

    def test_put_with_body_roundtrip(self):
        status, _, _ = self.api.clash_request("PUT", "configs", body=b'{"mode":"global"}',
                                              ctype="application/json")
        self.assertEqual(status, 204)
        self.assertEqual(FakeClash.last_body, b'{"mode":"global"}')
        self.assertEqual(FakeClash.last_auth, "Bearer s3cr3t-test-token")

    def test_ws_relay_end_to_end(self):
        # Fake upstream: validate the rebuilt upgrade request, answer 101, echo.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        got = {}

        def serve():
            conn, _ = listener.accept()
            req = b""
            while b"\r\n\r\n" not in req:
                req += conn.recv(4096)
            got["req"] = req
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        old_addr = self.api.CLASH_ADDR
        self.api.CLASH_ADDR = "127.0.0.1:%d" % listener.getsockname()[1]
        try:
            a, b = socket.socketpair()
            a.settimeout(10)
            relay = threading.Thread(target=self.api.ws_relay,
                                     args=(b, "traffic", {"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}),
                                     daemon=True)
            relay.start()
            resp = b""
            while b"\r\n\r\n" not in resp:
                resp += a.recv(4096)
            self.assertIn(b" 101 ", resp.split(b"\r\n", 1)[0])
            a.sendall(b"ping-123")
            echo = b""
            while len(echo) < 8:
                echo += a.recv(4096)
            self.assertEqual(echo, b"ping-123")
            a.close()
            relay.join(timeout=5)
            self.assertFalse(relay.is_alive())
            b.close()
        finally:
            self.api.CLASH_ADDR = old_addr
            listener.close()
        self.assertIn(b"GET /traffic HTTP/1.1", got["req"])
        self.assertIn(b"Authorization: Bearer s3cr3t-test-token", got["req"])

    def test_ws_relay_flushes_pending_on_upstream_close(self):
        # Regression: upstream answers 101, sends a trailing payload after a
        # beat, then closes immediately. The relay must forward the payload
        # before honoring the FIN instead of dropping buffered bytes.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        head = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
        payload = b"tail-bytes-" + bytes(range(256)) * 4

        def serve():
            conn, _ = listener.accept()
            req = b""
            while b"\r\n\r\n" not in req:
                req += conn.recv(4096)
            conn.sendall(head)
            time.sleep(0.3)          # let the relay settle, then race FIN
            conn.sendall(payload)
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        old_addr = self.api.CLASH_ADDR
        self.api.CLASH_ADDR = "127.0.0.1:%d" % listener.getsockname()[1]
        try:
            a, b = socket.socketpair()
            a.settimeout(10)
            relay = threading.Thread(target=self.api.ws_relay,
                                     args=(b, "traffic", {"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}),
                                     daemon=True)
            relay.start()
            want = head + payload
            got = b""
            while len(got) < len(want):
                chunk = a.recv(65536)
                if not chunk:
                    break
                got += chunk
            self.assertEqual(got, want)   # 101 head + full trailing payload
            a.close()
            relay.join(timeout=5)
            self.assertFalse(relay.is_alive())
            b.close()
        finally:
            self.api.CLASH_ADDR = old_addr
            listener.close()

class ProxyHandlerTests(unittest.TestCase):
    """Handler-level tests for the mihomo reverse proxy (real HTTP server)."""
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()
        cls.api.TOKEN = "t" * 16
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), cls.api.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)

    def test_proxy_payload_too_large_413(self):
        conn = self._conn()
        conn.putrequest("POST", "/api/mihomo/proxy/configs")
        conn.putheader("Authorization", "Bearer " + self.api.TOKEN)
        conn.putheader("Content-Length", "2000001")
        conn.endheaders(b"x")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        resp.read()
        conn.close()

    def test_proxy_bad_content_length_400(self):
        conn = self._conn()
        conn.putrequest("POST", "/api/mihomo/proxy/configs")
        conn.putheader("Authorization", "Bearer " + self.api.TOKEN)
        conn.putheader("Content-Length", "not-a-number")
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        resp.read()
        conn.close()

    def test_cors_allow_methods_include_write_verbs(self):
        conn = self._conn()
        conn.request("OPTIONS", "/api/mihomo/proxy/configs")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 204)
        allow = resp.getheader("Access-Control-Allow-Methods") or ""
        for m in ("PUT", "PATCH", "DELETE"):
            self.assertIn(m, allow)
        resp.read()
        conn.close()

if __name__ == "__main__":
    unittest.main()
