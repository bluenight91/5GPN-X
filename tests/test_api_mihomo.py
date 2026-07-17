#!/usr/bin/env python3
"""Unit tests for the api-server mihomo (Clash API) integration."""
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_api():
    spec = importlib.util.spec_from_file_location("apiserver", os.path.join(ROOT, "lib", "api-server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class FakeClash(BaseHTTPRequestHandler):
    last_auth = None
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
        if self.path == "/version": return self._j({"version": "1.19.28"})
        if self.path == "/memory": return self._j({"inuse": 123456, "oslimit": 0})
        if self.path == "/connections":
            return self._j({"downloadTotal": 1000, "uploadTotal": 500, "connections": [
                {"id": "1", "rule": "DomainSuffix", "chains": ["jp"]},
                {"id": "2", "rule": "DomainSuffix", "chains": ["jp"]},
                {"id": "3", "rule": "GeoIP", "chains": ["direct"]}]})
        if self.path == "/configs": return self._j({"mode": "rule"})
        self.send_response(404); self.end_headers()
    def do_PUT(self):
        FakeClash.last_auth = self.headers.get("Authorization")
        n = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(n)
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

if __name__ == "__main__":
    unittest.main()
