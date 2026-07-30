#!/usr/bin/env python3
"""Unit tests for the api-server mihomo (Clash API) integration."""
import base64
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
        if path == "/version":
            return self._j({"version": "1.19.28"})
        if path == "/memory":
            # mihomo's real /memory is an infinite one-object-per-second stream
            # whose first object is always inuse=0; emulate two ticks then EOF.
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"inuse": 0, "oslimit": 0}).encode() + b"\n")
            self.wfile.flush()
            self.wfile.write(json.dumps({"inuse": 123456, "oslimit": 0}).encode() + b"\n")
            self.wfile.flush()
            return
        if path == "/connections":
            return self._j({"downloadTotal": 1000, "uploadTotal": 500, "connections": [
                {"id": "1", "rule": "DomainSuffix", "chains": ["jp"]},
                {"id": "2", "rule": "DomainSuffix", "chains": ["jp"]},
                {"id": "3", "rule": "GeoIP", "chains": ["direct"]}]})
        if path == "/configs":
            return self._j({"mode": "rule"})
        if path == "/proxies/日本/delay":
            return self._j({"delay": 42})
        if path == "/proxies/warp/delay":
            return self._j({"delay": 28})
        self.send_response(404)
        self.end_headers()
    def do_PUT(self):
        FakeClash.last_auth = self.headers.get("Authorization")
        n = int(self.headers.get("Content-Length", "0") or 0)
        FakeClash.last_body = self.rfile.read(n)
        self.send_response(204)
        self.end_headers()
    def do_DELETE(self):
        FakeClash.last_auth = self.headers.get("Authorization")
        self.send_response(204)
        self.end_headers()

class MihomoApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()
        with tempfile.NamedTemporaryFile(delete=False) as cls.secret:
            cls.secret.write(b"s3cr3t-test-token")
        cls.api.CLASH_SECRET_FILE = cls.secret.name
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeClash)
        cls.api.CLASH_ADDR = f"127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        os.unlink(cls.secret.name)

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

    def _with_exit_type(self, name, typ):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, f"{name}.type"), "w", encoding="utf-8") as f:
            f.write(typ + "\n")
        old = self.api.EXITS_DIR
        self.addCleanup(setattr, self.api, "EXITS_DIR", old)
        self.api.EXITS_DIR = tmp

    def test_measure_latency_udp_exit_uses_clash_delay(self):
        self._with_exit_type("warp", "masque")
        res = self.api.measure_latency("warp")
        self.assertEqual(res, {"ms": 28.0, "method": "http"})

    def test_measure_latency_udp_exit_unreachable(self):
        self._with_exit_type("ghost", "masque")
        res = self.api.measure_latency("ghost")
        self.assertEqual(res, {"ms": None, "method": None})

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
        status, _, _ = self.api.clash_request("GET", "configs?timeout=99999&url=file:///etc/passwd&level=debug&bogus=1")
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

    def test_exit_endpoint_uri_and_wireguard(self):
        exits = tempfile.mkdtemp()
        wg = tempfile.mkdtemp()
        old_exits, old_wg = self.api.EXITS_DIR, self.api.WG_DIR
        self.addCleanup(setattr, self.api, "EXITS_DIR", old_exits)
        self.addCleanup(setattr, self.api, "WG_DIR", old_wg)
        self.api.EXITS_DIR, self.api.WG_DIR = exits, wg

        def mkexit(name, typ, uri=None):
            with open(os.path.join(exits, name + ".type"), "w") as f:
                f.write(typ)
            if uri:
                with open(os.path.join(exits, name + ".uri"), "w") as f:
                    f.write(uri + "\n")

        # SIP002 ss URI
        mkexit("jp", "shadowsocks", "ss://bWV0aG9kOnBhc3M=@1.2.3.4:8388#x")
        self.assertEqual(self.api.exit_endpoint("jp"), ("1.2.3.4", 8388))
        # vless without explicit port -> default 443
        mkexit("hk", "vless", "vless://uuid@hk.example.com?security=reality#x")
        self.assertEqual(self.api.exit_endpoint("hk"), ("hk.example.com", 443))
        # trojan with explicit port
        mkexit("us", "trojan", "trojan://pw@us.example.com:8443#x")
        self.assertEqual(self.api.exit_endpoint("us"), ("us.example.com", 8443))
        # legacy ss (fully base64-encoded payload)
        raw = "aes-128-gcm:pw@9.9.9.9:8080"
        mkexit("sg", "shadowsocks", "ss://" + base64.b64encode(raw.encode()).decode() + "#x")
        self.assertEqual(self.api.exit_endpoint("sg"), ("9.9.9.9", 8080))
        # vmess (base64-encoded json share object)
        raw = '{"add":"vm.example.com","port":"443","id":"uuid"}'
        mkexit("vm", "vmess", "vmess://" + base64.b64encode(raw.encode()).decode())
        self.assertEqual(self.api.exit_endpoint("vm"), ("vm.example.com", 443))
        # wireguard endpoint from the wg conf
        mkexit("uswg", "wireguard")
        with open(os.path.join(wg, "pgw-uswg.conf"), "w") as f:
            f.write("[Peer]\nEndpoint = 5.6.7.8:51820\n")
        self.assertEqual(self.api.exit_endpoint("uswg"), ("5.6.7.8", 51820))
        # router (smart) has no upstream node
        mkexit("smart", "router")
        self.assertEqual(self.api.exit_endpoint("smart"), (None, None))

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
        self.api.CLASH_ADDR = f"127.0.0.1:{listener.getsockname()[1]}"
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
        self.api.CLASH_ADDR = f"127.0.0.1:{listener.getsockname()[1]}"
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

    def test_static_path_traversal_blocked(self):
        # Own static root WITHOUT index.html, so the SPA fallback can't mask a
        # traversal miss — independent of the machine's real MIHOMO_STATIC_DIR.
        root = tempfile.mkdtemp()
        old = self.api.MIHOMO_STATIC_DIR
        self.api.MIHOMO_STATIC_DIR = root
        self.addCleanup(setattr, self.api, "MIHOMO_STATIC_DIR", old)
        self.assertIsNone(self.api.static_path("../install.sh"))
        self.assertIsNone(self.api.static_path("../../etc/passwd"))
        self.assertIsNone(self.api.static_path("/etc/passwd"))

    def test_static_path_resolution(self):
        root = tempfile.mkdtemp()
        old = self.api.MIHOMO_STATIC_DIR
        self.api.MIHOMO_STATIC_DIR = root
        self.addCleanup(setattr, self.api, "MIHOMO_STATIC_DIR", old)
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<html>xd</html>")
        os.makedirs(os.path.join(root, "assets"))
        with open(os.path.join(root, "assets", "app.js"), "w") as f:
            f.write("js")
        self.assertTrue(self.api.static_path("").endswith("index.html"))
        self.assertTrue(self.api.static_path("assets/app.js").endswith("assets/app.js"))
        # SPA fallback
        self.assertTrue(self.api.static_path("some/route").endswith("index.html"))
        # no index -> None
        os.unlink(os.path.join(root, "index.html"))
        self.assertIsNone(self.api.static_path("missing.js"))

class ProxyHandlerTests(unittest.TestCase):
    """Handler-level tests for the mihomo reverse proxy (real HTTP server)."""
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()
        cls.api.TOKEN = "t" * 16
        # A real static root so /mihomo/* resolves regardless of the machine.
        cls.static = tempfile.mkdtemp()
        with open(os.path.join(cls.static, "index.html"), "w", encoding="utf-8") as f:
            f.write("<html>xd</html>")
        with open(os.path.join(cls.static, "manifest.webmanifest"), "w", encoding="utf-8") as f:
            f.write('{"name":"xd"}')
        os.makedirs(os.path.join(cls.static, "_nuxt"))
        with open(os.path.join(cls.static, "_nuxt", "app.js"), "w", encoding="utf-8") as f:
            f.write("js")
        cls.old_static = cls.api.MIHOMO_STATIC_DIR
        cls.api.MIHOMO_STATIC_DIR = cls.static
        # Known Clash secret for the WS relay tests; dead port for HTTP proxy tests.
        with tempfile.NamedTemporaryFile(delete=False) as cls.secret:
            cls.secret.write(b"s3cr3t-test-token")
        cls.old_secret_file = cls.api.CLASH_SECRET_FILE
        cls.api.CLASH_SECRET_FILE = cls.secret.name
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cls.old_addr = cls.api.CLASH_ADDR
        cls.api.CLASH_ADDR = f"127.0.0.1:{s.getsockname()[1]}"
        s.close()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), cls.api.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.api.MIHOMO_STATIC_DIR = cls.old_static
        cls.api.CLASH_SECRET_FILE = cls.old_secret_file
        cls.api.CLASH_ADDR = cls.old_addr
        os.unlink(cls.secret.name)

    def _conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)

    def _get(self, path, headers=None):
        conn = self._conn()
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        status, hdrs = resp.status, dict(resp.getheaders())
        resp.read()
        conn.close()
        return status, hdrs

    def _bootstrap_cookie(self):
        status, hdrs = self._get("/mihomo/index.html?token=" + self.api.TOKEN)
        self.assertEqual(status, 200)
        sc = hdrs.get("Set-Cookie", "")
        self.assertIn("pgw_mihomo=", sc)
        value = urllib.parse.unquote(sc.split("pgw_mihomo=", 1)[1].split(";", 1)[0])
        self.assertTrue(value)
        self.assertNotEqual(value, self.api.TOKEN)
        self.assertTrue(self.api.valid_mihomo_session(value))
        return {"Cookie": "pgw_mihomo=" + urllib.parse.quote(value, safe="")}

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

    # --- query-token auth for iframe static + WS streams --------------------
    def test_static_query_token_ok_sets_cookie(self):
        status, hdrs = self._get("/mihomo/index.html?token=" + self.api.TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("Referrer-Policy"), "same-origin")
        sc = hdrs.get("Set-Cookie", "")
        self.assertIn("pgw_mihomo=", sc)
        value = urllib.parse.unquote(sc.split("pgw_mihomo=", 1)[1].split(";", 1)[0])
        self.assertNotEqual(value, self.api.TOKEN)
        self.assertTrue(self.api.valid_mihomo_session(value))
        self.assertIn("Path=/;", sc)          # Path=/ 覆盖 /mihomo 与 /api/mihomo/*
        self.assertNotIn("Path=/mihomo", sc)  # 不再局限于静态目录
        self.assertIn("HttpOnly", sc)
        self.assertIn("Secure", sc)
        self.assertIn("SameSite=Strict", sc)

    def test_static_wrong_and_missing_token_401(self):
        status, _ = self._get("/mihomo/index.html?token=wrong")
        self.assertEqual(status, 401)
        status, _ = self._get("/mihomo/index.html")
        self.assertEqual(status, 401)

    def test_static_cookie_auth_for_assets(self):
        # iframe 内相对路径子资源带不了 ?token=；文档响应种下的 cookie 供其鉴权
        status, _ = self._get("/mihomo/_nuxt/app.js", self._bootstrap_cookie())
        self.assertEqual(status, 200)
        status, _ = self._get("/mihomo/_nuxt/app.js", {"Cookie": "pgw_mihomo=wrong"})
        self.assertEqual(status, 401)
        status, _ = self._get("/mihomo/_nuxt/app.js")
        self.assertEqual(status, 401)

    # --- pgw_mihomo cookie 放行 /api/mihomo/*（面板 secret 留空） --------------
    def test_mihomo_api_cookie_auth_get_put_delete(self):
        ck = self._bootstrap_cookie()
        # GET：cookie 通过鉴权 -> 反代到死端口 -> 502（而非 401）
        status, _ = self._get("/api/mihomo/proxy/configs", ck)
        self.assertEqual(status, 502)
        # PUT：写方法同样放行
        conn = self._conn()
        conn.request("PUT", "/api/mihomo/proxy/configs", body=b'{"mode":"global"}',
                     headers=dict(ck, **{"Content-Type": "application/json"}))
        resp = conn.getresponse()
        self.assertEqual(resp.status, 502)
        resp.read()
        conn.close()
        # DELETE：同为 502 而非 401
        conn = self._conn()
        conn.request("DELETE", "/api/mihomo/proxy/connections", headers=ck)
        resp = conn.getresponse()
        self.assertEqual(resp.status, 502)
        resp.read()
        conn.close()

    def test_mihomo_api_cookie_wrong_value_401(self):
        status, _ = self._get("/api/mihomo/proxy/configs",
                              {"Cookie": "pgw_mihomo=wrong"})
        self.assertEqual(status, 401)

    def test_mihomo_cookie_not_accepted_on_other_api(self):
        # 最小权限：cookie 不越权到主控制台路径
        status, _ = self._get("/api/status", self._bootstrap_cookie())
        self.assertEqual(status, 401)

    def test_ws_upgrade_cookie_auth_end_to_end(self):
        # WS 白名单路径：cookie（无 ?token=、无 Bearer）通过鉴权 -> 101
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve():
            conn, _ = listener.accept()
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                req += chunk
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            time.sleep(0.2)
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        old_addr = self.api.CLASH_ADDR
        self.api.CLASH_ADDR = f"127.0.0.1:{listener.getsockname()[1]}"
        try:
            conn = self._conn()
            conn.putrequest("GET", "/api/mihomo/proxy/traffic")
            conn.putheader("Upgrade", "websocket")
            conn.putheader("Connection", "Upgrade")
            conn.putheader("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            conn.putheader("Sec-WebSocket-Version", "13")
            conn.putheader("Cookie", self._bootstrap_cookie()["Cookie"])
            conn.endheaders()
            resp = conn.getresponse()
            self.assertEqual(resp.status, 101)
            conn.close()
        finally:
            self.api.CLASH_ADDR = old_addr
            listener.close()

    def test_query_token_rejected_on_plain_api_paths(self):
        status, _ = self._get("/api/status?token=" + self.api.TOKEN)
        self.assertEqual(status, 401)

    def test_proxy_http_still_requires_bearer(self):
        # 非 Upgrade 的反代路径不认 query token
        status, _ = self._get("/api/mihomo/proxy/traffic?token=" + self.api.TOKEN)
        self.assertEqual(status, 401)
        # Bearer 仍走 HTTP 反代（测试环境无 mihomo -> 502）
        status, hdrs = self._get("/api/mihomo/proxy/traffic",
                                 {"Authorization": "Bearer " + self.api.TOKEN})
        self.assertEqual(status, 502)
        self.assertEqual(hdrs.get("Referrer-Policy"), "same-origin")

    def test_ws_upgrade_query_token_scope(self):
        hdrs = {"Upgrade": "websocket", "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}
        # 错误 token -> 401
        status, _ = self._get("/api/mihomo/proxy/traffic?token=wrong", hdrs)
        self.assertEqual(status, 401)
        # 正确 token 但非白名单路径 -> query token 不生效 -> 401
        status, _ = self._get("/api/mihomo/proxy/configs?token=" + self.api.TOKEN, hdrs)
        self.assertEqual(status, 401)
        # Bearer + 非白名单 Upgrade -> 过了鉴权，被白名单挡下 -> 403
        status, _ = self._get("/api/mihomo/proxy/configs",
                              dict(hdrs, Authorization="Bearer " + self.api.TOKEN))
        self.assertEqual(status, 403)

    def test_ws_upgrade_query_token_end_to_end(self):
        # Fake upstream: validate the rebuilt upgrade request, answer 101.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        got = {}

        def serve():
            conn, _ = listener.accept()
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                req += chunk
            got["req"] = req
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            time.sleep(0.2)
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        old_addr = self.api.CLASH_ADDR
        self.api.CLASH_ADDR = f"127.0.0.1:{listener.getsockname()[1]}"
        try:
            conn = self._conn()
            conn.putrequest("GET", "/api/mihomo/proxy/traffic?token=" + self.api.TOKEN)
            conn.putheader("Upgrade", "websocket")
            conn.putheader("Connection", "Upgrade")
            conn.putheader("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            conn.putheader("Sec-WebSocket-Version", "13")
            conn.endheaders()
            resp = conn.getresponse()
            self.assertEqual(resp.status, 101)
            conn.close()
        finally:
            self.api.CLASH_ADDR = old_addr
            listener.close()
        # query token 被剥掉，服务端注入真实 Clash secret
        self.assertIn(b"GET /traffic HTTP/1.1", got["req"])
        self.assertNotIn(b"token=", got["req"])
        self.assertIn(b"Authorization: Bearer s3cr3t-test-token", got["req"])

    def test_security_headers_on_api_and_static(self):
        status, hdrs = self._get("/api/status", {"Authorization": "Bearer " + self.api.TOKEN})
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(hdrs.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(hdrs.get("Strict-Transport-Security"), "max-age=31536000")
        self.assertEqual(hdrs.get("Referrer-Policy"), "same-origin")
        status, hdrs = self._get("/mihomo/index.html?token=" + self.api.TOKEN)
        self.assertEqual(status, 200)
        csp = hdrs.get("Content-Security-Policy") or ""
        self.assertIn("frame-ancestors 'self'", csp)
        self.assertIn("default-src 'self'", csp)
        self.assertIn("unsafe-inline", csp)
        self.assertIn("script-src", csp)
        self.assertEqual(hdrs.get("X-Frame-Options"), "SAMEORIGIN")
        # PWA manifest must load without ?token= / cookie (Chrome fetches it bare).
        status, _ = self._get("/mihomo/manifest.webmanifest")
        self.assertEqual(status, 200)

    def test_rate_limit_429(self):
        self.api._rate.clear()
        try:
            codes = [self._get("/api/health")[0] for _ in range(40)]
            self.assertIn(429, codes)
            self.assertEqual(codes[0], 200)
        finally:
            self.api._rate.clear()

    def test_log_message_silent(self):
        # PII: the request log must never print anything (token, query, client addr).
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.api.Handler.log_message(object(), "%s %s", "GET /api/x?token=abc", "200")
        self.assertEqual(buf.getvalue(), "")

if __name__ == "__main__":
    unittest.main()
