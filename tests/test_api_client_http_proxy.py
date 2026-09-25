"""Endpoint tests for private client HTTP proxy management."""

import http.client
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_api():
    spec = importlib.util.spec_from_file_location(
        "apiserver_http_proxy", os.path.join(ROOT, "lib", "api-server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ClientHttpProxyEndpointTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()
        cls.api.TOKEN = "test-token"
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.api.CONF_DIR = cls.tmpdir.name
        with open(os.path.join(cls.tmpdir.name, "client-http-proxy.port"), "w") as stream:
            stream.write("39080\n")
        with open(os.path.join(cls.tmpdir.name, "client-http-proxy.env"), "w") as stream:
            stream.write("HTTP_PROXY_USER=alice\nHTTP_PROXY_PASS=must-not-leak\n")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), cls.api.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.tmpdir.cleanup()

    def request(self, method, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        payload = json.dumps(body or {}).encode()
        conn.request(
            method,
            "/api/client-http-proxy",
            body=payload if method == "POST" else None,
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
            },
        )
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        conn.close()
        return response.status, data

    def test_get_masks_password_and_reports_configuration(self):
        status, data = self.request("GET")
        self.assertEqual(status, 200)
        self.assertFalse(data["enabled"])
        self.assertEqual(data["port"], "39080")
        self.assertEqual(data["user"], "alice")
        self.assertEqual(data["password"], "***")
        self.assertNotIn("must-not-leak", json.dumps(data))

    def test_enable_dispatches_cli_and_returns_one_time_credentials(self):
        output = (
            "私网 HTTP/HTTPS 代理已开启\n"
            "地址: 192.0.2.10:38444\n"
            "用户: 5gpn\n"
            "密码: abc123\n"
        )
        with mock.patch.object(self.api, "ctl", return_value=(True, output)) as ctl:
            status, data = self.request("POST", {"action": "enable"})
        self.assertEqual(status, 200)
        ctl.assert_called_once_with("--enable-client-http-proxy", timeout=180)
        self.assertEqual(data["host"], "192.0.2.10")
        self.assertEqual(data["port"], "38444")
        self.assertEqual(data["user"], "5gpn")
        self.assertEqual(data["password"], "abc123")

    def test_rejects_unknown_action(self):
        status, data = self.request("POST", {"action": "expose-publicly"})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])


if __name__ == "__main__":
    unittest.main()
