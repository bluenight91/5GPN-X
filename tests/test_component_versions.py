#!/usr/bin/env python3
"""Unit tests for component version endpoints (metacubexd / mihomo self-update)."""
import http.client
import importlib.util
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_api():
    spec = importlib.util.spec_from_file_location("apiserver", os.path.join(ROOT, "lib", "api-server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ComponentVersionHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        self.api.COMPONENTS["metacubexd"]["version_file"] = os.path.join(d, ".metacubexd-version")
        self.api.COMPONENTS["metacubexd"]["pin_file"] = os.path.join(d, "metacubexd.pin")
        self.api.COMPONENTS["mihomo"]["version_file"] = os.path.join(d, ".mihomo-version")
        self.api.COMPONENTS["mihomo"]["pin_file"] = os.path.join(d, "mihomo.pin")

    def test_read_version_first_line(self):
        path = self.api.COMPONENTS["mihomo"]["version_file"]
        with open(path, "w", encoding="utf-8") as f:
            f.write("1.19.28\n")
        self.assertEqual(self.api._read_version(path), "1.19.28")

    def test_read_version_missing_returns_none(self):
        self.assertIsNone(self.api._read_version(os.path.join(self.tmp.name, "nope")))

    def test_component_versions_shape(self):
        with open(self.api.COMPONENTS["metacubexd"]["version_file"], "w", encoding="utf-8") as f:
            f.write("1.270.5\n")
        with open(self.api.COMPONENTS["mihomo"]["pin_file"], "w", encoding="utf-8") as f:
            f.write("1.19.29\n")
        with mock.patch.object(self.api, "github_latest", side_effect=lambda repo: "9.9.9"):
            data = self.api.component_versions()
        self.assertEqual(data["metacubexd"]["current"], "1.270.5")
        self.assertIsNone(data["metacubexd"]["pinned"])
        self.assertEqual(data["mihomo"]["pinned"], "1.19.29")
        self.assertEqual(data["mihomo"]["latest"], "9.9.9")
        self.assertIsNone(data["mihomo"]["current"])

    def test_github_latest_strips_v_and_caches(self):
        self.api._latest_cache.clear()
        payload = io.BytesIO(json.dumps({"tag_name": "v1.270.5"}).encode())
        resp = mock.MagicMock()
        resp.__enter__ = lambda s: payload
        resp.__exit__ = mock.MagicMock(return_value=False)
        with mock.patch.object(self.api.urllib.request, "urlopen", return_value=resp) as uo:
            self.assertEqual(self.api.github_latest("MetaCubeX/metacubexd"), "1.270.5")
            self.assertEqual(self.api.github_latest("MetaCubeX/metacubexd"), "1.270.5")
        self.assertEqual(uo.call_count, 1)  # second call served from cache

    def test_github_latest_failure_returns_none_and_caches(self):
        self.api._latest_cache.clear()
        with mock.patch.object(self.api.urllib.request, "urlopen", side_effect=OSError("down")) as uo:
            self.assertIsNone(self.api.github_latest("MetaCubeX/mihomo"))
            self.assertIsNone(self.api.github_latest("MetaCubeX/mihomo"))
        self.assertEqual(uo.call_count, 1)

    def test_version_regex(self):
        self.assertTrue(self.api.COMPONENT_VERSION_RE.match("1.270.5"))
        self.assertFalse(self.api.COMPONENT_VERSION_RE.match("1.270.5; rm -rf /"))
        self.assertFalse(self.api.COMPONENT_VERSION_RE.match("../etc"))
        self.assertFalse(self.api.COMPONENT_VERSION_RE.match("1.270"))


class ComponentEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()
        cls.api.TOKEN = "test-token"
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), cls.api.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _req(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        payload = json.dumps(body or {}).encode()
        conn.request(method, path, body=payload if method == "POST" else None,
                     headers={"Authorization": "Bearer test-token",
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        return resp.status, data

    def test_versions_endpoint(self):
        with mock.patch.object(self.api, "github_latest", return_value=None):
            status, data = self._req("GET", "/api/component/versions")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertIn("metacubexd", data["components"])
        self.assertIn("mihomo", data["components"])
        self.assertEqual(set(data["components"]["mihomo"]), {"current", "pinned", "latest"})

    def test_update_rejects_unknown_component(self):
        status, data = self._req("POST", "/api/component/update", {"component": "nginx"})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])

    def test_update_rejects_bad_version(self):
        status, data = self._req("POST", "/api/component/update",
                                 {"component": "mihomo", "version": "1.2.3; reboot"})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])

    def test_update_dispatches_ctl(self):
        calls = []

        def fake_ctl(*args, **kw):
            calls.append(args)
            return True, "installed"

        with mock.patch.object(self.api, "ctl", side_effect=fake_ctl):
            status, data = self._req("POST", "/api/component/update",
                                     {"component": "metacubexd", "version": "v1.270.5"})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(calls, [("--update-webui", "1.270.5")])

    def test_update_without_version_omits_arg(self):
        calls = []

        def fake_ctl(*args, **kw):
            calls.append(args)
            return True, "installed"

        with mock.patch.object(self.api, "ctl", side_effect=fake_ctl):
            status, _ = self._req("POST", "/api/component/update", {"component": "mihomo"})
        self.assertEqual(status, 200)
        self.assertEqual(calls, [("--update-mihomo",)])

    def test_update_requires_auth(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/api/component/versions")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 401)


if __name__ == "__main__":
    unittest.main()
