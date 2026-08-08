#!/usr/bin/env python3
"""Unit tests for the api-server source allowlist (etc/api-allow.list)."""
import importlib.util
import os
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_api():
    spec = importlib.util.spec_from_file_location("apiserver_allow", os.path.join(ROOT, "lib", "api-server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SourceAllowTest(unittest.TestCase):
    def setUp(self):
        self.api = load_api()
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".list") as tmp:
            self.tmp_name = tmp.name
        os.unlink(self.tmp_name)            # start as "no file"
        self.api.ALLOW_FILE = self.tmp_name
        self.api._allow_cache["mtime"] = None
        self.api._allow_cache["nets"] = []

    def tearDown(self):
        if os.path.exists(self.tmp_name):
            os.unlink(self.tmp_name)

    def _write(self, text):
        with open(self.tmp_name, "w", encoding="utf-8") as f:
            f.write(text)
        # mtime granularity can hide same-second rewrites; bust the cache clock.
        self.api._allow_cache["mtime"] = None

    def test_missing_file_unrestricted(self):
        self.assertTrue(self.api.source_allowed("203.0.113.10"))

    def test_empty_file_unrestricted(self):
        self._write("")
        self.assertTrue(self.api.source_allowed("203.0.113.10"))

    def test_loopback_always_allowed(self):
        self._write("10.0.0.0/8\n")
        self.assertTrue(self.api.source_allowed("127.0.0.1"))
        self.assertTrue(self.api.source_allowed("::1"))

    def test_matching_cidr_allowed(self):
        self._write("203.0.113.0/24\n# comment\n\n172.22.0.0/16\n")
        self.assertTrue(self.api.source_allowed("203.0.113.10"))
        self.assertTrue(self.api.source_allowed("172.22.1.2"))
        self.assertFalse(self.api.source_allowed("198.51.100.7"))

    def test_single_host_without_slash(self):
        self._write("203.0.113.10\n")
        self.assertTrue(self.api.source_allowed("203.0.113.10"))
        self.assertFalse(self.api.source_allowed("203.0.113.11"))

    def test_invalid_lines_skipped(self):
        self._write("not-a-cidr\n203.0.113.0/24\n")
        self.assertTrue(self.api.source_allowed("203.0.113.10"))
        self.assertFalse(self.api.source_allowed("10.1.2.3"))

    def test_invalid_source_ip_rejected(self):
        self.assertFalse(self.api.source_allowed("garbage"))

    def test_hot_reload_on_change(self):
        self._write("203.0.113.0/24\n")
        self.assertFalse(self.api.source_allowed("198.51.100.7"))
        time.sleep(0.01)
        self._write("198.51.100.0/24\n")
        self.assertTrue(self.api.source_allowed("198.51.100.7"))
        self.assertFalse(self.api.source_allowed("203.0.113.10"))

    def test_file_deleted_after_list_reverts_to_unrestricted(self):
        self._write("203.0.113.0/24\n")
        self.assertFalse(self.api.source_allowed("198.51.100.7"))
        os.unlink(self.tmp_name)  # getmtime now fails → mtime None ≠ cached → refresh
        self.assertTrue(self.api.source_allowed("198.51.100.7"))


if __name__ == "__main__":
    unittest.main()
