"""Unit tests for client CIDR normalization and validation."""

import importlib.util
import os
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_api():
    spec = importlib.util.spec_from_file_location(
        "apiserver_client_cidr", os.path.join(ROOT, "lib", "api-server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ClientCidrTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()

    def test_accepts_single_host_alongside_default_network(self):
        value = "172.22.0.0/16,172.31.11.94/32"
        self.assertEqual(self.api.validate_client_cidr(value), value)

    def test_accepts_31_prefix(self):
        self.assertEqual(
            self.api.validate_client_cidr("172.31.11.94/31"),
            "172.31.11.94/31",
        )

    def test_normalizes_bare_ipv4_address_to_32(self):
        self.assertEqual(
            self.api.validate_client_cidr("172.31.11.94"),
            "172.31.11.94/32",
        )

    def test_rejects_wide_network_without_opt_in(self):
        with mock.patch.dict(os.environ, {"FORCE_WIDE_CIDR": "0"}):
            self.assertIsNone(self.api.validate_client_cidr("10.0.0.0/8"))

    def test_rejects_ipv6(self):
        self.assertIsNone(self.api.validate_client_cidr("2001:db8::1/128"))


if __name__ == "__main__":
    unittest.main()
