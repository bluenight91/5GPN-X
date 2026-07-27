#!/usr/bin/env python3
"""Unit tests for the TG bot component-version submenu (metacubexd / mihomo)."""
import importlib.util
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tgbot", root / "lib" / "tgbot.py")
tgbot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tgbot)


class ComponentMenuTest(unittest.TestCase):
    def test_ops_menu_links_components(self):
        callbacks = [b["callback_data"] for row in tgbot.ops_menu() for b in row]
        self.assertIn("menu:components", callbacks)

    def test_components_menu_callbacks(self):
        callbacks = [b["callback_data"] for row in tgbot.components_menu() for b in row]
        for expected in ("comp:check", "comp:up:metacubexd", "comp:up:mihomo",
                         "comp:manual:metacubexd", "comp:manual:mihomo", "menu:ops"):
            self.assertIn(expected, callbacks)

    def test_components_view_renders_versions(self):
        tgbot._comp_read_version = lambda p: {
            "cur_web": "1.270.0", "cur_bin": "1.19.28", "pin": None,
        }.get(p)
        tgbot._comp_github_latest = lambda repo, refresh=False: "1.270.5" if "metacubexd" in repo else "1.19.28"
        tgbot.COMPONENTS["metacubexd"]["version_file"] = "cur_web"
        tgbot.COMPONENTS["mihomo"]["version_file"] = "cur_bin"
        tgbot.COMPONENTS["metacubexd"]["pin_file"] = "pin"
        tgbot.COMPONENTS["mihomo"]["pin_file"] = "pin"
        text = tgbot.components_view()
        self.assertIn("1.270.0", text)
        self.assertIn("1.270.5", text)
        self.assertIn("可升级", text)  # metacubexd outdated -> marked
        # mihomo current == latest -> only one upgrade mark overall
        self.assertEqual(text.count("可升级"), 1)

    def test_components_view_latest_failure(self):
        tgbot._comp_read_version = lambda p: "1.270.5" if "cur" in p else None
        tgbot._comp_github_latest = lambda repo, refresh=False: None
        tgbot.COMPONENTS["metacubexd"]["version_file"] = "cur"
        tgbot.COMPONENTS["mihomo"]["version_file"] = "cur"
        tgbot.COMPONENTS["metacubexd"]["pin_file"] = "pin"
        tgbot.COMPONENTS["mihomo"]["pin_file"] = "pin"
        text = tgbot.components_view()
        self.assertIn("检查失败", text)
        self.assertNotIn("可升级", text)


class ComponentUpdateTest(unittest.TestCase):
    def test_update_component_success(self):
        calls = []

        def fake_run2(argv, timeout=None, **kwargs):
            calls.append(argv)
            return True, "mihomo 1.19.29 installed"

        tgbot.run2 = fake_run2
        result = tgbot.op_update_component("mihomo", "1.19.29")
        self.assertEqual(calls[0][:3], ["bash", tgbot.MGMT, "--update-mihomo"])
        self.assertEqual(calls[0][3], "1.19.29")
        self.assertIn("✅", result)

    def test_update_component_without_version(self):
        calls = []

        def fake_run2(argv, timeout=None, **kwargs):
            calls.append(argv)
            return True, "ok"

        tgbot.run2 = fake_run2
        tgbot.op_update_component("metacubexd")
        self.assertEqual(calls[0], ["bash", tgbot.MGMT, "--update-webui"])

    def test_update_component_rejects_bad_version(self):
        def boom(argv, timeout=None, **kwargs):
            raise AssertionError("run2 must not be called for invalid version")

        tgbot.run2 = boom
        result = tgbot.op_update_component("mihomo", "1.2.3; reboot")
        self.assertIn("无效", result)

    def test_update_component_unknown(self):
        self.assertIn("未知", tgbot.op_update_component("nginx"))

    def test_update_component_failure(self):
        tgbot.run2 = lambda argv, timeout=None, **kwargs: (False, "download failed")
        result = tgbot.op_update_component("metacubexd", "1.270.5")
        self.assertIn("❌", result)
        self.assertIn("download failed", result)


if __name__ == "__main__":
    unittest.main()
