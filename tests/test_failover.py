#!/usr/bin/env python3
"""Unit tests for the failover watchdog (lib/failover.py)."""
import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

spec = importlib.util.spec_from_file_location("failover", os.path.join(ROOT, "lib", "failover.py"))
fo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fo)


class FailoverTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="fo-")
        self.pgw = os.path.join(self.dir, "etc5gpn")
        self.conf = os.path.join(self.dir, "conf")
        self.wg = os.path.join(self.dir, "wg")
        for d in (self.pgw, self.conf, self.wg, os.path.join(self.pgw, "exits")):
            os.makedirs(d, exist_ok=True)
        fo.PGW_DIR = self.pgw
        fo.EXITS_DIR = os.path.join(self.pgw, "exits")
        fo.WG_DIR = self.wg
        fo.CONF_DIR = self.conf
        fo.STATE_FILE = os.path.join(self.pgw, "health", "failover.json")
        fo.ENV_FILE = os.path.join(self.pgw, "failover.env")
        fo.ENABLED_FILE = os.path.join(self.pgw, "failover.enabled")
        fo.CUR_EXIT_FILE = os.path.join(self.pgw, "current-exit")
        fo.LATENCY_FILE = os.path.join(self.conf, "latency.json")
        fo.FAIL_AFTER = 3
        fo.COOLDOWN_SEC = 600
        fo.MAX_SWITCHES_PER_HOUR = 3
        fo.GRACE_SEC = 300
        self.now = 1_800_000_000.0
        # exits: jp (current), hk, us
        for n in ("jp", "hk", "us"):
            with open(os.path.join(fo.EXITS_DIR, f"{n}.type"), "w") as f:
                f.write("ss\n")
        self._write("current-exit", "jp")
        self.notifications = []
        self.switched_to = []

    def _write(self, name, text, base=None):
        with open(os.path.join(base or self.pgw, name), "w") as f:
            f.write(text)

    def _enable(self):
        self._write("failover.enabled", "1\n")
        # current-exit mtime must be older than GRACE_SEC
        old = self.now - 10000
        os.utime(fo.CUR_EXIT_FILE, (old, old))

    def _latency(self, mapping):
        pts = [{"t": int(self.now) - 60, "v": mapping}]
        self._write("latency.json", json.dumps({"points": pts}), base=self.conf)

    def _tick(self, probe_map, now=None, switch_ok=True):
        """probe_map: iface -> bool; switches append to self.switched_to."""
        def probe_fn(iface):
            return probe_map.get(iface, False)

        def switch_fn(name):
            if not switch_ok:
                return False
            self.switched_to.append(name)
            self._write("current-exit", name)
            return True

        def notify_fn(text):
            self.notifications.append(text)

        return fo.tick(now=now or self.now, probe_fn=probe_fn,
                       switch_fn=switch_fn, notify_fn=notify_fn)

    # --- guards ---------------------------------------------------------------
    def test_disabled_is_noop(self):
        r = self._tick({})
        self.assertEqual(r["action"], "disabled")
        self.assertEqual(self.switched_to, [])

    def test_skip_local_and_smart(self):
        self._enable()
        self._write("current-exit", "smart")
        self.assertEqual(self._tick({})["action"], "skip")
        self._write("current-exit", "local")
        self.assertEqual(self._tick({})["action"], "skip")

    def test_grace_period_after_manual_switch(self):
        self._enable()
        os.utime(fo.CUR_EXIT_FILE, (self.now - 10, self.now - 10))  # just switched
        r = self._tick({"pgw-jp": False})
        self.assertEqual(r["action"], "grace")
        self.assertEqual(self.switched_to, [])

    # --- probe counting ---------------------------------------------------------
    def test_probe_ok_resets_fails(self):
        self._enable()
        r = self._tick({"pgw-jp": True})
        self.assertEqual(r["action"], "ok")
        self.assertEqual(fo.load_state().get("fails", 0), 0)

    def test_consecutive_failures_below_threshold(self):
        self._enable()
        for i in (1, 2):
            r = self._tick({"pgw-jp": False}, now=self.now + i * 60)
            self.assertEqual(r["action"], "fail")
            self.assertEqual(r["fails"], i)
        self.assertEqual(self.switched_to, [])

    # --- switching ----------------------------------------------------------------
    def test_switch_on_threshold_via_latency_order(self):
        self._enable()
        self._latency({"hk": 120, "us": 80, "jp": 50})   # us best after jp
        for i in (1, 2):
            self._tick({"pgw-jp": False}, now=self.now + i * 60)
        r = self._tick({"pgw-jp": False, "pgw-us": True}, now=self.now + 180)
        self.assertEqual(r["action"], "switched")
        self.assertEqual(r["to"], "us")
        self.assertIn("自动切换", self.notifications[0])
        self.assertIn("80", self.notifications[0])  # latency mentioned

    def test_failover_order_env_wins(self):
        self._enable()
        self._write("failover.env", 'FAILOVER_ORDER="hk,us"\n')
        self._latency({"hk": 300, "us": 80})
        for i in (1, 2):
            self._tick({"pgw-jp": False}, now=self.now + i * 60)
        r = self._tick({"pgw-jp": False, "pgw-hk": True}, now=self.now + 180)
        self.assertEqual(r["to"], "hk")  # configured order beats lower latency

    def test_first_candidate_fails_then_next(self):
        self._enable()
        self._latency({"hk": 80, "us": 120})
        for i in (1, 2):
            self._tick({"pgw-jp": False}, now=self.now + i * 60)
        # hk switch ok but probe fails → us should be tried and win
        probes = {"pgw-jp": False, "pgw-hk": False, "pgw-us": True}
        r = self._tick(probes, now=self.now + 180)
        self.assertEqual(r["action"], "switched")
        self.assertEqual(r["to"], "us")
        self.assertEqual(self.switched_to, ["hk", "us"])

    def test_stuck_alerts_when_no_candidate_works(self):
        self._enable()
        for i in (1, 2):
            self._tick({"pgw-jp": False}, now=self.now + i * 60)
        r = self._tick({"pgw-jp": False}, now=self.now + 180)
        self.assertEqual(r["action"], "stuck")
        self.assertIn("自愈失败", self.notifications[-1])

    # --- anti-flap ------------------------------------------------------------------
    def test_cooldown_blocks_immediate_retry(self):
        self._enable()
        for i in (1, 2):
            self._tick({"pgw-jp": False}, now=self.now + i * 60)
        self._tick({"pgw-jp": False}, now=self.now + 180, switch_ok=False)  # stuck → last_switch set
        r = self._tick({"pgw-jp": False}, now=self.now + 240)
        self.assertEqual(r["action"], "cooldown")
        self.assertEqual(self.switched_to, [])

    def test_hourly_cap(self):
        self._enable()
        st = {"exit": "jp", "fails": 3, "last_switch": self.now - 1000,
              "switches": [self.now - 100, self.now - 200, self.now - 300]}
        os.makedirs(os.path.dirname(fo.STATE_FILE), exist_ok=True)
        with open(fo.STATE_FILE, "w") as f:
            json.dump(st, f)
        r = self._tick({"pgw-jp": False})
        self.assertEqual(r["action"], "capped")

    # --- naming (I6) -----------------------------------------------------------------
    def test_iface_naming(self):
        self.assertEqual(fo.exit_iface("jp"), "pgw-jp")
        self.assertEqual(fo.exit_iface("a" * 11), "pgw-" + "a" * 11)
        import hashlib
        long_name = "a" * 12
        self.assertEqual(fo.exit_iface(long_name),
                         "pgw-" + hashlib.sha256(long_name.encode()).hexdigest()[:11])
        self.assertEqual(fo.exit_iface("香港节点"),
                         "pgw-" + hashlib.sha256("香港节点".encode()).hexdigest()[:11])

    def test_only_set_exit_path(self):
        """I11: no direct routing/firewall commands anywhere in the module."""
        with open(os.path.join(ROOT, "lib", "failover.py"), encoding="utf-8") as f:
            src = f.read()
        for forbidden in ("ip route", "ip rule", "nft ", "iptables"):
            self.assertNotIn(forbidden, src)
        self.assertIn('"--set-exit", name', src)


if __name__ == "__main__":
    unittest.main()
