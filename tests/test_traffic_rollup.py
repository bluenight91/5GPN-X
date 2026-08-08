#!/usr/bin/env python3
"""Unit tests for the api-server daily rollup (history-*.json, 62d window)."""
import calendar
import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_api():
    spec = importlib.util.spec_from_file_location("apiserver_rollup", os.path.join(ROOT, "lib", "api-server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def day_ts(iso):
    return calendar.timegm((int(iso[0:4]), int(iso[5:7]), int(iso[8:10]), 0, 0, 0, 0, 0, 0))


class RollupTest(unittest.TestCase):
    def setUp(self):
        self.api = load_api()
        self.tmpdir = tempfile.mkdtemp(prefix="rollup-")
        self.traffic_file = os.path.join(self.tmpdir, "history-traffic.json")
        self.latency_file = os.path.join(self.tmpdir, "history-latency.json")
        self.api.HISTORY_TRAFFIC_FILE = self.traffic_file
        self.api.HISTORY_LATENCY_FILE = self.latency_file
        # fixed "now": 2026-08-06 12:00 UTC
        self.now = day_ts("2026-08-06") + 12 * 3600

    def tearDown(self):
        for name in os.listdir(self.tmpdir):
            os.unlink(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def _read(self, path):
        with open(path) as f:
            return json.load(f)

    # --- traffic rollup ------------------------------------------------------

    def test_traffic_rollup_folds_completed_days(self):
        pts = [
            {"t": day_ts("2026-08-04") + 100, "v": {"smart": [100, 200]}},
            {"t": day_ts("2026-08-04") + 200, "v": {"smart": [50, 60], "warp": [7, 8]}},
            {"t": self.now - 60, "v": {"smart": [999, 999]}},  # today: not folded
        ]
        self.api.rollup_traffic(pts, now=self.now)
        hist = self._read(self.traffic_file)
        self.assertEqual(hist["days"]["2026-08-04"], {"smart": [150, 260], "warp": [7, 8]})
        self.assertNotIn("2026-08-06", hist["days"])
        self.assertIn("2026-08-04", hist["done"])

    def test_traffic_rollup_is_idempotent(self):
        pts = [{"t": day_ts("2026-08-04") + 100, "v": {"smart": [100, 200]}}]
        self.api.rollup_traffic(pts, now=self.now)
        self.api.rollup_traffic(pts, now=self.now)
        hist = self._read(self.traffic_file)
        self.assertEqual(hist["days"]["2026-08-04"], {"smart": [100, 200]})

    def test_rollup_prunes_to_62_days(self):
        pts = [{"t": day_ts("2026-05-01") + 100, "v": {"smart": [1, 1]}},
               {"t": day_ts("2026-06-01") + 100, "v": {"smart": [2, 2]}}]
        # pre-fill 62 old days so the new ones push the oldest out
        base = day_ts("2026-04-01")
        old = []
        for i in range(62):
            d = self.api._utc_day(base - i * 86400)
            old.append(d)
        hist = {"days": {d: {"smart": [1, 1]} for d in old}, "done": sorted(old)}
        with open(self.traffic_file, "w") as f:
            json.dump(hist, f)
        self.api.rollup_traffic(pts, now=self.now)
        out = self._read(self.traffic_file)
        self.assertEqual(len(out["days"]), 62)
        self.assertLessEqual(len(out["done"]), 62)
        self.assertIn("2026-06-01", out["days"])
        self.assertNotIn(self.api._utc_day(base - 61 * 86400), out["days"])

    # --- latency rollup ------------------------------------------------------

    def test_latency_rollup_keeps_sum_n_min_max(self):
        pts = [
            {"t": day_ts("2026-08-05") + 10, "v": {"jp": 30, "hk": 100}},
            {"t": day_ts("2026-08-05") + 20, "v": {"jp": 50, "hk": None}},
        ]
        self.api.rollup_latency(pts, now=self.now)
        hist = self._read(self.latency_file)
        jp = hist["days"]["2026-08-05"]["jp"]
        self.assertEqual((jp["sum"], jp["n"], jp["min"], jp["max"]), (80, 2, 30, 50))
        hk = hist["days"]["2026-08-05"]["hk"]
        self.assertEqual((hk["sum"], hk["n"]), (100, 1))

    def test_latency_avg_map(self):
        bucket = {"jp": {"sum": 80.0, "n": 2, "min": 30, "max": 50},
                  "hk": {"sum": 0.0, "n": 0, "min": None, "max": None}}
        self.assertEqual(self.api._latency_avg_map(bucket), {"jp": 40.0})

    # --- daily_series --------------------------------------------------------

    def test_daily_series_shape_and_current_bucket(self):
        days = {"2026-08-04": {"smart": [100, 200]}, "2026-08-05": {"smart": [50, 60]}}
        current = {"smart": [5, 6]}
        out = self.api.daily_series(days, 7, self.now, current)
        self.assertTrue(out["ok"])
        self.assertEqual(out["interval_sec"], 86400)
        self.assertEqual(out["series"], ["smart"])
        ts = [p["t"] for p in out["points"]]
        self.assertEqual(ts, [day_ts("2026-08-04"), day_ts("2026-08-05"), day_ts("2026-08-06")])
        self.assertEqual(out["points"][-1]["v"], {"smart": [5, 6]})

    def test_daily_series_clamps_days_and_maps_values(self):
        days = {f"2026-08-0{i}": {"jp": {"sum": float(i), "n": 1, "min": i, "max": i}}
                for i in range(1, 7)}
        out = self.api.daily_series(days, 3, self.now, None, self.api._latency_avg_map)
        self.assertEqual(len(out["points"]), 3)
        self.assertEqual(out["points"][-1]["t"], day_ts("2026-08-06"))
        self.assertEqual(out["points"][-1]["v"], {"jp": 6.0})
        out2 = self.api.daily_series(days, 999, self.now)
        self.assertLessEqual(len(out2["points"]), 62)

    def test_current_day_buckets(self):
        data = {"points": [
            {"t": self.now - 3600, "v": {"smart": [10, 20]}},
            {"t": self.now - 60, "v": {"smart": [1, 2]}},
            {"t": day_ts("2026-08-05") + 100, "v": {"smart": [99, 99]}},
        ]}
        self.assertEqual(self.api._current_traffic_day(data, now=self.now), {"smart": [11, 22]})
        lat = {"points": [
            {"t": self.now - 3600, "v": {"jp": 40}},
            {"t": self.now - 60, "v": {"jp": 60}},
        ]}
        cur = self.api._current_latency_day(lat, now=self.now)
        self.assertEqual((cur["jp"]["sum"], cur["jp"]["n"]), (100, 2))


if __name__ == "__main__":
    unittest.main()
