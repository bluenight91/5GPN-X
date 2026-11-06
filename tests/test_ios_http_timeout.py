#!/usr/bin/env python3
"""A stalled iOS profile connection must exit 0, not die by SIGALRM."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lib" / "ios-http.py"


class IosHttpTimeoutTests(unittest.TestCase):
    def _run(self, stdin, env, timeout):
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        try:
            out, err = proc.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.fail("ios-http.py did not exit")
        self.assertEqual(
            proc.returncode,
            0,
            f"expected exit 0, got {proc.returncode} (negative means signal death)\n{err!r}",
        )
        return out

    def test_stalled_peer_exits_zero(self):
        # Hold the pipe open and send nothing: the old SIGALRM path killed the
        # process, and systemd then failed the per-connection unit.
        env = os.environ.copy()
        env["IOS_HTTP_TIMEOUT"] = "1"
        r, w = os.pipe()
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT)],
            stdin=r,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        os.close(r)
        try:
            _out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.fail("stalled connection was not cut off")
        finally:
            os.close(w)
        self.assertEqual(proc.returncode, 0, err)

    def test_partial_request_line_exits_zero(self):
        env = os.environ.copy()
        env["IOS_HTTP_TIMEOUT"] = "1"
        r, w = os.pipe()
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT)],
            stdin=r,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        os.close(r)
        os.write(w, b"GET /ios")  # no newline; readline would block forever
        try:
            _out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.fail("partial request line was not cut off")
        finally:
            os.close(w)
        self.assertEqual(proc.returncode, 0, err)

    def test_serves_profile_before_timeout(self):
        with tempfile.TemporaryDirectory() as www:
            Path(www, "index.html").write_bytes(b"<h1>ok</h1>")
            Path(www, "ios-dot.mobileconfig").write_bytes(b"<plist>ok</plist>")
            env = os.environ.copy()
            env["WWW_DIR"] = www
            env["IOS_HTTP_TIMEOUT"] = "5"
            out = self._run(
                b"GET /ios-dot.mobileconfig HTTP/1.1\r\nHost: example.com\r\n\r\n",
                env,
                timeout=4,
            )
        self.assertIn(b"200 OK", out)
        self.assertIn(b"<plist>ok</plist>", out)
        self.assertIn(b"application/x-apple-aspen-config", out)


if __name__ == "__main__":
    unittest.main()
