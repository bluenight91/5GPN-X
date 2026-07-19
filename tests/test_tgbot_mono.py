#!/usr/bin/env python3
"""mono <pre> formatting must stay closed and within Telegram's 4096 limit."""
import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tgbot_mono", root / "lib" / "tgbot.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


class MonoTextTests(unittest.TestCase):
    def test_quote_heavy_log_stays_closed_under_limit(self):
        log = "\n".join(
            '2026-07-19T16:55:27Z kfc mosdns[1]: WARN fwd upstream error '
            '{"uqid": %d, "qname": "user.jpush.cn.", "error": "context deadline exceeded"}' % i
            for i in range(30)
        )
        out = bot.mono_text(log)
        self.assertLessEqual(len(out), 4096)
        self.assertTrue(out.startswith("<pre>"))
        self.assertTrue(out.endswith("</pre>"))

    def test_empty_shows_no_output(self):
        self.assertIn("(no output)", bot.mono_text(""))

    def test_html_is_escaped(self):
        out = bot.mono_text("a<b>&\"c\"")
        self.assertNotIn("a<b>", out)
        self.assertIn("&quot;", out)


if __name__ == "__main__":
    unittest.main()
