import importlib.util
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tgbot_rotate", root / "lib" / "tgbot.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


class RotateTokenTest(unittest.TestCase):
    def setUp(self):
        self.real_run2 = bot.run2

    def tearDown(self):
        bot.run2 = self.real_run2

    def test_success_shows_output_and_delete_advice(self):
        bot.run2 = lambda argv, timeout=120: (True, "[OK]   API token 已轮换\n  新令牌 (API_TOKEN): abc123")
        text = bot.op_rotate_token()
        self.assertIn("API 令牌已轮换", text)
        self.assertIn("abc123", text)
        self.assertIn("建议删除", text)

    def test_failure_reports_reason(self):
        bot.run2 = lambda argv, timeout=120: (False, "[ERR]  API 未安装；先运行 --setup-api")
        text = bot.op_rotate_token()
        self.assertIn("轮换失败", text)
        self.assertIn("API 未安装", text)

    def test_invokes_mgmt_rotate_token(self):
        seen = []

        def fake(argv, timeout=120):
            seen.append(argv)
            return True, "ok"

        bot.run2 = fake
        bot.op_rotate_token()
        self.assertEqual(seen[0][:3], ["bash", bot.MGMT, "--rotate-token"])


if __name__ == "__main__":
    unittest.main()
