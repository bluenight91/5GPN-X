#!/usr/bin/env python3
"""Focused WLOC Bot validation without requiring systemd or Telegram."""
import importlib.util
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tgbot_wloc", ROOT / "lib" / "tgbot.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)

assert bot._wloc_parse("35.681236, 139.767125") == (35.681236, 139.767125, 25)
for invalid in ("91,0", "1,181", "not coordinates"):
    try:
        bot._wloc_parse(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid WLOC coordinates accepted: %s" % invalid)

with tempfile.TemporaryDirectory() as root:
    wloc = Path(root) / "wloc"
    wloc.mkdir()
    bot.WLOC_DIR = str(wloc)
    bot.WLOC_LOCATION = str(wloc / "location.json")
    bot.WLOC_MODIFIER = str(wloc / "modifier.state")
    bot.WLOC_DOMAINS = str(Path(root) / "wloc.txt")
    original_getgrnam = bot.grp.getgrnam
    bot.grp.getgrnam = lambda _name: type("Group", (), {"gr_gid": os.getgid()})()
    try:
        bot._wloc_atomic_write(bot.WLOC_LOCATION, '{"active":"current"}\n')
        assert Path(bot.WLOC_LOCATION).read_text() == '{"active":"current"}\n'
    finally:
        bot.grp.getgrnam = original_getgrnam

text, keyboard = bot._wloc_page()
assert "WLOC" in text
assert any(button["callback_data"] == "wloc:input" for row in keyboard for button in row)
assert ("wloc", "WLOC 虚拟定位管理") in bot.BOT_COMMANDS
print("tgbot WLOC policy OK")
