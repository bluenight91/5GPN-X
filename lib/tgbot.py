#!/usr/bin/env python3
"""
5gpn Telegram control bot.

Stdlib-only (urllib) long-polling bot that drives the 5gpn management
commands and systemd services from Telegram, using inline-keyboard buttons.

Security model:
  * Bot token is read from the environment (systemd EnvironmentFile, root-only).
  * Only chat IDs listed in TG_ADMIN_IDS may run operations; everyone else is
    ignored (except /id, which only reveals the caller's own numeric id).
  * Every operation maps to a fixed argv list. User-supplied values (exit name,
    service name) are validated against strict allowlists/regex and are NEVER
    interpolated into a shell.

Environment:
  TG_BOT_TOKEN   Telegram bot token (required)
  TG_ADMIN_IDS   Comma/space separated numeric chat IDs allowed to operate
  MGMT           Path to the management script (default below)
"""

import base64
import grp
import hashlib
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse

TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
ADMIN_IDS = {
    int(x) for x in re.split(r"[,\s]+", os.environ.get("TG_ADMIN_IDS", "").strip()) if x
}
MGMT = os.environ.get("MGMT", "/opt/5gpn/bin/5gpn-ctl")
# Self-service component version bumps (mirrors install.sh pins; same files
# the API reads). The bot talks to MGMT directly so it keeps working even
# when the HTTP API is down.
COMPONENTS = {
    "metacubexd": {"label": "metacubexd 面板",
                   "version_file": "/opt/5gpn/webui/mihomo/.metacubexd-version",
                   "pin_file": "/opt/5gpn/etc/metacubexd.pin",
                   "repo": "MetaCubeX/metacubexd", "flag": "--update-webui"},
    "mihomo": {"label": "mihomo 引擎",
               "version_file": "/opt/5gpn/bin/.mihomo-version",
               "pin_file": "/opt/5gpn/etc/mihomo.pin",
               "repo": "MetaCubeX/mihomo", "flag": "--update-mihomo"},
}
COMP_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
DOCTOR = os.environ.get("DOCTOR", "/opt/5gpn/scripts/doctor.sh")
SNAPSHOT = os.environ.get("SNAPSHOT", "/opt/5gpn/scripts/snapshot.sh")
INSTALL_SH = "/opt/5gpn/install.sh"
API = f"https://api.telegram.org/bot{TOKEN}/"

# Services the bot may tail. Order matters for display only.
SERVICES = [
    "mosdns",
    "sniproxy",
    "wa-shim",
    "quic-proxy",
    "5gpn-wloc",
    "5gpn-ios-profile",
    "5gpn-tgbot",
    "5gpn-api",
    "5gpn-client-socks",
    "5gpn-mtproxy",
    "5gpn-client-mtproto",
]
RESTART_SERVICES = [
    "mosdns",
    "sniproxy",
    "wa-shim",
    "quic-proxy",
    "5gpn-ios-profile.socket",
]
EXIT_NAME_RE = re.compile(r"^(local|[\w\-\u4e00-\u9fff]{1,16})$", re.UNICODE)
EXIT_ADD_NAME_RE = re.compile(r"^[\w\-\u4e00-\u9fff]{1,16}$", re.UNICODE)  # 'local' is reserved
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
DNS_LIST_RE = re.compile(r"^[0-9A-Fa-f:.,\s]+$")
DNS_UPSTREAM_SCHEMES = {"https", "tls", "udp", "tcp"}
SNAP_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
WWW_DIR = "/opt/5gpn/www"
WLOC_DIR = "/opt/5gpn/etc/wloc"
WLOC_LOCATION = os.path.join(WLOC_DIR, "location.json")
WLOC_MODIFIER = os.path.join(WLOC_DIR, "modifier.state")
WLOC_CA = os.path.join(WLOC_DIR, "ca.der")
WLOC_DOMAINS = "/etc/mosdns/wloc.txt"
WLOC_SERVICE = "5gpn-wloc"
WLOC_HOSTS = ("gs-loc.apple.com", "gs-loc-cn.apple.com")
WLOC_PRESETS = {
    "tokyo": ("东京", 35.681236, 139.767125),
    "hongkong": ("香港", 22.319304, 114.169361),
    "singapore": ("新加坡", 1.304833, 103.831833),
    "losangeles": ("洛杉矶", 34.052235, -118.243683),
    "paris": ("巴黎", 48.856613, 2.352222),
    "frankfurt": ("法兰克福", 50.110924, 8.682127),
}

# Per-chat conversational state for multi-step flows (e.g. add-exit).
PENDING = {}
BUSY = set()
# Per-chat "console" message: menus, progress and results are edited into this
# single bubble instead of sending a new message every time.
CONSOLE = {}
LAST_FAILED_DOT_DOMAIN = {}
PROXY_URI_RE = re.compile(r"^(ss|vmess|trojan|vless|hysteria2|hy2|tuic|anytls|socks5h|socks5|socks|http|https)://", re.IGNORECASE)
SUPPORTED_EXIT_LINKS = "ss:// vmess:// trojan:// vless:// hysteria2:// tuic:// anytls:// socks5:// http://"


# --------------------------------------------------------------------------- #
# Telegram API
# --------------------------------------------------------------------------- #
_TG_LOCAL = threading.local()
_BG_EXECUTOR = ThreadPoolExecutor(max_workers=6, thread_name_prefix="pgw-bg")
_CALLBACK_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="pgw-callback")
_EXIT_WRITE_LOCK = threading.Lock()
_TG_API_TIMEOUT = 12
_TG_POLL_TIMEOUT = 35
_TG_API_IDLE_SECONDS = 25


def _tg_slot(method):
    return "poll" if method == "getUpdates" else "api"


def _close_tg_conn(slot):
    conn = getattr(_TG_LOCAL, slot + "_conn", None)
    try:
        if conn:
            conn.close()
    except Exception:  # noqa: BLE001, S110
        pass
    setattr(_TG_LOCAL, slot + "_conn", None)
    setattr(_TG_LOCAL, slot + "_last_used", 0.0)


def _configure_tg_socket(conn, timeout):
    """Keep long polls alive through short-idle NATs and bound API stalls."""
    conn.timeout = timeout
    sock = getattr(conn, "sock", None)
    if sock is None:
        return
    try:
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for name, value in (("TCP_KEEPIDLE", 15), ("TCP_KEEPINTVL", 5), ("TCP_KEEPCNT", 3)):
            option = getattr(socket, name, None)
            if option is not None:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
    except OSError:
        pass


def tg(method, **params):
    data = json.dumps(params).encode("utf-8")
    path = f"/bot{TOKEN}/{method}"
    headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
    slot = _tg_slot(method)
    timeout = _TG_POLL_TIMEOUT if slot == "poll" else _TG_API_TIMEOUT
    conn = getattr(_TG_LOCAL, slot + "_conn", None)
    last_used = getattr(_TG_LOCAL, slot + "_last_used", 0.0)
    if slot == "api" and conn is not None and time.monotonic() - last_used > _TG_API_IDLE_SECONDS:
        _close_tg_conn(slot)
    for attempt in (0, 1):
        try:
            conn = getattr(_TG_LOCAL, slot + "_conn", None)
            if conn is None:
                conn = http.client.HTTPSConnection("api.telegram.org", timeout=timeout)
                setattr(_TG_LOCAL, slot + "_conn", conn)
            _configure_tg_socket(conn, timeout)
            conn.request("POST", path, data, headers)
            _configure_tg_socket(conn, timeout)
            raw = conn.getresponse().read()
            setattr(_TG_LOCAL, slot + "_last_used", time.monotonic())
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception as e:  # noqa: BLE001
            try:
                conn = getattr(_TG_LOCAL, slot + "_conn", None)
                if conn:
                    conn.close()
            except Exception:  # noqa: BLE001, S110
                pass
            setattr(_TG_LOCAL, slot + "_conn", None)
            setattr(_TG_LOCAL, slot + "_last_used", 0.0)
            if attempt:
                return {"ok": False, "error": str(e)}


def background(fn, *args):
    def go():
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001
            print(f"[err] background task: {e}", file=sys.stderr)

    _BG_EXECUTOR.submit(go)


def answer_callback_async(cb_id):
    def go():
        tg("answerCallbackQuery", callback_query_id=cb_id)

    _CALLBACK_EXECUTOR.submit(go)


def send(chat_id, text, keyboard=None, mono=False):
    # mono=True: paginate raw command output across one or more monospace
    # messages (escaped + wrapped per chunk, so HTML never splits mid-tag).
    # Returns the message_id of the last message sent (None if unavailable).
    if mono:
        text = (text or "").strip() or "(no output)"
        chunks = [text[i : i + 3500] for i in range(0, len(text), 3500)] or [""]
        wrapped = ["<pre>" + html.escape(c) + "</pre>" for c in chunks]
    else:
        wrapped = list(_chunks(text, 3900))
    last = len(wrapped) - 1
    last_mid = None
    for i, chunk in enumerate(wrapped):
        params = {
            "chat_id": chat_id,
            "text": chunk,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if keyboard is not None and i == last:
            params["reply_markup"] = {"inline_keyboard": keyboard}
        r = tg("sendMessage", **params)
        if isinstance(r, dict) and r.get("ok"):
            mid = (r.get("result") or {}).get("message_id")
            if mid is not None:
                last_mid = mid
    return last_mid


def delete_message(chat_id, message_id):
    if message_id is None:
        print(f"[warn] deleteMessage failed chat_id={chat_id} message_id=None error_code=- description=missing message_id", file=sys.stderr)
        return False
    try:
        response = tg("deleteMessage", chat_id=chat_id, message_id=message_id)
    except Exception as e:  # noqa: BLE001
        response = {"ok": False, "error": f"exception:{type(e).__name__}"}
    if isinstance(response, dict) and response.get("ok"):
        return True
    if isinstance(response, dict):
        error_code = response.get("error_code", "-")
        description = response.get("description") or response.get("error") or "unknown error"
    else:
        error_code = "-"
        description = "malformed response"
    description = " ".join(str(description).split())[:500]
    print(f"[warn] deleteMessage failed chat_id={chat_id} message_id={message_id} error_code={error_code} description={description}", file=sys.stderr)
    return False


def _chunks(text, size):
    if not text:
        yield ""
        return
    for i in range(0, len(text), size):
        yield text[i : i + size]


def mono_text(text):
    """HTML-escape THEN truncate, so the <pre> always closes within Telegram's
    4096-char limit. Truncating before escaping lets entity expansion (every "
    becomes &quot;) push the closing tag past the limit — quote-heavy logs
    (e.g. mosdns's JSON lines) were rejected by Telegram and never showed."""
    esc = html.escape((text or "").strip() or "(no output)")
    return "<pre>" + esc[:3800] + "</pre>"


def edit_message(chat_id, message_id, text, keyboard=None, mono=False):
    """editMessageText without a callback_query. Returns True when the message
    now shows the requested content ("message is not modified" counts as
    success and is ignored quietly)."""
    if chat_id is None or message_id is None:
        return False
    if mono:
        text = mono_text(text)
    params = {
        "chat_id": chat_id, "message_id": message_id, "text": (text or "")[:4096],
        "parse_mode": "HTML", "disable_web_page_preview": True,
    }
    if keyboard is not None:
        params["reply_markup"] = {"inline_keyboard": keyboard}
    try:
        r = tg("editMessageText", **params)
    except Exception as e:  # noqa: BLE001
        print(f"[warn] editMessageText failed chat_id={chat_id} message_id={message_id} error={type(e).__name__}", file=sys.stderr)
        return False
    if isinstance(r, dict) and r.get("ok"):
        return True
    return "not modified" in str(r)


def upsert_console(chat_id, text, keyboard=None, mono=False, message_id=None):
    """Update the per-chat console message in place; fall back to a new
    message only when editing is impossible (deleted / too old / media).
    Returns the message_id that now shows the content."""
    mid = message_id if message_id is not None else CONSOLE.get(chat_id)
    if mid is not None and edit_message(chat_id, mid, text, keyboard, mono):
        CONSOLE[chat_id] = mid
        return mid
    new_mid = send(chat_id, text, keyboard, mono)
    if new_mid is not None:
        CONSOLE[chat_id] = new_mid
    return new_mid


def console_async(chat_id, text_fn, keyboard=None, mono=False, keyboard_fn=None, message_id=None):
    """Run text_fn in the background, then edit the result into the console
    message (no extra "processing"/"result" message pair)."""
    mid = message_id if message_id is not None else CONSOLE.get(chat_id)

    def go():
        text = text_fn()
        kb = keyboard_fn() if keyboard_fn else keyboard
        upsert_console(chat_id, text, kb, mono, message_id=mid)

    background(go)


def reanchor_console(chat_id, text, keyboard=None, mono=False):
    """Slash commands must always be visible: send a fresh console message at
    the bottom of the chat and drop the old one (editing an old/cleared
    message would look like the bot did not respond). Returns the new
    console message_id."""
    old = CONSOLE.pop(chat_id, None)
    new_mid = send(chat_id, text, keyboard, mono)
    if new_mid is not None:
        CONSOLE[chat_id] = new_mid
        if old is not None and old != new_mid:
            background(delete_message, chat_id, old)
    return new_mid


def edit(cb, text, keyboard=None, mono=False):
    """Edit the message the button belongs to (keeps everything in one bubble).
    Falls back to a new message if the edit can't be applied."""
    msg = cb.get("message", {})
    chat_id = msg.get("chat", {}).get("id")
    mid = msg.get("message_id")
    if mono:
        text = mono_text(text)
    params = {
        "chat_id": chat_id, "message_id": mid, "text": (text or "")[:4096],
        "parse_mode": "HTML", "disable_web_page_preview": True,
    }
    if keyboard is not None:
        params["reply_markup"] = {"inline_keyboard": keyboard}
    r = tg("editMessageText", **params)
    if r.get("ok"):
        CONSOLE[chat_id] = mid
        return
    if "not modified" in str(r):
        CONSOLE[chat_id] = mid
        return  # nothing to do
    # original may be a photo / too old / gone -> delete it and post a fresh
    # message so the user doesn't see an orphaned media bubble above the menu.
    # text is already HTML-formatted when mono=True; pass mono=False so send()
    # does not double-escape it.
    if mid is not None:
        delete_message(chat_id, mid)
    new_mid = send(chat_id, text, keyboard if keyboard else None, mono=False)
    if new_mid is not None:
        CONSOLE[chat_id] = new_mid


def _busy_key_from_cb(cb):
    msg = cb.get("message", {})
    chat_id = msg.get("chat", {}).get("id")
    mid = msg.get("message_id")
    return (chat_id, mid)


def edit_async(cb, text_fn, keyboard=None, mono=False):
    key = _busy_key_from_cb(cb)

    def go():
        try:
            edit(cb, text_fn(), keyboard, mono)
        finally:
            BUSY.discard(key)

    BUSY.add(key)
    background(go)


def edit_ios_async(cb, chat_id):
    key = _busy_key_from_cb(cb)

    def go():
        try:
            res = op_ios_send_inline(cb)
            if res:
                edit(cb, res, back_kb("menu:main"))
        finally:
            BUSY.discard(key)

    BUSY.add(key)
    background(go)


def back_kb(target="menu:main", label="« 返回"):
    return [[{"text": label, "callback_data": target}]]


def cancel_kb(section):
    return [[{"text": "✖ 取消", "callback_data": "cancel:" + section}]]


def add_exit_retry_kb():
    return [[{"text": "➕ 重新添加", "callback_data": "exit_add"}],
            [{"text": "« 返回", "callback_data": "menu:exits"}]]


def status_kb():
    return [[{"text": "🔄 刷新", "callback_data": "act:status_refresh"}],
            [{"text": "« 返回", "callback_data": "menu:main"}]]


def send_document(chat_id, path, caption="", filename=None):
    """Upload a local file via multipart/form-data (sendDocument)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return False
    name = filename or os.path.basename(path) or "report.txt"
    boundary = "----pgwDocBoundary9c1e4d"

    def _field(field_name, val):
        return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"\r\n\r\n{val}\r\n").encode()

    body = _field("chat_id", str(chat_id))
    if caption:
        body += _field("caption", caption) + _field("parse_mode", "HTML")
    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; "
             f"filename=\"{name}\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").encode()
    body += data + b"\r\n" + (f"--{boundary}--\r\n").encode()
    req = urllib.request.Request(
        API + "sendDocument", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8")).get("ok", False)
    except Exception as e:  # noqa: BLE001
        print(f"[warn] send_document failed: {e}", file=sys.stderr)
        return False


def send_photo(chat_id, path, caption=""):
    """Upload a local image via multipart/form-data (sendPhoto)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return False
    boundary = "----pgwQRboundary8f3a2b"

    def _field(name, val):
        return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{val}\r\n").encode()

    body = _field("chat_id", str(chat_id))
    if caption:
        body += _field("caption", caption) + _field("parse_mode", "HTML")
    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"photo\"; "
             "filename=\"qr.png\"\r\nContent-Type: image/png\r\n\r\n").encode()
    body += data + b"\r\n" + (f"--{boundary}--\r\n").encode()
    req = urllib.request.Request(
        API + "sendPhoto", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8")).get("ok", False)
    except Exception as e:  # noqa: BLE001
        # Rare: TG API rejects the photo upload (size, format, transient 5xx).
        # The caller falls back to a text-only URL reply, but without this
        # log we'd have zero forensic trail for "why did the QR disappear?".
        print(f"[warn] send_photo failed: {e}", file=sys.stderr)
        return False


def edit_message_media(cb, photo_path, caption="", keyboard=None):
    """Replace the callback message content with a photo in-place using
    editMessageMedia (multipart upload). Keeps the QR inside the same bubble
    instead of sending a separate photo message."""
    msg = cb.get("message", {})
    chat_id = msg.get("chat", {}).get("id")
    mid = msg.get("message_id")
    if chat_id is None or mid is None:
        return False
    try:
        with open(photo_path, "rb") as f:
            photo_data = f.read()
    except OSError:
        return False
    boundary = "----pgwEditMedia9c4e7d"

    def _field(name, val):
        return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{val}\r\n").encode()

    media_obj = {"type": "photo", "media": "attach://photo"}
    if caption:
        media_obj["caption"] = caption
        media_obj["parse_mode"] = "HTML"
    body = _field("chat_id", str(chat_id))
    body += _field("message_id", str(mid))
    body += _field("media", json.dumps(media_obj))
    if keyboard is not None:
        body += _field("reply_markup", json.dumps({"inline_keyboard": keyboard}))
    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"photo\"; "
             "filename=\"qr.png\"\r\nContent-Type: image/png\r\n\r\n").encode()
    body += photo_data + b"\r\n" + (f"--{boundary}--\r\n").encode()
    req = urllib.request.Request(
        API + "editMessageMedia", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            r = json.loads(resp.read().decode("utf-8"))
            if r.get("ok"):
                CONSOLE[chat_id] = mid
                return True
    except Exception as e:  # noqa: BLE001
        print(f"[warn] editMessageMedia failed: {e}", file=sys.stderr)
    return False


def pre(text):
    """Wrap command output in a monospace HTML block, safely escaped."""
    text = text.strip() or "(no output)"
    if len(text) > 3500:
        text = text[:3500] + "\n... (truncated)"
    return "<pre>" + html.escape(text) + "</pre>"


# --------------------------------------------------------------------------- #
# Operations (fixed argv, no shell)
# --------------------------------------------------------------------------- #
def run(argv, timeout=120, inp=None):
    try:
        p = subprocess.run(
            argv,
            check=False,
            input=inp,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        out = p.stdout or ""
        if p.returncode != 0:
            out += f"\n[exit code {p.returncode}]"
        return out
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return f"[command not found: {argv[0]}]"
    except Exception as e:  # noqa: BLE001  # pragma: no cover
        return f"[error: {e}]"


def validate_mgmt_path():
    if not os.path.isabs(MGMT) or not os.path.isfile(MGMT):
        print(f"MGMT must be an absolute path to the management script: {MGMT}",
              file=sys.stderr)
        sys.exit(1)


def heal_mgmt_ctl():
    """Rewrite a legacy full-copy 5gpn-ctl into a thin wrapper.

    Older installs copied install.sh into bin/5gpn-ctl; SCRIPT_DIR then became
    /opt/5gpn/bin and every Bot call bootstrap-cloned the repo. That made
    doctor/report flaky (false 'service not running' / missing fwmark).
    """
    path = MGMT
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return
    if "bootstrap_from_repo_if_needed" not in head and "REPO_URL=" not in head:
        return
    if not os.path.isfile(INSTALL_SH):
        print(f"[warn] legacy 5gpn-ctl detected but {INSTALL_SH} missing; skip heal",
              file=sys.stderr)
        return
    wrapper = (
        "#!/bin/bash\n"
        "if [[ $# -gt 0 && \"$1\" != -* ]]; then\n"
        "    set -- \"--$1\" \"${@:2}\"\n"
        "fi\n"
        "exec /opt/5gpn/install.sh \"$@\"\n"
    )
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(wrapper)
        os.chmod(path, 0o755)
        print(f"[info] healed legacy 5gpn-ctl into thin wrapper: {path}",
              file=sys.stderr)
    except OSError as exc:
        print(f"[warn] could not heal 5gpn-ctl: {exc}", file=sys.stderr)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s):
    return _ANSI_RE.sub("", s or "")


def run2(argv, timeout=120, inp=None, env=None, merge_stderr=True):
    """Run a command; return (ok, stripped_output)."""
    try:
        kwargs = {"input": inp, "stdout": subprocess.PIPE, "text": True,
                  "encoding": "utf-8", "errors": "replace", "timeout": timeout}
        if env is not None:
            kwargs["env"] = env
        if merge_stderr:
            kwargs["stderr"] = subprocess.STDOUT
        else:
            kwargs["stderr"] = subprocess.PIPE
        p = subprocess.run(argv, check=False, **kwargs)
        out = p.stdout or ""
        # Keep stderr available for callers that only want stdout parsed,
        # but append a short marker when the command failed.
        if not merge_stderr and p.stderr and p.returncode != 0 and not out.strip():
            out = p.stderr
        return p.returncode == 0, _strip_ansi(out)
    except subprocess.TimeoutExpired:
        return False, f"执行超时（{timeout}s）"
    except FileNotFoundError:
        return False, f"命令不存在：{argv[0]}"
    except Exception as e:  # noqa: BLE001  # pragma: no cover
        return False, f"错误：{e}"


def _host_unit_active(unit):
    for binary in ("/usr/bin/systemctl", "/bin/systemctl", "systemctl"):
        try:
            p = subprocess.run(
                [binary, "is-active", unit],
                check=False,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace", timeout=5,
            )
            if (p.stdout or "").strip() in ("active", "activating"):
                return True
        except Exception:  # noqa: BLE001, S112
            continue
    return False


def _host_port_listen(port):
    try:
        p = subprocess.run(
            ["bash", "-lc",
             f"ss -H -tln 2>/dev/null | grep -qE ':{int(port)}( |$)'"],
            check=False,
            timeout=5,
        )
        return p.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _host_fwmark_ok():
    try:
        p = subprocess.run(
            ["bash", "-lc",
             "ip rule show 2>/dev/null | grep -q 'fwmark 0x1 lookup 100'"],
            check=False,
            timeout=5,
        )
        return p.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _host_pgw_exit_ok():
    try:
        p = subprocess.run(
            ["bash", "-lc", "nft list table inet pgw_exit >/dev/null 2>&1"],
            check=False,
            timeout=5,
        )
        return p.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _reconcile_doctor_data(data):
    """Fix only the tgbot liveness false negative: this process is answering."""
    if not isinstance(data, dict):
        return data, []
    checks = list(data.get("checks") or [])
    fixed = []

    def bump_tgbot():
        nonlocal checks
        for c in checks:
            check_name = str(c.get("check") or "")
            if "5gpn-tgbot" in check_name and c.get("level") == "fail":
                c["level"] = "ok"
                c["detail"] = "running (bot process alive)"
                fixed.append(check_name)
                return

    # 复核层仅保留 tgbot「进程存活」兜底，去掉「仅端口开放就改 PASS」。
    bump_tgbot()

    pass_n = sum(1 for c in checks if c.get("level") == "ok")
    fail_n = sum(1 for c in checks if c.get("level") == "fail")
    warn_n = sum(1 for c in checks if c.get("level") == "warn")
    data["checks"] = checks
    data["pass"] = pass_n
    data["fail"] = fail_n
    data["warn"] = warn_n
    data["ok"] = fail_n == 0
    return data, fixed


def _doctor_env():
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/root",
        "BASE_DIR": "/opt/5gpn",
        "CONF_DIR": "/opt/5gpn/etc",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }


def _run_doctor_json(doctor):
    systemd_cmd = [
        "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        "-p", "User=root",
        "-E", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "-E", "LANG=C.UTF-8",
        "-E", "LC_ALL=C.UTF-8",
        "-E", "PYTHONIOENCODING=utf-8",
        "-E", "PYTHONUTF8=1",
        "-E", "HOME=/root",
        "/bin/bash", doctor, "--json",
    ]
    ok, out = run2(systemd_cmd, timeout=180, merge_stderr=False)
    if ok:
        return ok, out
    return run2(["/bin/bash", doctor, "--json"], timeout=180,
                env=_doctor_env(), merge_stderr=False)


def op_doctor():
    """Compact FAIL/WARN summary for Telegram (full detail → 诊断报告)."""
    doctor = DOCTOR if os.path.isfile(DOCTOR) else "/opt/5gpn/scripts/doctor.sh"
    ok, out = _run_doctor_json(doctor)
    raw = (out or "").strip()
    data = None
    if raw:
        # doctor --json prints a single JSON object; tolerate trailing noise.
        for line in reversed(raw.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    data = json.loads(line)
                    break
                except ValueError:
                    continue
        if data is None:
            try:
                data = json.loads(raw)
            except ValueError:
                data = None
    if data is None:
        body = html.escape(_strip_ansi(out)[-2500:] or "无输出")
        head = "✅ <b>doctor 通过</b>" if ok else "❌ <b>doctor 发现问题</b>"
        return f"{head}\n<pre>{body}</pre>"

    data, fixed = _reconcile_doctor_data(data)

    fail_n = int(data.get("fail", 0) or 0)
    warn_n = int(data.get("warn", 0) or 0)
    pass_n = int(data.get("pass", 0) or 0)
    cidr = data.get("client_cidr") or "?"
    checks = data.get("checks") or []
    fails = [c for c in checks if c.get("level") == "fail"]
    warns = [c for c in checks if c.get("level") == "warn"]

    if fail_n == 0:
        head = "✅ <b>doctor 通过</b>"
    else:
        head = "❌ <b>doctor 发现问题</b>"
    lines = [
        head,
        f"失败 <code>{fail_n}</code> / 警告 <code>{warn_n}</code> / 通过 <code>{pass_n}</code>",
        f"客户端网段：<code>{html.escape(str(cidr))}</code>",
        f"出口：<code>{html.escape(str(data.get('current_exit') or '?'))}</code>",
    ]
    if fails:
        lines.append("")
        lines.append("<b>失败</b>")
        for c in fails[:12]:
            lines.append(
                f"• {html.escape(str(c.get('check') or '?'))}：{html.escape(str(c.get('detail') or ''))}")
        if len(fails) > 12:
            lines.append(f"… 另有 {len(fails) - 12} 项失败")
    if warns:
        lines.append("")
        lines.append("<b>警告</b>")
        for c in warns[:8]:
            lines.append(
                f"• {html.escape(str(c.get('check') or '?'))}：{html.escape(str(c.get('detail') or ''))}")
        if len(warns) > 8:
            lines.append(f"… 另有 {len(warns) - 8} 项警告")
    if any("运行时一致性" in str(c.get("check") or "") for c in warns + fails):
        lines.append("")
        lines.append("💡 建议执行 <code>sudo 5gpn update</code> 完成运行时刷新")
    if fixed:
        lines.append("")
        lines.append(f"ℹ️ 已自动纠正 Bot 进程存活误报：<code>{html.escape(', '.join(fixed))}</code>")
    lines.append("")
    lines.append("完整现场请用「诊断报告」下载文件。")
    return "\n".join(lines)


def _reason(out, n=4):
    """A short, human-readable reason from command output (for failures)."""
    lines = [line.strip() for line in _strip_ansi(out).splitlines() if line.strip()]
    errs = [line for line in lines if re.search(r"\[!\]|\[ERR\]|error|fail|invalid|拒绝|失败", line, re.IGNORECASE)]
    picked = (errs or lines)[-n:]
    text = "\n".join(picked)
    return (text[:600] + "…") if len(text) > 600 else text


def _tail_output(out, n=20, limit=1800):
    lines = [line.rstrip() for line in _strip_ansi(out).splitlines() if line.strip()]
    text = "\n".join(lines[-n:]) or "(no output)"
    return (text[-limit:] + "…") if len(text) > limit else text


def _exit_ip():
    """Best-effort: the public egress IP as seen through the active exit."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://ipinfo.io/ip"):
        ok, out = run2(["sudo", "-u", "pxout", "curl", "-4", "-s", "--max-time", "10", url],
                       timeout=14)
        out = (out or "").strip()
        if ok and re.match(r"^[0-9.]+$", out):
            return out
    return ""


# (unit, friendly label) shown on the status card. Opt-in proxies are appended
# in op_status() when their .enabled markers exist.
STATUS_ITEMS = [
    ("mosdns", "mosdns"),
    ("sniproxy", "sniproxy"),
    ("wa-shim", "wa-shim"),
    ("quic-proxy", "quic-proxy"),
    ("5gpn-wloc", "WLOC"),
    ("5gpn-ios-profile.socket", "iOS 描述文件"),
    ("5gpn-api", "控制 API"),
    ("5gpn-tgbot", "Telegram Bot"),
]


def _read_file(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def _parse_env(path):
    d = {}
    for line in _read_file(path).splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def _is_active(unit):
    try:
        p = subprocess.run(["systemctl", "is-active", unit],
                           check=False,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=10)
        return p.stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


# --------------------------------------------------------------------------- #
# Live server metrics (read from /proc, sampled over a short interval)
# --------------------------------------------------------------------------- #
def _read_int(path, default=0):
    try:
        return int(_read_file(path))
    except (ValueError, OSError):
        return default


def _cpu_idle_total():
    try:
        with open("/proc/stat") as fh:
            vals = list(map(int, fh.readline().split()[1:]))
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
        return idle, sum(vals)
    except Exception:  # noqa: BLE001
        return 0, 0


def _default_iface():
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000" and (int(p[3], 16) & 0x2):  # default + RTF_GATEWAY
                    return p[0]
    except Exception:  # noqa: BLE001, S110
        pass
    return None


def _iface_bytes(iface):
    if not iface:
        return 0, 0
    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                if ":" in line:
                    name, rest = line.split(":", 1)
                    if name.strip() == iface:
                        f = rest.split()
                        return int(f[0]), int(f[8])  # rx, tx bytes
    except Exception:  # noqa: BLE001, S110
        pass
    return 0, 0


def _established():
    n = 0
    for p in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(p) as fh:
                for line in fh.readlines()[1:]:
                    if line.split()[3] == "01":  # ESTABLISHED
                        n += 1
        except Exception:  # noqa: BLE001, S110
            pass
    return n


def _fmt_bytes(n):
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return (f"{int(n)}{unit}") if unit == "B" else (f"{n:.1f}{unit}")
        n /= 1024
    return f"{n:.1f}P"


def system_metrics():
    idle0, tot0 = _cpu_idle_total()
    iface = _default_iface()
    rx0, tx0 = _iface_bytes(iface)
    time.sleep(0.7)
    idle1, tot1 = _cpu_idle_total()
    rx1, tx1 = _iface_bytes(iface)

    dtot = (tot1 - tot0) or 1
    cpu = max(0, min(100, round(100 * (1 - (idle1 - idle0) / dtot))))
    rx_rate = max(0, (rx1 - rx0) / 0.7)
    tx_rate = max(0, (tx1 - tx0) / 0.7)

    load = " ".join(_read_file("/proc/loadavg").split()[:3]) or "?"
    cores = os.cpu_count() or 1

    mi = {}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                k, v = line.split(":")
                mi[k.strip()] = int(v.split()[0])  # kB
    except Exception:  # noqa: BLE001, S110
        pass
    mt, ma = mi.get("MemTotal", 0) // 1024, mi.get("MemAvailable", 0) // 1024
    mu = mt - ma
    st, sf = mi.get("SwapTotal", 0) // 1024, mi.get("SwapFree", 0) // 1024
    su = st - sf

    dused = dtotal = 0
    try:
        sv = os.statvfs("/")
        dtotal = sv.f_blocks * sv.f_frsize
        dused = dtotal - sv.f_bavail * sv.f_frsize
    except Exception:  # noqa: BLE001, S110
        pass

    conn = _read_int("/proc/sys/net/netfilter/nf_conntrack_count", -1)
    est = _established()
    try:
        up_h = int(float(_read_file("/proc/uptime").split()[0]) // 3600)
    except Exception:  # noqa: BLE001
        up_h = 0

    def pct(u, t):
        return round(100 * u / t) if t else 0

    out = ["━━━━━━━━━━", "🖥 <b>服务器</b>"]
    out.append(f"⏱ 运行 {up_h} 小时")
    out.append(f"🧮 CPU {cpu}%（load {load} · {cores}核）")
    swap = (f"　Swap {su}/{st} MB") if st else ""
    out.append(f"🧠 内存 {mu}/{mt} MB（{pct(mu, mt)}%）{swap}")
    if dtotal:
        out.append(f"🗄 磁盘 {_fmt_bytes(dused)}/{_fmt_bytes(dtotal)}（{pct(dused, dtotal)}%）")
    conn_s = f"{conn}" if conn >= 0 else "n/a"
    out.append(f"🔌 连接 conntrack {conn_s} · 活跃 {est}")
    out.append(f"🌐 流量 ↓{_fmt_bytes(rx_rate)}/s ↑{_fmt_bytes(tx_rate)}/s（累计 ↓{_fmt_bytes(rx1)} ↑{_fmt_bytes(tx1)}）")
    return "\n".join(out)


def _status_items():
    """Core STATUS_ITEMS plus opt-in / current-exit units when present."""
    items = list(STATUS_ITEMS)
    if os.path.isfile("/opt/5gpn/etc/client-socks.enabled"):
        items.append(("5gpn-client-socks", "私网 SOCKS5"))
    if os.path.isfile("/opt/5gpn/etc/client-mtproto.enabled"):
        items.append(("5gpn-mtproxy", "MTProto core"))
        items.append(("5gpn-client-mtproto", "MTProto front"))
    cur = _read_file("/opt/5gpn/etc/current-exit") or "local"
    if cur and cur not in ("local",):
        items.append((f"5gpn-mihomo@{cur}", f"出口 {cur}"))
    return items


def op_status():
    """A compact, human-readable status card (no raw shell output)."""
    lines = ["<b>📊 Proxy Gateway 状态</b>", ""]
    down = []
    for unit, label in _status_items():
        st = _is_active(unit)
        ok = st == "active"
        # WLOC / wa-shim may be intentionally inactive — show as note, not ❌.
        if not ok and unit in ("5gpn-wloc", "wa-shim") and st in ("inactive", "dead"):
            lines.append("⚪ " + html.escape(label) + "（未启用）")
            continue
        lines.append(("✅ " if ok else "❌ ") + html.escape(label))
        if not ok:
            down.append(label)
    lines.append("")

    cur = _read_file("/opt/5gpn/etc/current-exit") or "local"
    if cur == "local":
        lines.append("🌐 出口：<b>local</b>（本机直出）")
    else:
        t = _read_file(f"/etc/5gpn/exits/{cur}.type") or "?"
        lines.append(f"🌐 出口：<b>{html.escape(cur)}</b>（{html.escape(t)}）")

    domain = _read_file("/etc/mosdns/.domain") or _read_file("/opt/5gpn/etc/.domain")
    if domain:
        lines.append(f"🔗 域名：<code>{html.escape(domain)}</code>")

    cs = _read_file("/etc/mosdns/.cache_size")
    if cs.isdigit():
        prof = "低内存" if int(cs) <= 50000 else "标准"
        lines.append(f"💾 内存档：{prof}")

    if down:
        lines += ["", f"⚠️ 异常：{html.escape('、'.join(down))}（用 📜 日志查看）"]

    try:
        lines += ["", system_metrics()]
    except Exception as e:  # metrics must never break the status card  # noqa: BLE001
        lines += ["", f"（服务器指标获取失败：{html.escape(str(e))}）"]
    return "\n".join(lines)


def op_rename_exit(old_name, new_name):
    if not EXIT_ADD_NAME_RE.match(old_name) or old_name in ("local", "smart"):
        return "原出口名无效。"
    if not EXIT_ADD_NAME_RE.match(new_name) or new_name in ("local", "smart"):
        return "新出口名无效（需 1-16 位字母/数字/中文/_/-，且不能为 local/smart）。"
    if old_name == new_name:
        return "新旧名称相同，无需重命名。"
    ok, out = run2(["bash", MGMT, "--rename-exit", old_name, new_name], timeout=180)
    if ok:
        return f"✅ 出口 <b>{html.escape(old_name)}</b> 已重命名为 <b>{html.escape(new_name)}</b>"
    return f"❌ <b>重命名失败</b>\n{html.escape(_reason(out))}"


def op_set_exit(name):
    if not EXIT_NAME_RE.match(name):
        return "出口名无效。"
    ok, out = run2(["bash", MGMT, "--set-exit", name], timeout=60)
    if not ok:
        return f"❌ <b>切换失败</b>\n{html.escape(_reason(out))}"
    if name == "local":
        return "✅ 已切回 <b>local</b>（本机直出）"
    t = _read_file(f"/etc/5gpn/exits/{name}.type") or "?"
    ip = _exit_ip()
    if ip:
        tail = f"\n🌍 出口 IP：<code>{html.escape(ip)}</code>"
    else:
        tail = "\n⚠️ 出口 IP 探测未成功（仅探测失败，不一定代表不通）。如访问异常，用「🩺 检查出口连通性」确认节点。"
    return f"✅ 已切换到 <b>{html.escape(name)}</b>（{html.escape(t)}）{tail}"


def exits_overview_text():
    cur = _read_file("/opt/5gpn/etc/current-exit") or "local"
    if cur == "local":
        desc = "本机直出"
    else:
        desc = _read_file(f"/etc/5gpn/exits/{cur}.type") or "?"
    ip = _exit_ip()
    if ip:
        ip_line = f"🌍 出口 IP：<code>{html.escape(ip)}</code>"
    else:
        ip_line = "🌍 出口 IP：<i>探测失败</i>"
    return (f"🌐 当前出口：<b>{html.escape(cur)}</b>（{html.escape(desc)}）\n{ip_line}\n\n"
            "选择要切换到的出口，或添加/删除：")


def op_add_exit(name, payload):
    if not EXIT_ADD_NAME_RE.match(name) or name == "local":
        return "出口名无效（需 1-16 位字母/数字/中文/_/-，且不能为 local）。"
    text = (payload or "").strip()
    is_uri = bool(PROXY_URI_RE.match(text))
    is_wg = "[Interface]" in payload and "[Peer]" in payload
    if not is_uri and not is_wg:
        return ("无法识别。请发送一段 WireGuard 配置（含 [Interface]/[Peer]），"
                "或一个 ss:// / vmess:// / trojan:// / vless:// / hysteria2:// / tuic:// / anytls:// / socks5:// / http:// URI。")
    ok, out = run2(["bash", MGMT, "--add-exit", name], inp=payload, timeout=180)
    if ok:
        m = re.search(r"type:\s*(\w+)", out)
        return (f"✅ 出口 <b>{html.escape(name)}</b> 已添加（{m.group(1) if m else '?'}）\n在「🌐 出口」里点它即可切换。")
    return f"❌ <b>添加失败</b>\n{html.escape(_reason(out))}"


def mask_uri_secret(uri):
    text = (uri or "").strip()
    if not text:
        return ""
    try:
        if text.lower().startswith("vmess://"):
            return "vmess://***"
        parsed = urlparse(text)
        if not parsed.scheme:
            return text[:24] + ("…" if len(text) > 24 else "")
        host = parsed.hostname or "?"
        port = f":{parsed.port}" if parsed.port else ""
        label = f"{parsed.scheme}://{host}{port}"
        if parsed.fragment:
            label += "#" + parsed.fragment[:12]
        return label
    except Exception:  # noqa: BLE001
        return text[:24] + ("…" if len(text) > 24 else "")


def _normalize_batch_add_line(line):
    raw = (line or "").strip()
    if not raw:
        return "", "", ""
    parts = raw.split(None, 1)
    if len(parts) == 2 and EXIT_ADD_NAME_RE.match(parts[0]) and parts[0] != "local" and PROXY_URI_RE.match(parts[1].strip()):
        return parts[0], parts[1].strip(), raw
    return "", raw, raw


def parse_add_exit_inputs(payload):
    lines = [(line or "").strip() for line in (payload or "").splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        return [], "请直接粘贴一条或多条节点链接，每行一条。"
    items = []
    for index, line in enumerate(lines, 1):
        explicit_name, config_text, raw = _normalize_batch_add_line(line)
        if "[Interface]" in config_text and "[Peer]" in config_text:
            return [], f"第 {index} 行是 WireGuard 配置。Bot 批量添加仅支持 URI；WireGuard 请改用命令行指定名称添加。"
        name, config, err = parse_add_exit_input(raw)
        if explicit_name:
            name = explicit_name
            config = config_text
            err = ""
        if err:
            return [], f"第 {index} 行：{err}"
        items.append({"index": index, "name": name, "payload": config.strip(), "masked": mask_uri_secret(config)})
    return items, ""


def op_add_exit_batch(items):
    if not items:
        return "没有可添加的出口。"

    try:
        results = []
        with _EXIT_WRITE_LOCK:
            reserved = set(parse_exit_names())
            assigned = set()
            for item in items:
                requested = item["name"]
                final = requested
                if final in reserved or final in assigned:
                    base = clean_exit_name(requested)
                    final = ""
                    if base:
                        for i in range(2, 100):
                            suffix = f"-{i}"
                            cand = (base[:16 - len(suffix)] + suffix).strip("-_")
                            if cand and cand not in reserved and cand not in assigned and EXIT_ADD_NAME_RE.match(cand):
                                final = cand
                                break
                    if not final:
                        results.append(f"❌ {item['index']}. <b>{html.escape(requested)}</b>：无法生成不冲突的名称")
                        continue
                assigned.add(final)
                item["final_name"] = final

            for item in items:
                final = item.get("final_name")
                if not final:
                    continue
                text = op_add_exit(final, item["payload"])
                item["payload"] = ""
                if text.startswith("✅"):
                    if final != item["name"]:
                        results.append(
                            f"✅ {item['index']}. <b>{html.escape(final)}</b>（由 {html.escape(item['name'])} 自动去重）")
                    else:
                        results.append(f"✅ {item['index']}. <b>{html.escape(final)}</b>")
                    reserved.add(final)
                else:
                    results.append(
                        f"❌ {item['index']}. <b>{html.escape(final)}</b>：添加失败，请检查服务日志")

        ok_count = sum(1 for line in results if line.startswith("✅"))
        fail_count = sum(1 for line in results if line.startswith("❌"))
        head = f"批量添加完成：✅ {ok_count}，❌ {fail_count}"
        return head + "\n" + "\n".join(results)
    finally:
        for item in items:
            item["payload"] = ""
            item.pop("masked", None)


def b64decode_text(s):
    pad = "=" * (-len(s) % 4)
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(s + pad).decode("utf-8")
        except Exception:  # noqa: BLE001, S112
            continue
    return ""


def clean_exit_name(name):
    name = unquote(name or "").strip()
    name = re.sub(r"[^\w\-\u4e00-\u9fff]+", "-", name, flags=re.UNICODE).strip("-_")
    name = name[:16]
    if not name or name == "local" or not EXIT_ADD_NAME_RE.match(name):
        return ""
    return name


def unique_exit_name(name):
    base = clean_exit_name(name)
    if not base:
        return ""
    existing = set(parse_exit_names())
    if base not in existing:
        return base
    for i in range(2, 100):
        suffix = f"-{i}"
        cand = (base[:16 - len(suffix)] + suffix).strip("-_")
        if cand and cand not in existing and EXIT_ADD_NAME_RE.match(cand):
            return cand
    return ""


def exit_name_from_uri(uri):
    if uri.lower().startswith("vmess://"):
        try:
            data = json.loads(b64decode_text(uri[len("vmess://"):].strip()))
        except Exception:  # noqa: BLE001
            data = {}
        return unique_exit_name(data.get("ps") or "")
    try:
        return unique_exit_name(urlparse(uri).fragment)
    except Exception:  # noqa: BLE001
        return ""


def parse_add_exit_input(payload):
    config = (payload or "").strip()
    if not config:
        return "", "", "请直接粘贴一条节点链接，或发送 <code>出口名 链接</code>。"
    first = config.splitlines()[0].strip()
    parts = first.split(None, 1)
    if len(parts) == 2 and EXIT_ADD_NAME_RE.match(parts[0]) and parts[0] != "local" and PROXY_URI_RE.match(parts[1].strip()):
        return parts[0], config.replace(first, parts[1].strip(), 1), ""
    if "[Interface]" in config and "[Peer]" in config:
        return "", "", "WireGuard 配置本身没有节点名称。请改用命令行指定出口名添加。"
    if not PROXY_URI_RE.match(first):
        return "", "", f"无法识别。请直接粘贴支持的节点链接：<code>{SUPPORTED_EXIT_LINKS}</code>，或整段 WireGuard 配置。"
    name = exit_name_from_uri(first)
    if not name:
        return "", "", "这条节点链接没有可用名称。请改用：<code>出口名 链接</code>。"
    return name, config, ""


RULE_TYPES = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "GEOSITE",
    "GEOIP",
    "IP-CIDR",
]
# Beginner-friendly Chinese button labels; callback_data keeps the raw type.
RULE_TYPE_LABELS = {
    "DOMAIN": "精确域名（DOMAIN）",
    "DOMAIN-SUFFIX": "域名及子域名（DOMAIN-SUFFIX）",
    "DOMAIN-KEYWORD": "域名关键词（DOMAIN-KEYWORD）",
    "GEOSITE": "网站分类（GEOSITE）",
    "GEOIP": "IP 归属地（GEOIP）",
    "IP-CIDR": "IP 网段（IP-CIDR）",
}


def rule_type_menu():
    rows = []
    for value in RULE_TYPES:
        rows.append([{"text": RULE_TYPE_LABELS.get(value, value),
                      "callback_data": f"raddt:{value}"}])
    rows.append([{"text": "⌨️ 手工完整规则", "callback_data": "rules:add_manual"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:rules"}])
    return rows


def _rule_target_buttons(prefix, back_target="rules:add"):
    rows, row = [], []
    for target in _targets():
        row.append({"text": target, "callback_data": f"{prefix}:{target}"})
        if len(row) == 3:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "🌍 直连", "callback_data": f"{prefix}:direct"},
                 {"text": "🚫 拒绝", "callback_data": f"{prefix}:block"}])
    rows.append([{"text": "« 返回", "callback_data": back_target}])
    return rows


def validate_rule_value(rule_type, value):
    value = (value or "").strip()
    if not value:
        return "匹配值不能为空。"
    if rule_type in ("DOMAIN", "DOMAIN-SUFFIX"):
        if not DOMAIN_RE.match(value):
            return "域名格式无效。"
    elif rule_type == "DOMAIN-KEYWORD":
        if any(ch in value for ch in "\r\n,"):
            return "DOMAIN-KEYWORD 不能包含逗号或换行。"
    elif rule_type in ("GEOSITE", "GEOIP"):
        if not re.match(r"^[A-Za-z0-9._:-]+$", value):
            return f"{rule_type} 名称无效。"
    elif rule_type == "IP-CIDR":
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return "IP-CIDR 格式无效。"
    return ""


def rule_value_prompt(rule_type):
    hints = {
        "DOMAIN": "精确匹配一个域名（不含子域名）。\n示例：<code>openai.com</code>",
        "DOMAIN-SUFFIX": "匹配该域名及其所有子域名。\n示例：<code>google.com</code>",
        "DOMAIN-KEYWORD": "域名中包含该关键词即匹配。\n示例：<code>netflix</code>",
        "GEOSITE": "按 GeoSite 网站分类匹配（如 telegram、netflix）。\n示例：<code>telegram</code>",
        "GEOIP": "按目标 IP 的归属地区匹配（国家/地区代码）。\n示例：<code>cn</code>",
        "IP-CIDR": "匹配目标 IP 网段（CIDR 格式）。\n示例：<code>1.2.3.0/24</code>",
    }
    return ("➕ <b>添加规则</b>\n\n"
            f"已选择类型：<code>{html.escape(rule_type)}</code>\n"
            f"请发送匹配值。\n\n{hints.get(rule_type, '')}")


def op_del_exit(name):
    if not EXIT_ADD_NAME_RE.match(name) or name in ("local", "smart"):
        return "出口名无效（不能删除 local/smart）。"
    ok, out = run2(["bash", MGMT, "--del-exit", name], timeout=30)
    if ok:
        return f"✅ 出口 <b>{html.escape(name)}</b> 已删除"
    return f"❌ <b>删除失败</b>\n{html.escape(_reason(out))}"


def op_update_rules():
    ok, out = run2(["bash", MGMT, "--update-rules"], timeout=600)
    if not ok:
        return f"❌ <b>规则更新失败</b>\n{html.escape(_reason(out))}"
    parts = ["✅ <b>规则已更新</b>"]
    gfw = re.search(r"GFWList:\s*(\d+)", out)
    cn = re.search(r"ChinaList:\s*(\d+)", out)
    if gfw:
        parts.append(f"• GFWList：{gfw.group(1)} 域名")
    if cn:
        parts.append("• ChinaList：%s 域名" % cn.group(1))  # noqa: UP031  # pinned by tests/test_tgbot_policy.sh
    # Also refresh mihomo smart routing rule-sets (re-download remote rule-sets)
    smart_active = _is_active("5gpn-mihomo@smart.service") == "active"
    if smart_active:
        run2(["systemctl", "restart", "5gpn-mihomo@smart.service"], timeout=60)
        parts.append("• 远程规则集已刷新（mihomo 重载）")
    return "\n".join(parts)


# --- component versions (metacubexd dashboard / mihomo engine) ---------------
_COMP_LATEST = {}    # repo -> (monotonic ts, version|None); 10-minute TTL
_COMP_LATEST_TTL = 600


def _comp_read_version(path):
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
    except OSError:
        return None
    return text.splitlines()[0].strip() if text else None


def _comp_github_latest(repo, refresh=False, timeout=8):
    now = time.monotonic()
    hit = _COMP_LATEST.get(repo)
    if not refresh and hit and now - hit[0] < _COMP_LATEST_TTL:
        return hit[1]
    ver = None
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/releases/latest",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "5gpn-tgbot"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            tag = str(json.load(resp).get("tag_name", ""))
        m = re.search(r"\d+\.\d+\.\d+", tag)
        ver = m.group(0) if m else None
    except Exception:  # noqa: BLE001
        ver = None
    _COMP_LATEST[repo] = (now, ver)
    return ver


def components_view(refresh=False):
    lines = ["🧩 <b>组件版本</b>"]
    for spec in COMPONENTS.values():
        cur = _comp_read_version(spec["version_file"]) or "未知"
        pin = _comp_read_version(spec["pin_file"])
        latest = _comp_github_latest(spec["repo"], refresh=refresh)
        latest_txt = latest or "检查失败"
        mark = " ⬆️可升级" if latest and cur != "未知" and latest != cur else ""
        pin_txt = f"（pin <code>{html.escape(pin)}</code>）" if pin else ""
        lines.append(f"• {spec['label']}：当前 <code>{html.escape(cur)}</code>{pin_txt}"
                     f" → 最新 <code>{html.escape(latest_txt)}</code>{mark}")
    lines.append("「升级」装上游最新版；「指定」装你填的版本（都会写入 pin，update 不降级）。")
    return "\n".join(lines)


def components_menu():
    return [
        [{"text": "🔄 检查更新", "callback_data": "comp:check"}],
        [{"text": "⬆️ 升级面板", "callback_data": "comp:up:metacubexd"},
         {"text": "⬆️ 升级引擎", "callback_data": "comp:up:mihomo"}],
        [{"text": "✏️ 指定面板版本", "callback_data": "comp:manual:metacubexd"},
         {"text": "✏️ 指定引擎版本", "callback_data": "comp:manual:mihomo"}],
        [{"text": "« 返回", "callback_data": "menu:ops"}],
    ]


def op_update_component(component, version=""):
    spec = COMPONENTS.get(component)
    if not spec:
        return "未知组件。"
    args = ["bash", MGMT, spec["flag"]]
    if version:
        if not COMP_VERSION_RE.match(version):
            return "版本号格式无效（应为 x.y.z）。"
        args.append(version)
    ok, out = run2(args, timeout=600)
    body = html.escape(_strip_ansi(out)[-2000:])
    if ok:
        return f"✅ <b>{spec['label']}升级完成</b>\n<pre>{body}</pre>"
    return f"❌ <b>{spec['label']}升级失败</b>\n<pre>{body}</pre>"


def edit_components_async(cb, refresh=False):
    key = _busy_key_from_cb(cb)

    def go():
        try:
            edit(cb, components_view(refresh=refresh), components_menu())
        finally:
            BUSY.discard(key)

    BUSY.add(key)
    background(go)


def op_renew_cert():
    ok, out = run2(["bash", MGMT, "--renew-cert"], timeout=600)
    if ok:
        return "✅ <b>证书已续期</b>并重载 mosdns"
    return f"❌ <b>证书续期失败</b>\n<pre>{html.escape(_tail_output(out))}</pre>"


DOT_CERT_PATH = "/etc/mosdns/certs/fullchain.pem"


def _cert_expiry(path=DOT_CERT_PATH):
    """Return (days_left, 'YYYY-MM-DD') for the DoT certificate, or (None, None)."""
    if not os.path.exists(path):
        return None, None
    ok, out = run2(["openssl", "x509", "-noout", "-enddate", "-in", path], timeout=10)
    if not ok or "notAfter=" not in out:
        return None, None
    raw = out.split("notAfter=", 1)[1].strip()
    try:
        expires = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None, None
    days = (expires - datetime.now(timezone.utc)).days
    return days, expires.strftime("%Y-%m-%d")


def _cert_status_line():
    days, date = _cert_expiry()
    if days is None:
        return "证书剩余：<code>未知（未找到证书）</code>"
    if days < 0:
        return f"证书剩余：⚠️ <b>已过期 {-days} 天</b>（到期：{date}）"
    if days <= 14:
        return f"证书剩余：⚠️ <b>{days} 天</b>（到期：{date}，建议尽快续期）"
    return f"证书剩余：<code>{days} 天</code>（到期：{date}）"


def op_dot_status():
    domain = _read_file("/etc/mosdns/.domain") or _read_file("/opt/5gpn/etc/.domain") or "未设置"
    remote_dns = (_read_file("/etc/mosdns/.remote_dns") or
                  _read_file("/etc/mosdns/.overseas_dns") or "?")
    local_dns = (_read_file("/etc/mosdns/.local_dns") or "?")
    direct_n = len(_direct_domain_entries())
    cidr = (_read_file("/etc/mosdns/.client_cidr")
            or _read_file("/opt/5gpn/etc/.client_cidr")
            or "172.22.0.0/16").strip()
    lines = [
        "🔐 <b>DoT 管理</b>",
        "当前域名：<code>%s</code>" % html.escape(domain),  # noqa: UP031  # pinned by tests/test_tgbot_policy.sh
    ]
    lines.extend([
        "国际 DNS：<code>%s</code>" % html.escape(remote_dns),  # noqa: UP031  # pinned by tests/test_tgbot_policy.sh
        "国内 DNS：<code>%s</code>" % html.escape(local_dns),  # noqa: UP031  # pinned by tests/test_tgbot_policy.sh
        f"客户端网段：<code>{html.escape(cidr)}</code>",
        f"DNS 直连名单：<code>{direct_n}</code> 个域名",
        _cert_status_line(),
    ])
    return "\n".join(lines)


def op_set_dot_domain(domain):
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        return ("域名格式无效。请发送类似 <code>dns.example.com</code> 的完整域名。", None)
    ok, out = run2(["bash", MGMT, "--set-dot-domain", domain], timeout=900)
    if ok:
        return (("✅ <b>DoT 域名已更新</b>\n"
                 f"当前域名：<code>{html.escape(domain)}</code>\n"
                 "证书已签发并重载 mosdns。iOS 用户请重新生成二维码。"), None)
    text = (f"❌ <b>DoT 域名更新失败</b>\n{html.escape(_reason(out))}\n\n"
            "如果你确认域名已经解析到本机，也可以强制更换域名。\n"
            "注意：强制更换会跳过本次证书签发，DoT 客户端可能因为证书不匹配暂时无法连接；修好 80 端口/certbot 问题后请再点续期证书。")
    return (text, domain)


def op_force_set_dot_domain(domain):
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        return "域名格式无效。"
    ok, out = run2(["bash", MGMT, "--set-dot-domain-force", domain], timeout=600)
    if ok:
        return ("⚠️ <b>DoT 域名已强制更换</b>\n"
                f"当前域名：<code>{html.escape(domain)}</code>\n"
                "本次没有签发新证书。请排查端口 80 / certbot 后，再点 <b>续期证书</b>。")
    return f"❌ <b>强制更换域名失败</b>\n{html.escape(_reason(out))}"


def force_dot_domain_kb():
    return [
        [{"text": "⚠️ 仍要强制更换域名", "callback_data": "dot:force_domain"}],
        [{"text": "« 返回", "callback_data": "menu:dot"}],
    ]


def _dns_arg(text):
    value = (text or "").strip()
    if not value:
        return ""
    items = value.replace(",", " ").split()
    for item in items:
        if "://" not in item:
            if not DNS_LIST_RE.fullmatch(item):
                return ""
            continue
        try:
            parsed = urlparse(item)
            ipaddress.ip_address(parsed.hostname or "")
            port = parsed.port
        except (ValueError, TypeError):
            return ""
        if (parsed.scheme not in DNS_UPSTREAM_SCHEMES or parsed.username or
                parsed.password or parsed.query or parsed.fragment or
                (port is not None and not 1 <= port <= 65535)):
            return ""
        if parsed.scheme == "https":
            if parsed.path != "/dns-query":
                return ""
        elif parsed.path not in ("", "/"):
            return ""
    return " ".join(items)


def current_remote_dns():
    return (_read_file("/etc/mosdns/.remote_dns") or
            _read_file("/etc/mosdns/.overseas_dns") or "?")


def current_local_dns():
    return _read_file("/etc/mosdns/.local_dns") or "?"


def op_set_dns(kind, text):
    dns = _dns_arg(text)
    if not dns:
        return ("DNS 格式无效。支持 IP[:端口]，或 https://IP/dns-query、"
                "tls://IP:853、udp://IP:53、tcp://IP:53；多个地址用空格或逗号分隔。")
    if kind == "remote":
        remote_dns = dns
        local_dns = current_local_dns()
    elif kind == "local":
        remote_dns = current_remote_dns()
        local_dns = dns
    else:
        return "DNS 类型无效。"
    if remote_dns == "?" or local_dns == "?":
        return "当前 DNS 配置不完整，请先在服务器上执行一次 --set-dns。"
    cmd = ["bash", MGMT, "--set-dns", remote_dns, local_dns]
    ok, out = run2(cmd, timeout=600)
    if ok:
        label = "国际 DNS" if kind == "remote" else "国内 DNS"
        return f"✅ <b>{label} 已更新</b>\n<code>{html.escape(dns)}</code>"
    return f"❌ <b>DNS 上游更新失败</b>\n{html.escape(_reason(out))}"


GFWLIST_PATH = "/etc/mosdns/gfwlist.txt"
DIRECT_DOMAINS_PATH = "/etc/mosdns/direct-domains.txt"


def _direct_domain_entries():
    txt = _read_file(DIRECT_DOMAINS_PATH)
    out, seen = [], set()
    for line in (txt.splitlines() if txt else []):
        d = line.strip().lower().rstrip(".")
        if not d or d.startswith("#"):
            continue
        if not DOMAIN_RE.match(d) or d in seen:
            continue
        seen.add(d)
        out.append(d)
    return out


def op_show_direct_domains():
    entries = _direct_domain_entries()
    if not entries:
        return ("🔓 <b>DNS 直连名单</b>（空）\n\n"
                "私网客户端会把非 ChinaList 域名解析成网关 IP。"
                "把 SSH 主机名加进来后返回真实 A 记录。")
    body = "\n".join(f"{i + 1}. <code>{html.escape(d)}</code>"
                     for i, d in enumerate(entries))
    return f"🔓 <b>DNS 直连名单</b>（{len(entries)}）：\n{body}"


def op_add_direct_domain(domain):
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        return "域名格式无效。请发送类似 <code>box2.example.com</code> 的完整域名。"
    ok, out = run2(["bash", MGMT, "--add-direct-domain", domain], timeout=120)
    if ok:
        return (f"✅ <b>已加入 DNS 直连名单</b>\n<code>{html.escape(domain)}</code>\n"
                "私网客户端将对该域名（及其子域）返回真实解析。")
    return f"❌ <b>添加失败</b>\n{html.escape(_reason(out))}"


def op_del_direct_domain(domain):
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        return "域名格式无效。"
    ok, out = run2(["bash", MGMT, "--del-direct-domain", domain], timeout=120)
    if ok:
        return f"✅ <b>已从 DNS 直连名单移除</b>\n<code>{html.escape(domain)}</code>"
    return f"❌ <b>删除失败</b>\n{html.escape(_reason(out))}"


def op_set_direct_domains(text):
    lines = []
    for raw in (text or "").splitlines():
        d = raw.strip().lower().rstrip(".")
        if not d or d.startswith("#"):
            continue
        if not DOMAIN_RE.match(d):
            return f"域名格式无效：<code>{html.escape(d)}</code>"
        lines.append(d)
    # Deduplicate while preserving order.
    seen, uniq = set(), []
    for d in lines:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    payload = "\n".join(uniq) + ("\n" if uniq else "")
    ok, out = run2(["bash", MGMT, "--set-direct-domains"], inp=payload, timeout=120)
    if ok:
        return f"✅ <b>DNS 直连名单已替换</b>（{len(uniq)} 个域名）"
    return f"❌ <b>保存失败</b>\n{html.escape(_reason(out))}"


def validate_ecs(value):
    value = (value or "").strip()
    if not value:
        return ""
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            if net.version != 4 or net.prefixlen > 30:
                return ""
        else:
            ip = ipaddress.ip_address(value)
            if ip.version != 4:
                return ""
    except ValueError:
        return ""
    return value


def op_set_ecs(value):
    ecs = validate_ecs(value)
    if not ecs:
        return "ECS 格式无效。请发送 IPv4 地址或 IPv4/前缀，例如 <code>139.226.48.0/24</code>。"
    ok, out = run2(["bash", MGMT, "--set-ecs", ecs], timeout=180)
    if ok:
        return f"✅ <b>ECS 已更新</b>\n<code>{html.escape(ecs)}</code>\n{html.escape(_strip_ansi(out)[-800:])}"
    return f"❌ <b>ECS 设置失败</b>\n{html.escape(_reason(out))}"


def _domain_suffix_set(path):
    values = set()
    for line in _read_file(path).splitlines():
        d = line.strip().lower().strip(".")
        if d and not d.startswith("#"):
            values.add(d)
    return values


def _domain_hijacked(domain, suffixes):
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in suffixes:
            return True
    return domain in suffixes


def route_test(domain):
    d = (domain or "").lower().strip().strip(".").lstrip("*.")
    if not DOMAIN_RE.match(d):
        return {"error": "请输入合法域名"}
    gset = _domain_suffix_set(GFWLIST_PATH)
    dset = _domain_suffix_set(DIRECT_DOMAINS_PATH)
    in_direct = _domain_hijacked(d, dset)
    in_gfw = _domain_hijacked(d, gset)
    final = None
    matched = None
    for raw in _read_file(RULES_PATH).splitlines():
        s = raw.strip()
        if not s or s[0] in "#;":
            continue
        parts = [x.strip() for x in s.split(",")]
        typ = parts[0].upper()
        if typ == "FINAL" and len(parts) >= 2:
            final = parts[-1]
            continue
        if matched:
            continue
        if typ == "DOMAIN-SUFFIX" and len(parts) >= 3:
            value = parts[1].lower().lstrip(".")
            if d == value or d.endswith("." + value):
                matched = (s, parts[-1])
        elif typ == "DOMAIN" and len(parts) >= 3 and d == parts[1].lower() or typ == "DOMAIN-KEYWORD" and len(parts) >= 3 and parts[1].lower() in d:
            matched = (s, parts[-1])
    category = matched[1] if matched else (final or "Proxy")
    policy = dict(_policy_map())
    target = category if category in ("direct", "block") else policy.get(category, category)
    return {
        "domain": d,
        "hijacked": not in_direct,
        "direct_bypass": in_direct,
        "in_gfwlist": in_gfw,
        "matched": matched[0] if matched else ("FINAL," + (final or "?")),
        "category": category,
        "target": target,
    }


def op_route_test(domain):
    result = route_test(domain)
    if result.get("error"):
        return result["error"]
    return (
        f"🧪 <b>路由测试</b>：<code>{html.escape(result['domain'])}</code>\n"
        f"DNS 劫持：<b>{'是' if result['hijacked'] else '否'}</b>（直连名单：{'是' if result['direct_bypass'] else '否'} / GFWList：{'是' if result['in_gfwlist'] else '否'}）\n"
        f"命中规则：<code>{html.escape(result['matched'])}</code>\n"
        f"分类：<code>{html.escape(result['category'])}</code> → mihomo 出口：<b>{html.escape(result['target'])}</b>\n\n"
        "说明：规则里的分组名先查 <code>policy-map.conf</code>，再映射到 mihomo 出口；"
        "RULE-SET / GEOSITE / GEOIP / ChinaList 不在此轻量测试中展开。"
    )


def op_proxy_domain(domain, target):
    domain = (domain or "").strip().lower().rstrip(".").lstrip("*.")
    valid_targets = set(_targets()) | {"direct", "block"}
    if not DOMAIN_RE.match(domain):
        return "域名格式无效。请发送类似 <code>openai.com</code> 的完整域名。"
    if target not in valid_targets:
        return "目标已变化，请重新选择。"
    ok, out = run2(["bash", MGMT, "--proxy-domain", domain, target], timeout=600)
    if ok:
        return ("✅ <b>代理域名规则已应用</b>\n"
                f"<code>{html.escape(domain)}</code> → <b>{html.escape(target)}</b>\n<pre>{html.escape(_strip_ansi(out)[-1200:])}</pre>")
    return f"❌ <b>代理域名失败</b>\n{html.escape(_reason(out))}"


def direct_domains_menu():
    return [
        [{"text": "📋 查看名单", "callback_data": "dd:show"}],
        [{"text": "➕ 添加域名", "callback_data": "dd:add"},
         {"text": "🗑 删除域名", "callback_data": "dd:del"}],
        [{"text": "✏️ 整份替换", "callback_data": "dd:set"}],
        [{"text": "« 返回", "callback_data": "menu:dot"}],
    ]


def direct_domains_del_menu():
    rows = []
    for index, d in enumerate(_direct_domain_entries()):
        rows.append([{"text": "🗑 " + d,
                      "callback_data": f"ddel:{index}:{_entry_token(d)}"}])
    if not rows:
        rows.append([{"text": "(名单为空)", "callback_data": "menu:direct"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:direct"}])
    return rows


def op_del_direct_domain_button(index, token):
    entries = _direct_domain_entries()
    if index < 0 or index >= len(entries) or _entry_token(entries[index]) != token:
        return "名单已变化，请返回后重新打开删除列表。"
    return op_del_direct_domain(entries[index])


def op_restart_services():
    results = []
    failed = False
    for svc in RESTART_SERVICES:
        run2(["systemctl", "restart", svc], timeout=60)
        state = _is_active(svc)
        ok = state in ("active", "listening")
        failed = failed or not ok
        label = svc.removesuffix(".socket")
        results.append(("✅" if ok else "❌") + " " + html.escape(label) + f"（{html.escape(state)}）")
    head = "❌ <b>部分服务重启异常</b>" if failed else "✅ <b>服务已重启</b>"
    return head + "\n" + "\n".join(results)


def op_report():
    """Generate a redacted report; returns (ok, path_or_error)."""
    ok, out = run2(["bash", MGMT, "--report"], timeout=240)
    path = ""
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("/tmp/") and line.endswith(".txt"):
            path = line
        elif "report written:" in line:
            path = line.split()[-1]
    if not (ok and path and os.path.isfile(path)):
        return False, html.escape(_reason(out) or "report missing")
    return True, path


def deliver_report(cb, chat_id):
    """Send the redacted report as a Telegram document (no inline dump)."""
    ok, path_or_err = op_report()
    if not ok:
        edit(cb, f"❌ <b>报告生成失败</b>\n{path_or_err}", back_kb("menu:ops"))
        return
    path = path_or_err
    if send_document(chat_id, path,
                     caption="5GPN 脱敏诊断报告",
                     filename=os.path.basename(path)):
        edit(cb,
             ("✅ <b>诊断报告已发送</b>（已脱敏）\n"
              "请查看上方文件附件。"),
             back_kb("menu:ops"))
        return
    edit(cb,
         ("❌ <b>报告文件发送失败</b>\n"
          f"服务器本地文件：<code>{html.escape(path)}</code>"),
         back_kb("menu:ops"))


def edit_report_async(cb, chat_id):
    key = _busy_key_from_cb(cb)

    def go():
        try:
            deliver_report(cb, chat_id)
        finally:
            BUSY.discard(key)

    BUSY.add(key)
    background(go)


def _client_cidr():
    return (_read_file("/etc/mosdns/.client_cidr")
            or _read_file("/opt/5gpn/etc/.client_cidr")
            or "172.22.0.0/16").strip()


def op_show_client_cidr():
    cidr = _client_cidr()
    return ("🛡 <b>客户端网段</b>\n"
            f"当前：<code>{html.escape(cidr)}</code>\n"
            "私网客户端来自此段时走劫持/透明代理策略；"
            "改后会刷新 mosdns（managed 防火墙也会尝试同步）。")


def client_cidr_menu():
    return [
        [{"text": "✏️ 设置网段", "callback_data": "cidr:set"},
         {"text": "🔎 自动探测", "callback_data": "cidr:detect"}],
        [{"text": "« 返回", "callback_data": "menu:dot"}],
    ]


def op_set_client_cidr(text):
    cidr = (text or "").strip()
    if not cidr:
        return "请发送 IPv4 CIDR，例如 <code>172.22.0.0/16</code>"
    ok, out = run2(["bash", MGMT, "--set-client-cidr", cidr], timeout=180)
    if ok:
        return (f"✅ <b>客户端网段已更新</b>\n<code>{html.escape(_client_cidr())}</code>\n{html.escape(_strip_ansi(out)[-800:])}")
    return f"❌ <b>设置失败</b>\n{html.escape(_reason(out))}"


def op_detect_client_cidr():
    ok, out = run2(["bash", MGMT, "--detect-client-cidr"], timeout=180)
    if ok:
        return (f"✅ <b>已探测并应用客户端网段</b>\n当前：<code>{html.escape(_client_cidr())}</code>\n{html.escape(_strip_ansi(out)[-800:])}")
    return f"❌ <b>探测失败</b>\n{html.escape(_reason(out))}"


def op_snapshot():
    ok, out = run2(["bash", MGMT, "--snapshot", "manual-bot"], timeout=120)
    if ok:
        return f"✅ <b>快照已保存</b>\n<pre>{html.escape(_strip_ansi(out)[-1500:])}</pre>"
    return f"❌ <b>快照失败</b>\n{html.escape(_reason(out))}"


def _snapshot_script():
    return SNAPSHOT if os.path.isfile(SNAPSHOT) else "/opt/5gpn/scripts/snapshot.sh"


def _snapshot_list_raw():
    return run2(["bash", _snapshot_script(), "list"], timeout=60)


def _snapshot_ids_from_list(out):
    ids = []
    for line in _strip_ansi(out).splitlines():
        parts = line.strip().split()
        if not parts or parts[0] == "ID":
            continue
        snap_id = parts[0]
        if SNAP_ID_RE.match(snap_id):
            ids.append(snap_id)
    return ids


def op_snapshot_list():
    ok, out = _snapshot_list_raw()
    body = html.escape(_strip_ansi(out)[-2500:] or "（没有快照）")
    if ok:
        return f"📜 <b>快照列表</b>\n<pre>{body}</pre>"
    return f"❌ <b>读取快照失败</b>\n<pre>{body}</pre>"


def op_delete_snapshot(snap_id):
    if not SNAP_ID_RE.match(snap_id) and snap_id != "latest":
        return "快照 ID 无效。"
    ok, out = run2(["bash", _snapshot_script(), "delete", snap_id], timeout=120)
    if ok:
        return (f"✅ <b>已删除快照</b> <code>{html.escape(snap_id)}</code>\n<pre>{html.escape(_strip_ansi(out)[-1200:])}</pre>")
    return f"❌ <b>删除失败</b>\n{html.escape(_reason(out))}"


def snapshot_list_view():
    ok, out = _snapshot_list_raw()
    body = html.escape(_strip_ansi(out)[-2500:] or "（没有快照）")
    head = "📜 <b>快照列表</b>" if ok else "❌ <b>读取快照失败</b>"
    rows = []
    if ok:
        for snap_id in _snapshot_ids_from_list(out)[:5]:
            rows.append([
                {"text": "⏪ " + snap_id[:18], "callback_data": "rollback:" + snap_id},
                {"text": "🗑", "callback_data": "snapdel:" + snap_id},
            ])
    rows.append([{"text": "⏪ 回滚最新", "callback_data": "act:rollback"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:ops"}])
    return f"{head}\n<pre>{body}</pre>\n点 ⏪ 回滚，点 🗑 删除。", rows


def edit_snapshot_list_async(cb):
    key = _busy_key_from_cb(cb)

    def go():
        try:
            text, keyboard = snapshot_list_view()
            edit(cb, text, keyboard)
        finally:
            BUSY.discard(key)

    BUSY.add(key)
    background(go)


def op_rollback(snap_id="latest"):
    snap_id = (snap_id or "latest").strip()
    if snap_id != "latest" and not SNAP_ID_RE.match(snap_id):
        return "快照 ID 无效。"
    argv = ["bash", MGMT, "--rollback"]
    if snap_id != "latest":
        argv.append(snap_id)
    ok, out = run2(argv, timeout=300)
    if ok:
        label = "最近快照" if snap_id == "latest" else f"快照 {snap_id}"
        return (f"✅ <b>已回滚到{html.escape(label)}</b>\n<pre>{html.escape(_strip_ansi(out)[-1500:])}</pre>")
    return f"❌ <b>回滚失败</b>\n{html.escape(_reason(out))}"


def op_logs(svc):
    # Logs are the one place where the raw content IS the requested result.
    if svc not in SERVICES:
        return "未知服务。"
    return _strip_ansi(run(
        ["journalctl", "-u", svc, "-n", "30", "--no-pager", "-o", "short-iso"],
        timeout=30,
    ))


# --------------------------------------------------------------------------- #
# Smart-routing rules (the 'smart' exit)
# --------------------------------------------------------------------------- #
RULES_PATH = "/etc/5gpn/rules.conf"


def _rule_entries():
    """(all file lines, [(line_index, text)] for effective rules)."""
    txt = _read_file(RULES_PATH)
    lines = txt.splitlines() if txt else []
    entries = [(i, line) for i, line in enumerate(lines)
               if line.strip() and not line.strip().startswith(("#", ";"))]
    return lines, entries


def op_show_rules():
    _, entries = _rule_entries()
    if not entries:
        return "（还没有分流规则）\n用「✏️ 规则设置」粘贴一份，或「➕ 添加规则」逐条添加。"
    body = "\n".join(f"{i + 1}. {e[1].strip()}" for i, e in enumerate(entries))
    return f"📋 <b>当前分流规则</b>（{len(entries)} 条）：\n<pre>{html.escape(body)}</pre>"


def _ruleset_entries():
    """Return (all file lines, [(line_index, text)] for RULE-SET lines only)."""
    txt = _read_file(RULES_PATH)
    lines = txt.splitlines() if txt else []
    entries = [(i, line) for i, line in enumerate(lines)
               if line.strip().upper().startswith("RULE-SET,")]
    return lines, entries


def _plain_rule_entries():
    """Return effective rules excluding RULE-SET entries managed separately."""
    lines, entries = _rule_entries()
    return lines, [(i, line) for i, line in entries
                   if not line.strip().upper().startswith("RULE-SET,")]


def op_show_rulesets():
    _, entries = _ruleset_entries()
    if not entries:
        return "（还没有规则集）\n用「➕ 添加规则集」添加远程或本地规则集。"
    body = []
    for i, (_, line) in enumerate(entries):
        parts = line.strip().split(",", 2)
        if len(parts) >= 3:
            url = parts[1].strip()
            target = parts[2].strip()
            # shorten long URLs for display
            short_url = url if len(url) <= 50 else url[:47] + "…"
            body.append(f"{i + 1}. {html.escape(short_url)} → <b>{html.escape(target)}</b>")
        else:
            body.append(f"{i + 1}. {html.escape(line.strip())}")
    joined = "\n".join(body)
    return f"📚 <b>当前规则集</b>（{len(entries)} 个）：\n{joined}"


def _entry_token(text):
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:10]


def _delete_entry(entries_fn, index, token, empty_text):
    lines, entries = entries_fn()
    if not entries:
        return empty_text
    if index < 0 or index >= len(entries) or _entry_token(entries[index][1]) != token:
        return "规则列表已经变化，请返回后重新打开删除列表。"
    drop = entries[index][0]
    return op_set_rules("\n".join(line for i, line in enumerate(lines) if i != drop) + "\n")


def op_del_ruleset_button(index, token):
    return _delete_entry(_ruleset_entries, index, token, "当前没有规则集可删除。")


def op_set_rules(text):
    text = (text or "").strip()
    # Goes through --set-rules; mihomo validates before commit.
    ok, out = run2(["bash", MGMT, "--set-rules"], inp=text + "\n" if text else "\n", timeout=180)
    if ok:
        m = re.search(r"\((\d+) rules\)", out)
        count = m.group(1) if m else "0"
        return (f"✅ <b>分流规则已更新</b>（{count} 条）\n用「⚡ 启用分流」或在 🌐 出口 选 smart 生效。")
    return f"❌ <b>规则设置失败</b>\n{html.escape(_reason(out))}"


def op_add_rule(line):
    line = (line or "").strip()
    if not line:
        return "规则不能为空。"
    txt = _read_file(RULES_PATH)
    newtext = (txt.rstrip("\n") + "\n" + line + "\n") if txt.strip() else (line + "\n")
    return op_set_rules(newtext)


def op_add_ruleset(text):
    parts = (text or "").strip().split(None, 1)
    if len(parts) != 2:
        return "请发送规则集 URL。"
    source, target = parts
    if not re.match(r"^https?://\S+$", source):
        return "规则集必须是 http(s) URL。"
    if not target.strip() or any(ch in target for ch in "\r\n,"):
        return "规则集目标无效。"
    ok, out = run2(["bash", MGMT, "--add-ruleset", source, target.strip()], timeout=600)
    if ok:
        return f"✅ <b>规则集已添加</b>\n<code>{html.escape(source)}</code> → <b>{html.escape(target.strip())}</b>"
    return f"❌ <b>规则集添加失败</b>\n{html.escape(_reason(out))}"


def validate_ruleset_url(url):
    """Return error string if invalid, else empty string."""
    url = (url or "").strip()
    if not url:
        return "URL 不能为空。"
    if not re.match(r"^https?://\S+$", url):
        return "规则集必须是 http(s) URL。"
    return ""


def op_del_rule_button(index, token):
    return _delete_entry(_plain_rule_entries, index, token, "当前没有规则可删除。")


# --------------------------------------------------------------------------- #
# Category -> exit policy map
# --------------------------------------------------------------------------- #
POLICY_PATH = "/etc/5gpn/policy-map.conf"


def _policy_map():
    out = []
    for line in _read_file(POLICY_PATH).splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out.append((k.strip(), v.strip()))
    return out


def op_set_policy(cat, target):
    # Rebuilds the router (may fetch/compile rule-sets) — give it room.
    ok, out = run2(["bash", MGMT, "--set-policy", cat, target], timeout=600)
    if ok:
        return f"✅ <b>{html.escape(cat)}</b> → <b>{html.escape(target)}</b>，分流已重建。"
    return f"❌ <b>映射失败</b>\n{html.escape(_reason(out))}"


def _targets():
    return [n for n in parse_exit_names() if n != "local"]


def _format_check_exit_row(name, endpoint, state):
    mapping = {"UP": "✅", "DOWN": "❌", "N/A": "➖", "N/A?": "➖", "n/a": "➖", "UDP": "🔌"}
    mark = mapping.get(state.upper() if state else "", "➖")
    detail = f"<code>{html.escape(endpoint)}</code>" if endpoint and endpoint != "-" else "<i>n/a</i>"
    return f"{mark} <b>{html.escape(name)}</b>  {detail}"


def parse_check_exits_output(out):
    rows = []
    for raw in _strip_ansi(out).splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = re.split(r"\s{2,}", line)
        if len(parts) >= 3:
            name = parts[0].strip()
            endpoint = parts[1].strip() or "-"
            state = parts[2].strip()
        else:
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            state = parts[-1]
            endpoint = " ".join(parts[1:-1]).strip() or "-"
        rows.append((name, endpoint if endpoint != "?" else "-", state))
    return rows


def op_check_exits():
    ok, out = run2(["bash", MGMT, "--check-exits"], timeout=60)
    out = out.strip()
    if not out:
        return "（没有可检查的出口）"
    items = parse_check_exits_output(out)
    if not items:
        if ok:
            return "（没有可检查的出口）"
        return f"❌ <b>出口检查失败</b>\n{html.escape(_reason(out))}"
    bad = any(state.upper() == "DOWN" for _, _, state in items)
    lines = ["🩺 <b>出口节点连通性</b>%s" % ("　⚠️ 有节点不可达！" if bad else "")]
    lines.extend(_format_check_exit_row(name, endpoint, state) for name, endpoint, state in items)
    return "\n".join(lines)


def parse_exit_names():
    names = ["local"]
    seen = set()
    try:
        for f in sorted(os.listdir("/etc/5gpn/exits")):
            if f.endswith(".type"):
                seen.add(f[: -len(".type")])
    except OSError:
        pass
    try:
        for f in sorted(os.listdir("/etc/wireguard")):
            if f.startswith("pgw-") and f.endswith(".conf"):
                if os.path.islink(os.path.join("/etc/wireguard", f)):
                    continue  # runtime iface aliases for Unicode names
                seen.add(f[len("pgw-") : -len(".conf")])
    except OSError:
        pass
    names.extend(sorted(seen))
    return names


def op_ios_send(chat_id):
    """Send the iOS profile QR as an image (with the URL as caption)."""
    domain = _read_file("/etc/mosdns/.domain") or _read_file("/opt/5gpn/etc/.domain")
    if domain:
        url = "http://%s:8111/ios-dot.mobileconfig" % domain  # noqa: UP031  # pinned by tests/test_tgbot_policy.sh
    else:
        url = _read_file(os.path.join(WWW_DIR, "ios-profile-url.txt"))
    if not url:
        return "未找到 iOS 描述文件地址,先在服务器上 `--ios` 生成。"
    cap = (f"📱 <b>iOS DoT 描述文件</b>\n扫码安装(仅蜂窝网启用):\n<code>{html.escape(url)}</code>")
    fd, png = tempfile.mkstemp(prefix="pgw-ios-qr-", suffix=".png")
    os.close(fd)
    try:
        ok, _ = run2(["qrencode", "-o", png, "-s", "8", "-m", "2", url], timeout=15)
        if ok and send_photo(chat_id, png, cap):
            return None  # delivered as a photo
    finally:
        try:
            os.unlink(png)
        except OSError:
            pass
    # fallback: just the URL (text)
    return cap


def op_ios_send_inline(cb):
    """Edit the callback message in-place to show the iOS QR code.
    Returns an error string on failure, or None on success."""
    domain = _read_file("/etc/mosdns/.domain") or _read_file("/opt/5gpn/etc/.domain")
    if domain:
        url = "http://%s:8111/ios-dot.mobileconfig" % domain  # noqa: UP031  # pinned by tests/test_tgbot_policy.sh
    else:
        url = _read_file(os.path.join(WWW_DIR, "ios-profile-url.txt"))
    if not url:
        return "未找到 iOS 描述文件地址,先在服务器上 `--ios` 生成。"
    cap = (f"📱 <b>iOS DoT 描述文件</b>\n扫码安装(仅蜂窝网启用):\n<code>{html.escape(url)}</code>")
    fd, png = tempfile.mkstemp(prefix="pgw-ios-qr-", suffix=".png")
    os.close(fd)
    try:
        ok, _ = run2(["qrencode", "-o", png, "-s", "8", "-m", "2", url], timeout=15)
        if ok and edit_message_media(cb, png, cap, back_kb("menu:main")):
            return None  # success: edited in-place
    finally:
        try:
            os.unlink(png)
        except OSError:
            pass
    # fallback: just the URL as text
    return cap


# --------------------------------------------------------------------------- #
# WLOC (scoped Apple network-location rewriting)
# --------------------------------------------------------------------------- #
_WLOC_COORDS_RE = re.compile(
    r"^\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*(?:,|，|\s+)\s*"
    r"([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*$"
)


def _wloc_atomic_write(path, content, mode=0o640):
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o750, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".wloc-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if path.startswith(WLOC_DIR + os.sep):
            try:
                os.chown(temp, 0, grp.getgrnam("wloc").gr_gid)
            except (PermissionError, KeyError):
                # chown is best-effort hardening; atomicity comes from the
                # rename. Non-root environments (dev machines, tests) may
                # lack the permission or the wloc group entirely.
                pass
        os.chmod(temp, mode)
        os.replace(temp, path)
    except Exception:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def _wloc_load():
    try:
        data = json.loads(_read_file(WLOC_LOCATION))
        entry = data["presets"][data["active"]]
        return bool(_read_file(WLOC_MODIFIER) == "active"), entry
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False, None


def _wloc_validate(lat, lon, accuracy=25):
    try:
        lat, lon, accuracy = float(lat), float(lon), int(accuracy)
    except (TypeError, ValueError) as exc:
        raise ValueError("经纬度和精度必须是数字") from exc
    if not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise ValueError("纬度需在 -90~90，经度需在 -180~180")
    if not 1 <= accuracy <= 100000:
        raise ValueError("精度需在 1~100000 米")
    return lat, lon, accuracy


def _wloc_parse(text):
    match = _WLOC_COORDS_RE.fullmatch(text or "")
    if not match:
        raise ValueError("格式应为：纬度,经度，例如 <code>35.681236,139.767125</code>")
    return _wloc_validate(match.group(1), match.group(2))


def _wloc_page():
    enabled, entry = _wloc_load()
    service = _is_active(WLOC_SERVICE) == "active"
    if entry:
        target = (f"<code>{entry.get('lat', 0):.6f}, {entry.get('lon', 0):.6f}</code>"
                  f" (±{entry.get('accuracy_m', 25)}m)")
    else:
        target = "未设置"
    text = (
        "📍 <b>WLOC 虚拟定位</b>\n\n"
        "仅劫持 <code>gs-loc.apple.com</code> 与 <code>gs-loc-cn.apple.com</code> 的定位响应，"
        "不会扩大到其他 Apple 或普通流量。\n\n"
        f"状态：<b>{'已开启' if enabled else '已关闭'}</b>\n"
        f"拦截器：{'🟢 运行中' if service else '⚪ 未运行'}\n"
        f"目标：{target}\n\n"
        "首次使用请安装 WLOC CA，并在 iOS 的「证书信任设置」中开启完全信任。"
        "切换后 locationd 可能有缓存，必要时重启设备。"
    )
    rows = [[{"text": "📜 下载 WLOC CA", "callback_data": "wloc:ca"}]]
    preset_row = []
    for key, (label, _lat, _lon) in WLOC_PRESETS.items():
        preset_row.append({"text": "📌 " + label, "callback_data": "wloc:set:" + key})
        if len(preset_row) == 2:
            rows.append(preset_row)
            preset_row = []
    if preset_row:
        rows.append(preset_row)
    rows.append([{"text": "✍️ 输入经纬度", "callback_data": "wloc:input"}])
    if enabled:
        rows.append([{"text": "♻️ 关闭 WLOC", "callback_data": "wloc:off"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:main"}])
    return text, rows


def _wloc_apply(lat, lon, label=None, accuracy=25):
    try:
        lat, lon, accuracy = _wloc_validate(lat, lon, accuracy)
    except ValueError as exc:
        return "❌ " + html.escape(str(exc))
    if not os.path.isfile("/etc/systemd/system/5gpn-wloc.service"):
        return "❌ WLOC 运行时未安装。请先在服务器执行一次最新版 <code>install.sh</code>。"
    value = {
        "active": "current", "default_accuracy_m": accuracy,
        "presets": {"current": {"lat": lat, "lon": lon, "accuracy_m": accuracy,
                                  "datum": "wgs84", "label": label or "自定义地点"}},
    }
    try:
        _wloc_atomic_write(WLOC_LOCATION, json.dumps(value, ensure_ascii=False) + "\n")
        _wloc_atomic_write(WLOC_MODIFIER, "active\n")
        ok, out = run2(["systemctl", "enable", "--now", WLOC_SERVICE], timeout=30)
        if not ok:
            _wloc_atomic_write(WLOC_MODIFIER, "paused\n")
            return f"❌ WLOC 拦截器启动失败：{html.escape(_reason(out))}"
        _wloc_atomic_write(WLOC_DOMAINS, "".join(f"full:{host}\n" for host in WLOC_HOSTS), 0o644)
        ok, out = run2(["systemctl", "restart", "mosdns"], timeout=30)
        if not ok:
            _wloc_atomic_write(WLOC_DOMAINS, "", 0o644)
            _wloc_atomic_write(WLOC_MODIFIER, "paused\n")
            return f"❌ DNS 劫持未生效，已回滚：{html.escape(_reason(out))}"
    except OSError as exc:
        return f"❌ WLOC 状态写入失败：{html.escape(str(exc))}"
    name = (label + " ") if label else ""
    return f"✅ <b>WLOC 已开启</b>\n{html.escape(name)}<code>{lat:.6f}, {lon:.6f}</code> (±{accuracy}m)"


def _wloc_disable():
    try:
        _wloc_atomic_write(WLOC_MODIFIER, "paused\n")
        _wloc_atomic_write(WLOC_DOMAINS, "", 0o644)
        ok, out = run2(["systemctl", "restart", "mosdns"], timeout=30)
        if not ok:
            return f"❌ DNS 恢复失败：{html.escape(_reason(out))}"
        run2(["systemctl", "disable", "--now", WLOC_SERVICE], timeout=30)
    except OSError as exc:
        return f"❌ WLOC 状态写入失败：{html.escape(str(exc))}"
    return "✅ <b>WLOC 已关闭</b>\nApple 网络定位已恢复原始直连。"


def _send_wloc_ca(chat_id):
    try:
        with open(WLOC_CA, "rb") as fh:
            cert = fh.read()
    except OSError:
        return "未找到 WLOC CA。请先运行最新版 <code>install.sh</code>。"
    boundary = "----pgwWlocCA"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat_id}\r\n").encode()
    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n"
             "WLOC CA：安装后请在 iOS「设置 -> 通用 -> 关于本机 -> 证书信任设置」开启完全信任。\r\n").encode()
    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"5GPN-WLOC-CA.cer\"\r\n"
             "Content-Type: application/pkix-cert\r\n\r\n").encode() + cert
    body += (f"\r\n--{boundary}--\r\n").encode()
    try:
        req = urllib.request.Request(API + "sendDocument", data=body,
                                     headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return None if json.loads(resp.read().decode()).get("ok") else "CA 文件发送失败。"
    except Exception:  # noqa: BLE001
        return "CA 文件发送失败。"


# --------------------------------------------------------------------------- #
# Keyboards
# --------------------------------------------------------------------------- #
def main_menu():
    return [
        [{"text": "📊 状态", "callback_data": "act:status"},
         {"text": "🌐 出口管理", "callback_data": "menu:exits"}],
        [{"text": "📑 分流管理", "callback_data": "menu:rules"},
         {"text": "🔐 DoT 管理", "callback_data": "menu:dot"}],
        [{"text": "📡 WLOC 管理", "callback_data": "menu:wloc"},
         {"text": "🛠 运维", "callback_data": "menu:ops"}],
        [{"text": "📱 iOS 二维码", "callback_data": "act:ios"}],
    ]


def ops_menu():
    return [
        [{"text": "🩺 自检 doctor", "callback_data": "act:doctor"},
         {"text": "🧾 诊断报告", "callback_data": "act:report"}],
        [{"text": "💾 创建快照", "callback_data": "act:snapshot"},
         {"text": "📜 快照列表", "callback_data": "act:snaplist"}],
        [{"text": "⏪ 回滚最新", "callback_data": "act:rollback"},
         {"text": "🧭 向导", "callback_data": "wiz:start"}],
        [{"text": "🧦 私网 SOCKS5", "callback_data": "menu:socks"},
         {"text": "📡 私网 MTProto", "callback_data": "menu:mtproto"}],
        [{"text": "🧩 组件版本", "callback_data": "menu:components"},
         {"text": "♻️ 重启服务", "callback_data": "act:restart"}],
        [{"text": "📜 日志", "callback_data": "menu:logs"}],
        [{"text": "« 返回", "callback_data": "menu:main"}],
    ]


def client_socks_menu():
    return [
        [{"text": "▶️ 开启", "callback_data": "socks:enable"},
         {"text": "⏹ 关闭", "callback_data": "socks:disable"}],
        [{"text": "🔑 重置密码", "callback_data": "socks:reset"},
         {"text": "🔄 刷新状态", "callback_data": "socks:status"}],
        [{"text": "« 返回", "callback_data": "menu:ops"}],
    ]


def client_mtproto_menu():
    return [
        [{"text": "▶️ 开启", "callback_data": "mtproto:enable"},
         {"text": "⏹ 关闭", "callback_data": "mtproto:disable"}],
        [{"text": "🔑 填写密钥", "callback_data": "mtproto:set_secret"},
         {"text": "🎲 生成密钥", "callback_data": "mtproto:generate"}],
        [{"text": "🔄 刷新状态", "callback_data": "mtproto:status"}],
        [{"text": "« 返回", "callback_data": "menu:ops"}],
    ]


def op_client_socks_status():
    _, out = run2(["bash", MGMT, "--client-socks-status"], timeout=60)
    body = html.escape(_strip_ansi(out)[-2000:] or "无输出")
    return (f"🧦 <b>私网 SOCKS5</b>\n<pre>{body}</pre>\n"
            "仅客户端网段可访问；出站跟随当前出口。")


def op_enable_client_socks():
    ok, out = run2(["bash", MGMT, "--enable-client-socks"], timeout=180)
    body = html.escape(_strip_ansi(out)[-2500:])
    if ok:
        return (f"✅ <b>SOCKS5 已开启</b>\n<pre>{body}</pre>\n"
                "请立即保存用户名/密码；之后状态页会隐藏密码。")
    return f"❌ <b>开启失败</b>\n{html.escape(_reason(out))}"


def op_disable_client_socks():
    ok, out = run2(["bash", MGMT, "--disable-client-socks"], timeout=120)
    if ok:
        return f"✅ <b>SOCKS5 已关闭</b>\n{html.escape(_strip_ansi(out)[-800:])}"
    return f"❌ <b>关闭失败</b>\n{html.escape(_reason(out))}"


def op_reset_client_socks_creds():
    ok, out = run2(["bash", MGMT, "--reset-client-socks-creds"], timeout=120)
    body = html.escape(_strip_ansi(out)[-2000:])
    if ok:
        return (f"✅ <b>凭据已轮换</b>\n<pre>{body}</pre>\n请立即保存新密码。")
    return f"❌ <b>轮换失败</b>\n{html.escape(_reason(out))}"


def op_client_mtproto_status():
    _, out = run2(["bash", MGMT, "--client-mtproto-status"], timeout=60)
    body = html.escape(_strip_ansi(out)[-2000:] or "无输出")
    return (f"📡 <b>私网 MTProto</b>\n<pre>{body}</pre>\n"
            "仅客户端网段可访问；端口 5753；Telegram 直接填 32 位 hex 密钥。")


def op_enable_client_mtproto():
    ok, out = run2(["bash", MGMT, "--enable-client-mtproto"], timeout=240)
    body = html.escape(_strip_ansi(out)[-2500:])
    if ok:
        return (f"✅ <b>MTProto 已开启</b>\n<pre>{body}</pre>\n"
                "请立即保存密钥/链接；之后状态页会隐藏密钥。")
    return f"❌ <b>开启失败</b>\n{html.escape(_reason(out))}"


def op_disable_client_mtproto():
    ok, out = run2(["bash", MGMT, "--disable-client-mtproto"], timeout=120)
    if ok:
        return f"✅ <b>MTProto 已关闭</b>\n{html.escape(_strip_ansi(out)[-800:])}"
    return f"❌ <b>关闭失败</b>\n{html.escape(_reason(out))}"


def op_generate_client_mtproto_secret():
    ok, out = run2(["bash", MGMT, "--generate-client-mtproto-secret"], timeout=180)
    body = html.escape(_strip_ansi(out)[-2500:])
    if ok:
        return (f"✅ <b>密钥已生成</b>\n<pre>{body}</pre>\n请立即保存；若已开启服务会自动重载。")
    return f"❌ <b>生成失败</b>\n{html.escape(_reason(out))}"


def op_set_client_mtproto_secret(secret):
    secret = (secret or "").strip()
    if not secret or any(c.isspace() for c in secret):
        return "❌ 密钥不能为空，且不能含空白字符。"
    ok, out = run2(["bash", MGMT, "--set-client-mtproto-secret", secret], timeout=180)
    body = html.escape(_strip_ansi(out)[-2500:])
    if ok:
        return (f"✅ <b>密钥已更新</b>\n<pre>{body}</pre>\n请立即保存链接。")
    return f"❌ <b>设置失败</b>\n{html.escape(_reason(out))}"


def rules_menu():
    return [
        [{"text": "📋 规则列表", "callback_data": "rules:show"},
         {"text": "📚 规则集", "callback_data": "rules:showrs"},
         {"text": "✏️ 规则设置", "callback_data": "rules:set"}],
        [{"text": "➕ 添加规则", "callback_data": "rules:add"},
         {"text": "🗑 删除规则", "callback_data": "menu:rules_del"}],
        [{"text": "➕ 添加规则集", "callback_data": "rules:addset"},
         {"text": "🗑 删规则集", "callback_data": "menu:rulesets_del"}],
        [{"text": "🌐 代理域名", "callback_data": "rules:proxy_domain"},
         {"text": "🧪 路由测试", "callback_data": "rules:route_test"}],
        [{"text": "🎯 分类→出口映射", "callback_data": "menu:policy"}],
        [{"text": "🔄 更新规则", "callback_data": "act:update_rules"},
         {"text": "⚡ 启用分流", "callback_data": "rules:enable"}],
        [{"text": "« 返回", "callback_data": "menu:main"}],
    ]


def _short_button_text(text, limit=48):
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def rules_del_menu():
    rows = []
    _, entries = _plain_rule_entries()
    for index, (_, line) in enumerate(entries):
        label = _short_button_text(line.strip())
        data = f"ruledel:{index}:{_entry_token(line)}"
        rows.append([{"text": "🗑 " + label, "callback_data": data}])
    if not rows:
        rows.append([{"text": "（没有可删除的规则）", "callback_data": "menu:rules"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:rules"}])
    return rows


def rulesets_del_menu():
    rows = []
    _, entries = _ruleset_entries()
    for index, (_, line) in enumerate(entries):
        parts = line.strip().split(",", 2)
        if len(parts) == 3:
            source = parts[1].strip()
            target = parts[2].strip()
            parsed = urlparse(source)
            name = os.path.basename(parsed.path.rstrip("/")) or parsed.netloc or source
            label = f"{name} → {target}"
        else:
            label = line.strip()
        data = f"rulesetdel:{index}:{_entry_token(line)}"
        rows.append([{"text": "🗑 " + _short_button_text(label), "callback_data": data}])
    if not rows:
        rows.append([{"text": "（没有可删除的规则集）", "callback_data": "menu:rules"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:rules"}])
    return rows


def policy_menu():
    rows = []
    pm = _policy_map()
    if not pm:
        rows.append([{"text": "（还没有分类：用「分类→出口映射」添加，或 CLI: 5gpn set-policy / import-rules）",
                      "callback_data": "menu:rules"}])
    for i, (cat, tgt) in enumerate(pm):
        rows.append([{"text": f"{cat} → {tgt}", "callback_data": f"pol:{i}"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:rules"}])
    return rows


def policy_targets_menu(idx):
    rows, row = [], []
    for e in _targets():
        row.append({"text": e, "callback_data": f"ps:{idx}:{e}"})
        if len(row) == 3:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "🌍 直连", "callback_data": f"ps:{idx}:direct"},
                 {"text": "🚫 拒绝", "callback_data": f"ps:{idx}:block"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:policy"}])
    return rows


def exits_menu():
    rows = []
    for name in parse_exit_names():
        rows.append([{"text": "➡ " + name, "callback_data": "exit:" + name}])
    rows.append([{"text": "➕ 添加出口", "callback_data": "exit_add"},
                 {"text": "✏️ 重命名", "callback_data": "menu:exits_rename"}])
    rows.append([{"text": "🗑 删除出口", "callback_data": "menu:exits_del"}])
    rows.append([{"text": "🩺 检查出口连通性", "callback_data": "exits:check"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:main"}])
    return rows


def exits_del_menu():
    rows = []
    for name in parse_exit_names():
        if name in ("local", "smart"):
            continue
        rows.append([{"text": "🗑 " + name, "callback_data": "exitdel:" + name}])
    if not rows:
        rows.append([{"text": "(没有可删除的出口)", "callback_data": "menu:exits"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:exits"}])
    return rows


def exits_rename_menu():
    rows = []
    for name in parse_exit_names():
        if name in ("local", "smart"):
            continue
        rows.append([{"text": "✏️ " + name, "callback_data": "exitren:" + name}])
    if not rows:
        rows.append([{"text": "(没有可重命名的出口)", "callback_data": "menu:exits"}])
    rows.append([{"text": "« 返回", "callback_data": "menu:exits"}])
    return rows


def dot_menu():
    return [
        [{"text": "🌐 更改域名", "callback_data": "dot:domain"}],
        [{"text": "🌍 更改国际 DNS", "callback_data": "dot:dns_remote"}],
        [{"text": "🇨🇳 更改国内 DNS", "callback_data": "dot:dns_local"}],
        [{"text": "🛡 客户端网段", "callback_data": "menu:cidr"},
         {"text": "🌏 设置 ECS", "callback_data": "dot:ecs"}],
        [{"text": "🔓 DNS 直连域名", "callback_data": "menu:direct"}],
        [{"text": "🔄 续期证书", "callback_data": "act:renew"}],
        [{"text": "« 返回", "callback_data": "menu:main"}],
    ]


def wizard_menu():
    return [
        [{"text": "1️⃣ 探测客户端网段", "callback_data": "wiz:cidr"}],
        [{"text": "2️⃣ 添加出口", "callback_data": "wiz:add_exit"}],
        [{"text": "3️⃣ doctor 自检", "callback_data": "wiz:doctor"}],
        [{"text": "« 返回", "callback_data": "menu:ops"}],
    ]


def services_menu(prefix, back_target="menu:main"):
    rows = [[{"text": s, "callback_data": f"{prefix}:{s}"}] for s in SERVICES]
    rows.append([{"text": "« 返回", "callback_data": back_target}])
    return rows


# --------------------------------------------------------------------------- #
# Update handling
# --------------------------------------------------------------------------- #
def authorized(uid):
    return uid in ADMIN_IDS


def process_add_exit_message(chat_id, message_id, payload, prompt_mid=None):
    items = []
    try:
        deleted = delete_message(chat_id, message_id)
        delete_warning = ("\n\n⚠️ 未能自动删除含凭据的消息，请手动删除上一条节点消息。"
                          if not deleted else "")
        items, err = parse_add_exit_inputs(payload)
        payload = ""
        if err:
            upsert_console(chat_id, err + delete_warning, add_exit_retry_kb(),
                           message_id=prompt_mid)
            return
        prompt_mid = upsert_console(
            chat_id, f"⏳ 正在后台添加 {len(items)} 个出口…{delete_warning}",
            message_id=prompt_mid)
        result = op_add_exit_batch(items)
        upsert_console(chat_id, result, exits_menu(), message_id=prompt_mid)
    except Exception:  # noqa: BLE001
        print(f"[err] add-exit background task failed chat_id={chat_id} message_id={message_id}", file=sys.stderr)
        try:
            upsert_console(chat_id, "❌ 添加出口时发生内部错误，请重新进入添加流程。",
                           add_exit_retry_kb(), message_id=prompt_mid)
        except Exception:  # noqa: BLE001
            print(f"[err] add-exit failure notification failed chat_id={chat_id} message_id={message_id}", file=sys.stderr)
    finally:
        payload = ""
        for item in items:
            item["payload"] = ""
            item.pop("masked", None)
        items.clear()


def handle_message(msg):
    chat_id = msg["chat"]["id"]
    uid = msg.get("from", {}).get("id")
    text = (msg.get("text") or "").strip()

    # /id is always allowed: it only reveals the caller's own numeric id,
    # which is needed to bootstrap TG_ADMIN_IDS.
    if text.startswith("/id"):
        send(chat_id, f"你的 Telegram 数字 ID: <code>{uid}</code>")
        return

    if not authorized(uid):
        send(chat_id, "⛔ 未授权。把你的 ID 加入 TG_ADMIN_IDS 后重试。")
        return

    if text == "/cancel":
        PENDING.pop(chat_id, None)
        reanchor_console(chat_id, "已取消。选择一个操作：", main_menu())
        return

    # A slash command always aborts any in-progress flow.
    if text.startswith("/"):
        PENDING.pop(chat_id, None)
        if text.startswith(("/start", "/menu")):
            reanchor_console(chat_id, "<b>5GPN 控制台</b>\n选择一个操作：", main_menu())
        elif text.startswith("/status"):
            mid = reanchor_console(chat_id, "⏳ 正在获取运行状态…")
            console_async(chat_id, op_status, keyboard_fn=status_kb, message_id=mid)
        elif text.startswith("/exits"):
            mid = reanchor_console(chat_id, "⏳ 正在获取当前出口信息…")
            console_async(chat_id, exits_overview_text, keyboard_fn=exits_menu, message_id=mid)
        elif text.startswith("/rules"):
            reanchor_console(chat_id, "📑 <b>分流管理</b>：按域名分流到不同出口 / 直连 / 拒绝。", rules_menu())
        elif text.startswith("/wloc"):
            page, keyboard = _wloc_page()
            reanchor_console(chat_id, page, keyboard)
        else:
            send(chat_id, "未知命令。发送 /menu 打开操作面板。")
        return

    # Conversational flows (e.g. adding an exit).
    state = PENDING.get(chat_id)
    if state and state.get("action") == "add_exit_link":
        payload = msg.get("text") or ""
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        background(process_add_exit_message, chat_id, msg.get("message_id"), payload, prompt_mid)
        msg["text"] = ""
        payload = ""
        text = ""
        return
    if state and state.get("action") == "rename_exit":
        old_name = state.get("old") or ""
        new_name = text
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, f"⏳ 正在重命名出口 <b>{html.escape(old_name)}</b>…",
                             message_id=prompt_mid)
        console_async(chat_id, lambda: op_rename_exit(old_name, new_name),
                      keyboard_fn=exits_menu, message_id=mid)
        return
    if state and state.get("action") == "comp_manual":
        comp = state.get("component") or ""
        prompt_mid = state.get("prompt_mid")
        version = text.strip().lstrip("v")
        if comp not in COMPONENTS or not COMP_VERSION_RE.match(version):
            state["prompt_mid"] = upsert_console(
                chat_id, "版本号格式无效（应为 x.y.z），请重发；或点返回取消。",
                back_kb("menu:components"), message_id=prompt_mid)
            return
        PENDING.pop(chat_id, None)
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id,
                             f"⏳ 正在升级{COMPONENTS[comp]['label']}到 <code>{html.escape(version)}</code>…",
                             message_id=prompt_mid)
        console_async(chat_id, lambda: op_update_component(comp, version),
                      components_menu(), message_id=mid)
        return
    if state and state.get("action") == "rules_set":
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        rules_text = msg.get("text") or ""
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在校验并应用规则…", message_id=prompt_mid)
        console_async(chat_id, lambda: op_set_rules(rules_text), rules_menu(), message_id=mid)
        return
    if state and state.get("action") == "rules_add_value":
        rule_type = state.get("rule_type") or ""
        prompt_mid = state.get("prompt_mid")
        background(delete_message, chat_id, msg.get("message_id"))
        err = validate_rule_value(rule_type, text)
        if err:
            state["prompt_mid"] = upsert_console(chat_id, err, cancel_kb("rules"),
                                                 message_id=prompt_mid)
            return
        mid = upsert_console(
            chat_id,
            f"请选择目标：<code>{html.escape(rule_type)},{html.escape(text.strip())},?</code>",
            _rule_target_buttons("raddo"), message_id=prompt_mid)
        PENDING[chat_id] = {"action": "rules_add_target", "rule_type": rule_type,
                            "rule_value": text.strip(), "prompt_mid": mid}
        return
    if state and state.get("action") == "rules_add":
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        rule_line = text
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在添加规则…", message_id=prompt_mid)
        console_async(chat_id, lambda: op_add_rule(rule_line), rules_menu(), message_id=mid)
        return
    if state and state.get("action") == "rules_addset":
        prompt_mid = state.get("prompt_mid")
        ruleset_url = text.strip()
        background(delete_message, chat_id, msg.get("message_id"))
        err = validate_ruleset_url(ruleset_url)
        if err:
            state["prompt_mid"] = upsert_console(chat_id, err, cancel_kb("rules"),
                                                 message_id=prompt_mid)
            return
        mid = upsert_console(
            chat_id,
            f"请选择目标：<code>{html.escape(ruleset_url)}</code>",
            _rule_target_buttons("rsadd"), message_id=prompt_mid)
        PENDING[chat_id] = {"action": "rules_addset_target",
                            "ruleset_url": ruleset_url, "prompt_mid": mid}
        return
    if state and state.get("action") == "proxy_domain":
        prompt_mid = state.get("prompt_mid")
        domain_text = text.strip().lower().rstrip(".").lstrip("*.")
        background(delete_message, chat_id, msg.get("message_id"))
        if not DOMAIN_RE.match(domain_text):
            state["prompt_mid"] = upsert_console(
                chat_id,
                "域名格式无效。请发送类似 <code>openai.com</code> 的完整域名。",
                cancel_kb("rules"), message_id=prompt_mid)
            return
        mid = upsert_console(
            chat_id,
            f"请选择 <code>{html.escape(domain_text)}</code> 的目标出口 / 直连 / 拒绝：",
            _rule_target_buttons("pdomt", "menu:rules"), message_id=prompt_mid)
        PENDING[chat_id] = {"action": "proxy_domain_target",
                            "domain": domain_text, "prompt_mid": mid}
        return
    if state and state.get("action") == "route_test":
        prompt_mid = state.get("prompt_mid")
        domain_text = text
        PENDING.pop(chat_id, None)
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在测试域名路由…", message_id=prompt_mid)
        console_async(chat_id, lambda: op_route_test(domain_text), rules_menu(), message_id=mid)
        return
    if state and state.get("action") == "ecs_set":
        prompt_mid = state.get("prompt_mid")
        ecs_text = text
        PENDING.pop(chat_id, None)
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在设置 ECS 并刷新 DNS 规则…", message_id=prompt_mid)
        console_async(chat_id, lambda: op_set_ecs(ecs_text), dot_menu(), message_id=mid)
        return
    if state and state.get("action") == "wloc_location":
        prompt_mid = state.get("prompt_mid")
        try:
            lat, lon, accuracy = _wloc_parse(text)
        except ValueError as exc:
            state["prompt_mid"] = upsert_console(chat_id, "❌ " + str(exc),
                                                   cancel_kb("wloc"), message_id=prompt_mid)
            return
        PENDING.pop(chat_id, None)
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在启用 WLOC…", message_id=prompt_mid)
        console_async(chat_id, lambda: _wloc_apply(lat, lon, "自定义地点", accuracy),
                      keyboard_fn=lambda: _wloc_page()[1], message_id=mid)
        return
    if state and state.get("action") == "dot_domain":
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        domain_text = text
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在校验域名 A 记录并签发证书，可能需要 1-2 分钟…",
                             message_id=prompt_mid)
        def do_set_dot_domain():
            result, failed_domain = op_set_dot_domain(domain_text)
            if failed_domain:
                LAST_FAILED_DOT_DOMAIN[chat_id] = failed_domain
                upsert_console(chat_id, result, force_dot_domain_kb(), message_id=mid)
            else:
                LAST_FAILED_DOT_DOMAIN.pop(chat_id, None)
                upsert_console(chat_id, result, dot_menu(), message_id=mid)

        background(do_set_dot_domain)
        return
    if state and state.get("action") in ("dot_dns_remote", "dot_dns_local"):
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        dns_text = text
        kind = "remote" if state.get("action") == "dot_dns_remote" else "local"
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在更新 DNS 上游并重载 mosdns/sniproxy…",
                             message_id=prompt_mid)
        console_async(chat_id, lambda: op_set_dns(kind, dns_text), dot_menu(), message_id=mid)
        return
    if state and state.get("action") == "dd_add":
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        domain_text = text
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在加入 DNS 直连名单…", message_id=prompt_mid)
        console_async(chat_id, lambda: op_add_direct_domain(domain_text),
                      direct_domains_menu(), message_id=mid)
        return
    if state and state.get("action") == "dd_set":
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        list_text = msg.get("text") or ""
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在替换 DNS 直连名单…", message_id=prompt_mid)
        console_async(chat_id, lambda: op_set_direct_domains(list_text),
                      direct_domains_menu(), message_id=mid)
        return
    if state and state.get("action") == "cidr_set":
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        cidr_text = text
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在设置客户端网段…", message_id=prompt_mid)
        console_async(chat_id, lambda: op_set_client_cidr(cidr_text),
                      client_cidr_menu(), message_id=mid)
        return
    if state and state.get("action") == "mtproto_set_secret":
        prompt_mid = state.get("prompt_mid")
        PENDING.pop(chat_id, None)
        secret_text = text
        background(delete_message, chat_id, msg.get("message_id"))
        mid = upsert_console(chat_id, "⏳ 正在设置 MTProto 密钥…", message_id=prompt_mid)
        console_async(chat_id, lambda: op_set_client_mtproto_secret(secret_text),
                      client_mtproto_menu(), message_id=mid)
        return

    send(chat_id, "未知命令。发送 /menu 打开操作面板。")


def handle_callback(cb):
    uid = cb.get("from", {}).get("id")
    chat_id = cb["message"]["chat"]["id"]
    data = cb.get("data", "")
    cb_id = cb["id"]
    cb_mid = cb.get("message", {}).get("message_id")

    if not authorized(uid):
        tg("answerCallbackQuery", callback_query_id=cb_id, text="⛔ 未授权", show_alert=True)
        return

    if _busy_key_from_cb(cb) in BUSY:
        tg("answerCallbackQuery", callback_query_id=cb_id, text="正在处理上一项操作，请稍候…", show_alert=False)
        return

    # Stop the button spinner without adding another Telegram round-trip before the edit.
    answer_callback_async(cb_id)

    # ---- navigation (edit the same bubble) ----
    if data == "cancel:rules":
        PENDING.pop(chat_id, None)
        edit(cb, "📑 <b>分流管理</b>\n选择一个操作：", rules_menu())
    elif data == "cancel:exits":
        PENDING.pop(chat_id, None)
        edit(cb, "🌐 <b>出口管理</b>\n选择一个操作：", exits_menu())
    elif data == "cancel:dot":
        PENDING.pop(chat_id, None)
        edit(cb, op_dot_status(), dot_menu())
    elif data == "cancel:direct":
        PENDING.pop(chat_id, None)
        edit(cb, "🔓 <b>DNS 直连域名</b>\n私网客户端跳过劫持、返回真实 A 记录的域名名单。",
             direct_domains_menu())
    elif data == "cancel:wloc":
        PENDING.pop(chat_id, None)
        page, keyboard = _wloc_page()
        edit(cb, page, keyboard)
    elif data == "cancel:ops":
        PENDING.pop(chat_id, None)
        edit(cb, "🛠 <b>运维</b>\n选择一个操作：", ops_menu())
    elif data == "menu:main":
        PENDING.pop(chat_id, None)
        edit(cb, "选择一个操作：", main_menu())
    elif data == "menu:rules":
        edit(cb, "📑 <b>分流管理</b>：按域名把代理流量分到不同出口 / 直连 / 拒绝。", rules_menu())
    elif data == "menu:rules_del":
        edit(cb, "选择要删除的规则：", rules_del_menu())
    elif data == "menu:rulesets_del":
        edit(cb, "选择要删除的规则集：", rulesets_del_menu())
    elif data == "menu:policy":
        edit(cb,
             "🎯 <b>分类 → 出口</b> 映射（点一个分类来修改目标）：\n"
             "规则里的分组名先进入 <code>policy-map.conf</code>，再映射到 mihomo 出口 / direct / block。",
             policy_menu())
    elif data == "menu:exits":
        edit(cb, "⏳ 正在获取当前出口信息…")
        edit_async(cb, exits_overview_text, keyboard=exits_menu())
    elif data == "menu:exits_rename":
        edit(cb, "选择要重命名的出口：", exits_rename_menu())
    elif data == "menu:exits_del":
        edit(cb, "选择要删除的出口：", exits_del_menu())
    elif data == "menu:dot":
        edit(cb, op_dot_status(), dot_menu())
    elif data == "menu:cidr":
        edit(cb, op_show_client_cidr(), client_cidr_menu())
    elif data == "menu:direct":
        edit(cb, "🔓 <b>DNS 直连域名</b>\n私网客户端跳过劫持、返回真实 A 记录的域名名单。",
             direct_domains_menu())
    elif data == "menu:wloc":
        page, keyboard = _wloc_page()
        edit(cb, page, keyboard)
    elif data == "menu:ops":
        edit(cb, "🛠 <b>运维</b>\n选择一个操作：", ops_menu())
    elif data == "menu:components":
        PENDING.pop(chat_id, None)
        edit(cb, "⏳ 正在读取组件版本…")
        edit_components_async(cb)
    elif data == "comp:check":
        edit(cb, "⏳ 正在检查上游最新版本…")
        edit_components_async(cb, refresh=True)
    elif data == "comp:up:metacubexd":
        edit(cb, "⏳ 正在升级 metacubexd 面板…")
        edit_async(cb, lambda: op_update_component("metacubexd"), components_menu())
    elif data == "comp:up:mihomo":
        edit(cb, "⚠️ <b>升级 mihomo 引擎</b>\n将重启运行中的出口实例，代理流量会短暂中断。",
             [[{"text": "✅ 确认升级", "callback_data": "comp:up!:mihomo"},
               {"text": "« 取消", "callback_data": "menu:components"}]])
    elif data == "comp:up!:mihomo":
        edit(cb, "⏳ 正在升级 mihomo 引擎并重启出口实例…")
        edit_async(cb, lambda: op_update_component("mihomo"), components_menu())
    elif data.startswith("comp:manual:"):
        comp = data[len("comp:manual:"):]
        spec = COMPONENTS.get(comp)
        if not spec:
            edit(cb, "未知组件。", back_kb("menu:ops"))
        else:
            PENDING[chat_id] = {"action": "comp_manual", "component": comp, "prompt_mid": cb_mid}
            edit(cb, f"✏️ <b>指定{spec['label']}版本</b>\n"
                     "发送版本号（如 <code>1.270.5</code>），将写入 pin 并安装。",
                 back_kb("menu:components"))
    elif data == "menu:socks":
        edit(cb, "⏳ 正在读取 SOCKS5 状态…")
        edit_async(cb, op_client_socks_status, client_socks_menu())
    elif data == "menu:mtproto":
        PENDING.pop(chat_id, None)
        edit(cb, "⏳ 正在读取 MTProto 状态…")
        edit_async(cb, op_client_mtproto_status, client_mtproto_menu())
    elif data == "menu:logs":
        edit(cb, "选择要查看日志的服务：", services_menu("logs", "menu:ops"))
    elif data == "wiz:start":
        edit(cb,
             "🧭 <b>首次配置向导</b>\n\n"
             "建议按顺序完成：\n"
             "1. 探测客户端网段（用于 DNS 劫持和防火墙放行）\n"
             "2. 添加至少一个出口节点\n"
             "3. 运行 doctor 确认服务、路由和规则状态",
             wizard_menu())

    # ---- conversational starts (edit prompt into the same bubble) ----
    elif data == "rules:set":
        PENDING[chat_id] = {"action": "rules_set", "prompt_mid": cb_mid}
        edit(cb,
             "✏️ <b>规则设置</b>\n\n"
             "粘贴完整的分流规则（将替换当前所有规则，首行优先匹配）。\n\n"
             "格式：<code>类型,匹配值,出口</code>\n"
             "出口：出口名 / <code>direct</code>（直连）/ <code>block</code>（拦截）\n\n"
             "示例：\n"
             "<pre>DOMAIN-SUFFIX,google.com,us\n"
             "GEOSITE,netflix,us\n"
             "GEOIP,cn,direct\n"
             "FINAL,us</pre>",
             cancel_kb("rules"))
    elif data == "rules:add":
        edit(cb,
             "➕ <b>添加规则</b>\n\n"
             "选择一种快捷类型，或继续使用手工完整规则入口。",
             rule_type_menu())
    elif data == "rules:add_manual":
        PENDING[chat_id] = {"action": "rules_add", "prompt_mid": cb_mid}
        edit(cb,
             "➕ <b>添加规则</b>\n\n"
             "发送一条规则，将追加到现有规则末尾。\n\n"
             "格式：<code>类型,匹配值,出口</code>\n"
             "示例：<code>DOMAIN-SUFFIX,youtube.com,us</code>\n\n"
             "常用类型：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / GEOSITE / GEOIP / IP-CIDR",
             cancel_kb("rules"))
    elif data.startswith("raddt:"):
        rule_type = data.split(":", 1)[1]
        if rule_type not in RULE_TYPES:
            edit(cb, "规则类型无效，请重新选择。", rule_type_menu())
        else:
            PENDING[chat_id] = {"action": "rules_add_value", "rule_type": rule_type,
                                "prompt_mid": cb_mid}
            edit(cb, rule_value_prompt(rule_type), cancel_kb("rules"))
    elif data.startswith("raddo:"):
        state = PENDING.get(chat_id) or {}
        parts = data.split(":", 1)
        target = parts[1] if len(parts) == 2 else ""
        rule_type = state.get("rule_type") or ""
        value = state.get("rule_value") or ""
        valid_targets = set(_targets()) | {"direct", "block"}
        if state.get("action") != "rules_add_target" or not rule_type or not value:
            edit(cb, "规则输入已过期，请重新开始。", rule_type_menu())
        elif target not in valid_targets:
            edit(cb, "目标已变化，请重新选择。", _rule_target_buttons("raddo"))
        else:
            PENDING.pop(chat_id, None)
            line = f"{rule_type},{value},{target}"
            edit(cb, f"⏳ 正在添加规则 <code>{html.escape(line)}</code>…")
            edit_async(cb, lambda: op_add_rule(line), back_kb("menu:rules"))
    elif data == "rules:addset":
        PENDING[chat_id] = {"action": "rules_addset", "prompt_mid": cb_mid}
        edit(cb,
             "➕ <b>添加规则集</b>\n\n"
             "发送规则集 URL。\n\n"
             "示例：<code>https://example.com/openai.mrs</code>\n\n"
             "支持格式：mihomo <code>.mrs</code>、Clash YAML、纯文本规则集\n"
             "下一步选择目标出口。添加后点「🔄 更新规则」可立即拉取生效。",
             cancel_kb("rules"))
    elif data == "rules:proxy_domain":
        PENDING[chat_id] = {"action": "proxy_domain", "prompt_mid": cb_mid}
        edit(cb,
             "🌐 <b>代理域名</b>\n\n"
             "发送一个域名；下一步选择目标出口 / direct / block。\n"
             "这会同时写入 DNS 劫持名单和分流规则。\n\n"
             "示例：<code>openai.com</code>",
             cancel_kb("rules"))
    elif data == "rules:route_test":
        PENDING[chat_id] = {"action": "route_test", "prompt_mid": cb_mid}
        edit(cb,
             "🧪 <b>路由测试</b>\n\n"
             "发送一个域名，我会根据 <code>rules.conf</code>、<code>policy-map.conf</code>、"
             "GFWList 和 DNS 直连名单估算它会走哪个 mihomo 出口。\n\n"
             "示例：<code>chat.openai.com</code>",
             cancel_kb("rules"))
    elif data.startswith("rsadd:"):
        state = PENDING.get(chat_id) or {}
        parts = data.split(":", 1)
        target = parts[1] if len(parts) == 2 else ""
        ruleset_url = state.get("ruleset_url") or ""
        valid_targets = set(_targets()) | {"direct", "block"}
        if state.get("action") != "rules_addset_target" or not ruleset_url:
            edit(cb, "规则集输入已过期，请重新开始。", back_kb("menu:rules"))
        elif target not in valid_targets:
            edit(cb, "目标已变化，请重新选择。", _rule_target_buttons("rsadd"))
        else:
            PENDING.pop(chat_id, None)
            edit(cb, f"⏳ 正在添加规则集 <code>{html.escape(ruleset_url)}</code> → <b>{html.escape(target)}</b>…")
            edit_async(cb, lambda: op_add_ruleset(f"{ruleset_url} {target}"),
                       back_kb("menu:rules"))
    elif data.startswith("pdomt:"):
        state = PENDING.get(chat_id) or {}
        parts = data.split(":", 1)
        target = parts[1] if len(parts) == 2 else ""
        domain = state.get("domain") or ""
        valid_targets = set(_targets()) | {"direct", "block"}
        if state.get("action") != "proxy_domain_target" or not domain:
            edit(cb, "代理域名输入已过期，请重新开始。", back_kb("menu:rules"))
        elif target not in valid_targets:
            edit(cb, "目标已变化，请重新选择。", _rule_target_buttons("pdomt", "menu:rules"))
        else:
            PENDING.pop(chat_id, None)
            edit(cb, f"⏳ 正在设置 <code>{html.escape(domain)}</code> → <b>{html.escape(target)}</b>…")
            edit_async(cb, lambda: op_proxy_domain(domain, target), back_kb("menu:rules"))
    elif data == "exit_add":
        PENDING[chat_id] = {"action": "add_exit_link", "prompt_mid": cb_mid}
        edit(cb,
             "➕ <b>添加出口</b>\n\n"
             "直接发送一条或多条节点链接，每行一条；我会优先使用链接里的节点名称作为出口名。\n\n"
             f"支持：<code>{SUPPORTED_EXIT_LINKS}</code>\n\n"
             "链接没有名称时，也可以发 <code>出口名 链接</code> 指定名称；同名会自动去重。\n\n"
             "🔐 为避免凭据留在聊天记录中，进入此步骤后，你发送的下一条消息会在读取后尝试自动删除；"
             "即使解析失败也会删除。删除失败时会提醒你手动处理。",
             cancel_kb("exits"))
    elif data == "wiz:add_exit":
        PENDING[chat_id] = {"action": "add_exit_link", "prompt_mid": cb_mid}
        edit(cb,
             "2️⃣ <b>添加出口</b>\n\n"
             "直接发送一条或多条节点链接，每行一条；我会优先使用链接里的节点名称作为出口名。\n\n"
             f"支持：<code>{SUPPORTED_EXIT_LINKS}</code>\n\n"
             "链接没有名称时，也可以发 <code>出口名 链接</code> 指定名称；同名会自动去重。\n\n"
             "🔐 为避免凭据留在聊天记录中，进入此步骤后，你发送的下一条消息会在读取后尝试自动删除。",
             cancel_kb("ops"))
    elif data.startswith("exitren:"):
        name = data[len("exitren:"):]
        if name in ("local", "smart") or not EXIT_ADD_NAME_RE.match(name):
            edit(cb, "出口已变化，请重新打开。", exits_rename_menu())
        else:
            PENDING[chat_id] = {"action": "rename_exit", "old": name, "prompt_mid": cb_mid}
            edit(cb,
                 "✏️ <b>重命名出口</b>\n\n"
                 f"当前出口：<b>{html.escape(name)}</b>\n"
                 "请发送新的名称。",
                 cancel_kb("exits"))
    elif data == "dot:domain":
        PENDING[chat_id] = {"action": "dot_domain", "prompt_mid": cb_mid}
        edit(cb,
             "🌐 <b>更改 DoT 域名</b>\n\n"
             "发送新的完整域名。\n"
             "示例：<code>dns.example.com</code>\n\n"
             "域名 A 记录必须已经指向本机公网 IP，否则不会修改当前配置。",
             cancel_kb("dot"))
    elif data == "dot:dns_remote":
        PENDING[chat_id] = {"action": "dot_dns_remote", "prompt_mid": cb_mid}
        edit(cb,
             "🌍 <b>更改国际 DNS</b>\n\n"
             "发送新的 DNS 地址，多个地址用空格或逗号分隔。\n\n"
             "示例：<pre>1.1.1.1 8.8.8.8</pre>",
             cancel_kb("dot"))
    elif data == "dot:dns_local":
        PENDING[chat_id] = {"action": "dot_dns_local", "prompt_mid": cb_mid}
        edit(cb,
             "🇨🇳 <b>更改国内 DNS</b>\n\n"
             "发送新的 DNS 地址，多个地址用空格或逗号分隔。\n\n"
             "示例：<pre>223.5.5.5 119.29.29.29</pre>",
             cancel_kb("dot"))
    elif data == "dot:ecs":
        PENDING[chat_id] = {"action": "ecs_set", "prompt_mid": cb_mid}
        edit(cb,
             "🌏 <b>设置 ECS</b>\n\n"
             "发送 China-chain DNS 查询携带的 ECS 子网。\n"
             "示例：<code>139.226.48.0/24</code> 或 <code>112.96.54.1</code>",
             cancel_kb("dot"))
    elif data == "dot:force_domain":
        domain = LAST_FAILED_DOT_DOMAIN.get(chat_id)
        if not domain:
            edit(cb, "没有可强制更换的域名，请重新点更改域名。", dot_menu())
        else:
            edit(cb, f"⏳ 正在强制更换 DoT 域名为 <code>{html.escape(domain)}</code>…")
            def do_force_domain():
                result = op_force_set_dot_domain(domain)
                if "已强制更换" in result:
                    LAST_FAILED_DOT_DOMAIN.pop(chat_id, None)
                return result

            edit_async(cb, do_force_domain, dot_menu())
    elif data == "dd:show":
        edit(cb, "⏳ 正在读取 DNS 直连名单…")
        edit_async(cb, op_show_direct_domains, direct_domains_menu())
    elif data == "cidr:set":
        PENDING[chat_id] = {"action": "cidr_set", "prompt_mid": cb_mid}
        edit(cb,
             ("✏️ <b>设置客户端网段</b>\n\n"
              "发送一个 IPv4 CIDR（前缀 /8–/30）。\n\n"
              f"当前：<code>{html.escape(_client_cidr())}</code>\n"
              "示例：<code>172.22.0.0/16</code> 或 <code>10.10.0.0/16</code>"),
             cancel_kb("dot"))
    elif data == "cidr:detect":
        edit(cb, "⏳ 正在从本机网卡探测客户端网段…")
        edit_async(cb, op_detect_client_cidr, client_cidr_menu())
    elif data == "dd:add":
        PENDING[chat_id] = {"action": "dd_add", "prompt_mid": cb_mid}
        edit(cb,
             "➕ <b>添加 DNS 直连域名</b>\n\n"
             "发送一个完整域名。该域名及其子域在私网客户端上将返回真实 A 记录。\n\n"
             "示例：<code>box2.example.com</code>\n"
             "或整段：<code>servers.example.com</code>",
             cancel_kb("direct"))
    elif data == "dd:del":
        edit(cb, "选择要删除的域名：", direct_domains_del_menu())
    elif data == "dd:set":
        PENDING[chat_id] = {"action": "dd_set", "prompt_mid": cb_mid}
        edit(cb,
             "✏️ <b>整份替换 DNS 直连名单</b>\n\n"
             "发送完整名单（每行一个域名），将替换当前全部条目。\n"
             "发送空内容可清空名单。\n\n"
             "示例：\n<pre>box1.example.com\nbox2.example.com\nservers.example.com</pre>",
             cancel_kb("direct"))
    elif data.startswith("ddel:"):
        try:
            _, raw_index, token = data.split(":", 2)
            index = int(raw_index)
        except (ValueError, TypeError):
            edit(cb, "删除按钮无效，请重新打开名单。", direct_domains_del_menu())
        else:
            edit(cb, "⏳ 正在从 DNS 直连名单删除…")
            edit_async(cb, lambda: op_del_direct_domain_button(index, token),
                       direct_domains_del_menu())
    elif data == "wloc:input":
        PENDING[chat_id] = {"action": "wloc_location", "prompt_mid": cb_mid}
        edit(cb,
             "✍️ <b>自定义 WLOC 地点</b>\n\n"
             "发送 WGS84 经纬度，格式：<code>纬度,经度</code>\n"
             "示例：<code>35.681236,139.767125</code>\n\n"
             "该消息会在读取后尝试自动删除。",
             cancel_kb("wloc"))
    elif data.startswith("wloc:set:"):
        preset = WLOC_PRESETS.get(data[len("wloc:set:"):])
        if not preset:
            page, keyboard = _wloc_page()
            edit(cb, "地点列表已变化，请重新选择。", keyboard)
        else:
            label, lat, lon = preset
            edit(cb, f"⏳ 正在把 WLOC 切换到 <b>{html.escape(label)}</b>…")
            edit_async(cb, lambda: _wloc_apply(lat, lon, label), _wloc_page()[1])
    elif data == "wloc:off":
        edit(cb, "⏳ 正在关闭 WLOC 并恢复原始定位…")
        edit_async(cb, _wloc_disable, _wloc_page()[1])
    elif data == "wloc:ca":
        result = _send_wloc_ca(chat_id)
        page, keyboard = _wloc_page()
        if result:
            edit(cb, f"❌ {html.escape(result)}\n\n{page}", keyboard)
        else:
            edit(cb, "✅ WLOC CA 已作为文件发送。\n\n" + page, keyboard)

    # ---- views ----
    elif data == "rules:show":
        edit(cb, op_show_rules(), back_kb("menu:rules"))
    elif data == "rules:showrs":
        edit(cb, op_show_rulesets(), back_kb("menu:rules"))
    elif data == "act:status":
        edit(cb, "⏳ 正在获取运行状态…")
        edit_async(cb, op_status, status_kb())
    elif data == "act:status_refresh":
        edit(cb, "⏳ 正在刷新状态…")
        edit_async(cb, op_status, status_kb())
    elif data.startswith("logs:"):
        svc = data[len("logs:"):]
        edit(cb, f"📜 正在取 <b>{html.escape(svc)}</b> 日志…")
        edit_async(cb, lambda: op_logs(svc), back_kb("menu:logs"), mono=True)
    elif data == "exits:check":
        edit(cb, "⏳ 正在检查出口连通性…")
        edit_async(cb, op_check_exits, back_kb("menu:exits"))
    elif data.startswith("ruledel:"):
        try:
            _, raw_index, token = data.split(":", 2)
            index = int(raw_index)
        except (ValueError, IndexError):
            edit(cb, "删除按钮无效，请重新打开规则列表。", back_kb("menu:rules_del"))
        else:
            edit(cb, "⏳ 正在删除规则并校验配置…")
            edit_async(cb, lambda: op_del_rule_button(index, token), back_kb("menu:rules_del"))
    elif data.startswith("rulesetdel:"):
        try:
            _, raw_index, token = data.split(":", 2)
            index = int(raw_index)
        except (ValueError, IndexError):
            edit(cb, "删除按钮无效，请重新打开规则集列表。", back_kb("menu:rulesets_del"))
        else:
            edit(cb, "⏳ 正在删除规则集并校验配置…")
            edit_async(cb, lambda: op_del_ruleset_button(index, token), back_kb("menu:rulesets_del"))

    # ---- actions (⏳ then result, all in one bubble) ----
    elif data == "act:update_rules":
        edit(cb, "⏳ 正在更新规则，请稍候…")
        edit_async(cb, op_update_rules, back_kb("menu:rules"))
    elif data == "act:renew":
        edit(cb, "⏳ 正在续期证书，请稍候…")
        edit_async(cb, op_renew_cert, back_kb("menu:main"))
    elif data == "act:doctor":
        edit(cb, "⏳ 正在运行 doctor 自检…")
        edit_async(cb, op_doctor, back_kb("menu:ops"))
    elif data == "socks:status":
        edit(cb, "⏳ 正在读取 SOCKS5 状态…")
        edit_async(cb, op_client_socks_status, client_socks_menu())
    elif data == "socks:enable":
        edit(cb, "⏳ 正在开启私网 SOCKS5…")
        edit_async(cb, op_enable_client_socks, client_socks_menu())
    elif data == "socks:disable":
        edit(cb, "⏳ 正在关闭私网 SOCKS5…")
        edit_async(cb, op_disable_client_socks, client_socks_menu())
    elif data == "socks:reset":
        edit(cb, "⏳ 正在轮换 SOCKS5 凭据…")
        edit_async(cb, op_reset_client_socks_creds, client_socks_menu())
    elif data == "mtproto:status":
        edit(cb, "⏳ 正在读取 MTProto 状态…")
        edit_async(cb, op_client_mtproto_status, client_mtproto_menu())
    elif data == "mtproto:enable":
        edit(cb, "⏳ 正在开启私网 MTProto…")
        edit_async(cb, op_enable_client_mtproto, client_mtproto_menu())
    elif data == "mtproto:disable":
        edit(cb, "⏳ 正在关闭私网 MTProto…")
        edit_async(cb, op_disable_client_mtproto, client_mtproto_menu())
    elif data == "mtproto:generate":
        edit(cb, "⏳ 正在生成 MTProto 密钥…")
        edit_async(cb, op_generate_client_mtproto_secret, client_mtproto_menu())
    elif data == "mtproto:set_secret":
        PENDING[chat_id] = {"action": "mtproto_set_secret", "prompt_mid": cb_mid}
        edit(cb,
             "📡 <b>填写 MTProto 密钥</b>\n"
             "发送一行 <b>32 位 hex</b>（Telegram 里填同一个）。\n"
             "也可用 <code>dd</code>+32hex；旧 ee… FakeTLS 会提取其中的 key。\n"
             "端口固定 <code>5753</code>；仅客户端网段可连。",
             back_kb("menu:mtproto"))
    elif data == "act:report":
        edit(cb, "⏳ 正在生成脱敏诊断报告…")
        edit_report_async(cb, chat_id)
    elif data == "act:snapshot":
        edit(cb, "⏳ 正在保存配置快照…")
        edit_async(cb, op_snapshot, back_kb("menu:ops"))
    elif data == "act:snaplist":
        edit(cb, "⏳ 正在读取快照列表…")
        edit_snapshot_list_async(cb)
    elif data == "act:rollback":
        edit(cb, "⏳ 正在回滚到最近快照…")
        edit_async(cb, op_rollback, back_kb("menu:ops"))
    elif data.startswith("rollback:"):
        snap_id = data[len("rollback:"):]
        if not SNAP_ID_RE.match(snap_id):
            edit(cb, "快照 ID 无效，请重新打开列表。", back_kb("menu:ops"))
        else:
            edit(cb, f"⏳ 正在回滚到快照 <code>{html.escape(snap_id)}</code>…")
            edit_async(cb, lambda: op_rollback(snap_id), back_kb("menu:ops"))
    elif data.startswith("snapdel:"):
        snap_id = data[len("snapdel:"):]
        if not SNAP_ID_RE.match(snap_id):
            edit(cb, "快照 ID 无效，请重新打开列表。", back_kb("menu:ops"))
        else:
            edit(cb, f"⏳ 正在删除快照 <code>{html.escape(snap_id)}</code>…")
            edit_async(cb, lambda: op_delete_snapshot(snap_id), back_kb("menu:ops"))
    elif data == "act:restart":
        edit(cb, "⏳ 正在重启服务…")
        edit_async(cb, op_restart_services, back_kb("menu:ops"))
    elif data == "wiz:cidr":
        edit(cb, "⏳ 正在探测客户端网段…")
        edit_async(cb, op_detect_client_cidr, wizard_menu())
    elif data == "wiz:doctor":
        edit(cb, "⏳ 正在运行 doctor 自检…")
        edit_async(cb, op_doctor, wizard_menu())
    elif data == "rules:enable":
        edit(cb, "⏳ 正在启用智能分流…")
        edit_async(cb, lambda: op_set_exit("smart"), back_kb("menu:rules"))
    elif data.startswith("exit:"):
        name = data[len("exit:"):]
        edit(cb, f"⏳ 正在切换出口到 <b>{html.escape(name)}</b>…")
        edit_async(cb, lambda: op_set_exit(name), back_kb("menu:exits"))
    elif data.startswith("exitdel:"):
        name = data[len("exitdel:"):]
        edit(cb, f"⏳ 正在删除出口 <b>{html.escape(name)}</b>…")
        edit_async(cb, lambda: op_del_exit(name), back_kb("menu:exits"))
    elif data == "act:ios":
        edit(cb, "⏳ 正在生成 iOS 二维码…")
        edit_ios_async(cb, chat_id)
    elif data.startswith("pol:"):
        try:
            idx = int(data.split(":")[1])
        except (ValueError, IndexError):
            idx = -1
        pm = _policy_map()
        if 0 <= idx < len(pm):
            edit(cb, f"把分类 <b>{html.escape(pm[idx][0])}</b>（现为 {html.escape(pm[idx][1])}）路由到哪里？", policy_targets_menu(idx))
        else:
            edit(cb, "分类已变化，请重新打开。", policy_menu())
    elif data.startswith("ps:"):
        parts = data.split(":", 2)
        pm = _policy_map()
        try:
            idx, target = int(parts[1]), parts[2]
        except (ValueError, IndexError):
            idx, target = -1, ""
        if 0 <= idx < len(pm):
            cat = pm[idx][0]
            edit(cb, f"⏳ 正在设置 <b>{html.escape(cat)}</b> → <b>{html.escape(target)}</b> 并重建分流（可能较久）…")
            edit_async(cb, lambda: op_set_policy(cat, target), back_kb("menu:policy"))
        else:
            edit(cb, "分类已变化，请重新打开。", policy_menu())
    else:
        edit(cb, "未知操作。", back_kb("menu:main"))


# Quick command menu (the Telegram "Menu" button / typing "/"), Chinese labels.
BOT_COMMANDS = [
    ("menu", "打开操作面板"),
    ("status", "查看运行状态"),
    ("exits", "出口管理（切换/添加/删除）"),
    ("rules", "分流管理"),
    ("wloc", "WLOC 虚拟定位管理"),
    ("id", "获取我的 Telegram ID"),
]


def set_commands():
    """Register the Chinese quick-command menu and enable the Menu button."""
    commands = [{"command": c, "description": d} for c, d in BOT_COMMANDS]

    # Old projects may have left narrower scopes (especially all_private_chats)
    # with only /start and /cancel, which Telegram prefers over the default
    # scope in the command menu. Clear common stale scopes, then register the
    # current command set for both default and private chats so fresh installs
    # reliably show the full menu.
    for scope in (
        None,
        {"type": "all_private_chats"},
        {"type": "all_group_chats"},
        {"type": "all_chat_administrators"},
    ):
        params = {}
        if scope is not None:
            params["scope"] = scope
        r = tg("deleteMyCommands", **params)
        if not r.get("ok"):
            print(f"[warn] deleteMyCommands failed for {scope or 'default'}: {r}", file=sys.stderr)

    for scope in (
        None,
        {"type": "all_private_chats"},
    ):
        params = {"commands": commands}
        if scope is not None:
            params["scope"] = scope
        r = tg("setMyCommands", **params)
        if not r.get("ok"):
            print(f"[warn] setMyCommands failed for {scope or 'default'}: {r}", file=sys.stderr)

    # Make the input-box button show the command menu.
    tg("setChatMenuButton", menu_button={"type": "commands"})


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
def main():
    if not TOKEN:
        print("TG_BOT_TOKEN is not set", file=sys.stderr)
        sys.exit(1)
    validate_mgmt_path()
    heal_mgmt_ctl()
    if not ADMIN_IDS:
        print("[warn] TG_ADMIN_IDS is empty; no one can operate. Use /id to find yours.",
              file=sys.stderr)

    set_commands()
    print(f"5gpn tgbot started; admins={sorted(ADMIN_IDS)}", file=sys.stderr)
    offset = None
    while True:
        # Stay below common 30s idle TCP timeouts so the next update does not
        # wait for a stale long-poll socket to fail first.
        params = {"timeout": 25}
        if offset is not None:
            params["offset"] = offset
        resp = tg("getUpdates", **params)
        if not resp.get("ok"):
            time.sleep(3)
            continue
        for upd in resp.get("result", []):
            offset = upd["update_id"] + 1
            try:
                if "message" in upd:
                    handle_message(upd["message"])
                elif "callback_query" in upd:
                    handle_callback(upd["callback_query"])
            except Exception as e:  # never let one bad update kill the loop  # noqa: BLE001
                print(f"[err] handling update: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
