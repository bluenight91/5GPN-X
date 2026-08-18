#!/usr/bin/env python3
"""
5GPN-X HTTP control API.

A small, stdlib-only HTTPS service that exposes the same operations as the
Telegram bot by shelling out to the SAME backend (5gpn-ctl) and reading
the SAME state files. So the web UI and the bot are always in sync — there is
one source of truth (/etc/5gpn + the ctl).

Auth:  every /api/* call (except /api/health) needs  Authorization: Bearer <API_TOKEN>.

Env (systemd EnvironmentFile):
  API_TOKEN         required bearer token (service refuses to start if unset/short)
  API_PORT          listen port                     (default 8444; 8443 is sniproxy)
  API_BIND          bind address                    (default 127.0.0.1)
  API_TLS_CERT      TLS fullchain                   (default /etc/mosdns/certs/fullchain.pem)
  API_TLS_KEY       TLS private key                 (default /etc/mosdns/certs/privkey.pem)
  API_ALLOW_ORIGIN  CORS allowed origin             (default ""; set * explicitly for wildcard)
  MGMT              path to 5gpn-ctl                (default /opt/5gpn/bin/5gpn-ctl)
  CONF_DIR          gateway state dir               (default /opt/5gpn/etc)
"""
import base64
import calendar
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("API_TOKEN", "")
PORT = int(re.sub(r"\D", "", os.environ.get("API_PORT", "8444")) or "8444")
BIND = os.environ.get("API_BIND", "127.0.0.1")
CERT = os.environ.get("API_TLS_CERT", "/etc/mosdns/certs/fullchain.pem")
KEY = os.environ.get("API_TLS_KEY", "/etc/mosdns/certs/privkey.pem")
ORIGIN = os.environ.get("API_ALLOW_ORIGIN", "").strip()
MGMT = os.environ.get("MGMT", "/opt/5gpn/bin/5gpn-ctl")
CONF_DIR = os.environ.get("CONF_DIR", "/opt/5gpn/etc")
DOCTOR = os.environ.get("DOCTOR", "/opt/5gpn/scripts/doctor.sh")
SNAPSHOT = os.environ.get("SNAPSHOT", "/opt/5gpn/scripts/snapshot.sh")
REPORT = os.environ.get("REPORT", "/opt/5gpn/scripts/report.sh")
WEBUI_DIR = os.environ.get("WEBUI_DIR", "/opt/5gpn/webui")

PGW_DIR = "/etc/5gpn"
EXITS_DIR = PGW_DIR + "/exits"
POLICY_MAP = PGW_DIR + "/policy-map.conf"
RULES_FILE = PGW_DIR + "/rules.conf"
WG_DIR = "/etc/wireguard"
TRAFFIC_FILE = os.environ.get("TRAFFIC_FILE", CONF_DIR + "/traffic.json")
TRAFFIC_INTERVAL = int(re.sub(r"\D", "", os.environ.get("TRAFFIC_INTERVAL", "300")) or "300")
TRAFFIC_MAX = 24 * 3600 // TRAFFIC_INTERVAL + 2   # ~24h of samples
LATENCY_FILE = os.environ.get("LATENCY_FILE", CONF_DIR + "/latency.json")
LATENCY_INTERVAL = TRAFFIC_INTERVAL
ALLOW_FILE = os.environ.get("API_ALLOW_FILE", CONF_DIR + "/api-allow.list")
HISTORY_TRAFFIC_FILE = os.environ.get("HISTORY_TRAFFIC_FILE", CONF_DIR + "/history-traffic.json")
HISTORY_LATENCY_FILE = os.environ.get("HISTORY_LATENCY_FILE", CONF_DIR + "/history-latency.json")
HISTORY_DAYS = 62
AI_CONF = os.environ.get("AI_CONF", CONF_DIR + "/ai.json")
STARTED = time.time()

# Matches install.sh's exit-name validator (letters/digits/Chinese/_/-, 1-16).
EXIT_NAME_RE = re.compile(r"^[\w一-鿿-]{1,16}$")
CAT_RE = re.compile(r"^[A-Za-z0-9_一-鿿-]{1,40}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
DIRECT_DOMAINS_FILE = "/etc/mosdns/direct-domains.txt"
CLIENT_CIDR_FILE = "/etc/mosdns/.client_cidr"
CLIENT_CIDR_DEFAULT = "172.22.0.0/16"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Self-service component version bumps (mirrors install.sh's pin mechanism):
# current version files written by the installer, optional pins in CONF_DIR.
COMPONENTS = {
    "metacubexd": {
        "version_file": WEBUI_DIR + "/mihomo/.metacubexd-version",
        "pin_file": CONF_DIR + "/metacubexd.pin",
        "repo": "MetaCubeX/metacubexd",
        "flag": "--update-webui",
    },
    "mihomo": {
        "version_file": "/opt/5gpn/bin/.mihomo-version",
        "pin_file": CONF_DIR + "/mihomo.pin",
        "repo": "MetaCubeX/mihomo",
        "flag": "--update-mihomo",
    },
}
COMPONENT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
# Core units always reported on /api/status. Opt-in proxies are appended when
# their .enabled markers exist so the dashboard reflects the full deploy.
SERVICES = [
    "mosdns",
    "sniproxy",
    "wa-shim",
    "quic-proxy",
    "5gpn-ios-profile.socket",
    "5gpn-tgbot",
    "5gpn-api",
]

CLASH_ADDR = os.environ.get("CLASH_ADDR", "127.0.0.1:9090")
CLASH_SECRET_FILE = os.environ.get("MIHOMO_API_SECRET_FILE", "/etc/5gpn/mihomo-api-secret")
MIHOMO_STATIC_DIR = os.environ.get("MIHOMO_STATIC_DIR", "/opt/5gpn/webui/mihomo")
CLASH_WS_PATHS = {"traffic", "logs", "connections", "memory"}
SESSION_TTL = 3600
_mihomo_sessions = {}      # opaque sid -> expiry monotonic
_session_lock = threading.Lock()
_session_next_prune = 0.0

# CSP for the vendored metacubexd (same-origin app; frames allowed same-origin
# so our console can embed it, everything else locked down).
# metacubexd (Nuxt) boots via small inline scripts; script-src 'self' alone
# blocks them and the UI white-screens with TypeError on undefined `app`.
# connect-src must reach beyond 'self': the dashboard's IP-info and latency
# widgets (and its user-configurable latency-test URLs) fetch third-party
# endpoints straight from the browser; 'self' alone makes them all fail.
XD_CSP = ("default-src 'self'; "
          "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; "
          "style-src 'self' 'unsafe-inline'; "
          "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' https: wss:; "
          "worker-src 'self' blob:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'")

# Per-source-IP token bucket for /api/* (brute-force and abuse protection).
RATE_MAX = 30.0          # burst tokens
RATE_REFILL = 10.0       # tokens per second
_rate_lock = threading.Lock()
_rate = {}               # ip -> [tokens, last]


def rate_ok(ip):
    now = time.monotonic()
    with _rate_lock:
        ent = _rate.setdefault(ip, [RATE_MAX, now])
        ent[0] = min(RATE_MAX, ent[0] + (now - ent[1]) * RATE_REFILL)
        ent[1] = now
        if len(_rate) > 4096:      # bound memory under spoofed-source floods
            drop = max(1, len(_rate) // 4)
            for old_ip, _ in sorted(_rate.items(), key=lambda kv: kv[1][1])[:drop]:
                _rate.pop(old_ip, None)
        if ent[0] < 1.0:
            return False
        ent[0] -= 1.0
        return True


def rate_limited_path(path):
    return path.startswith(("/api/", "/mihomo"))


# --- optional source allowlist (etc/api-allow.list) ----------------------------
# One CIDR per line; '#' comments ok. Empty/missing file = unrestricted
# (backwards compatible). Loopback is always allowed so local health checks
# and the mihomo reverse proxy keep working. The list is the enforcement of
# record: the project never opens the API port in any firewall template, so a
# broad operator-side ACCEPT would defeat nft/iptables-layer restriction.
_allow_lock = threading.Lock()
_allow_cache = {"mtime": None, "nets": []}


def _allow_nets():
    try:
        mtime = os.path.getmtime(ALLOW_FILE)
    except OSError:
        mtime = None
    with _allow_lock:
        if mtime != _allow_cache["mtime"]:
            nets = []
            if mtime is not None:
                try:
                    with open(ALLOW_FILE, encoding="utf-8") as f:
                        for line in f:
                            line = line.split("#", 1)[0].strip()
                            if not line:
                                continue
                            try:
                                nets.append(ipaddress.ip_network(line, strict=False))
                            except ValueError:
                                continue
                except OSError:
                    nets = []
            _allow_cache["mtime"] = mtime
            _allow_cache["nets"] = nets
        return _allow_cache["nets"]


def source_allowed(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    nets = _allow_nets()
    if not nets:
        return True
    return any(ip in n for n in nets)


def _prune_mihomo_sessions(now):
    expired = [sid for sid, exp in _mihomo_sessions.items() if exp <= now]
    for sid in expired:
        _mihomo_sessions.pop(sid, None)


def mint_mihomo_session():
    global _session_next_prune
    now = time.monotonic()
    sid = secrets.token_urlsafe(32)
    with _session_lock:
        if now >= _session_next_prune or len(_mihomo_sessions) > 4096:
            _prune_mihomo_sessions(now)
            _session_next_prune = now + 60
        _mihomo_sessions[sid] = now + SESSION_TTL
    return sid


def valid_mihomo_session(sid):
    global _session_next_prune
    if not sid:
        return False
    now = time.monotonic()
    with _session_lock:
        if now >= _session_next_prune or len(_mihomo_sessions) > 4096:
            _prune_mihomo_sessions(now)
            _session_next_prune = now + 60
        exp = _mihomo_sessions.get(sid)
        if not exp or exp <= now:
            _mihomo_sessions.pop(sid, None)
            return False
        return True


def run(argv, inp=None, timeout=180):
    try:
        p = subprocess.run(argv, input=inp, capture_output=True, text=True, timeout=timeout,
                           check=False)
        out = ANSI.sub("", (p.stdout or "") + (p.stderr or ""))
        return p.returncode == 0, out.strip()
    except subprocess.TimeoutExpired:
        return False, "操作超时"
    except FileNotFoundError:
        return False, f"命令不存在：{argv[0]}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def ctl(*args, inp=None, timeout=180):
    return run(["bash", MGMT, *args], inp=inp, timeout=timeout)


# --- mihomo (Clash API) integration ------------------------------------------
def clash_secret():
    return read_file(CLASH_SECRET_FILE).strip()


def normalize_sub(raw):
    """Decode, validate and normalize a Clash API sub-path (path + filtered
    query). Returns the normalized string, or None when invalid."""
    raw = raw.split("#", 1)[0]
    path, _, query = raw.partition("?")
    path = urllib.parse.unquote(path).strip("/")
    if not path or ".." in path:
        return None
    if not re.fullmatch(r"[\w./\-一-鿿]+", path):
        return None
    if not query:
        return path
    allowed = []
    for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if k == "timeout" and v.isdigit():
            allowed.append(("timeout", str(max(100, min(10000, int(v))))))
        elif k == "url" and re.match(r"^https?://", v):
            allowed.append(("url", v))
        elif k == "force" and v in ("true", "false"):
            allowed.append((k, v))
        elif k == "level" and v in ("debug", "info", "warning", "error", "silent"):
            allowed.append(("level", v))
    return path + ("?" + urllib.parse.urlencode(allowed) if allowed else "")


def clash_request(method, sub, body=None, ctype=None, timeout=30):
    """Call the loopback Clash API with the server-side secret. Returns
    (status, content_type, response_bytes)."""
    sub = normalize_sub(sub)
    if sub is None:
        return 400, "application/json", json.dumps({"message": "bad path"}).encode()
    secret = clash_secret()
    if not secret:
        return 503, "application/json", json.dumps({"message": "mihomo api not configured"}).encode()
    path, _, query = sub.partition("?")
    url = f"http://{CLASH_ADDR}/{urllib.parse.quote(path, safe='/')}"
    if query:
        url += "?" + query
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", "Bearer " + secret)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type", "application/json"), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", "application/json"), e.read()
    except Exception as e:  # noqa: BLE001
        return 502, "application/json", json.dumps({"message": f"mihomo unreachable: {e}"}).encode()


def ws_allowed(sub):
    norm = normalize_sub(sub)
    return bool(norm) and norm.split("?", 1)[0] in CLASH_WS_PATHS


def build_ws_request(sub, client_headers):
    """Rebuild the client's WS upgrade request for the loopback Clash API,
    injecting the server-side secret. Returns raw bytes."""
    lines = [f"GET /{sub} HTTP/1.1",
             f"Host: {CLASH_ADDR}",
             "Upgrade: websocket",
             "Connection: Upgrade",
             f"Sec-WebSocket-Version: {client_headers.get('Sec-WebSocket-Version', '13')}",
             f"Sec-WebSocket-Key: {client_headers.get('Sec-WebSocket-Key', '')}",
             f"Authorization: Bearer {clash_secret()}"]
    proto = client_headers.get("Sec-WebSocket-Protocol")
    if proto:
        lines.append(f"Sec-WebSocket-Protocol: {proto}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def ws_relay(client_sock, sub, client_headers):
    """Upgrade with mihomo, then pipe bytes both ways until either side closes.
    Runs synchronously in the handler thread; caller must not touch the socket
    afterwards."""
    host, port = CLASH_ADDR.rsplit(":", 1)
    upstream = socket.create_connection((host, int(port)), timeout=10)
    try:
        upstream.sendall(build_ws_request(sub, client_headers))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = upstream.recv(4096)
            if not chunk:
                return
            resp += chunk
            if len(resp) > 65536:
                return
        head, _, rest = resp.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            return
        client_sock.sendall(head + b"\r\n\r\n" + rest)
        client_sock.setblocking(False)
        upstream.setblocking(False)
        # The client socket is read raw from here on, bypassing the handler's
        # buffered rfile. Browsers don't send WS frames before the 101, so
        # rfile has no buffered client bytes here.
        peer = {client_sock: upstream, upstream: client_sock}
        pending = {client_sock: bytearray(), upstream: bytearray()}
        # Sides that sent EOF (or errored on read) / were shut for writing.
        # A FIN right after a final payload must not drop buffered bytes: we
        # stop reading the closed side, flush pending[peer], then propagate a
        # half-close (SHUT_WR) so the peer sees EOF too.
        closed_read = set()
        closed_write = set()
        # Transient non-blocking conditions: SSLWantRead/WantWrite on the TLS
        # client socket, BlockingIOError on the plain upstream socket.
        WANT = (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError)
        MAX_PENDING = 4 * 1024 * 1024   # tear down if a stalled peer piles up
        while True:
            for s in pending:
                p = peer[s]
                if s in closed_read and p not in closed_write and not pending[p]:
                    try:
                        p.shutdown(socket.SHUT_WR)
                    except (OSError, ValueError):
                        pass
                    closed_write.add(p)
            if len(closed_write) == 2:
                return                  # both directions fully closed
            readers = [s for s in pending if s not in closed_read]
            writers = [s for s in pending if pending[s]]
            if not readers and not writers:
                return                  # both sides done and buffers drained
            r, w, x = select.select(readers, writers, list(pending), 300)
            if x:
                return
            if not r and not w and not readers:
                return                  # flush-only mode stalled for 300s
            for s in r:
                try:
                    data = s.recv(65536)
                except WANT:
                    continue            # TLS record not complete yet; retry
                except OSError:
                    data = b""          # read error: treat like EOF
                if not data:
                    closed_read.add(s)  # stop reading; flush pending[peer[s]]
                    continue
                pending[peer[s]] += data
                if len(pending[peer[s]]) > MAX_PENDING:
                    return
            for s in w:
                try:
                    n = s.send(pending[s])
                except WANT:
                    continue            # retry the SAME bytes once writable
                except OSError:
                    return              # write failed: nothing more we can do
                if n <= 0:
                    return
                del pending[s][:n]      # drop only what was actually sent
    finally:
        try:
            upstream.close()
        except OSError:
            pass


def mihomo_overview():
    secret = clash_secret()
    if not secret:
        return None, "mihomo API 未配置（缺少 secret，运行 install.sh --setup-api）"
    def get(p):
        req = urllib.request.Request(f"http://{CLASH_ADDR}{p}")
        req.add_header("Authorization", "Bearer " + secret)
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())

    def get_memory():
        # mihomo's /memory is an INFINITE one-object-per-second stream (plain
        # HTTP included), and its first object is always inuse=0 by design.
        # Reading to EOF would hang forever — take the first two lines instead.
        req = urllib.request.Request(f"http://{CLASH_ADDR}/memory")
        req.add_header("Authorization", "Bearer " + secret)
        with urllib.request.urlopen(req, timeout=6) as r:
            first = json.loads((r.readline() or b"{}").decode() or "{}")
            try:
                second = json.loads((r.readline() or b"{}").decode() or "{}")
            except Exception:  # noqa: BLE001
                second = {}
            return second if second.get("inuse") else first

    try:
        conns = get("/connections")
        mem = get_memory()
        ver = get("/version")
    except Exception as e:  # noqa: BLE001
        return None, f"mihomo 不可达（smart 出口未启用？）: {e}"
    cl = conns.get("connections") or []
    top = {}
    for c in cl:
        key = c.get("rule") or "(direct)"
        top[key] = top.get(key, 0) + 1
    top5 = sorted(top.items(), key=lambda kv: -kv[1])[:5]
    return {"ok": True, "connections": len(cl),
            "upload": conns.get("uploadTotal", 0), "download": conns.get("downloadTotal", 0),
            "memory": mem.get("inuse", 0), "version": ver.get("version", ""),
            "top_rules": [{"rule": k, "count": v} for k, v in top5]}, None


MIME = {".html": "text/html", ".js": "text/javascript", ".css": "text/css",
        ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png",
        ".woff2": "font/woff2", ".woff": "font/woff", ".map": "application/json",
        ".ico": "image/x-icon", ".webmanifest": "application/manifest+json"}


def static_path(sub):
    """Resolve a /mihomo/* URL path to a file under MIHOMO_STATIC_DIR.
    Returns None for traversal attempts or missing files (with SPA fallback)."""
    sub = sub.split("?", 1)[0].lstrip("/") or "index.html"
    norm = os.path.normpath(sub)
    if norm.startswith("..") or os.path.isabs(norm):
        return None
    root = os.path.realpath(MIHOMO_STATIC_DIR)
    full = os.path.realpath(os.path.join(root, norm))
    try:
        if os.path.commonpath((root, full)) != root:
            return None          # symlink inside the static root pointing out
    except ValueError:
        return None              # unresolvable/mixed paths: reject
    if os.path.isfile(full):
        return full
    fallback = os.path.join(root, "index.html")
    if os.path.isfile(fallback):
        return fallback
    return None


def read_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception:  # noqa: BLE001
        return ""


def current_exit():
    return read_file(CONF_DIR + "/current-exit").strip() or "local"


# --- component versions (metacubexd dashboard / mihomo engine) ----------------
_latest_cache = {}   # repo -> (monotonic ts, version|None); 10-minute TTL
_LATEST_TTL = 600


def _read_version(path):
    text = read_file(path).strip()
    return text.splitlines()[0].strip() if text else None


def github_latest(repo, timeout=8):
    """Latest release tag (x.y.z, no leading v) for a GitHub repo, cached."""
    now = time.monotonic()
    hit = _latest_cache.get(repo)
    if hit and now - hit[0] < _LATEST_TTL:
        return hit[1]
    ver = None
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/releases/latest",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "5gpn-api"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            tag = str(json.load(resp).get("tag_name", ""))
        m = re.search(r"\d+\.\d+\.\d+", tag)
        ver = m.group(0) if m else None
    except Exception:  # noqa: BLE001
        ver = None
    _latest_cache[repo] = (now, ver)
    return ver


def component_versions():
    return {name: {"current": _read_version(spec["version_file"]),
                   "pinned": _read_version(spec["pin_file"]),
                   "latest": github_latest(spec["repo"])}
            for name, spec in COMPONENTS.items()}


def list_exits():
    names = set()
    try:
        for f in os.listdir(EXITS_DIR):
            if f.endswith(".type"):
                names.add(f[:-5])
    except Exception:  # noqa: BLE001, S110
        pass
    try:
        for f in os.listdir(WG_DIR):
            if f.startswith("pgw-") and f.endswith(".conf"):
                names.add(f[4:-5])
    except Exception:  # noqa: BLE001, S110
        pass
    cur = current_exit()
    out = []
    for n in sorted(names):
        if n in ("local", "smart"):
            continue
        t = read_file(EXITS_DIR + f"/{n}.type").strip() or "wireguard"
        server = ""
        try:
            with open(EXITS_DIR + f"/{n}.json") as f:
                o = json.load(f)["outbounds"][0]
            if o.get("server"):
                server = f"{o['server']}:{o.get('server_port', '')}"
        except Exception:  # noqa: BLE001, S110
            pass
        out.append({"name": n, "type": t, "server": server, "active": n == cur})
    return out, cur


def policy_map():
    d = {}
    for line in read_file(POLICY_MAP).splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def memory():
    try:
        mi = {}
        for line in read_file("/proc/meminfo").splitlines():
            k, _, v = line.partition(":")
            mi[k.strip()] = int(v.strip().split()[0])  # kB
        total = mi.get("MemTotal", 0) // 1024
        avail = mi.get("MemAvailable", 0) // 1024
        sw_t = mi.get("SwapTotal", 0) // 1024
        sw_f = mi.get("SwapFree", 0) // 1024
        return {"total_mb": total, "available_mb": avail, "used_mb": max(0, total - avail),
                "swap_total_mb": sw_t, "swap_used_mb": max(0, sw_t - sw_f)}
    except Exception:  # noqa: BLE001
        return {}


def parse_rules(text):
    """Parse non-comment rule lines into {i (1-based), raw, type, value, target}."""
    out, i = [], 0
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s[0] in "#;":
            continue
        i += 1
        parts = [p.strip() for p in s.split(",")]
        typ = parts[0].upper() if parts else ""
        if typ == "FINAL" and len(parts) >= 2:
            value, target = "", parts[-1]
        elif len(parts) >= 3:
            value, target = ",".join(parts[1:-1]), parts[-1]
        elif len(parts) == 2:
            value, target = parts[1], ""
        else:
            value, target = "", ""
        out.append({"i": i, "raw": s, "type": typ, "value": value, "target": target})
    return out


def rules_set(text):
    return ctl("--set-rules", inp=text, timeout=400)


def parse_check(out):
    res = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 2 and p[-1] in ("UP", "DOWN", "n/a", "udp"):
            res.append({"name": p[0], "server": p[1] if len(p) >= 3 else "", "state": p[-1]})
    return res


# --- server resources (CPU / mem / disk / uptime / load) --------------------
_cpu_lock = threading.Lock()
_cpu_cache = (0.0, 0.0)
_cpu_prev = None


def _cpu_snap():
    f = [int(x) for x in read_file("/proc/stat").splitlines()[0].split()[1:]]
    idle = f[3] + (f[4] if len(f) > 4 else 0)
    return sum(f), idle


def cpu_percent(window=0.25):
    del window  # kept for callers; sampling is cache/delta based and non-blocking.
    global _cpu_cache, _cpu_prev
    now = time.monotonic()
    with _cpu_lock:
        ts, val = _cpu_cache
        if now - ts < 2.0:
            return val
        try:
            cur = _cpu_snap()
            if _cpu_prev:
                dt, di = cur[0] - _cpu_prev[0], cur[1] - _cpu_prev[1]
                val = round((1 - di / dt) * 100, 1) if dt > 0 else 0.0
            else:
                val = 0.0
            _cpu_prev = cur
            _cpu_cache = (now, val)
            return val
        except Exception:  # noqa: BLE001
            _cpu_cache = (now, 0.0)
            return 0.0


def resources():
    r = memory()
    try:
        s = os.statvfs("/")
        r["disk_total_mb"] = (s.f_blocks * s.f_frsize) // (1024 * 1024)
        r["disk_used_mb"] = ((s.f_blocks - s.f_bfree) * s.f_frsize) // (1024 * 1024)
    except Exception:  # noqa: BLE001, S110
        pass
    try:
        r["uptime_sec"] = int(float(read_file("/proc/uptime").split()[0]))
    except Exception:  # noqa: BLE001, S110
        pass
    try:
        r["load"] = [float(x) for x in read_file("/proc/loadavg").split()[:3]]
    except Exception:  # noqa: BLE001, S110
        pass
    r["cpu_cores"] = os.cpu_count() or 1
    r["cpu_percent"] = cpu_percent()
    return r


# --- 24h traffic ring buffer (per pgw-* exit device + the primary NIC) -------
_traffic_lock = threading.Lock()


def primary_iface():
    try:
        for line in read_file("/proc/net/route").splitlines()[1:]:
            f = line.split()
            if len(f) >= 2 and f[1] == "00000000":
                return f[0]
    except Exception:  # noqa: BLE001, S110
        pass
    return "eth0"


def read_net_dev():
    out = {}
    for line in read_file("/proc/net/dev").splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 9:
            try:
                out[name.strip()] = {"rx": int(f[0]), "tx": int(f[8])}
            except ValueError:
                pass
    return out


def tracked(dev, primary):
    # device name -> friendly label ("server" or the exit name)
    m = {}
    for n in dev:
        if n == primary:
            m[n] = "server"
        elif n.startswith("pgw-"):
            m[n] = n[4:]
    return m


def _load_traffic():
    try:
        return json.load(open(TRAFFIC_FILE))
    except Exception:  # noqa: BLE001
        return {"interval_sec": TRAFFIC_INTERVAL, "raw": {}, "raw_ts": 0, "points": []}


def _save_traffic(data):
    try:
        tmp = TRAFFIC_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, TRAFFIC_FILE)
    except Exception:  # noqa: BLE001, S110
        pass


def traffic_tick():
    with _traffic_lock:
        data = _load_traffic()
        primary = primary_iface()
        dev = read_net_dev()
        now = int(time.time())
        raw = data.get("raw", {})
        # Append a delta point, but skip if there was a long gap (avoids a spike
        # lumping all of the downtime's traffic into one bucket).
        if raw and data.get("raw_ts") and 0 < (now - data["raw_ts"]) <= TRAFFIC_INTERVAL * 3:
            d = {}
            for dn, lbl in tracked(dev, primary).items():
                if dn in raw:
                    d[lbl] = [max(0, dev[dn]["rx"] - raw[dn]["rx"]),
                              max(0, dev[dn]["tx"] - raw[dn]["tx"])]
            if d:
                data.setdefault("points", []).append({"t": now, "v": d})
                data["points"] = data["points"][-TRAFFIC_MAX:]
        data["raw"] = {dn: dev[dn] for dn in tracked(dev, primary)}
        data["raw_ts"] = now
        data["interval_sec"] = TRAFFIC_INTERVAL
        _save_traffic(data)
        try:
            rollup_traffic(data.get("points", []), now=now)
        except Exception:  # noqa: BLE001, S110
            pass


def traffic_loop():
    try:
        traffic_tick()      # establish a baseline immediately
    except Exception:  # noqa: BLE001, S110
        pass
    while True:
        time.sleep(TRAFFIC_INTERVAL)
        try:
            traffic_tick()
        except Exception:  # noqa: BLE001, S110
            pass


# --- daily rollup (62d history, UTC day buckets) ------------------------------
# The 24h rings above survive restarts but age out after a day; the rollup
# aggregates each completed UTC day once (marker in hist["done"]) so the webui
# can show 7d/30d windows. Same atomic .tmp + os.replace write pattern.


def _utc_day(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return default


def _save_json(path, obj):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001, S110
        pass


def _rollup_days(ring_points, hist, value_fn, now=None):
    """Fold every completed UTC day found in ring_points into hist['days']
    exactly once; prune to HISTORY_DAYS. Returns hist (mutated)."""
    now = time.time() if now is None else now
    today = _utc_day(now)
    days = hist.setdefault("days", {})
    done = set(hist.get("done", []))
    by_day = {}
    for p in ring_points:
        d = _utc_day(p.get("t", 0))
        if d < today and d not in done:
            by_day.setdefault(d, []).append(p)
    for d in sorted(by_day):
        days[d] = value_fn(by_day[d], days.get(d))
        done.add(d)
    hist["done"] = sorted(done)[-HISTORY_DAYS:]
    for old in sorted(days)[:-HISTORY_DAYS]:
        days.pop(old, None)
    return hist


def _traffic_day_value(pts, bucket):
    bucket = bucket or {}
    for p in pts:
        for lbl, pair in (p.get("v") or {}).items():
            if isinstance(pair, list) and len(pair) == 2:
                cur = bucket.setdefault(lbl, [0, 0])
                cur[0] += pair[0]
                cur[1] += pair[1]
    return bucket


def _latency_day_value(pts, bucket):
    bucket = bucket or {}
    for p in pts:
        for name, ms in (p.get("v") or {}).items():
            if not isinstance(ms, (int, float)):
                continue
            cur = bucket.setdefault(name, {"sum": 0.0, "n": 0, "min": None, "max": None})
            cur["sum"] += ms
            cur["n"] += 1
            cur["min"] = ms if cur["min"] is None else min(cur["min"], ms)
            cur["max"] = ms if cur["max"] is None else max(cur["max"], ms)
    return bucket


def rollup_traffic(points, now=None):
    hist = _rollup_days(points, _load_json(HISTORY_TRAFFIC_FILE, {}),
                        _traffic_day_value, now=now)
    _save_json(HISTORY_TRAFFIC_FILE, hist)


def rollup_latency(points, now=None):
    hist = _rollup_days(points, _load_json(HISTORY_LATENCY_FILE, {}),
                        _latency_day_value, now=now)
    _save_json(HISTORY_LATENCY_FILE, hist)


def daily_series(hist_days, n, now, current=None, value_map=None):
    """Uniform chart payload for the webui: one synthetic point per UTC day
    (midnight), same shape as /api/traffic & /api/latency. `current` is the
    in-progress today's bucket (not yet persisted)."""
    n = max(1, min(HISTORY_DAYS, n))
    today = _utc_day(now)
    days = dict(hist_days or {})
    if current:
        days[today] = current
    keys = sorted(days)[-n:]
    points = []
    names = set()
    for d in keys:
        v = days[d]
        if value_map:
            v = value_map(v)
        names.update(v.keys())
        ts = calendar.timegm(time.strptime(d, "%Y-%m-%d"))
        points.append({"t": ts, "v": v})
    return {"ok": True, "now": int(now), "interval_sec": 86400,
            "series": sorted(names), "points": points}


def _current_traffic_day(data, now=None):
    return _traffic_day_value(
        [p for p in data.get("points", []) if _utc_day(p.get("t", 0)) == _utc_day(now or time.time())],
        {})


def _current_latency_day(data, now=None):
    return _latency_day_value(
        [p for p in data.get("points", []) if _utc_day(p.get("t", 0)) == _utc_day(now or time.time())],
        {})


def _latency_avg_map(bucket):
    return {name: round(v["sum"] / v["n"], 1)
            for name, v in (bucket or {}).items() if v.get("n")}



# --- exit latency (ICMP ping, falling back to TCP-ping) + 24h history --------
_lat_lock = threading.Lock()


def _uri_host_port(uri):
    """Best-effort (host, port) from a proxy URI (SIP002 / standard forms)."""
    try:
        u = urllib.parse.urlsplit(uri)
    except ValueError:
        return None, None
    if u.scheme == "ss" and "@" not in u.netloc:
        # legacy ss://base64(method:pass@host:port)#tag
        try:
            dec = base64.b64decode(u.netloc + "===").decode("utf-8", "ignore")
            m = re.search(r"@([^@:/]+):(\d+)$", dec)
            if m:
                return m.group(1), int(m.group(2))
        except Exception:  # noqa: BLE001, S110
            pass
        return None, None
    if u.scheme == "vmess" and "@" not in u.netloc:
        # vmess://base64(json share object)
        try:
            o = json.loads(base64.b64decode(u.netloc + "===").decode("utf-8", "ignore"))
            host = o.get("add") or o.get("host")
            return host, int(o.get("port") or 443) if host else (None, None)
        except Exception:  # noqa: BLE001
            return None, None
    if u.hostname:
        try:
            port = u.port
        except ValueError:
            port = None
        return u.hostname, port or (80 if u.scheme == "http" else 443)
    return None, None


def exit_endpoint(name):
    """(host, port) of an exit's upstream node, or (None, None)."""
    t = read_file(EXITS_DIR + f"/{name}.type").strip()
    if t == "wireguard":
        m = re.search(r"(?im)^\s*Endpoint\s*=\s*(.+):(\d+)\s*$", read_file(WG_DIR + f"/pgw-{name}.conf"))
        if m:
            return m.group(1), int(m.group(2))
        return None, None
    # URI exits keep the original link in <name>.uri (mihomo TUN engine)
    first = read_file(EXITS_DIR + f"/{name}.uri").strip().splitlines()
    if first:
        return _uri_host_port(first[0].strip())
    return None, None


def ping_ms(host):
    ok, out = run(["ping", "-n", "-c", "1", "-W", "1", host], timeout=4)
    if ok:
        m = re.search(r"time[=<]\s*([\d.]+)\s*ms", out)
        if m:
            return float(m.group(1))
    return None


def tcp_ms(host, port):
    try:
        t0 = time.monotonic()
        s = socket.create_connection((host, port), timeout=3)
        s.close()
        return (time.monotonic() - t0) * 1000.0
    except Exception:  # noqa: BLE001
        return None


UDP_EXIT_TYPES = ("hysteria2", "tuic", "masque")


def clash_delay_ms(name):
    """Real HTTP delay through the smart router's Clash API. Only available
    while the smart instance is running (exit = smart)."""
    query = urllib.parse.urlencode({"timeout": "3000", "url": "http://www.gstatic.com/generate_204"})
    status, _ctype, data = clash_request("GET", f"proxies/{name}/delay?{query}", timeout=6)
    if status != 200:
        return None
    try:
        return round(float(json.loads(data).get("delay")), 1)
    except Exception:  # noqa: BLE001
        return None


def measure_latency(name):
    typ = read_file(EXITS_DIR + f"/{name}.type").strip()
    if typ in UDP_EXIT_TYPES:
        # UDP transports: ICMP echo and TCP connect are not applicable (MASQUE
        # has no TCP listener at all). Measure the real delay through the
        # smart router's Clash API instead.
        ms = clash_delay_ms(name)
        return {"ms": ms, "method": "http" if ms is not None else None}
    host, port = exit_endpoint(name)
    if not host:
        return {"ms": None, "method": None}
    p = ping_ms(host)
    if p is not None:
        return {"ms": round(p, 1), "method": "icmp"}
    if port:
        t = tcp_ms(host, port)
        if t is not None:
            return {"ms": round(t, 1), "method": "tcp"}
    return {"ms": None, "method": None}


def all_latency():
    names = [e["name"] for e in list_exits()[0]]
    res = {}
    threads = []

    def work(n):
        res[n] = measure_latency(n)
    for n in names:
        th = threading.Thread(target=work, args=(n,))
        th.start()
        threads.append(th)
    for th in threads:
        th.join(timeout=8)
    return res


def _load_latency():
    try:
        return json.load(open(LATENCY_FILE))
    except Exception:  # noqa: BLE001
        return {"interval_sec": LATENCY_INTERVAL, "points": []}


def _save_latency(data):
    try:
        tmp = LATENCY_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, LATENCY_FILE)
    except Exception:  # noqa: BLE001, S110
        pass


def latency_tick():
    res = all_latency()
    with _lat_lock:
        data = _load_latency()
        v = {n: res[n]["ms"] for n in res}   # ms, or None on timeout
        data.setdefault("points", []).append({"t": int(time.time()), "v": v})
        data["points"] = data["points"][-TRAFFIC_MAX:]
        data["interval_sec"] = LATENCY_INTERVAL
        _save_latency(data)
        try:
            rollup_latency(data.get("points", []))
        except Exception:  # noqa: BLE001, S110
            pass


def latency_loop():
    while True:
        try:
            latency_tick()
        except Exception:  # noqa: BLE001, S110
            pass
        time.sleep(LATENCY_INTERVAL)


# --- AI assistant: bind an OpenAI-compatible API, propose a routing plan ------
AI_SYS = (
    "你是 5gpn 网关的分流配置助手。根据用户意图和给定的 GitHub 仓库，产出一份分流方案。\n"
    "规则语法(每条一行): TYPE,VALUE,TARGET。TYPE ∈ {DOMAIN-SUFFIX,DOMAIN,DOMAIN-KEYWORD,"
    "IP-CIDR,RULE-SET,GEOSITE,GEOIP}；兜底用 FINAL,TARGET。\n"
    "RULE-SET 的 VALUE 是一个可直接 HTTP 访问的规则列表 URL(可用仓库的 raw 前缀拼接其中的规则文件路径)。\n"
    "TARGET 必须是: 某个可用出口名 / direct / block / 或一个你新建的分类名。\n"
    "若意图是用某出口加速(例如“走 IIJ 加速”), 把相关域名/规则集归到一个分类, 并在 policy 里把该分类映射到该出口。\n"
    "只输出 JSON, 不要任何解释性文字或 markdown 围栏, 结构: "
    '{"rules":["TYPE,VALUE,TARGET", ...], "policy":{"分类名":"出口名"}, "explanation":"中文一句话说明"}。\n'
    "rules 里出现的分类名必须在 policy 里给出映射; 优先用仓库里现成的规则集文件(RULE-SET), 没有再用该服务的核心域名(DOMAIN-SUFFIX)。"
)


def _ai_config():
    try:
        return json.load(open(AI_CONF))
    except Exception:  # noqa: BLE001
        return {}


def _save_ai_config(cfg):
    try:
        tmp = AI_CONF + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, AI_CONF)
        return True
    except Exception:  # noqa: BLE001
        return False


def _http_json(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "5gpn", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(1_000_000).decode("utf-8", "ignore"))


def _http_text(url, timeout=20, limit=8000):
    req = urllib.request.Request(url, headers={"User-Agent": "5gpn"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(limit).decode("utf-8", "ignore")


def github_context(repo_url):
    m = re.search(r"github\.com/([^/\s]+)/([^/\s#?]+)", repo_url or "")
    if not m:
        return None
    owner, repo = m.group(1), m.group(2).replace(".git", "")
    info = _http_json(f"https://api.github.com/repos/{owner}/{repo}")
    branch = info.get("default_branch", "main")
    ctx = {"owner": owner, "repo": repo, "branch": branch,
           "description": info.get("description") or "",
           "raw_base": f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/",
           "files": [], "readme": ""}
    try:
        for it in _http_json(f"https://api.github.com/repos/{owner}/{repo}/contents"):
            if it.get("type") == "file" and re.search(r"\.(list|ya?ml|txt|conf|srs)$", it.get("name", ""), re.IGNORECASE):
                ctx["files"].append(it["path"])
        ctx["files"] = ctx["files"][:40]
    except Exception:  # noqa: BLE001, S110
        pass
    for fn in ("README.md", "readme.md", "README.MD"):
        try:
            ctx["readme"] = _http_text(ctx["raw_base"] + fn, limit=3000)
            if ctx["readme"]:
                break
        except Exception:  # noqa: BLE001, S112
            continue
    return ctx


def ai_chat(cfg, user):
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": cfg.get("model") or "gpt-4o-mini",
        "temperature": 0.2,
        "messages": [{"role": "system", "content": AI_SYS}, {"role": "user", "content": user}],
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + cfg["key"]})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.loads(r.read(2_000_000).decode("utf-8", "ignore"))
    return data["choices"][0]["message"]["content"]


def extract_json(text):
    t = (text or "").strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if m:
        t = m.group(1).strip()
    i, j = t.find("{"), t.rfind("}")
    if 0 <= i < j:
        try:
            return json.loads(t[i:j + 1])
        except Exception:  # noqa: BLE001
            return None
    return None


def ai_plan(repo, intent):
    cfg = _ai_config()
    if not cfg.get("base_url") or not cfg.get("key"):
        return None, "AI 未配置（先在面板填入 Base URL 和 Key）"
    ctx = None
    try:
        ctx = github_context(repo) if repo else None
    except Exception as e:  # noqa: BLE001
        ctx = {"error": f"仓库读取失败: {e}"}
    exits = [e["name"] for e in list_exits()[0]]
    cats = list(policy_map().keys())
    lines = ["意图: " + intent, "",
             "可用出口: " + (", ".join(exits) or "(无)"),
             "现有分类: " + (", ".join(cats) or "(无)")]
    if ctx and not ctx.get("error"):
        lines += ["", f"GitHub 仓库: {ctx['owner']}/{ctx['repo']}",
                  "描述: " + ctx["description"], "raw 前缀: " + ctx["raw_base"]]
        if ctx["files"]:
            lines.append("规则文件:")
            lines += ["  - " + f for f in ctx["files"]]
        if ctx["readme"]:
            lines += ["README 摘要:", ctx["readme"][:2500]]
    elif ctx and ctx.get("error"):
        lines += ["", ctx["error"]]
    try:
        raw = ai_chat(cfg, "\n".join(lines))
    except Exception as e:  # noqa: BLE001
        return None, f"AI 调用失败: {e}"
    return {"plan": extract_json(raw), "raw": raw, "exits": exits}, None


# --- live stats (instantaneous rate + connection count) ----------------------
_live_lock = threading.Lock()
_live_prev = {"t": 0.0, "dev": {}}
_conn_lock = threading.Lock()
_conn_cache = {"t": 0.0, "conns": 0}


def live_stats():
    primary = primary_iface()
    dev = read_net_dev()
    now = time.monotonic()
    with _live_lock:
        prev_t = float(_live_prev.get("t") or 0.0)
        prev_dev = _live_prev.get("dev") or {}
        dt = now - prev_t

        def rate(n):
            if dt >= 0.5 and n in prev_dev and n in dev:
                return (int(max(0, dev[n]["rx"] - prev_dev[n]["rx"]) / dt),
                        int(max(0, dev[n]["tx"] - prev_dev[n]["tx"]) / dt))
            return 0, 0

        srx, stx = rate(primary)
        exits = {}
        for n in dev:
            if n.startswith("pgw-"):
                rx, tx = rate(n)
                exits[n[4:]] = {"rx": rx, "tx": tx}
        _live_prev["t"] = now
        _live_prev["dev"] = dev

    with _conn_lock:
        conns = _conn_cache["conns"]
        if now - _conn_cache["t"] >= 5.0:
            ok, out = run(["ss", "-tnH", "state", "established"], timeout=4)
            if ok:
                conns = len([x for x in out.splitlines() if x.strip()])
            _conn_cache["t"] = now
            _conn_cache["conns"] = conns
    return {"server": {"rx": srx, "tx": stx}, "exits": exits, "conns": conns}


# --- route tester: would this domain be hijacked, and to which exit? ----------
_gfw_lock = threading.Lock()
_gfw_cache = (None, set())


def gfwlist_set():
    global _gfw_cache
    path = "/etc/mosdns/gfwlist.txt"
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    with _gfw_lock:
        if _gfw_cache[0] == mtime:
            return set(_gfw_cache[1])
    s = set()
    for line in read_file(path).splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            s.add(line.strip("."))
    with _gfw_lock:
        _gfw_cache = (mtime, set(s))
    return s


def direct_domains_set():
    s = set()
    for line in read_file(DIRECT_DOMAINS_FILE).splitlines():
        line = line.strip().lower().strip(".")
        if line and not line.startswith("#"):
            s.add(line)
    return s


def _domain_hijacked(d, gset):
    parts = d.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in gset:
            return True
    return d in gset


def list_direct_domains():
    out = []
    for line in read_file(DIRECT_DOMAINS_FILE).splitlines():
        d = line.strip().lower().strip(".")
        if d and not d.startswith("#") and DOMAIN_RE.match(d):
            out.append(d)
    # stable unique order
    seen, uniq = set(), []
    for d in out:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


def _split_client_cidrs(value):
    raw = str(value or "").replace("\n", ",")
    return [p.strip() for p in raw.split(",") if p.strip()]


def _normalize_client_cidrs(value):
    parts = _split_client_cidrs(value)
    if not parts:
        return None
    force_wide = os.environ.get("FORCE_WIDE_CIDR", "0") == "1"
    out = []
    seen = set()
    for part in parts:
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            return None
        if net.version != 4 or not (8 <= net.prefixlen <= 30):
            return None
        if net.prefixlen < 16 and not force_wide:
            return None
        norm = str(net)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def get_client_cidrs():
    raw = (read_file(CLIENT_CIDR_FILE) or CLIENT_CIDR_DEFAULT).strip()
    cidrs = _normalize_client_cidrs(raw)
    return cidrs or [CLIENT_CIDR_DEFAULT]


def get_client_cidr():
    return ",".join(get_client_cidrs())


def validate_client_cidr(value):
    cidrs = _normalize_client_cidrs(value)
    return ",".join(cidrs) if cidrs else None


def route_test(domain):
    d = (domain or "").lower().strip().strip(".").lstrip("*.")
    if not d or "." not in d:
        return {"error": "请输入合法域名"}
    gset = gfwlist_set()
    dset = direct_domains_set()
    in_direct = _domain_hijacked(d, dset)
    in_gfw = _domain_hijacked(d, gset)
    final = None
    matched = None
    for raw in read_file(RULES_FILE).splitlines():
        s = raw.strip()
        if not s or s[0] in "#;":
            continue
        p = [x.strip() for x in s.split(",")]
        typ = p[0].upper()
        if typ == "FINAL" and len(p) >= 2:
            final = p[-1]
            continue
        if matched:
            continue
        if typ == "DOMAIN-SUFFIX" and len(p) >= 3:
            v = p[1].lower().lstrip(".")
            if d == v or d.endswith("." + v):
                matched = (s, p[-1])
        elif typ == "DOMAIN" and len(p) >= 3 and d == p[1].lower() or typ == "DOMAIN-KEYWORD" and len(p) >= 3 and p[1].lower() in d:
            matched = (s, p[-1])
    pm = policy_map()
    cat = matched[1] if matched else (final or "Proxy")
    target = cat if cat in ("direct", "block") else pm.get(cat, cat)
    # Private-client spoof: everything except ChinaList / direct-domains.
    # ChinaList is not fully expanded here; direct bypass is authoritative.
    hijacked = not in_direct
    return {"domain": d, "hijacked": hijacked, "direct_bypass": in_direct,
            "in_gfwlist": in_gfw,
            "matched": matched[0] if matched else ("FINAL," + (final or "?")),
            "category": cat, "target": target,
            "note": "私网客户端（172.22.0.0/16）：直连名单内域名返回真实 A 记录；"
                    "其余非 ChinaList 域名解析为网关 IP。公网 DoT 默认不劫持。"
                    " RULE-SET / GEOSITE / IP-CIDR / ChinaList 未在此展开。"}


# --- config backup / restore -------------------------------------------------
BACKUP_PATHS = ["etc/5gpn", "etc/mosdns/gfwlist-extra-local.txt",
                "etc/mosdns/direct-domains.txt", "etc/mosdns/.client_cidr",
                "etc/mosdns/.remote_dns", "etc/mosdns/.local_dns",
                "etc/mosdns/.ecs", "etc/mosdns/.sniproxy_dns",
                "etc/wireguard", "opt/5gpn/etc/current-exit",
                "opt/5gpn/etc/.client_cidr", "opt/5gpn/etc/client-socks.port",
                "opt/5gpn/etc/client-mtproto.port", "opt/5gpn/etc/clash-remote.port"]


def _backup_secret_name(name):
    base = os.path.basename(name).lower()
    if base in ("api.env", "tgbot.env", "client-socks.env", "client-mtproto.env",
                "clash-remote.env", "mtg.toml", "mtprotoproxy.conf.py", "mihomo-api-secret"):
        return True
    if base.endswith(".pem"):
        return True
    return any(x in base for x in ("secret", "token", "passwd", "password"))


def _backup_filter(ti):
    """Default backup excludes secret-looking filenames. A future query/param
    can opt into sensitive material explicitly; for now all API backups are
    redacted by filename."""
    name = ti.name.lstrip("./")
    if "/rulesets" in name or _backup_secret_name(name):
        return None
    return ti


def make_backup():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel in BACKUP_PATHS:
            full = "/" + rel
            if not os.path.exists(full):
                continue
            if rel == "etc/wireguard":
                for f in os.listdir(full):           # only pgw-*.conf
                    if f.startswith("pgw-") and f.endswith(".conf"):
                        tf.add(os.path.join(full, f), arcname=rel + "/" + f,
                               filter=_backup_filter)
            elif rel == "etc/5gpn":
                tf.add(full, arcname=rel, filter=_backup_filter)
            else:
                tf.add(full, arcname=rel, filter=_backup_filter)
    return buf.getvalue()


def _backup_allowed(name):
    name = name.lstrip("./")
    if ".." in name.split("/"):
        return False
    if _backup_secret_name(name):
        return False
    return bool((name == "etc/5gpn" or name.startswith("etc/5gpn/"))
                or name == "etc/mosdns/gfwlist-extra-local.txt"
                or name == "etc/mosdns/direct-domains.txt"
                or name in ("etc/mosdns/.client_cidr", "etc/mosdns/.remote_dns",
                            "etc/mosdns/.local_dns", "etc/mosdns/.ecs",
                            "etc/mosdns/.sniproxy_dns")
                or re.match(r"etc/wireguard/pgw-[^/]+\.conf$", name)
                or name in ("opt/5gpn/etc/current-exit", "opt/5gpn/etc/.client_cidr",
                            "opt/5gpn/etc/client-socks.port",
                            "opt/5gpn/etc/client-mtproto.port",
                            "opt/5gpn/etc/clash-remote.port"))


def restore_backup(b64):
    raw = base64.b64decode(b64)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        members = [m for m in tf.getmembers() if (m.isfile() or m.isdir()) and _backup_allowed(m.name)]
        if not members:
            return False, "备份内容无效（无可识别的配置文件）"
        tf.extractall("/", members=members)
    ctl("--set-rules", inp=read_file(RULES_FILE), timeout=400)   # rebuild router from restored rules
    run(["systemctl", "restart", "mosdns"], timeout=30)          # pick up restored lists
    run(["/usr/local/bin/5gpn-apply-exit.sh"], timeout=30)
    return True, f"已恢复 {len(members)} 个文件，并重建路由。如需重建劫持名单可再执行『更新规则集』。"


def _tok_eq(a, b):
    """hmac.compare_digest that rejects non-ASCII input instead of raising."""
    try:
        return hmac.compare_digest(a, b)
    except TypeError:
        return False


def _json_output(out):
    try:
        return json.loads(out or "{}")
    except Exception:  # noqa: BLE001
        return extract_json(out)


def _doctor_env():
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/root",
        "BASE_DIR": "/opt/5gpn",
        "CONF_DIR": CONF_DIR,
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }


def run_doctor_json():
    """Run doctor.sh --json with a sudo-like environment.

    Prefer systemd-run so systemctl/ip/nft probes match interactive
    `sudo 5gpn doctor` (API's inherited PATH is often too minimal).
    """
    doctor = DOCTOR if os.path.isfile(DOCTOR) else "/opt/5gpn/scripts/doctor.sh"
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
    try:
        p = subprocess.run(systemd_cmd, capture_output=True, text=True, timeout=180,
                           encoding="utf-8", errors="replace", check=False)
        out = ANSI.sub("", (p.stdout or "")).strip()
        if out:
            return p.returncode == 0, out
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    try:
        p = subprocess.run(["/bin/bash", doctor, "--json"],
                           capture_output=True, text=True, timeout=180,
                           env=_doctor_env(), encoding="utf-8", errors="replace", check=False)
        out = ANSI.sub("", (p.stdout or "") + (p.stderr or "")).strip()
        return p.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, "操作超时"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def parse_doctor_json(out):
    raw = (out or "").strip()
    if not raw:
        return None
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return _json_output(raw)


def report_path(out):
    for line in reversed((out or "").splitlines()):
        s = line.strip()
        if s.startswith("report written:"):
            return s.split(":", 1)[1].strip()
        if s.startswith("/"):
            return s
    return ""


def parse_snapshots(out):
    rows = []
    for line in (out or "").splitlines()[1:]:
        line = line.rstrip()
        if not line.strip():
            continue
        parts = re.split(r"\s{2,}", line, maxsplit=2)
        if len(parts) < 3:
            continue
        label = parts[2].strip()
        latest = label.endswith("*")
        if latest:
            label = label[:-1].rstrip()
        rows.append({"id": parts[0].strip(), "git": parts[1].strip(),
                     "label": label, "latest": latest})
    return rows


def _metric_label(v):
    return re.sub(r'["\\\n]', "_", str(v))


def metrics_text():
    live = live_stats()
    mem = memory()
    cpu = cpu_percent()
    lines = [
        "# HELP pgw_api_process_up API process liveness.",
        "# TYPE pgw_api_process_up gauge",
        "pgw_api_process_up 1",
        "# HELP pgw_api_process_uptime_seconds API process uptime.",
        "# TYPE pgw_api_process_uptime_seconds gauge",
        f"pgw_api_process_uptime_seconds {max(0, time.time() - STARTED):.0f}",
        "# HELP pgw_api_cpu_percent CPU usage percent.",
        "# TYPE pgw_api_cpu_percent gauge",
        f"pgw_api_cpu_percent {cpu:.1f}",
        "# HELP pgw_api_memory_bytes Memory size in bytes.",
        "# TYPE pgw_api_memory_bytes gauge",
        f'pgw_api_memory_bytes{{kind="total"}} {int(mem.get("total_mb", 0)) * 1024 * 1024}',
        f'pgw_api_memory_bytes{{kind="used"}} {int(mem.get("used_mb", 0)) * 1024 * 1024}',
        "# HELP pgw_api_live_bytes_per_second Instantaneous network rate.",
        "# TYPE pgw_api_live_bytes_per_second gauge",
        f'pgw_api_live_bytes_per_second{{scope="server",direction="rx"}} {live["server"]["rx"]}',
        f'pgw_api_live_bytes_per_second{{scope="server",direction="tx"}} {live["server"]["tx"]}',
    ]
    for name, vals in sorted(live.get("exits", {}).items()):
        label = _metric_label(name)
        lines.append(f'pgw_api_live_bytes_per_second{{scope="exit",exit="{label}",direction="rx"}}'
                     f' {vals.get("rx", 0)}')
        lines.append(f'pgw_api_live_bytes_per_second{{scope="exit",exit="{label}",direction="tx"}}'
                     f' {vals.get("tx", 0)}')
    lines += [
        "# HELP pgw_api_live_connections Established TCP connections.",
        "# TYPE pgw_api_live_connections gauge",
        f"pgw_api_live_connections {int(live.get('conns', 0))}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def webui_index_path():
    full = os.path.realpath(os.path.join(WEBUI_DIR, "index.html"))
    root = os.path.realpath(WEBUI_DIR)
    try:
        if os.path.commonpath((root, full)) != root:
            return None
    except ValueError:
        return None
    return full if os.path.isfile(full) else None


class Handler(BaseHTTPRequestHandler):
    server_version = "pgw-api"

    def log_message(self, *a):  # keep the journal quiet — request lines may carry ?token= credentials
        pass

    def _cors(self):
        """CORS is opt-in by default. Set API_ALLOW_ORIGIN to a concrete
        origin, or explicitly to * for wildcard behavior."""
        if ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

    def _sec_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Referrer-Policy", "same-origin")

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._sec_headers()
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:  # noqa: BLE001, S110
            pass

    def _send_raw(self, code, data, ctype="application/json", extra=None):
        self.send_response(code)
        if "charset" not in ctype and ctype.startswith(("text/", "application/json")):
            ctype += "; charset=utf-8"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self._sec_headers()
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:  # noqa: BLE001, S110
            pass

    def _auth(self):
        """Bearer 是主凭据。浏览器无法给 iframe/WS 子请求加自定义头，因此
        额外接受 ?token= query 凭据，但仅限两类 GET 请求：
          (a) /mihomo 静态文件（iframe 文档及其资源）；
          (b) /api/mihomo/proxy/ 下且属 WS 白名单的 Upgrade 请求。
        其余路径一律不认 query token。query 鉴权成功的 /mihomo 响应会种一个
        pgw_mihomo 同源不透明短期会话 cookie；该 cookie 放行 /mihomo 静态与
        /api/mihomo/*（全部方法，含 WS Upgrade 与写方法），不覆盖其他 /api/*
        （最小权限，主控制台仍仅 Bearer）。放行写方法的两个前提，改动 cookie
        属性时必须保持：SameSite=Strict —— 跨站请求不携带 cookie，CSRF 不可行；
        HttpOnly —— JS 读不到 cookie 值，XSS 偷不走。"""
        self._via_query = False
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer ") and _tok_eq(h[7:], TOKEN):
            return True
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        is_static = path == "/mihomo" or path.startswith("/mihomo/")
        if is_static or path.startswith("/api/mihomo/"):
            m = re.search(r"(?:^|;\s*)pgw_mihomo=([^;]*)", self.headers.get("Cookie", ""))
            if m and valid_mihomo_session(urllib.parse.unquote(m.group(1))):
                return True
        # PWA metadata is often fetched without cookies; it has no secrets.
        if self.command == "GET" and is_static:
            base = os.path.basename(path.split("?", 1)[0]).lower()
            if base in ("manifest.webmanifest", "favicon.ico", "favicon.svg"):
                return True
        if self.command != "GET":
            return False
        is_ws = False
        if not is_static and path.startswith("/api/mihomo/proxy/") and \
                self.headers.get("Upgrade", "").lower() == "websocket":
            sub = normalize_sub(path.split("/api/mihomo/proxy/", 1)[1])
            is_ws = bool(sub) and sub.split("?", 1)[0] in CLASH_WS_PATHS
        if not (is_static or is_ws):
            return False
        tok = urllib.parse.parse_qs(self.path.partition("?")[2]).get("token", [""])[0]
        if tok and _tok_eq(tok, TOKEN):
            self._via_query = True
            return True
        return False

    def _json_body(self):
        try:
            n = int(self.headers.get("Content-Length", "0") or 0)
            if n <= 0 or n > 2_000_000:
                return {}
            data = self.rfile.read(n).decode("utf-8")
            obj = json.loads(data or "{}")
            return obj if isinstance(obj, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    def _proxy_mihomo(self, sub):
        """Reverse-proxy one request (any method) to the loopback Clash API."""
        try:
            n = int(self.headers.get("Content-Length", "0") or 0)
        except (TypeError, ValueError):
            return self._send(400, {"ok": False, "error": "bad content-length"})
        if n > 2_000_000:
            return self._send(413, {"ok": False, "error": "payload too large"})
        body = self.rfile.read(n) if n > 0 else None
        status, ctype, data = clash_request(self.command, sub, body=body,
                                            ctype=self.headers.get("Content-Type"))
        return self._send_raw(status, data, ctype)

    def _serve_mihomo_static(self, sub):
        full = static_path(sub)
        if not full:
            return self._send(404, {"ok": False, "error": "metacubexd 未安装（运行 install.sh --setup-api）或路径无效"})
        ext = os.path.splitext(full)[1].lower()
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            return self._send(404, {"ok": False, "error": "not found"})
        extra = [("Content-Security-Policy", XD_CSP)]
        # metacubexd is a PWA: stale Service Worker / index.html will keep showing
        # the old appVersion after we replace /opt/5gpn/webui/mihomo. Never cache
        # the shell / SW; hashed _nuxt assets can be immutable.
        base = os.path.basename(full).lower()
        rel = os.path.relpath(full, os.path.realpath(MIHOMO_STATIC_DIR)).replace("\\", "/")
        if base in ("index.html", "sw.js", "200.html", "404.html", "manifest.webmanifest") \
                or base.startswith("workbox-") or rel in (".", "index.html"):
            extra.append(("Cache-Control", "no-cache, no-store, must-revalidate"))
        elif "/_nuxt/" in ("/" + rel) or rel.startswith("_nuxt/"):
            extra.append(("Cache-Control", "public, max-age=31536000, immutable"))
        else:
            extra.append(("Cache-Control", "no-cache"))
        if getattr(self, "_via_query", False):
            # iframe 内相对路径资源与面板 API 调用带不了 ?token=；种同源会话
            # cookie（Path=/ 覆盖 /mihomo 与 /api/mihomo/*）供其鉴权。
            sid = mint_mihomo_session()
            extra.append(("Set-Cookie",
                          f"pgw_mihomo={urllib.parse.quote(sid, safe='')}; Path=/; HttpOnly; Secure; SameSite=Strict"))
        return self._send_raw(200, data, MIME.get(ext, "application/octet-stream"), extra=extra)

    def _serve_webui_index(self):
        full = webui_index_path()
        if not full:
            return self._send(404, {"ok": False, "error": "webui not installed"})
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            return self._send(404, {"ok": False, "error": "webui not installed"})
        return self._send_raw(200, data, "text/html")

    def _dispatch(self, method):
        """PUT/PATCH/DELETE are only routed to the mihomo reverse proxy."""
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if not source_allowed(self.client_address[0]):
            return self._send(403, {"ok": False, "error": "forbidden"})
        if rate_limited_path(path) and not rate_ok(self.client_address[0]):
            return self._send(429, {"ok": False, "error": "请求过于频繁，请稍后再试"})
        if not self._auth():
            return self._send(401, {"ok": False, "error": "unauthorized"})
        if path.startswith("/api/mihomo/proxy/"):
            return self._proxy_mihomo(self.path.split("/api/mihomo/proxy/", 1)[1])
        return self._send(404, {"ok": False, "error": "not found"})

    def do_PUT(self):
        self._dispatch("PUT")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if not source_allowed(self.client_address[0]):
            return self._send(403, {"ok": False, "error": "forbidden"})
        if rate_limited_path(path) and not rate_ok(self.client_address[0]):
            return self._send(429, {"ok": False, "error": "请求过于频繁，请稍后再试"})
        if path == "/api/health":
            return self._send(200, {"ok": True, "service": "5gpn-api"})
        if path in ("/", "/console", "/webui"):
            return self._serve_webui_index()
        if not self._auth():
            return self._send(401, {"ok": False, "error": "unauthorized"})
        if path == "/api/mihomo/overview":
            data, err = mihomo_overview()
            return self._send(200 if data else 502, data or {"ok": False, "error": err})
        if path.startswith("/api/mihomo/proxy/") and self.headers.get("Upgrade", "").lower() == "websocket":
            sub = normalize_sub(self.path.split("/api/mihomo/proxy/", 1)[1])
            if not sub or sub.split("?", 1)[0] not in CLASH_WS_PATHS:
                return self._send(403, {"ok": False, "error": "forbidden"})
            try:
                self.close_connection = True
                ws_relay(self.connection, sub, self.headers)
            except Exception:  # noqa: BLE001, S110
                pass
            return
        if path.startswith("/api/mihomo/proxy/"):
            sub = self.path.split("/api/mihomo/proxy/", 1)[1]
            status, ctype, data = clash_request("GET", sub)
            return self._send_raw(status, data, ctype)
        if path == "/mihomo" or path.startswith("/mihomo/"):
            return self._serve_mihomo_static(self.path[len("/mihomo"):])
        if path == "/api/status":
            exits, cur = list_exits()
            units = list(SERVICES)
            if os.path.isfile(os.path.join(CONF_DIR, "client-socks.enabled")):
                units.append("5gpn-client-socks")
            if os.path.isfile(os.path.join(CONF_DIR, "client-mtproto.enabled")):
                units.extend(["5gpn-mtproxy", "5gpn-client-mtproto"])
            if os.path.isfile(os.path.join(CONF_DIR, "clash-remote.enabled")):
                units.append("5gpn-clash-remote")
            if cur and cur not in ("local", ""):
                units.append(f"5gpn-mihomo@{cur}")
            services = {s: run(["systemctl", "is-active", s], timeout=5)[0] for s in units}
            res = resources()
            return self._send(200, {"ok": True, "current": cur, "exits": exits,
                                    "resources": res, "memory": res, "services": services,
                                    "policy": policy_map(),
                                    "client_cidr": get_client_cidr()})
        if path == "/api/traffic":
            with _traffic_lock:
                data = _load_traffic()
            cutoff = int(time.time()) - 24 * 3600
            pts = [p for p in data.get("points", []) if p.get("t", 0) >= cutoff]
            series = sorted({k for p in pts for k in p.get("v", {})})
            return self._send(200, {"ok": True, "now": int(time.time()),
                                    "interval_sec": data.get("interval_sec", TRAFFIC_INTERVAL),
                                    "series": series, "points": pts})
        if path == "/api/latency":
            with _lat_lock:
                data = _load_latency()
            cutoff = int(time.time()) - 24 * 3600
            pts = [p for p in data.get("points", []) if p.get("t", 0) >= cutoff]
            series = sorted({k for p in pts for k in p.get("v", {})})
            return self._send(200, {"ok": True, "now": int(time.time()),
                                    "interval_sec": data.get("interval_sec", LATENCY_INTERVAL),
                                    "series": series, "points": pts})
        if path == "/api/traffic/daily":
            q = urllib.parse.parse_qs(self.path.partition("?")[2])
            try:
                n = max(1, min(HISTORY_DAYS, int(q.get("days", ["7"])[0])))
            except (TypeError, ValueError):
                n = 7
            with _traffic_lock:
                data = _load_traffic()
                hist = _load_json(HISTORY_TRAFFIC_FILE, {})
                current = _current_traffic_day(data)
            return self._send(200, daily_series(hist.get("days", {}), n,
                                                int(time.time()), current))
        if path == "/api/latency/daily":
            q = urllib.parse.parse_qs(self.path.partition("?")[2])
            try:
                n = max(1, min(HISTORY_DAYS, int(q.get("days", ["7"])[0])))
            except (TypeError, ValueError):
                n = 7
            with _lat_lock:
                data = _load_latency()
                hist = _load_json(HISTORY_LATENCY_FILE, {})
                current = _current_latency_day(data)
            return self._send(200, daily_series(hist.get("days", {}), n,
                                                int(time.time()), current,
                                                _latency_avg_map))
        if path == "/api/exits/latency":
            return self._send(200, {"ok": True, "latency": all_latency()})
        if path == "/api/component/versions":
            return self._send(200, {"ok": True, "components": component_versions()})
        if path == "/api/ai/config":
            c = _ai_config()
            return self._send(200, {"ok": True, "configured": bool(c.get("base_url") and c.get("key")),
                                    "base_url": c.get("base_url", ""), "model": c.get("model", "")})
        if path == "/api/live":
            return self._send(200, dict(ok=True, **live_stats()))
        if path == "/api/doctor":
            ok, out = run_doctor_json()
            data = parse_doctor_json(out)
            if data is None:
                return self._send(500, {"ok": False, "data": None, "output": out})
            # API answering this request implies 5gpn-api itself is up.
            checks = list(data.get("checks") or [])
            for c in checks:
                if c.get("check") == "服务 5gpn-api" and c.get("level") == "fail":
                    c["level"] = "ok"
                    c["detail"] = "running (api process alive)"
            pass_n = sum(1 for c in checks if c.get("level") == "ok")
            fail_n = sum(1 for c in checks if c.get("level") == "fail")
            warn_n = sum(1 for c in checks if c.get("level") == "warn")
            data["checks"] = checks
            data["pass"] = pass_n
            data["fail"] = fail_n
            data["warn"] = warn_n
            data["ok"] = fail_n == 0
            return self._send(200, {"ok": bool(data.get("ok", ok)), "data": data,
                                    "pass": pass_n, "fail": fail_n, "warn": warn_n,
                                    "output": out})
        if path == "/api/report":
            ok, out = run(["bash", REPORT], timeout=240)
            return self._send(200 if ok else 500, {"ok": ok, "output": out, "path": report_path(out)})
        if path == "/api/snapshots":
            ok, out = run(["bash", SNAPSHOT, "list"], timeout=60)
            return self._send(200 if ok else 500, {"ok": ok, "output": out,
                                                   "snapshots": parse_snapshots(out)})
        if path == "/api/metrics":
            return self._send_raw(200, metrics_text(), "text/plain; version=0.0.4")
        if path == "/api/backup":
            try:
                data = make_backup()
                return self._send(200, {"ok": True, "filename": "5gpn-backup.tar.gz",
                                        "data": base64.b64encode(data).decode()})
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"ok": False, "error": str(e)})
        if path == "/api/exits":
            exits, cur = list_exits()
            return self._send(200, {"ok": True, "current": cur, "exits": exits})
        if path == "/api/policy":
            return self._send(200, {"ok": True, "policy": policy_map()})
        if path == "/api/rules":
            txt = read_file(RULES_FILE)
            entries = parse_rules(txt)
            return self._send(200, {"ok": True, "count": len(entries), "rules": txt, "entries": entries})
        if path == "/api/direct-domains":
            domains = list_direct_domains()
            return self._send(200, {"ok": True, "count": len(domains), "domains": domains,
                                    "text": "\n".join(domains) + ("\n" if domains else "")})
        if path == "/api/client-cidr":
            return self._send(200, {"ok": True, "cidr": get_client_cidr(),
                                    "cidrs": get_client_cidrs(),
                                    "default": CLIENT_CIDR_DEFAULT})
        if path == "/api/client-socks":
            enabled = os.path.isfile(os.path.join(CONF_DIR, "client-socks.enabled"))
            port = read_file(os.path.join(CONF_DIR, "client-socks.port")).strip() or "38443"
            user = ""
            env = read_file(os.path.join(CONF_DIR, "client-socks.env"))
            for line in env.splitlines():
                if line.startswith("SOCKS_USER="):
                    user = line.split("=", 1)[1].strip()
            running = False
            if enabled:
                running = run(["systemctl", "is-active", "5gpn-client-socks"], timeout=5)[0]
            host = read_file("/etc/mosdns/.public_ip").strip() or ""
            return self._send(200, {
                "ok": True, "enabled": enabled, "running": running,
                "host": host, "port": port, "user": user,
                "password": "***" if enabled or user else "",
                "allow_cidr": get_client_cidr(),
                "note": "password is masked; use enable/reset-creds to receive it once",
            })
        if path == "/api/client-mtproto":
            enabled = os.path.isfile(os.path.join(CONF_DIR, "client-mtproto.enabled"))
            port = read_file(os.path.join(CONF_DIR, "client-mtproto.port")).strip() or "5753"
            has_secret = False
            secret_raw = ""
            env = read_file(os.path.join(CONF_DIR, "client-mtproto.env"))
            for line in env.splitlines():
                if line.startswith("MTPROTO_SECRET="):
                    secret_raw = line.split("=", 1)[1].strip()
                    has_secret = bool(secret_raw)
                    break
            front = run(["systemctl", "is-active", "5gpn-client-mtproto"], timeout=5)[0] if enabled else False
            core = run(["systemctl", "is-active", "5gpn-mtproxy"], timeout=5)[0] if enabled else False
            running = bool(front and core)
            secret_ok = bool(re.fullmatch(r"[0-9a-fA-F]{32}", secret_raw or ""))
            host = read_file("/etc/mosdns/.public_ip").strip() or ""
            note = "classic 32-hex secret; paste into Telegram as-is"
            if enabled and has_secret and not secret_ok:
                note = "secret is not classic 32-hex; set/generate a 32-hex key for Telegram"
            return self._send(200, {
                "ok": True, "enabled": enabled, "running": running,
                "mtg_running": bool(core), "core_running": bool(core),
                "front_running": bool(front),
                "host": host, "port": port,
                "secret": "***" if has_secret else "",
                "secret_ok": secret_ok if has_secret else False,
                "link": "",
                "allow_cidr": get_client_cidr(),
                "engine": "mtprotoproxy",
                "note": note,
            })
        if path == "/api/clash-remote":
            enabled = os.path.isfile(os.path.join(CONF_DIR, "clash-remote.enabled"))
            port = read_file(os.path.join(CONF_DIR, "clash-remote.port")).strip() or "9443"
            extra = ""
            allow = get_client_cidr()
            has_secret = False
            env = read_file(os.path.join(CONF_DIR, "clash-remote.env"))
            for line in env.splitlines():
                if line.startswith("CLASH_REMOTE_EXTRA_CIDR="):
                    extra = line.split("=", 1)[1].strip()
                elif line.startswith("CLASH_REMOTE_ALLOW_CIDR="):
                    allow = line.split("=", 1)[1].strip() or allow
                elif line.startswith("CLASH_REMOTE_SECRET="):
                    has_secret = bool(line.split("=", 1)[1].strip())
            running = False
            if enabled:
                running = run(["systemctl", "is-active", "5gpn-clash-remote"], timeout=5)[0]
            host = read_file("/etc/mosdns/.public_ip").strip() or ""
            domain = read_file(os.path.join(CONF_DIR, ".domain")).strip() \
                or read_file("/etc/mosdns/.domain").strip()
            url = f"https://{domain}:{port}" if domain else (f"https://{host}:{port}" if host else "")
            return self._send(200, {
                "ok": True, "enabled": enabled, "running": running,
                "host": host, "domain": domain, "port": port, "url": url,
                "secret": "***" if has_secret else "",
                "extra_cidr": extra,
                "allow_cidr": allow,
                "note": "secret is masked; use enable/reset-secret to receive it once. "
                        "Third-party panels: URL + secret; leave API path empty.",
            })
        return self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if not source_allowed(self.client_address[0]):
            return self._send(403, {"ok": False, "error": "forbidden"})
        if rate_limited_path(path) and not rate_ok(self.client_address[0]):
            return self._send(429, {"ok": False, "error": "请求过于频繁，请稍后再试"})
        if not self._auth():
            return self._send(401, {"ok": False, "error": "unauthorized"})
        if path.startswith("/api/mihomo/proxy/"):
            return self._proxy_mihomo(self.path.split("/api/mihomo/proxy/", 1)[1])
        b = self._json_body()

        if path == "/api/exits/set":
            name = str(b.get("name", "")).strip()
            if name not in ("local", "smart") and not EXIT_NAME_RE.match(name):
                return self._send(400, {"ok": False, "error": "invalid name"})
            ok, out = ctl("--set-exit", name, timeout=120)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/exits/add":
            name = str(b.get("name", "")).strip()
            cfg = b.get("config", "")
            if not EXIT_NAME_RE.match(name) or name == "local":
                return self._send(400, {"ok": False, "error": "invalid name (1-16 letters/digits/Chinese/_/-, not 'local')"})
            if not isinstance(cfg, str) or not cfg.strip():
                return self._send(400, {"ok": False, "error": "empty config"})
            ok, out = ctl("--add-exit", name, inp=cfg, timeout=200)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/exits/edit":
            name = str(b.get("name", "")).strip()
            cfg = b.get("config", "")
            if not EXIT_NAME_RE.match(name) or name in ("local", "smart"):
                return self._send(400, {"ok": False, "error": "invalid name"})
            if not isinstance(cfg, str) or not cfg.strip():
                return self._send(400, {"ok": False, "error": "empty config"})
            ok, out = ctl("--edit-exit", name, inp=cfg, timeout=300)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/exits/del":
            name = str(b.get("name", "")).strip()
            if not EXIT_NAME_RE.match(name):
                return self._send(400, {"ok": False, "error": "invalid name"})
            ok, out = ctl("--del-exit", name, timeout=90)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/exits/check":
            ok, out = ctl("--check-exits", timeout=150)
            return self._send(200, {"ok": ok, "output": out, "exits": parse_check(out)})

        if path == "/api/policy":
            cat = str(b.get("category", "")).strip()
            tgt = str(b.get("target", "")).strip()
            if not CAT_RE.match(cat):
                return self._send(400, {"ok": False, "error": "invalid category"})
            if tgt not in ("direct", "block") and not EXIT_NAME_RE.match(tgt):
                return self._send(400, {"ok": False, "error": "invalid target"})
            ok, out = ctl("--set-policy", cat, tgt, timeout=300)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/policy/del":
            cat = str(b.get("category", "")).strip()
            if not CAT_RE.match(cat):
                return self._send(400, {"ok": False, "error": "invalid category"})
            ok, out = ctl("--del-policy", cat, timeout=300)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/policy/rename":
            old = str(b.get("old", "")).strip()
            new = str(b.get("new", "")).strip()
            if not CAT_RE.match(old) or not CAT_RE.match(new):
                return self._send(400, {"ok": False, "error": "invalid name"})
            ok, out = ctl("--rename-policy", old, new, timeout=400)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/rules":
            rules = b.get("rules", "")
            if not isinstance(rules, str) or not rules.strip():
                return self._send(400, {"ok": False, "error": "empty rules"})
            ok, out = rules_set(rules)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/rules/add":
            rule = str(b.get("rule", "")).strip()
            if not rule or "\n" in rule or len(rule) > 2000:
                return self._send(400, {"ok": False, "error": "invalid rule"})
            txt = read_file(RULES_FILE)
            newtext = (txt.rstrip("\n") + "\n" + rule + "\n") if txt.strip() else (rule + "\n")
            ok, out = rules_set(newtext)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/rules/del":
            try:
                idx = int(b.get("index"))
            except (TypeError, ValueError):
                return self._send(400, {"ok": False, "error": "invalid index"})
            keep, n, dropped = [], 0, False
            for ln in read_file(RULES_FILE).splitlines():
                s = ln.strip()
                if s and s[0] not in "#;":
                    n += 1
                    if n == idx:
                        dropped = True
                        continue
                keep.append(ln)
            if not dropped:
                return self._send(400, {"ok": False, "error": "index out of range"})
            ok, out = rules_set("\n".join(keep) + "\n")
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/rules/edit":
            try:
                idx = int(b.get("index"))
            except (TypeError, ValueError):
                return self._send(400, {"ok": False, "error": "invalid index"})
            rule = str(b.get("rule", "")).strip()
            if not rule or "\n" in rule or len(rule) > 2000:
                return self._send(400, {"ok": False, "error": "invalid rule"})
            out_lines, n, replaced = [], 0, False
            for ln in read_file(RULES_FILE).splitlines():
                s = ln.strip()
                if s and s[0] not in "#;":
                    n += 1
                    if n == idx:
                        out_lines.append(rule)
                        replaced = True
                        continue
                out_lines.append(ln)
            if not replaced:
                return self._send(400, {"ok": False, "error": "index out of range"})
            ok, out = rules_set("\n".join(out_lines) + "\n")
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/update-rules":
            ok, out = ctl("--update-rules", timeout=400)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/component/update":
            component = str(b.get("component", "")).strip()
            spec = COMPONENTS.get(component)
            if not spec:
                return self._send(400, {"ok": False, "error": "unknown component"})
            version = str(b.get("version", "")).strip().lstrip("v")
            args = [spec["flag"]]
            if version:
                if not COMPONENT_VERSION_RE.match(version):
                    return self._send(400, {"ok": False, "error": "invalid version"})
                args.append(version)
            ok, out = ctl(*args, timeout=300)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/ai/config":
            cur = _ai_config()
            base = str(b.get("base_url", "")).strip()
            model = str(b.get("model", "")).strip()
            key = str(b.get("key", ""))
            if base:
                cur["base_url"] = base
            if model:
                cur["model"] = model
            if key:                       # blank key keeps the existing one
                cur["key"] = key
            if not cur.get("base_url") or not cur.get("key"):
                return self._send(400, {"ok": False, "error": "need base_url and key"})
            ok = _save_ai_config(cur)
            return self._send(200 if ok else 500, {"ok": ok})

        if path == "/api/route/test":
            return self._send(200, {"ok": True, "result": route_test(str(b.get("domain", "")))})

        if path == "/api/snapshots":
            action = str(b.get("action", "")).strip().lower()
            if action == "create":
                label = str(b.get("label", "manual")).strip()[:64] or "manual"
                ok, out = run(["bash", SNAPSHOT, "create", label], timeout=180)
                snap_id = ""
                for line in reversed(out.splitlines()):
                    s = line.strip()
                    if re.match(r"^[0-9TZ._A-Za-z-]+$", s):
                        snap_id = s
                        break
                return self._send(200 if ok else 500, {"ok": ok, "id": snap_id, "output": out})
            if action == "restore":
                snap_id = str(b.get("id", "latest")).strip() or "latest"
                if snap_id != "latest" and not re.match(r"^[0-9TZ._A-Za-z-]{1,96}$", snap_id):
                    return self._send(400, {"ok": False, "error": "invalid snapshot id"})
                ok, out = run(["bash", SNAPSHOT, "restore", snap_id], timeout=300)
                return self._send(200 if ok else 500, {"ok": ok, "id": snap_id, "output": out})
            if action == "delete":
                snap_id = str(b.get("id", "")).strip()
                if snap_id != "latest" and not re.match(r"^[0-9TZ._A-Za-z-]{1,96}$", snap_id):
                    return self._send(400, {"ok": False, "error": "invalid snapshot id"})
                if not snap_id:
                    return self._send(400, {"ok": False, "error": "missing snapshot id"})
                ok, out = run(["bash", SNAPSHOT, "delete", snap_id], timeout=120)
                return self._send(200 if ok else 500, {"ok": ok, "id": snap_id, "output": out})
            return self._send(400, {"ok": False, "error": "action must be create|restore|delete"})

        if path == "/api/proxy-domain":
            domain = str(b.get("domain", "")).strip().lower()
            target = str(b.get("target", "")).strip()
            if not re.match(r"^[a-z0-9.-]{2,253}$", domain) or "." not in domain:
                return self._send(400, {"ok": False, "error": "域名无效"})
            if target not in ("direct", "block") and not EXIT_NAME_RE.match(target):
                return self._send(400, {"ok": False, "error": "目标无效"})
            ok, out = ctl("--proxy-domain", domain, target, timeout=400)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/direct-domains/add":
            domain = str(b.get("domain", "")).strip().lower().rstrip(".")
            if not DOMAIN_RE.match(domain):
                return self._send(400, {"ok": False, "error": "域名无效"})
            ok, out = ctl("--add-direct-domain", domain, timeout=120)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/direct-domains/del":
            domain = str(b.get("domain", "")).strip().lower().rstrip(".")
            if not DOMAIN_RE.match(domain):
                return self._send(400, {"ok": False, "error": "域名无效"})
            ok, out = ctl("--del-direct-domain", domain, timeout=120)
            return self._send(200 if ok else 500, {"ok": ok, "output": out})

        if path == "/api/direct-domains":
            # Replace whole list. Accept {domains:["a","b"]} or {text:"a\\nb"}.
            raw = b.get("domains", None)
            if isinstance(raw, list):
                lines = [str(x).strip().lower().rstrip(".") for x in raw]
            else:
                text = b.get("text", b.get("domains", ""))
                if not isinstance(text, str):
                    return self._send(400, {"ok": False, "error": "domains must be a list or text"})
                lines = [ln.strip().lower().rstrip(".") for ln in text.splitlines()]
            cleaned = []
            for d in lines:
                if not d or d.startswith("#"):
                    continue
                if not DOMAIN_RE.match(d):
                    return self._send(400, {"ok": False, "error": f"无效域名: {d}"})
                cleaned.append(d)
            ok, out = ctl("--set-direct-domains", inp="\n".join(cleaned) + ("\n" if cleaned else ""),
                          timeout=120)
            return self._send(200 if ok else 500, {"ok": ok, "output": out,
                                                   "count": len(cleaned)})

        if path == "/api/client-cidr":
            if b.get("detect"):
                ok, out = ctl("--detect-client-cidr", timeout=180)
                return self._send(200 if ok else 500, {"ok": ok, "output": out,
                                                        "cidr": get_client_cidr()})
            cidr = validate_client_cidr(b.get("cidr", ""))
            if not cidr:
                return self._send(400, {"ok": False,
                                        "error": "invalid cidr (IPv4 /16../30 by default; comma-separated; /8../15 require FORCE_WIDE_CIDR=1)"})
            ok, out = ctl("--set-client-cidr", cidr, timeout=180)
            return self._send(200 if ok else 500, {"ok": ok, "output": out,
                                                    "cidr": get_client_cidr()})

        if path == "/api/client-socks":
            action = str(b.get("action", "")).strip().lower()
            if action == "enable":
                ok, out = ctl("--enable-client-socks", timeout=180)
            elif action == "disable":
                ok, out = ctl("--disable-client-socks", timeout=120)
            elif action == "reset-creds":
                ok, out = ctl("--reset-client-socks-creds", timeout=120)
            else:
                return self._send(400, {"ok": False,
                                        "error": "action must be enable|disable|reset-creds"})
            host = port = user = password = ""
            for line in (out or "").splitlines():
                s = line.strip()
                if "地址:" in s or "地址：" in s:
                    val = s.split(":", 1)[-1].split("：", 1)[-1].strip()
                    # drop leading spaces after OK prefix noise
                    if ":" in val and not val.startswith("http"):
                        host, port = val.rsplit(":", 1)
                elif "用户:" in s or "用户：" in s:
                    user = s.split(":", 1)[-1].split("：", 1)[-1].strip()
                elif "密码:" in s or "密码：" in s:
                    password = s.split(":", 1)[-1].split("：", 1)[-1].strip()
            return self._send(200 if ok else 500, {
                "ok": ok, "output": out,
                "enabled": os.path.isfile(os.path.join(CONF_DIR, "client-socks.enabled")),
                "host": host, "port": port, "user": user, "password": password,
                "allow_cidr": get_client_cidr(),
                "note": ("password returned once; future GET responses mask it"
                         if action in ("enable", "reset-creds") else "password is masked"),
            })

        if path == "/api/client-mtproto":
            action = str(b.get("action", "")).strip().lower()
            if action == "enable":
                ok, out = ctl("--enable-client-mtproto", timeout=240)
            elif action == "disable":
                ok, out = ctl("--disable-client-mtproto", timeout=120)
            elif action == "generate-secret":
                ok, out = ctl("--generate-client-mtproto-secret", timeout=180)
            elif action == "set-secret":
                secret = str(b.get("secret", "")).strip()
                if not secret or any(c.isspace() for c in secret):
                    return self._send(400, {"ok": False, "error": "secret required (no whitespace)"})
                ok, out = ctl("--set-client-mtproto-secret", secret, timeout=180)
            else:
                return self._send(400, {"ok": False,
                                        "error": "action must be enable|disable|set-secret|generate-secret"})
            host = port = secret = link = ""
            for line in (out or "").splitlines():
                s = line.strip()
                if "地址:" in s or "地址：" in s:
                    val = s.split(":", 1)[-1].split("：", 1)[-1].strip()
                    if ":" in val and not val.startswith("http") and not val.startswith("tg:"):
                        host, port = val.rsplit(":", 1)
                elif "密钥:" in s or "密钥：" in s:
                    secret = s.split(":", 1)[-1].split("：", 1)[-1].strip()
                elif "链接:" in s or "链接：" in s:
                    link = s.split(":", 1)[-1].split("：", 1)[-1].strip()
                    if not link.startswith("tg:") and "tg://" in s:
                        link = s[s.find("tg://"):].strip()
            if not link and host and port and secret:
                link = f"tg://proxy?server={host}&port={port}&secret={secret}"
            return self._send(200 if ok else 500, {
                "ok": ok, "output": out,
                "enabled": os.path.isfile(os.path.join(CONF_DIR, "client-mtproto.enabled")),
                "host": host,
                "port": port or read_file(os.path.join(CONF_DIR, "client-mtproto.port")).strip() or "5753",
                "secret": secret,
                "link": link,
                "allow_cidr": get_client_cidr(),
                "note": ("secret returned once; future GET responses mask it"
                         if action in ("enable", "set-secret", "generate-secret") else "secret is masked"),
            })

        if path == "/api/clash-remote":
            action = str(b.get("action", "")).strip().lower()
            if action == "enable":
                ok, out = ctl("--enable-clash-remote", timeout=180)
            elif action == "disable":
                ok, out = ctl("--disable-clash-remote", timeout=120)
            elif action == "reset-secret":
                ok, out = ctl("--reset-clash-remote-secret", timeout=120)
            elif action == "set-extra-cidr":
                extra = str(b.get("extra_cidr", "")).strip()
                ok, out = ctl("--set-clash-remote-extra-cidr", extra, timeout=120)
            else:
                return self._send(400, {"ok": False,
                                        "error": "action must be enable|disable|reset-secret|set-extra-cidr"})
            host = port = secret = url = ""
            for line in (out or "").splitlines():
                s = line.strip()
                if s.startswith("URL:") or "URL:" in s or "URL：" in s:
                    url = s.split(":", 1)[-1].split("：", 1)[-1].strip()
                elif "地址:" in s or "地址：" in s:
                    val = s.split(":", 1)[-1].split("：", 1)[-1].strip()
                    if ":" in val and not val.startswith("http"):
                        host, port = val.rsplit(":", 1)
                elif "密钥:" in s or "密钥：" in s:
                    secret = s.split(":", 1)[-1].split("：", 1)[-1].strip()
            if not url:
                domain = read_file(os.path.join(CONF_DIR, ".domain")).strip()
                if domain and port:
                    url = f"https://{domain}:{port}"
                elif host and port:
                    url = f"https://{host}:{port}"
            extra = ""
            allow = get_client_cidr()
            env = read_file(os.path.join(CONF_DIR, "clash-remote.env"))
            for line in env.splitlines():
                if line.startswith("CLASH_REMOTE_EXTRA_CIDR="):
                    extra = line.split("=", 1)[1].strip()
                elif line.startswith("CLASH_REMOTE_ALLOW_CIDR="):
                    allow = line.split("=", 1)[1].strip() or allow
            return self._send(200 if ok else 500, {
                "ok": ok, "output": out,
                "enabled": os.path.isfile(os.path.join(CONF_DIR, "clash-remote.enabled")),
                "host": host,
                "port": port or read_file(os.path.join(CONF_DIR, "clash-remote.port")).strip() or "9443",
                "url": url,
                "secret": secret,
                "extra_cidr": extra,
                "allow_cidr": allow,
                "note": ("secret returned once; future GET responses mask it"
                         if action in ("enable", "reset-secret") else "secret is masked"),
            })

        if path == "/api/restore":
            try:
                ok, msg = restore_backup(str(b.get("data", "")))
                return self._send(200 if ok else 400, {"ok": ok, "output": msg})
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"ok": False, "error": f"恢复失败: {e}"})

        if path == "/api/ai/plan":
            res, err = ai_plan(str(b.get("repo", "")).strip(), str(b.get("intent", "")).strip())
            if err:
                return self._send(400, {"ok": False, "error": err})
            return self._send(200, {"ok": True, "plan": res["plan"], "raw": res["raw"]})

        if path == "/api/ai/apply":
            rules = b.get("rules") or []
            policy = b.get("policy") or {}
            if not isinstance(rules, list) or not isinstance(policy, dict):
                return self._send(400, {"ok": False, "error": "invalid plan"})
            out = []
            for cat, tgt in policy.items():
                cat, tgt = str(cat).strip(), str(tgt).strip()
                if not CAT_RE.match(cat):
                    out.append(f"跳过分类(名称无效): {cat}")
                    continue
                if tgt not in ("direct", "block") and not EXIT_NAME_RE.match(tgt):
                    out.append(f"跳过 {cat}(目标无效): {tgt}")
                    continue
                ok, o = ctl("--set-policy", cat, tgt, timeout=300)
                out.append(f"分类 {cat} -> {tgt}: {'ok' if ok else o}")
            clean = [r.strip() for r in rules if isinstance(r, str) and r.strip() and "\n" not in r][:300]
            if clean:
                txt = read_file(RULES_FILE)
                txt = (txt.rstrip("\n") + "\n" + "\n".join(clean) + "\n") if txt.strip() else ("\n".join(clean) + "\n")
                ok, o = rules_set(txt)
                out.append(f"新增 {len(clean)} 条规则: {'ok' if ok else o}")
            return self._send(200, {"ok": True, "output": "\n".join(out)})

        return self._send(404, {"ok": False, "error": "not found"})


class TLSServer(ThreadingHTTPServer):
    """TLS terminates per-connection in the worker thread (NOT in the accept
    loop). Wrapping the listening socket would run the handshake inside accept(),
    so one stalled client (e.g. a port scanner on the public 8444) wedges the
    whole server. Here accept() returns a plain socket and the handshake — with a
    short timeout — happens in the request thread."""
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64
    ssl_ctx = None

    def get_request(self):
        return self.socket.accept()      # plain accept; no TLS here

    def process_request_thread(self, request, client_address):  # runs in a thread
        try:
            request.settimeout(10)
            request = self.ssl_ctx.wrap_socket(request, server_side=True)
            request.settimeout(None)
        except Exception:  # noqa: BLE001
            try:
                self.shutdown_request(request)
            except Exception:  # noqa: BLE001, S110
                pass
            return
        super().process_request_thread(request, client_address)


def main():
    if not TOKEN or len(TOKEN) < 16:
        sys.stderr.write("API_TOKEN unset or too short (need >=16 chars); refusing to start.\n")
        sys.exit(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"TLS cert load failed ({CERT} / {KEY}): {e}\n")
        sys.exit(1)
    threading.Thread(target=traffic_loop, daemon=True).start()
    threading.Thread(target=latency_loop, daemon=True).start()
    httpd = TLSServer((BIND, PORT), Handler)
    httpd.ssl_ctx = ctx
    sys.stderr.write(f"5gpn-api listening on {BIND}:{PORT} (TLS)\n")
    sys.stderr.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
