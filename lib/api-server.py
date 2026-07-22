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
  API_BIND          bind address                    (default 0.0.0.0)
  API_TLS_CERT      TLS fullchain                   (default /etc/mosdns/certs/fullchain.pem)
  API_TLS_KEY       TLS private key                 (default /etc/mosdns/certs/privkey.pem)
  API_ALLOW_ORIGIN  CORS allowed origin             (default *)
  MGMT              path to 5gpn-ctl                (default /opt/5gpn/bin/5gpn-ctl)
  CONF_DIR          gateway state dir               (default /opt/5gpn/etc)
"""
import base64
import hmac
import io
import ipaddress
import json
import os
import re
import select
import socket
import tarfile
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("API_TOKEN", "")
PORT = int(re.sub(r"\D", "", os.environ.get("API_PORT", "8444")) or "8444")
BIND = os.environ.get("API_BIND", "0.0.0.0")
CERT = os.environ.get("API_TLS_CERT", "/etc/mosdns/certs/fullchain.pem")
KEY = os.environ.get("API_TLS_KEY", "/etc/mosdns/certs/privkey.pem")
ORIGIN = os.environ.get("API_ALLOW_ORIGIN", "*")
MGMT = os.environ.get("MGMT", "/opt/5gpn/bin/5gpn-ctl")
CONF_DIR = os.environ.get("CONF_DIR", "/opt/5gpn/etc")

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
AI_CONF = os.environ.get("AI_CONF", CONF_DIR + "/ai.json")

# Matches install.sh's exit-name validator (letters/digits/Chinese/_/-, 1-16).
EXIT_NAME_RE = re.compile(r"^[\w一-鿿-]{1,16}$")
CAT_RE = re.compile(r"^[A-Za-z0-9_一-鿿-]{1,40}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
DIRECT_DOMAINS_FILE = "/etc/mosdns/direct-domains.txt"
CLIENT_CIDR_FILE = "/etc/mosdns/.client_cidr"
CLIENT_CIDR_DEFAULT = "172.22.0.0/16"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SERVICES = ["mosdns", "sniproxy", "wa-shim", "quic-proxy",
            "5gpn-tgbot", "5gpn-api"]

CLASH_ADDR = os.environ.get("CLASH_ADDR", "127.0.0.1:9090")
CLASH_SECRET_FILE = os.environ.get("MIHOMO_API_SECRET_FILE", "/etc/5gpn/mihomo-api-secret")
MIHOMO_STATIC_DIR = os.environ.get("MIHOMO_STATIC_DIR", "/opt/5gpn/webui/mihomo")
CLASH_WS_PATHS = {"traffic", "logs", "connections", "memory"}

# CSP for the vendored metacubexd (same-origin app; frames allowed same-origin
# so our console can embed it, everything else locked down).
XD_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
          "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
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
            _rate.clear()
        if ent[0] < 1.0:
            return False
        ent[0] -= 1.0
        return True


def run(argv, inp=None, timeout=180):
    try:
        p = subprocess.run(argv, input=inp, capture_output=True, text=True, timeout=timeout)
        out = ANSI.sub("", (p.stdout or "") + (p.stderr or ""))
        return p.returncode == 0, out.strip()
    except subprocess.TimeoutExpired:
        return False, "操作超时"
    except FileNotFoundError:
        return False, "命令不存在：%s" % argv[0]
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
    url = "http://%s/%s" % (CLASH_ADDR, urllib.parse.quote(path, safe="/"))
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
        return 502, "application/json", json.dumps({"message": "mihomo unreachable: %s" % e}).encode()


def ws_allowed(sub):
    norm = normalize_sub(sub)
    return bool(norm) and norm.split("?", 1)[0] in CLASH_WS_PATHS


def build_ws_request(sub, client_headers):
    """Rebuild the client's WS upgrade request for the loopback Clash API,
    injecting the server-side secret. Returns raw bytes."""
    lines = ["GET /%s HTTP/1.1" % sub,
             "Host: %s" % CLASH_ADDR,
             "Upgrade: websocket",
             "Connection: Upgrade",
             "Sec-WebSocket-Version: %s" % client_headers.get("Sec-WebSocket-Version", "13"),
             "Sec-WebSocket-Key: %s" % client_headers.get("Sec-WebSocket-Key", ""),
             "Authorization: Bearer %s" % clash_secret()]
    proto = client_headers.get("Sec-WebSocket-Protocol")
    if proto:
        lines.append("Sec-WebSocket-Protocol: %s" % proto)
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
        req = urllib.request.Request("http://%s%s" % (CLASH_ADDR, p))
        req.add_header("Authorization", "Bearer " + secret)
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())

    def get_memory():
        # mihomo's /memory is an INFINITE one-object-per-second stream (plain
        # HTTP included), and its first object is always inuse=0 by design.
        # Reading to EOF would hang forever — take the first two lines instead.
        req = urllib.request.Request("http://%s/memory" % CLASH_ADDR)
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
        return None, "mihomo 不可达（smart 出口未启用？）: %s" % e
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


def list_exits():
    names = set()
    try:
        for f in os.listdir(EXITS_DIR):
            if f.endswith(".type"):
                names.add(f[:-5])
    except Exception:  # noqa: BLE001
        pass
    try:
        for f in os.listdir(WG_DIR):
            if f.startswith("pgw-") and f.endswith(".conf"):
                names.add(f[4:-5])
    except Exception:  # noqa: BLE001
        pass
    cur = current_exit()
    out = []
    for n in sorted(names):
        if n in ("local", "smart"):
            continue
        t = read_file(EXITS_DIR + "/%s.type" % n).strip() or "wireguard"
        server = ""
        try:
            o = json.load(open(EXITS_DIR + "/%s.json" % n))["outbounds"][0]
            if o.get("server"):
                server = "%s:%s" % (o["server"], o.get("server_port", ""))
        except Exception:  # noqa: BLE001
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
def cpu_percent(window=0.25):
    def snap():
        f = [int(x) for x in read_file("/proc/stat").splitlines()[0].split()[1:]]
        idle = f[3] + (f[4] if len(f) > 4 else 0)
        return sum(f), idle
    try:
        t1, i1 = snap()
        time.sleep(window)
        t2, i2 = snap()
        dt, di = t2 - t1, i2 - i1
        return round((1 - di / dt) * 100, 1) if dt > 0 else 0.0
    except Exception:  # noqa: BLE001
        return 0.0


def resources():
    r = memory()
    try:
        s = os.statvfs("/")
        r["disk_total_mb"] = (s.f_blocks * s.f_frsize) // (1024 * 1024)
        r["disk_used_mb"] = ((s.f_blocks - s.f_bfree) * s.f_frsize) // (1024 * 1024)
    except Exception:  # noqa: BLE001
        pass
    try:
        r["uptime_sec"] = int(float(read_file("/proc/uptime").split()[0]))
    except Exception:  # noqa: BLE001
        pass
    try:
        r["load"] = [float(x) for x in read_file("/proc/loadavg").split()[:3]]
    except Exception:  # noqa: BLE001
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
    except Exception:  # noqa: BLE001
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
    except Exception:  # noqa: BLE001
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


def traffic_loop():
    try:
        traffic_tick()      # establish a baseline immediately
    except Exception:  # noqa: BLE001
        pass
    while True:
        time.sleep(TRAFFIC_INTERVAL)
        try:
            traffic_tick()
        except Exception:  # noqa: BLE001
            pass


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
        except Exception:  # noqa: BLE001
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
    t = read_file(EXITS_DIR + "/%s.type" % name).strip()
    if t == "wireguard":
        m = re.search(r"(?im)^\s*Endpoint\s*=\s*(.+):(\d+)\s*$", read_file(WG_DIR + "/pgw-%s.conf" % name))
        if m:
            return m.group(1), int(m.group(2))
        return None, None
    # URI exits keep the original link in <name>.uri (mihomo TUN engine)
    first = read_file(EXITS_DIR + "/%s.uri" % name).strip().splitlines()
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


def measure_latency(name):
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
    except Exception:  # noqa: BLE001
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


def latency_loop():
    while True:
        try:
            latency_tick()
        except Exception:  # noqa: BLE001
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
    info = _http_json("https://api.github.com/repos/%s/%s" % (owner, repo))
    branch = info.get("default_branch", "main")
    ctx = {"owner": owner, "repo": repo, "branch": branch,
           "description": info.get("description") or "",
           "raw_base": "https://raw.githubusercontent.com/%s/%s/%s/" % (owner, repo, branch),
           "files": [], "readme": ""}
    try:
        for it in _http_json("https://api.github.com/repos/%s/%s/contents" % (owner, repo)):
            if it.get("type") == "file" and re.search(r"\.(list|ya?ml|txt|conf|srs)$", it.get("name", ""), re.I):
                ctx["files"].append(it["path"])
        ctx["files"] = ctx["files"][:40]
    except Exception:  # noqa: BLE001
        pass
    for fn in ("README.md", "readme.md", "README.MD"):
        try:
            ctx["readme"] = _http_text(ctx["raw_base"] + fn, limit=3000)
            if ctx["readme"]:
                break
        except Exception:  # noqa: BLE001
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
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
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
        ctx = {"error": "仓库读取失败: %s" % e}
    exits = [e["name"] for e in list_exits()[0]]
    cats = list(policy_map().keys())
    lines = ["意图: " + intent, "",
             "可用出口: " + (", ".join(exits) or "(无)"),
             "现有分类: " + (", ".join(cats) or "(无)")]
    if ctx and not ctx.get("error"):
        lines += ["", "GitHub 仓库: %s/%s" % (ctx["owner"], ctx["repo"]),
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
        return None, "AI 调用失败: %s" % e
    return {"plan": extract_json(raw), "raw": raw, "exits": exits}, None


# --- live stats (instantaneous rate + connection count) ----------------------
def live_stats():
    primary = primary_iface()
    a = read_net_dev()
    time.sleep(1.0)
    b = read_net_dev()

    def rate(n):
        if n in a and n in b:
            return max(0, b[n]["rx"] - a[n]["rx"]), max(0, b[n]["tx"] - a[n]["tx"])
        return 0, 0
    srx, stx = rate(primary)
    exits = {}
    for n in b:
        if n.startswith("pgw-"):
            rx, tx = rate(n)
            exits[n[4:]] = {"rx": rx, "tx": tx}
    conns = 0
    ok, out = run(["ss", "-tnH", "state", "established"], timeout=4)
    if ok:
        conns = len([x for x in out.splitlines() if x.strip()])
    return {"server": {"rx": srx, "tx": stx}, "exits": exits, "conns": conns}


# --- route tester: would this domain be hijacked, and to which exit? ----------
def gfwlist_set():
    s = set()
    for line in read_file("/etc/mosdns/gfwlist.txt").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            s.add(line.strip("."))
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


def get_client_cidr():
    raw = (read_file(CLIENT_CIDR_FILE) or CLIENT_CIDR_DEFAULT).strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
        if net.version != 4 or not (8 <= net.prefixlen <= 30):
            return CLIENT_CIDR_DEFAULT
        return str(net)
    except ValueError:
        return CLIENT_CIDR_DEFAULT


def validate_client_cidr(value):
    try:
        net = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4 or not (8 <= net.prefixlen <= 30):
        return None
    return str(net)


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
        elif typ == "DOMAIN" and len(p) >= 3 and d == p[1].lower():
            matched = (s, p[-1])
        elif typ == "DOMAIN-KEYWORD" and len(p) >= 3 and p[1].lower() in d:
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
                "etc/mosdns/direct-domains.txt",
                "etc/wireguard", "opt/5gpn/etc/current-exit"]


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
                        tf.add(os.path.join(full, f), arcname=rel + "/" + f)
            elif rel == "etc/5gpn":
                tf.add(full, arcname=rel, filter=lambda ti: None if "/rulesets" in ti.name else ti)
            else:
                tf.add(full, arcname=rel)
    return buf.getvalue()


def _backup_allowed(name):
    name = name.lstrip("./")
    if ".." in name.split("/"):
        return False
    return bool(name.startswith("etc/5gpn") or name == "etc/mosdns/gfwlist-extra-local.txt"
                or name == "etc/mosdns/direct-domains.txt"
                or re.match(r"etc/wireguard/pgw-[^/]+\.conf$", name)
                or name == "opt/5gpn/etc/current-exit")


def restore_backup(b64):
    raw = base64.b64decode(b64)
    tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    members = [m for m in tf.getmembers() if (m.isfile() or m.isdir()) and _backup_allowed(m.name)]
    if not members:
        return False, "备份内容无效（无可识别的配置文件）"
    tf.extractall("/", members=members)
    ctl("--set-rules", inp=read_file(RULES_FILE), timeout=400)   # rebuild router from restored rules
    run(["systemctl", "restart", "mosdns"], timeout=30)          # pick up restored lists
    run(["/usr/local/bin/5gpn-apply-exit.sh"], timeout=30)
    return True, "已恢复 %d 个文件，并重建路由。如需重建劫持名单可再执行『更新规则集』。" % len(members)


def _tok_eq(a, b):
    """hmac.compare_digest that rejects non-ASCII input instead of raising."""
    try:
        return hmac.compare_digest(a, b)
    except TypeError:
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "pgw-api"

    def log_message(self, *a):  # keep the journal quiet — request lines may carry ?token= credentials
        pass

    def _cors(self):
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
        except Exception:  # noqa: BLE001
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
        except Exception:  # noqa: BLE001
            pass

    def _auth(self):
        """Bearer 是主凭据。浏览器无法给 iframe/WS 子请求加自定义头，因此
        额外接受 ?token= query 凭据，但仅限两类 GET 请求：
          (a) /mihomo 静态文件（iframe 文档及其资源）；
          (b) /api/mihomo/proxy/ 下且属 WS 白名单的 Upgrade 请求。
        其余路径一律不认 query token。query 鉴权成功的 /mihomo 响应会种一个
        pgw_mihomo 同源会话 cookie；该 cookie 放行 /mihomo 静态与
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
            if m and _tok_eq(urllib.parse.unquote(m.group(1)), TOKEN):
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
        if getattr(self, "_via_query", False):
            # iframe 内相对路径资源与面板 API 调用带不了 ?token=；种同源会话
            # cookie（Path=/ 覆盖 /mihomo 与 /api/mihomo/*）供其鉴权。
            extra.append(("Set-Cookie", "pgw_mihomo=%s; Path=/; HttpOnly; Secure; SameSite=Strict"
                          % urllib.parse.quote(TOKEN, safe="")))
        return self._send_raw(200, data, MIME.get(ext, "application/octet-stream"), extra=extra)

    def _dispatch(self, method):
        """PUT/PATCH/DELETE are only routed to the mihomo reverse proxy."""
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path.startswith("/api/") and not rate_ok(self.client_address[0]):
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
        if path.startswith("/api/") and not rate_ok(self.client_address[0]):
            return self._send(429, {"ok": False, "error": "请求过于频繁，请稍后再试"})
        if path == "/api/health":
            return self._send(200, {"ok": True, "service": "5gpn-api"})
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
            except Exception:  # noqa: BLE001
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
            services = {s: run(["systemctl", "is-active", s], timeout=5)[0] for s in SERVICES}
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
        if path == "/api/exits/latency":
            return self._send(200, {"ok": True, "latency": all_latency()})
        if path == "/api/ai/config":
            c = _ai_config()
            return self._send(200, {"ok": True, "configured": bool(c.get("base_url") and c.get("key")),
                                    "base_url": c.get("base_url", ""), "model": c.get("model", "")})
        if path == "/api/live":
            return self._send(200, dict(ok=True, **live_stats()))
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
                                    "default": CLIENT_CIDR_DEFAULT})
        return self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path.startswith("/api/") and not rate_ok(self.client_address[0]):
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
                    return self._send(400, {"ok": False, "error": "无效域名: %s" % d})
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
                                        "error": "invalid cidr (IPv4 /8../30, e.g. 172.22.0.0/16)"})
            ok, out = ctl("--set-client-cidr", cidr, timeout=180)
            return self._send(200 if ok else 500, {"ok": ok, "output": out,
                                                    "cidr": get_client_cidr()})

        if path == "/api/restore":
            try:
                ok, msg = restore_backup(str(b.get("data", "")))
                return self._send(200 if ok else 400, {"ok": ok, "output": msg})
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"ok": False, "error": "恢复失败: %s" % e})

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
                    out.append("跳过分类(名称无效): %s" % cat)
                    continue
                if tgt not in ("direct", "block") and not EXIT_NAME_RE.match(tgt):
                    out.append("跳过 %s(目标无效): %s" % (cat, tgt))
                    continue
                ok, o = ctl("--set-policy", cat, tgt, timeout=300)
                out.append("分类 %s -> %s: %s" % (cat, tgt, "ok" if ok else o))
            clean = [r.strip() for r in rules if isinstance(r, str) and r.strip() and "\n" not in r][:300]
            if clean:
                txt = read_file(RULES_FILE)
                txt = (txt.rstrip("\n") + "\n" + "\n".join(clean) + "\n") if txt.strip() else ("\n".join(clean) + "\n")
                ok, o = rules_set(txt)
                out.append("新增 %d 条规则: %s" % (len(clean), "ok" if ok else o))
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
            except Exception:  # noqa: BLE001
                pass
            return
        super().process_request_thread(request, client_address)


def main():
    if not TOKEN or len(TOKEN) < 16:
        sys.stderr.write("API_TOKEN unset or too short (need >=16 chars); refusing to start.\n")
        sys.exit(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("TLS cert load failed (%s / %s): %s\n" % (CERT, KEY, e))
        sys.exit(1)
    threading.Thread(target=traffic_loop, daemon=True).start()
    threading.Thread(target=latency_loop, daemon=True).start()
    httpd = TLSServer((BIND, PORT), Handler)
    httpd.ssl_ctx = ctx
    sys.stderr.write("5gpn-api listening on %s:%d (TLS)\n" % (BIND, PORT))
    sys.stderr.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
