#!/usr/bin/env python3
"""Scoped Apple network-location interceptor for 5GPN-X WLOC.

Xray terminates VLESS/REALITY, sniffs only the supported Apple location hosts,
and redirects their raw inner TLS stream to this loopback listener. This daemon:

  1. terminates that TLS with a leaf the phone trusts,
     offering only HTTP/1.1;
  2. reads the phone's `POST /clls/wloc` request;
  3. re-originates the request to the REAL Apple gs-loc server (forcing
     Accept-Encoding: identity so the protobuf comes back uncompressed);
  4. rewrites the coordinates in the response to the active static preset via
     gsloc_rewrite (recomputing the header block-length field);
  5. returns the rewritten response to the phone.

The scoped Apple location-assist host family (`gspe85*-ssl.ls.apple.com`) is
also diverted here so its WifiTile response can be translated. This public
build deliberately contains no raw request/response capture facility.
"""
import collections
import datetime
import gzip
import io
import os
import re
import socket
import ssl
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import wloc_rewrite as gx
import wloc_wifitile as wx


def _bounded_env_int(name, default, minimum, maximum):
    value = int(os.environ.get(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_env_float(name, default, minimum, maximum):
    value = float(os.environ.get(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


LISTEN_HOST = os.environ.get("GSLOC_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = _bounded_env_int("GSLOC_LISTEN_PORT", 10451, 1, 65535)
LEAF_CRT = os.environ.get("GSLOC_LEAF_CRT", "/etc/home-location-endpoint/leaf.crt")
LEAF_KEY = os.environ.get("GSLOC_LEAF_KEY", "/etc/home-location-endpoint/leaf.key")
PRESETS = os.environ.get("GSLOC_PRESETS", "/etc/home-location-endpoint/location.json")
JITTER_SEED = os.environ.get("GSLOC_JITTER_SEED", "/etc/home-location-endpoint/jitter.seed")
MODIFIER_STATE = os.environ.get(
    "GSLOC_MODIFIER_STATE", "/var/lib/home-location-endpoint/modifier.state"
)
LOG = os.environ.get("GSLOC_LOG", "/var/log/home-location-endpoint/interceptor.log")
UPSTREAM_TIMEOUT = _bounded_env_float("GSLOC_UPSTREAM_TIMEOUT", 10, 1, 120)
UPSTREAM_ATTEMPTS = _bounded_env_int("GSLOC_UPSTREAM_ATTEMPTS", 2, 1, 5)
UPSTREAM_RETRY_DELAY = _bounded_env_float(
    "GSLOC_UPSTREAM_RETRY_DELAY", 0.15, 0, 10
)
CLIENT_TIMEOUT = _bounded_env_float("GSLOC_CLIENT_TIMEOUT", 15, 1, 120)
UPSTREAM_INSECURE = os.environ.get("GSLOC_UPSTREAM_INSECURE", "0") == "1"
FAIL_CLOSED = os.environ.get("GSLOC_FAIL_CLOSED", "1") != "0"
MAX_REQUEST_BODY = _bounded_env_int(
    "GSLOC_MAX_REQUEST_BODY", 2 * 1024 * 1024, 1024, 16 * 1024 * 1024
)
MAX_RESPONSE_BODY = _bounded_env_int(
    "GSLOC_MAX_RESPONSE_BODY", 8 * 1024 * 1024, 1024, 64 * 1024 * 1024
)
MAX_DECOMPRESSED_BODY = _bounded_env_int(
    "GSLOC_MAX_DECOMPRESSED_BODY", 16 * 1024 * 1024, 1024, 128 * 1024 * 1024
)
MAX_WORKERS = _bounded_env_int("GSLOC_MAX_WORKERS", 4, 1, 32)
MAX_LOG_BYTES = _bounded_env_int(
    "GSLOC_MAX_LOG_BYTES", 16 * 1024 * 1024, 1024 * 1024, 1024 * 1024 * 1024
)
RECENT_WIFI_TTL = _bounded_env_int("GSLOC_RECENT_WIFI_TTL", 1800, 30, 86400)
RECENT_WIFI_MAX = _bounded_env_int("GSLOC_RECENT_WIFI_MAX", 256, 8, 1024)
NO_FIX_MIN_LOCATIONS = _bounded_env_int(
    "GSLOC_NO_FIX_MIN_LOCATIONS", 32, 8, 128
)
WIFI_TEMPLATE_TTL = _bounded_env_int(
    "GSLOC_WIFI_TEMPLATE_TTL", 24 * 60 * 60, 300, 7 * 24 * 60 * 60
)
# Public Cardiff example documented by apple-corelocation-experiments. It is
# fetched only after the phone's requested tile returns 404 and never written
# to disk.
WIFI_SEED_TILEKEY = os.environ.get("GSLOC_WIFI_SEED_TILEKEY", "81644851").strip()
if WIFI_SEED_TILEKEY and not re.fullmatch(r"[0-9]{1,20}", WIFI_SEED_TILEKEY):
    raise ValueError("GSLOC_WIFI_SEED_TILEKEY must be decimal or empty")

# Only these hosts get their /clls/wloc body rewritten; both CN and non-CN so a
# successful spoof that flips the device off the -cn endpoint stays covered.
GSLOC_HOSTS = {"gs-loc.apple.com", "gs-loc-cn.apple.com"}
ASSIST_HOST_RE = re.compile(
    r"^gspe85(?:-[0-9]+)?(?:-cn)?-ssl\.ls\.apple\.com$", re.IGNORECASE
)
WIFI_TILE_PATH = "/wifi_request_tile"
WIFI_TILE_GLOBAL_HOST = "gspe85-ssl.ls.apple.com"

HOP_BY_HOP_REQUEST_HEADERS = {
    "connection",
    "content-length",
    "expect",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
HOP_BY_HOP_RESPONSE_HEADERS = set(HOP_BY_HOP_REQUEST_HEADERS)
SINGLETON_HEADERS = {"content-length", "host", "transfer-encoding"}
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

_log_lock = threading.Lock()
_presets_cache = {"mtime": None, "value": None}
_presets_lock = threading.Lock()
_jitter_seed_cache = {"fingerprint": None, "value": None}
_jitter_seed_lock = threading.Lock()
_recent_wifi = collections.OrderedDict()
_recent_wifi_lock = threading.Lock()
_recent_request_wifi = collections.OrderedDict()
_recent_request_wifi_lock = threading.Lock()
_wifi_template_cache = {"payload": None, "seen": None}
_wifi_template_lock = threading.Lock()
_worker_slots = threading.BoundedSemaphore(MAX_WORKERS)


def log(msg):
    # Naive local time is deliberate: existing log consumers expect no offset.
    stamp = datetime.datetime.now().isoformat(timespec="seconds")  # noqa: DTZ005
    line = f"{stamp} {msg}"
    with _log_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        fd = None
        try:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(LOG, flags, 0o600)
            os.fchmod(fd, 0o600)
            if os.fstat(fd).st_size >= MAX_LOG_BYTES:
                return
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                fd = None
                handle.write(line + "\n")
        except OSError:
            pass
        finally:
            if fd is not None:
                os.close(fd)


def _bssid_to_int(value):
    """Normalize a textual or six-byte BSSID without logging the identifier."""
    if not isinstance(value, str):
        return None
    raw = value.encode("latin1", errors="ignore")
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(compact) == 12:
        try:
            return int(compact, 16)
        except ValueError:
            return None
    if len(raw) == 6:
        return int.from_bytes(raw, "big")
    return None


def _remember_wifi_values_in(cache, lock, values, now=None):
    timestamp = time.monotonic() if now is None else float(now)
    normalized = []
    for value in values:
        bssid = _bssid_to_int(value)
        if bssid is not None:
            normalized.append(bssid)
    if not normalized:
        return 0
    with lock:
        cutoff = timestamp - RECENT_WIFI_TTL
        while cache:
            _key, seen = next(iter(cache.items()))
            if seen >= cutoff:
                break
            cache.popitem(last=False)
        for bssid in normalized:
            cache.pop(bssid, None)
            cache[bssid] = timestamp
        while len(cache) > RECENT_WIFI_MAX:
            cache.popitem(last=False)
    return len(normalized)


def _remember_wifi_values(values, now=None):
    """Keep request and response BSSIDs for no-coverage recovery."""
    return _remember_wifi_values_in(
        _recent_wifi, _recent_wifi_lock, values, now=now
    )


def _remember_request_wifi_values(values, now=None):
    """Keep only phone-requested BSSIDs for normal WifiTile supplementation."""
    return _remember_wifi_values_in(
        _recent_request_wifi, _recent_request_wifi_lock, values, now=now
    )


def remember_wloc_wifi(request_body=None, response_body=None, now=None):
    """Learn BSSID identities in RAM; never persist coordinates or bodies."""
    request_values = set()
    response_values = set()
    if request_body:
        try:
            request_values.update(
                gx.parse_request_context(request_body)["wifi_bssids"]
            )
        except (KeyError, TypeError, ValueError):
            pass
    if response_body:
        try:
            response_values.update(
                entry["bssid"]
                for entry in gx.decode_response(response_body)
                if entry["kind"] == "wifi" and entry["bssid"]
            )
        except (KeyError, TypeError, ValueError):
            pass
    _remember_request_wifi_values(request_values, now=now)
    return _remember_wifi_values(request_values | response_values, now=now)


def _recent_wifi_values_from(cache, lock, now=None):
    timestamp = time.monotonic() if now is None else float(now)
    with lock:
        cutoff = timestamp - RECENT_WIFI_TTL
        while cache:
            _key, seen = next(iter(cache.items()))
            if seen >= cutoff:
                break
            cache.popitem(last=False)
        return list(cache.keys())


def recent_wifi_values(now=None):
    return _recent_wifi_values_from(
        _recent_wifi, _recent_wifi_lock, now=now
    )


def recent_request_wifi_values(now=None):
    return _recent_wifi_values_from(
        _recent_request_wifi, _recent_request_wifi_lock, now=now
    )


def build_no_coverage_tile(target_lat, target_lon, now=None):
    values = recent_wifi_values(now=now)
    if not values:
        return b"", 0
    return wx.build_synthetic_wifi_tile(values, target_lat, target_lon)


def remember_wifi_template(payload, now=None):
    """Cache one complete Apple WifiTile in memory for no-coverage targets."""
    payload = bytes(payload)
    if not payload or len(payload) > MAX_DECOMPRESSED_BODY:
        raise ValueError("WifiTile template has invalid size")
    count = len(wx.decode_locations(payload))
    if count == 0:
        raise ValueError("WifiTile template has no recognized devices")
    timestamp = time.monotonic() if now is None else float(now)
    with _wifi_template_lock:
        _wifi_template_cache["payload"] = payload
        _wifi_template_cache["seen"] = timestamp
    return count


def recent_wifi_template(now=None):
    timestamp = time.monotonic() if now is None else float(now)
    with _wifi_template_lock:
        payload = _wifi_template_cache["payload"]
        seen = _wifi_template_cache["seen"]
        if payload is None or seen is None or timestamp - seen > WIFI_TEMPLATE_TTL:
            _wifi_template_cache["payload"] = None
            _wifi_template_cache["seen"] = None
            return None
        return payload


def build_template_coverage_tile(target_lat, target_lon, now=None):
    payload = recent_wifi_template(now=now)
    if payload is None:
        return b"", 0, None
    return wx.translate_wifi_tile(payload, target_lat, target_lon)


def load_jitter_seed():
    """Load the root-managed seed and reload it only when the file changes."""
    try:
        stat_result = os.stat(JITTER_SEED)
    except OSError as exc:
        raise RuntimeError(f"jitter seed unreadable: {exc!r}")
    fingerprint = (stat_result.st_ino, stat_result.st_mtime_ns, stat_result.st_size)
    with _jitter_seed_lock:
        if _jitter_seed_cache["fingerprint"] != fingerprint:
            try:
                with open(JITTER_SEED, "rb") as handle:
                    seed = handle.read(65)
            except OSError as exc:
                raise RuntimeError(f"jitter seed unreadable: {exc!r}")
            if not 16 <= len(seed) <= 64:
                raise RuntimeError("jitter seed must contain 16-64 bytes")
            _jitter_seed_cache["value"] = seed
            _jitter_seed_cache["fingerprint"] = fingerprint
        return _jitter_seed_cache["value"]


def active_target(now=None):
    """Return the active target plus its deterministic smooth micro-drift."""
    with _presets_lock:
        try:
            stat_result = os.stat(PRESETS)
        except OSError as exc:
            raise RuntimeError(f"presets unreadable: {exc!r}")
        fingerprint = (stat_result.st_ino, stat_result.st_mtime_ns, stat_result.st_size)
        if _presets_cache["mtime"] != fingerprint:
            _presets_cache["value"] = gx.load_presets(PRESETS)
            _presets_cache["mtime"] = fingerprint
        presets = _presets_cache["value"]
    key = presets["active"]
    lat, lon, accuracy = gx.resolve_target(presets, key)
    radius_m, period_s = gx.resolve_jitter(presets, key)
    if radius_m > 0:
        lat, lon = gx.smooth_jitter_target(
            lat, lon, radius_m, period_s, load_jitter_seed(), key,
            timestamp=time.time() if now is None else now,
        )
    return lat, lon, accuracy


def modification_is_active():
    """Return the persistent rewrite state; old installations default active."""
    try:
        with open(MODIFIER_STATE, "r", encoding="ascii") as handle:
            value = handle.read(16).strip()
            if handle.read(1):
                raise RuntimeError("modifier state is too large")
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise RuntimeError(f"modifier state unreadable: {exc!r}") from exc
    if value not in {"active", "paused"}:
        raise RuntimeError(f"invalid modifier state: {value!r}")
    return value == "active"


def effective_origin_host(upstream, method, path, modifier_active):
    if not modifier_active:
        return upstream
    return select_origin_host(upstream, method, path)


def is_assist_host(host):
    return ASSIST_HOST_RE.fullmatch(host or "") is not None


def is_allowed_host(host):
    host = str(host or "").strip().rstrip(".").lower()
    return host in GSLOC_HOSTS or is_assist_host(host)


def normalize_location_host(value):
    value = str(value or "").strip()
    if not value or value.startswith("[") or value.count(":") > 1:
        raise ValueError("invalid location Host header")
    host, separator, port = value.rpartition(":")
    if separator:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("invalid port in location Host header")
    else:
        host = value
    host = host.rstrip(".").lower()
    if not is_allowed_host(host):
        raise ValueError(f"unexpected upstream host: {host}")
    return host


def is_wifi_tile_request(host, method, path):
    clean_path = path.split("?", 1)[0]
    return is_assist_host(host) and method == "GET" and clean_path == WIFI_TILE_PATH


def select_origin_host(requested_host, method, path):
    """Use Apple's global WifiTile data when the CN endpoint has no tile.

    iOS may select ``gspe85-cn`` from its CN GeoServices manifest, but observed
    tile keys return 404 there while the identical key exists on ``gspe85``.
    This substitution is deliberately limited to the one location-assist path.
    """
    if (
        is_wifi_tile_request(requested_host, method, path)
        and requested_host.lower() == "gspe85-cn-ssl.ls.apple.com"
    ):
        return WIFI_TILE_GLOBAL_HOST
    return requested_host


def operational_path(path):
    """Keep routine logs useful without retaining URL query material."""
    return str(path or "").split("?", 1)[0]


def is_wloc_request(host, method, path):
    return (
        host in GSLOC_HOSTS
        and method == "POST"
        and operational_path(path) == "/clls/wloc"
    )


def decode_wifi_tile_payload(body, content_encoding):
    """Return a bounded uncompressed WifiTile plus its transport encoding."""
    encoding = (content_encoding or "").strip().lower()
    if encoding in {"", "identity"}:
        plain = body
    elif encoding == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as archive:
            plain = archive.read(MAX_DECOMPRESSED_BODY + 1)
        if len(plain) > MAX_DECOMPRESSED_BODY:
            raise ValueError("WifiTile decompressed body too large")
    else:
        raise ValueError(f"unsupported WifiTile content encoding: {encoding}")
    if len(plain) > MAX_DECOMPRESSED_BODY:
        raise ValueError("WifiTile decompressed body too large")
    return plain, encoding


def rewrite_wifi_tile_response(
    body,
    content_encoding,
    lat,
    lon,
    recent_bssids=None,
):
    """Translate a WifiTile and append missing recent AP identities."""
    plain, encoding = decode_wifi_tile_payload(body, content_encoding)
    remember_wifi_template(plain)

    replacement, count, anchor = wx.translate_wifi_tile(plain, lat, lon)
    if count == 0:
        if FAIL_CLOSED and plain:
            raise ValueError("WifiTile response has no recognized devices")
        return body, 0, anchor, 0
    replacement, injected = wx.supplement_wifi_tile(
        replacement,
        recent_bssids,
        lat,
        lon,
    )
    if encoding == "gzip":
        replacement = gzip.compress(replacement, mtime=0)
    return replacement, count, anchor, injected


# --- minimal HTTP/1.1 helpers ------------------------------------------------

def _read_crlf_line(reader, limit):
    line = reader.readline(limit + 1)
    if not line:
        raise ConnectionError("EOF before CRLF")
    if len(line) > limit or not line.endswith(b"\r\n"):
        raise ValueError("HTTP line too large or missing CRLF")
    return line[:-2]


def read_headers(reader):
    """Read start line + headers. Returns (start_line:str, header_lines:list[str])."""
    total = 0
    start_line = _read_crlf_line(reader, 8192)
    total += len(start_line) + 2
    lines = []
    while True:
        line = _read_crlf_line(reader, 16384)
        total += len(line) + 2
        if total > 65536:
            raise ValueError("header block too large")
        if not line:
            break
        lines.append(line.decode("latin1"))
    return start_line.decode("latin1"), lines


def header_map(lines):
    out = {}
    for line in lines:
        if not line or line[0] in " \t" or ":" not in line:
            raise ValueError("malformed or folded HTTP header")
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not HEADER_NAME_RE.fullmatch(key):
            raise ValueError("invalid HTTP header name")
        if any(
            (ord(character) < 32 and character != "\t") or ord(character) == 127
            for character in value
        ):
            raise ValueError("control character in HTTP header value")
        if key in SINGLETON_HEADERS and key in out:
            raise ValueError(f"duplicate singleton HTTP header: {key}")
        out[key] = value if key not in out else out[key] + ", " + value
    if "content-length" in out and "transfer-encoding" in out:
        raise ValueError("both Content-Length and Transfer-Encoding are present")
    return out


def read_body(reader, headers, max_bytes=MAX_REQUEST_BODY):
    te = headers.get("transfer-encoding", "").lower()
    if te and te != "chunked":
        raise ValueError("unsupported Transfer-Encoding")
    if te == "chunked":
        body = bytearray()
        while True:
            size_line = _read_crlf_line(reader, 128)
            size_text = size_line.split(b";", 1)[0].strip()
            if not size_text or not re.fullmatch(rb"[0-9A-Fa-f]+", size_text):
                raise ValueError("invalid chunk size")
            size = int(size_text, 16)
            if size < 0:
                raise ValueError("negative chunk size")
            if size == 0:
                trailer_bytes = 0
                while True:
                    trailer = _read_crlf_line(reader, 8192)
                    trailer_bytes += len(trailer) + 2
                    if trailer_bytes > 16384:
                        raise ValueError("chunk trailers too large")
                    if not trailer:
                        break
                break
            if len(body) + size > max_bytes:
                raise ValueError("HTTP body too large")
            body += _read_exact(reader, size)
            if _read_exact(reader, 2) != b"\r\n":
                raise ValueError("chunk data is not followed by CRLF")
        return bytes(body)
    if "content-length" in headers:
        content_length = headers["content-length"].strip()
        if not content_length.isdigit():
            raise ValueError("invalid Content-Length")
        size = int(content_length)
        if size < 0 or size > max_bytes:
            raise ValueError("HTTP body too large")
        return _read_exact(reader, size)
    return b""  # no body (typical for a request); responses use CL or chunked


def _read_exact(reader, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = reader.read(n - len(buf))
        if not chunk:
            raise ConnectionError(f"EOF: wanted {n}, got {len(buf)}")
        buf += chunk
    return bytes(buf)


def read_response_body(reader, headers):
    """Response bodies may also be delimited by connection close."""
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te or "content-length" in headers:
        return read_body(reader, headers, max_bytes=MAX_RESPONSE_BODY)
    body = reader.read(MAX_RESPONSE_BODY + 1)  # until EOF, but never unbounded
    if len(body) > MAX_RESPONSE_BODY:
        raise ValueError("HTTP response body too large")
    return body


# --- upstream fetch ----------------------------------------------------------

def build_upstream_request(host, request_line, header_lines, body):
    """Rebuild a de-chunked HTTP/1.1 request without dropping Apple X-* headers."""
    forwarded = [("Host", host)]
    connection_tokens = set()
    for line in header_lines:
        if ":" in line and line.split(":", 1)[0].strip().lower() == "connection":
            connection_tokens.update(
                token.strip().lower() for token in line.split(":", 1)[1].split(",")
            )
    for line in header_lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() in HOP_BY_HOP_REQUEST_HEADERS | connection_tokens:
            continue
        if name.strip().lower() == "accept-encoding":
            continue
        forwarded.append((name.strip(), value.strip()))
    # Identity makes protobuf processing deterministic. If an upstream nevertheless
    # returns encoded bytes, build_response preserves Content-Encoding on passthrough.
    forwarded.append(("Accept-Encoding", "identity"))
    forwarded.append(("Content-Length", str(len(body))))
    forwarded.append(("Connection", "close"))
    head = request_line + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in forwarded) + "\r\n"
    return head.encode("latin1") + body


def replace_request_header(header_lines, name, value):
    """Replace one request header while removing duplicate copies."""
    wanted = name.lower()
    replaced = False
    result = []
    for line in header_lines:
        if ":" in line and line.split(":", 1)[0].strip().lower() == wanted:
            if not replaced:
                result.append(f"{name}: {value}")
                replaced = True
            continue
        result.append(line)
    if not replaced:
        result.append(f"{name}: {value}")
    return result


def fetch_upstream(host, request_line, header_lines, body):
    ctx = ssl.create_default_context()
    if UPSTREAM_INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])

    request_bytes = build_upstream_request(host, request_line, header_lines, body)
    last_error = None
    for attempt in range(1, UPSTREAM_ATTEMPTS + 1):
        raw = None
        tls = None
        try:
            raw = socket.create_connection((host, 443), timeout=UPSTREAM_TIMEOUT)
            raw.settimeout(UPSTREAM_TIMEOUT)
            tls = ctx.wrap_socket(raw, server_hostname=host)
            tls.sendall(request_bytes)
            reader = tls.makefile("rb")
            return read_final_response(reader)
        except (ConnectionError, OSError, ssl.SSLError) as exc:
            last_error = exc
            if attempt < UPSTREAM_ATTEMPTS:
                log(f"UPSTREAM_RETRY host={host} attempt={attempt}/{UPSTREAM_ATTEMPTS}"
                    f" err={exc!r}")
                if UPSTREAM_RETRY_DELAY:
                    time.sleep(UPSTREAM_RETRY_DELAY)
        finally:
            _safe_close(tls)
            if tls is None:
                _safe_close(raw)
    raise last_error


def fetch_seed_wifi_template(host, request_line, header_lines, body):
    """Fetch one known-valid public tile when the requested region has none."""
    if not WIFI_SEED_TILEKEY:
        raise ValueError("WifiTile seed key disabled")
    seed_headers = replace_request_header(
        header_lines, "X-tilekey", WIFI_SEED_TILEKEY
    )
    status_line, response_lines, headers, response_body = fetch_upstream(
        host, request_line, seed_headers, body
    )
    if status_line.split(" ")[1:2] != ["200"]:
        raise ValueError("WifiTile seed returned non-200")
    return status_line, response_lines, headers, response_body


def read_final_response(reader):
    for _ in range(6):
        status_line, response_header_lines = read_headers(reader)
        validate_status_line(status_line)
        headers = header_map(response_header_lines)
        status_code = int(status_line.split(" ", 2)[1])
        if 100 <= status_code < 200:
            if status_code == 101:
                raise ValueError("upstream protocol upgrades are unsupported")
            continue
        if status_code in {204, 304}:
            resp_body = b""
        else:
            resp_body = read_response_body(reader, headers)
        return status_line, response_header_lines, headers, resp_body
    raise ValueError("too many informational upstream responses")


def validate_request_line(request_line):
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise ValueError("malformed HTTP request line")
    method, path, version = parts
    if method not in {"GET", "POST"} or version != "HTTP/1.1":
        raise ValueError("unsupported HTTP method or version")
    if (
        not path.startswith("/")
        or any(not 0x21 <= ord(character) <= 0x7E for character in path)
    ):
        raise ValueError("invalid origin-form request target")
    return method, path


def validate_status_line(status_line):
    parts = status_line.split(" ", 2)
    if (
        len(parts) < 2
        or parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or len(parts[1]) != 3
        or not parts[1].isdigit()
        or any(ord(character) < 32 or ord(character) == 127 for character in status_line)
    ):
        raise ValueError("malformed upstream HTTP status line")


def build_response(status_line, header_lines, headers, body, strip_content_encoding=False):
    keep = []
    connection_tokens = {
        token.strip().lower()
        for token in headers.get("connection", "").split(",")
        if token.strip()
    }
    for line in header_lines:
        if ":" not in line:
            continue
        name = line.split(":", 1)[0].strip().lower()
        if name in HOP_BY_HOP_RESPONSE_HEADERS | connection_tokens:
            continue
        if strip_content_encoding and name == "content-encoding":
            continue
        keep.append(line)
    keep.append(f"Content-Length: {len(body)}")
    keep.append("Connection: close")
    head = status_line + "\r\n" + "\r\n".join(keep) + "\r\n\r\n"
    return head.encode("latin1") + body


def build_error_response():
    return (
        b"HTTP/1.1 502 Bad Gateway\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n\r\n"
    )


# --- connection handling -----------------------------------------------------

def handle(conn, addr, ctx):
    conn.settimeout(CLIENT_TIMEOUT)
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError) as exc:
        # A single leaf whose SAN covers both gs-loc hosts is presented, so a
        # TLS_FAIL here (with the CA trusted on the phone) means pinning, not SNI.
        log(f"TLS_FAIL peer={addr[0]}:{addr[1]} err={exc!r}")
        _safe_close(conn)
        return

    upstream = ""
    try:
        reader = tls.makefile("rb")
        request_line, header_lines = read_headers(reader)
        req_headers = header_map(header_lines)
        body = read_body(reader, req_headers)

        method, path = validate_request_line(request_line)
        # Upstream host comes from the phone's HTTP/1.1 Host header (mandatory);
        # no reliance on SNI, so a single shared TLS context stays thread-safe.
        upstream = normalize_location_host(req_headers.get("host", ""))

        modifier_active = modification_is_active()
        origin = effective_origin_host(upstream, method, path, modifier_active)
        if origin != upstream:
            log(f"ORIGIN_SUBSTITUTE requested={upstream} origin={origin}"
                f" path={operational_path(path)}")
        status_line, up_header_lines, up_headers, resp_body = fetch_upstream(
            origin, request_line, header_lines, body
        )
        status_code = int(status_line.split(" ", 2)[1])
        if not modifier_active:
            tls.sendall(build_response(
                status_line, up_header_lines, up_headers, resp_body
            ))
            log(f"MODIFIER_PAUSED_PASSTHRU host={upstream}"
                f" path={operational_path(path)}"
                f" code={status_line.split(' ')[1:2]} bytes={len(resp_body)}")
            return
        assist = is_assist_host(upstream)
        if assist:
            tile_state = "present" if req_headers.get("x-tilekey") else "none"
            log(f"ASSIST host={upstream} method={method}"
                f" path={operational_path(path)}"
                f" code={status_line.split(' ')[1:2]} tile={tile_state}"
                f" type={up_headers.get('content-type', '-')}"
                f" encoding={up_headers.get('content-encoding', 'identity')}"
                f" req={len(body)} resp={len(resp_body)}")
        if is_wloc_request(upstream, method, path):
            remember_wloc_wifi(
                request_body=body,
                response_body=resp_body if status_code == 200 else None,
            )
        rewritten = False
        strip_content_encoding = False
        count = 0
        if (
            is_wloc_request(upstream, method, path)
            and status_code == 200
        ):
            try:
                lat, lon, acc = active_target()
                prepared_body, nofix_original, nofix_prepared = (
                    gx.supplement_sparse_no_fix_response(
                        resp_body,
                        recent_wifi_values(),
                        minimum_locations=NO_FIX_MIN_LOCATIONS,
                    )
                )
                new_body, count, anchor, anchor_source = gx.translate_response(
                    prepared_body,
                    lat,
                    lon,
                    request_body=body,
                    accuracy=acc,
                )
                if count > 0:
                    resp_body = new_body
                    rewritten = True
                    strip_content_encoding = True
                    anchor_state = "present" if anchor is not None else "none"
                    if anchor_source == gx.NO_FIX_SOURCE:
                        if nofix_prepared > nofix_original:
                            log(f"TRANSLATE_NOFIX_STABILIZED host={upstream}"
                                f" path={operational_path(path)}"
                                f" original={nofix_original} locations={count}"
                                f" bytes={len(new_body)}")
                        else:
                            log(f"TRANSLATE_NOFIX_CLUSTER host={upstream}"
                                f" path={operational_path(path)}"
                                f" locations={count} bytes={len(new_body)}")
                    else:
                        log(f"TRANSLATE host={upstream} path={operational_path(path)}"
                            f" locations={count} anchor={anchor_state}"
                            f" source={anchor_source} bytes={len(new_body)}")
                elif anchor_source == gx.NO_FIX_SOURCE:
                    # Non-empty sentinel batches are synthesized above and have
                    # count > 0. This branch is the proven empty no-fix response;
                    # unknown or malformed unanchored responses never reach it.
                    resp_body = new_body
                    log(f"TRANSLATE_NOFIX_EMPTY host={upstream}"
                        f" path={operational_path(path)} bytes={len(new_body)}")
                else:
                    if FAIL_CLOSED and len(resp_body) > 10:
                        log(f"TRANSLATE_EMPTY_FAIL_CLOSED host={upstream}"
                            f" bytes={len(resp_body)}")
                        tls.sendall(build_error_response())
                        return
                    log(f"TRANSLATE_EMPTY host={upstream}"
                        f" path={operational_path(path)}"
                        f" bytes={len(resp_body)} (unchanged)")
            except Exception as exc:  # noqa: BLE001
                if FAIL_CLOSED:
                    log(f"TRANSLATE_FAIL_CLOSED host={upstream} err={exc!r}")
                    tls.sendall(build_error_response())
                    return
                log(f"TRANSLATE_SKIP host={upstream} err={exc!r}"
                    " (returned real response)")

        tile_request = is_wifi_tile_request(upstream, method, path)
        if tile_request and status_code == 404:
            tile_count = 0
            target = None
            try:
                lat, lon, _acc = active_target()
                target = (lat, lon)
            except Exception as exc:  # noqa: BLE001
                log(f"WIFITILE_TARGET_SKIP host={upstream} err={exc!r}"
                    " (returned upstream 404)")
            try:
                if target is None:
                    raise ValueError("active target unavailable")
                new_body, tile_count, _tile_anchor = build_template_coverage_tile(*target)
                if tile_count > 0:
                    resp_body = new_body
                    status_line = "HTTP/1.1 200 OK"
                    up_header_lines = [
                        "Content-Type: application/octet-stream",
                        "Cache-Control: max-age=120",
                    ]
                    up_headers = {"content-type": "application/octet-stream"}
                    rewritten = True
                    strip_content_encoding = True
                    count += tile_count
                    log(f"WIFITILE_TEMPLATE_404 host={upstream} source=cache"
                        f" devices={tile_count} bytes={len(new_body)}")
            except Exception as exc:  # noqa: BLE001
                log(f"WIFITILE_TEMPLATE_CACHE_SKIP host={upstream} err={exc!r}")

            if tile_count == 0 and target is not None:
                try:
                    seed_status, seed_lines, seed_headers, seed_body = (
                        fetch_seed_wifi_template(
                            origin, request_line, header_lines, body
                        )
                    )
                    (
                        new_body,
                        tile_count,
                        _tile_anchor,
                        _injected,
                    ) = rewrite_wifi_tile_response(
                        seed_body,
                        seed_headers.get("content-encoding", ""),
                        target[0],
                        target[1],
                    )
                    if tile_count > 0:
                        resp_body = new_body
                        status_line = seed_status
                        up_header_lines = seed_lines
                        up_headers = seed_headers
                        rewritten = True
                        strip_content_encoding = False
                        count += tile_count
                        log(f"WIFITILE_TEMPLATE_404 host={upstream} source=seed"
                            f" devices={tile_count} bytes={len(new_body)}")
                except Exception as exc:  # noqa: BLE001
                    log(f"WIFITILE_TEMPLATE_SEED_SKIP host={upstream} err={exc!r}")

            if tile_count == 0 and target is not None:
                try:
                    new_body, tile_count = build_no_coverage_tile(*target)
                    if tile_count > 0:
                        resp_body = new_body
                        status_line = "HTTP/1.1 200 OK"
                        up_header_lines = [
                            "Content-Type: application/octet-stream",
                            "Cache-Control: max-age=120",
                        ]
                        up_headers = {"content-type": "application/octet-stream"}
                        rewritten = True
                        strip_content_encoding = True
                        count += tile_count
                        log(f"WIFITILE_SYNTHETIC_404 host={upstream}"
                            f" devices={tile_count} bytes={len(new_body)}")
                    else:
                        log(f"WIFITILE_SYNTHETIC_EMPTY host={upstream}"
                            " (returned upstream 404)")
                except Exception as exc:  # noqa: BLE001
                    # Optional fallbacks must not turn an honest upstream 404
                    # into a broader location outage.
                    log(f"WIFITILE_SYNTHETIC_SKIP host={upstream} err={exc!r}"
                        " (returned upstream 404)")
        elif tile_request and status_code == 200:
            try:
                lat, lon, _acc = active_target()
                (
                    new_body,
                    tile_count,
                    tile_anchor,
                    injected,
                ) = rewrite_wifi_tile_response(
                    resp_body,
                    up_headers.get("content-encoding", ""),
                    lat,
                    lon,
                    recent_bssids=recent_request_wifi_values(),
                )
                if tile_count > 0:
                    resp_body = new_body
                    rewritten = True
                    count += tile_count + injected
                    anchor_state = "present" if tile_anchor is not None else "none"
                    log(
                        f"WIFITILE_TRANSLATE host={upstream} devices={tile_count}"
                        f" injected={injected} anchor={anchor_state}"
                        f" bytes={len(new_body)}"
                    )
                else:
                    log(f"WIFITILE_EMPTY host={upstream}"
                        f" bytes={len(resp_body)} (unchanged)")
            except Exception as exc:  # noqa: BLE001
                if FAIL_CLOSED:
                    log(f"WIFITILE_FAIL_CLOSED host={upstream} err={exc!r}")
                    tls.sendall(build_error_response())
                    return
                log(f"WIFITILE_SKIP host={upstream} err={exc!r}"
                    " (returned real response)")

        tls.sendall(build_response(
            status_line, up_header_lines, up_headers, resp_body,
            strip_content_encoding=strip_content_encoding,
        ))
        if not rewritten and not assist:
            log(f"PASSTHRU host={upstream} {method} {operational_path(path)}"
                f" code={status_line.split(' ')[1:2]} bytes={len(resp_body)}")
    except Exception as exc:  # noqa: BLE001
        log(f"ERROR peer={addr[0]}:{addr[1]} host={upstream} err={exc!r}")
        try:
            tls.sendall(build_error_response())
        except (OSError, ssl.SSLError):
            pass
    finally:
        _safe_close(tls)


def _safe_close(sock):
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _handle_with_slot(conn, addr, ctx):
    try:
        handle(conn, addr, ctx)
    finally:
        _worker_slots.release()


def main():
    if not (os.path.exists(LEAF_CRT) and os.path.exists(LEAF_KEY)):
        sys.exit(f"missing leaf material: {LEAF_CRT} / {LEAF_KEY}")
    try:
        active_target()
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"invalid location target configuration: {exc!r}")
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
    except OSError:
        pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=LEAF_CRT, keyfile=LEAF_KEY)
    ctx.set_alpn_protocols(["http/1.1"])

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(max(8, MAX_WORKERS * 2))
    log(f"LISTENING {LISTEN_HOST}:{LISTEN_PORT} leaf={LEAF_CRT} presets={PRESETS}"
        f" insecure_upstream={UPSTREAM_INSECURE} attempts={UPSTREAM_ATTEMPTS}"
        f" fail_closed={FAIL_CLOSED} max_workers={MAX_WORKERS}")
    try:
        while True:
            conn, addr = srv.accept()
            if not _worker_slots.acquire(blocking=False):
                log(f"BUSY peer={addr[0]}:{addr[1]} workers={MAX_WORKERS}")
                _safe_close(conn)
                continue
            threading.Thread(
                target=_handle_with_slot, args=(conn, addr, ctx), daemon=True
            ).start()
    except KeyboardInterrupt:
        log("STOPPED")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
