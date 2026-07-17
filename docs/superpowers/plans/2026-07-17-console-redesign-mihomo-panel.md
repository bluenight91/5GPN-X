# 控制台重构 + mihomo 面板接入 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 重写 `webui/index.html`（双主题 + iOS Safari 移动端 + 六页结构），并通过 api-server 同源反代把 metacubexd 安全接入控制台（mihomo 仅回环，secret 不出服务端）。

**Architecture:** 见 `docs/superpowers/specs/2026-07-17-console-redesign-mihomo-panel-design.md`。唯一公网入口 8444（TLS + Bearer API_TOKEN）；api-server 新增 `/mihomo/*` 静态服务、`/api/mihomo/proxy/*` 反代（注入 Clash secret，HTTP + WS 中继）、`/api/mihomo/overview` 聚合端点；smart 路由实例开启 `external-controller: 127.0.0.1:9090`。

**Tech Stack:** bash（install.sh）、Python3 stdlib（api-server / 测试）、单文件 HTML/CSS/JS（webui，零依赖零构建）、mihomo 1.19.28、metacubexd v1.269.0。

**仓库:** `/Users/danielzhao/Kimi/tmp_repo_compare/5GPN-X-fork`，分支 `feat/web-console`。所有命令在仓库根目录执行。

**关键既有事实（执行者需知）：**
- `lib/api-server.py` 是 stdlib-only HTTPS 服务，`Handler.do_GET/do_POST` 里按 `path` 分发；`_auth()` 校验 Bearer；`_send(code, obj)` 返回 JSON；`run(argv)` / `ctl(*args)` 执行子命令；模块级常量（如 `CONF_DIR`）在函数调用时读取，测试可直接猴子补丁模块属性。
- `lib/mihomo-router-config.py` 末尾（约 254-262 行）构造 `config` dict 并 `json.dumps` 输出；`install.sh` 的 `regen_smart()` 以 `EXITS_DIR=... WG_DIR=... PGW_RULESET_CACHE=... PGW_POLICY_MAP=... python3 "${MIHOMO_ROUTER_GEN}" "$eff"` 调用它，并用 `mihomo -t` 校验。
- `install.sh` 常量区在文件头部（`EXITS_DIR="/etc/5gpn/exits"` 等）；`setup_api()` 在 `setup_tgbot()` 之后；既有锁定版本模式：`MIHOMO_VERSION_DEFAULT="1.19.28"`。
- 测试约定：`tests/*.sh` 是 grep 级 policy 断言（见 `tests/test_api_setup_policy.sh`）；Python 测试用 stdlib `unittest`，以 FakeApi/mock 方式（见 `tests/test_tgbot_console.py`）。
- 现有 `webui/index.html`（856 行）包含全部 API 调用逻辑（`api("/api/...")`），重写时逐页迁移。

---

## Task 1: mihomo router 配置开启 external-controller

**Files:**
- Modify: `lib/mihomo-router-config.py`（config dict 构造处，约 254-262 行）
- Create: `tests/test_mihomo_api_policy.sh`

- [ ] **Step 1: 写失败的 policy 测试**

```bash
#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gen="$(cat "${root}/lib/mihomo-router-config.py")"
install_body="$(cat "${root}/install.sh")"
fail() { echo "$1" >&2; exit 1; }

# --- router config enables the Clash API on loopback only --------------------
[[ "${gen}" == *'external-controller'* ]] || fail "router config must set external-controller"
[[ "${gen}" == *'127.0.0.1:9090'* ]] || fail "external-controller must bind 127.0.0.1:9090"
[[ "${gen}" == *'MIHOMO_API_SECRET_FILE'* ]] || fail "router generator must read the secret file path from env"
[[ "${gen}" == *'/etc/5gpn/mihomo-api-secret'* ]] || fail "default secret file must be /etc/5gpn/mihomo-api-secret"

# --- installer creates the secret --------------------------------------------
[[ "${install_body}" == *'ensure_mihomo_api_secret() {'* ]] || fail "install.sh must define ensure_mihomo_api_secret()"
[[ "${install_body}" == *'openssl rand -hex 32'* ]] || fail "secret must be openssl rand -hex 32"
[[ "${install_body}" == *'MIHOMO_API_SECRET_FILE='/etc/5gpn/mihomo-api-secret''* ]] || fail "install.sh must define MIHOMO_API_SECRET_FILE"

echo "test_mihomo_api_policy: OK"
```

- [ ] **Step 2: 运行确认失败**

Run: `bash tests/test_mihomo_api_policy.sh`
Expected: FAIL `router config must set external-controller`

- [ ] **Step 3: 实现 router 生成器改动**

`lib/mihomo-router-config.py`：在文件头部 import 区域后加：

```python
SECRET_FILE = os.environ.get("MIHOMO_API_SECRET_FILE", "/etc/5gpn/mihomo-api-secret")
```

在 `config = {...}` 构造之后、`sys.stdout.write(...)` 之前加：

```python
    secret = ""
    try:
        with open(SECRET_FILE, encoding="utf-8") as fh:
            secret = fh.read().strip()
    except OSError:
        secret = ""
    if secret:
        config["external-controller"] = "127.0.0.1:9090"
        config["secret"] = secret
```

- [ ] **Step 4: 实现 install.sh secret 生成**

常量区（`EXITS_DIR="/etc/5gpn/exits"` 附近）加：

```bash
MIHOMO_API_SECRET_FILE='/etc/5gpn/mihomo-api-secret'
```

`setup_api()` 之前加函数：

```bash
ensure_mihomo_api_secret() {
    if [[ ! -s "${MIHOMO_API_SECRET_FILE}" ]]; then
        mkdir -p /etc/5gpn; chmod 700 /etc/5gpn
        openssl rand -hex 32 > "${MIHOMO_API_SECRET_FILE}"
        chmod 600 "${MIHOMO_API_SECRET_FILE}"
    fi
}
```

并在 `setup_api()` 内 `info "Installing HTTP control API..."` 之后加一行：`ensure_mihomo_api_secret`

- [ ] **Step 5: 运行测试确认通过**

Run: `bash tests/test_mihomo_api_policy.sh`
Expected: PASS `test_mihomo_api_policy: OK`

- [ ] **Step 6: 全量回归 + 提交**

Run: `for t in tests/*.sh; do bash "$t" >/dev/null 2>&1 || echo "FAIL: $t"; done`（仅 2 个 macOS 环境预置失败可接受：test_exit_proxy_types_policy.sh、test_sniproxy_dns_rewrite_idempotent.sh）

```bash
git add lib/mihomo-router-config.py install.sh tests/test_mihomo_api_policy.sh
git commit -m "feat(mihomo): expose Clash API on loopback for smart router + installer-generated secret"
```

---

## Task 2: install.sh 安装 metacubexd + 重建 smart 配置

**Files:**
- Modify: `install.sh`（常量区、`setup_api()`）
- Modify: `tests/test_mihomo_api_policy.sh`

- [ ] **Step 1: 扩充 policy 测试（先失败）**

在 `test_mihomo_api_policy.sh` 末尾 `echo` 前追加：

```bash
# --- installer vendors metacubexd (pinned version, download at install) ------
[[ "${install_body}" == *'METACUBEXD_VERSION_DEFAULT="1.269.0"'* ]] || fail "install.sh must pin METACUBEXD_VERSION_DEFAULT"
[[ "${install_body}" == *'install_metacubexd() {'* ]] || fail "install.sh must define install_metacubexd()"
[[ "${install_body}" == *'MetaCubeX/metacubexd/releases/download/v${ver}/compressed-dist.tgz'* ]] || fail "metacubexd must come from the pinned GitHub release asset"
[[ "${install_body}" == *'${BASE_DIR}/webui/mihomo'* ]] || fail "metacubexd must unpack to \${BASE_DIR}/webui/mihomo"
[[ "${install_body}" == *'( regen_smart )'* ]] || fail "setup_api must rebuild the smart config in a subshell"
```

- [ ] **Step 2: 运行确认失败**

Run: `bash tests/test_mihomo_api_policy.sh`
Expected: FAIL `install.sh must pin METACUBEXD_VERSION_DEFAULT`

- [ ] **Step 3: 实现**

`install.sh` 常量区（`MIHOMO_VERSION_DEFAULT` 附近）加：

```bash
METACUBEXD_VERSION_DEFAULT="1.269.0"
```

`ensure_mihomo_api_secret()` 之后加：

```bash
install_metacubexd() {
    local ver="${METACUBEXD_VERSION:-${METACUBEXD_VERSION_DEFAULT}}"
    local url="https://github.com/MetaCubeX/metacubexd/releases/download/v${ver}/compressed-dist.tgz"
    local tmp; tmp="$(mktemp)"
    info "Downloading metacubexd v${ver}..."
    if ! curl -fsSL "$url" -o "$tmp"; then
        warn "metacubexd 下载失败（可稍后重跑 --setup-api）；mihomo 监控页暂不可用，其余功能不受影响。"
        rm -f "$tmp"; return 0
    fi
    mkdir -p "${BASE_DIR}/webui/mihomo"
    tar -xzf "$tmp" -C "${BASE_DIR}/webui/mihomo" 2>/dev/null || tar -xf "$tmp" -C "${BASE_DIR}/webui/mihomo"
    rm -f "$tmp"
    ok "metacubexd v${ver} installed to ${BASE_DIR}/webui/mihomo"
}
```

`setup_api()` 内 `ensure_mihomo_api_secret` 之后加：

```bash
    install_metacubexd
    if [[ -f "${RULES_FILE}" ]]; then
        info "Rebuilding smart router config to enable the mihomo API..."
        ( regen_smart ) || warn "smart 配置重建失败；配置规则后可重跑 --setup-api"
    fi
```

- [ ] **Step 4: 运行测试 + 回归 + 提交**

Run: `bash tests/test_mihomo_api_policy.sh` → PASS；`bash -n install.sh` → OK

```bash
git add install.sh tests/test_mihomo_api_policy.sh
git commit -m "feat(install): setup-api installs metacubexd + rebuilds smart config with Clash API"
```

---

## Task 3: api-server — Clash HTTP 反代 + overview 聚合

**Files:**
- Modify: `lib/api-server.py`（常量区 + `Handler`）
- Create: `tests/test_api_mihomo.py`

- [ ] **Step 1: 写失败的 unittest**

```python
#!/usr/bin/env python3
"""Unit tests for the api-server mihomo (Clash API) integration."""
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_api():
    spec = importlib.util.spec_from_file_location("apiserver", os.path.join(ROOT, "lib", "api-server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class FakeClash(BaseHTTPRequestHandler):
    last_auth = None
    def log_message(self, *a): pass
    def _j(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        FakeClash.last_auth = self.headers.get("Authorization")
        if self.path == "/version": return self._j({"version": "1.19.28"})
        if self.path == "/memory": return self._j({"inuse": 123456, "oslimit": 0})
        if self.path == "/connections":
            return self._j({"downloadTotal": 1000, "uploadTotal": 500, "connections": [
                {"id": "1", "rule": "DomainSuffix", "chains": ["jp"]},
                {"id": "2", "rule": "DomainSuffix", "chains": ["jp"]},
                {"id": "3", "rule": "GeoIP", "chains": ["direct"]}]})
        if self.path == "/configs": return self._j({"mode": "rule"})
        self.send_response(404); self.end_headers()
    def do_PUT(self):
        FakeClash.last_auth = self.headers.get("Authorization")
        n = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(n)
        self.send_response(204); self.end_headers()

class MihomoApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load_api()
        cls.secret = tempfile.NamedTemporaryFile(delete=False)
        cls.secret.write(b"s3cr3t-test-token"); cls.secret.close()
        cls.api.CLASH_SECRET_FILE = cls.secret.name
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeClash)
        cls.api.CLASH_ADDR = "127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); os.unlink(cls.secret.name)

    def test_clash_request_injects_secret(self):
        status, _, data = self.api.clash_request("GET", "configs")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["mode"], "rule")
        self.assertEqual(FakeClash.last_auth, "Bearer s3cr3t-test-token")

    def test_clash_request_rejects_bad_path(self):
        status, _, _ = self.api.clash_request("GET", "../etc/passwd")
        self.assertEqual(status, 400)
        status, _, _ = self.api.clash_request("GET", "a b")
        self.assertEqual(status, 400)

    def test_clash_request_missing_secret_returns_503(self):
        self.api.CLASH_SECRET_FILE = "/nonexistent/nope"
        status, _, _ = self.api.clash_request("GET", "configs")
        self.assertEqual(status, 503)
        self.api.CLASH_SECRET_FILE = self.secret.name

    def test_overview_aggregates(self):
        data, err = self.api.mihomo_overview()
        self.assertIsNone(err)
        self.assertEqual(data["connections"], 3)
        self.assertEqual(data["download"], 1000)
        self.assertEqual(data["memory"], 123456)
        self.assertEqual(data["version"], "1.19.28")
        self.assertEqual(data["top_rules"][0], {"rule": "DomainSuffix", "count": 2})

    def test_ws_whitelist(self):
        self.assertTrue(self.api.ws_allowed("traffic"))
        self.assertTrue(self.api.ws_allowed("logs?level=info"))
        self.assertTrue(self.api.ws_allowed("connections"))
        self.assertTrue(self.api.ws_allowed("memory"))
        self.assertFalse(self.api.ws_allowed("configs"))
        self.assertFalse(self.api.ws_allowed("proxies"))

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行确认失败**

Run: `python3 -m unittest tests.test_api_mihomo -v`（仓库根目录，tests 无 `__init__.py` 时用 `python3 tests/test_api_mihomo.py`）
Expected: FAIL `AttributeError: module ... has no attribute 'clash_request'`

- [ ] **Step 3: 实现**

`lib/api-server.py` 常量区（`SERVICES` 之后）加：

```python
CLASH_ADDR = os.environ.get("CLASH_ADDR", "127.0.0.1:9090")
CLASH_SECRET_FILE = os.environ.get("MIHOMO_API_SECRET_FILE", "/etc/5gpn/mihomo-api-secret")
MIHOMO_STATIC_DIR = os.environ.get("MIHOMO_STATIC_DIR", "/opt/5gpn/webui/mihomo")
CLASH_WS_PATHS = {"traffic", "logs", "connections", "memory"}
```

新增函数（放在 `ctl()` 之后）：

```python
# --- mihomo (Clash API) integration ------------------------------------------
def clash_secret():
    return read_file(CLASH_SECRET_FILE).strip()


def clash_request(method, sub, body=None, ctype=None, timeout=30):
    """Call the loopback Clash API with the server-side secret. Returns
    (status, content_type, response_bytes)."""
    sub = sub.split("?", 1)[0].strip("/")
    if not sub or not re.match(r"^[A-Za-z0-9_./-]+$", sub) or ".." in sub:
        return 400, "application/json", b'{"message":"bad path"}'
    secret = clash_secret()
    if not secret:
        return 503, "application/json", b'{"message":"mihomo api not configured"}'
    req = urllib.request.Request("http://%s/%s" % (CLASH_ADDR, sub),
                                 data=body, method=method)
    req.add_header("Authorization", "Bearer " + secret)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type", "application/json"), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", "application/json"), e.read()
    except Exception as e:  # noqa: BLE001
        return 502, "application/json", ('{"message":"mihomo unreachable: %s"}' % e).encode()


def ws_allowed(sub):
    return sub.split("?", 1)[0].strip("/") in CLASH_WS_PATHS


def mihomo_overview():
    secret = clash_secret()
    if not secret:
        return None, "mihomo API 未配置（缺少 secret，运行 install.sh --setup-api）"
    def get(p):
        req = urllib.request.Request("http://%s%s" % (CLASH_ADDR, p))
        req.add_header("Authorization", "Bearer " + secret)
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    try:
        conns = get("/connections")
        mem = get("/memory")
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
```

`Handler.do_GET` 中、`/api/health` 之后、`_auth()` 校验**之后**的位置加（注意：必须在 auth 之后）：

```python
        if path == "/api/mihomo/overview":
            data, err = mihomo_overview()
            return self._send(200 if data else 502, data or {"ok": False, "error": err})
        if path.startswith("/api/mihomo/proxy/"):
            sub = self.path.split("/api/mihomo/proxy/", 1)[1]
            status, ctype, data = clash_request("GET", sub)
            return self._send_raw(status, data, ctype)
        if path.startswith("/mihomo"):
            return self._serve_mihomo_static(self.path[len("/mihomo"):])
```

`Handler.do_POST` 中 auth 之后加：

```python
        if path.startswith("/api/mihomo/proxy/"):
            sub = self.path.split("/api/mihomo/proxy/", 1)[1]
            n = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(n) if 0 < n <= 2_000_000 else None
            status, ctype, data = clash_request(self.command, sub, body=body,
                                                ctype=self.headers.get("Content-Type"))
            return self._send_raw(status, data, ctype)
```

新增 `_send_raw`（`_send` 之后）：

```python
    def _send_raw(self, code, data, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith(("text/", "application/json")) else ""))
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:  # noqa: BLE001
            pass
```

注意：`_serve_mihomo_static` 在 Task 5 实现，本任务先让 `/mihomo` 分支指向一个返回 404 的占位方法或直接留到 Task 5 再加该路由行。**本任务只加 overview + proxy 两个分支。**

文件头 import 加 `import urllib.error`（已有 `urllib.request`）。

- [ ] **Step 4: 运行测试确认通过**

Run: `python3 tests/test_api_mihomo.py`
Expected: `OK`（5 个测试）

- [ ] **Step 5: 回归 + 提交**

Run: `python3 -m py_compile lib/api-server.py && for t in tests/*.sh; do bash "$t" >/dev/null 2>&1 || echo "FAIL: $t"; done && python3 -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -1`

```bash
git add lib/api-server.py tests/test_api_mihomo.py
git commit -m "feat(api): clash reverse proxy with server-side secret + mihomo overview endpoint"
```

---

## Task 4: api-server — WebSocket 中继

**Files:**
- Modify: `lib/api-server.py`
- Modify: `tests/test_api_mihomo.py`

- [ ] **Step 1: 追加失败的 unittest**

```python
    def test_build_ws_request(self):
        headers = {"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                   "Sec-WebSocket-Version": "13",
                   "Sec-WebSocket-Protocol": "chat"}
        req = self.api.build_ws_request("logs?level=info", headers).decode()
        self.assertIn("GET /logs?level=info HTTP/1.1", req)
        self.assertIn("Upgrade: websocket", req)
        self.assertIn("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", req)
        self.assertIn("Authorization: Bearer s3cr3t-test-token", req)
        self.assertTrue(req.endswith("\r\n\r\n"))
```

- [ ] **Step 2: 运行确认失败** → `AttributeError: ... 'build_ws_request'`

- [ ] **Step 3: 实现**

`lib/api-server.py` import 区加 `import select`。新增：

```python
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
        socks = [client_sock, upstream]
        while True:
            r, _, x = select.select(socks, [], socks, 300)
            if x:
                return
            if not r:
                continue
            for s in r:
                try:
                    data = s.recv(65536)
                except OSError:
                    return
                other = upstream if s is client_sock else client_sock
                if not data:
                    return
                try:
                    other.sendall(data)
                except OSError:
                    return
    finally:
        try:
            upstream.close()
        except OSError:
            pass
```

`Handler` 里加分支（`do_GET` 中 proxy 分支**之前**）：

```python
        if path.startswith("/api/mihomo/proxy/") and self.headers.get("Upgrade", "").lower() == "websocket":
            sub = self.path.split("/api/mihomo/proxy/", 1)[1]
            if not ws_allowed(sub):
                return self._send(403, {"ok": False, "error": "forbidden"})
            try:
                self.close_connection = True
                ws_relay(self.connection, sub, self.headers)
            except Exception:  # noqa: BLE001
                pass
            return
```

- [ ] **Step 4: 测试 + 回归 + 提交**

Run: `python3 tests/test_api_mihomo.py` → OK（6 个测试）；`python3 -m py_compile lib/api-server.py`

```bash
git add lib/api-server.py tests/test_api_mihomo.py
git commit -m "feat(api): websocket relay for clash traffic/logs/connections/memory streams"
```

---

## Task 5: api-server — metacubexd 静态服务

**Files:**
- Modify: `lib/api-server.py`
- Modify: `tests/test_api_mihomo.py`

- [ ] **Step 1: 追加失败的 unittest**

```python
    def test_static_path_traversal_blocked(self):
        self.assertIsNone(self.api.static_path("../install.sh"))
        self.assertIsNone(self.api.static_path("../../etc/passwd"))
        self.assertIsNone(self.api.static_path("/etc/passwd"))

    def test_static_path_resolution(self):
        root = tempfile.mkdtemp()
        self.api.MIHOMO_STATIC_DIR = root
        with open(os.path.join(root, "index.html"), "w") as f:
            f.write("<html>xd</html>")
        os.makedirs(os.path.join(root, "assets"))
        with open(os.path.join(root, "assets", "app.js"), "w") as f:
            f.write("js")
        self.assertTrue(self.api.static_path("").endswith("index.html"))
        self.assertTrue(self.api.static_path("assets/app.js").endswith("assets/app.js"))
        # SPA fallback
        self.assertTrue(self.api.static_path("some/route").endswith("index.html"))
        # no index -> None
        os.unlink(os.path.join(root, "index.html"))
        self.assertIsNone(self.api.static_path("missing.js"))
```

- [ ] **Step 2: 运行确认失败** → `AttributeError: ... 'static_path'`

- [ ] **Step 3: 实现**

```python
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
    full = os.path.join(MIHOMO_STATIC_DIR, norm)
    if os.path.isfile(full):
        return full
    fallback = os.path.join(MIHOMO_STATIC_DIR, "index.html")
    if os.path.isfile(fallback):
        return fallback
    return None
```

`Handler` 加方法：

```python
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
        return self._send_raw(200, data, MIME.get(ext, "application/octet-stream"))
```

并在 `do_GET`（auth 之后）启用 Task 3 预留的 `/mihomo` 分支。

- [ ] **Step 4: 测试 + 回归 + 提交**

Run: `python3 tests/test_api_mihomo.py` → OK（8 个测试）

```bash
git add lib/api-server.py tests/test_api_mihomo.py
git commit -m "feat(api): authenticated static hosting for the vendored metacubexd build"
```

---

## Task 6: webui 重写 — 主题系统与布局壳

**Files:**
- Rewrite: `webui/index.html`
- Create: `tests/test_webui_policy.sh`

- [ ] **Step 1: 写失败的 policy 测试**

```bash
#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ui="$(cat "${root}/webui/index.html")"
fail() { echo "$1" >&2; exit 1; }

# --- dual theme via CSS variables + system preference -------------------------
[[ "${ui}" == *'prefers-color-scheme'* ]] || fail "must follow system color scheme"
[[ "${ui}" == *'data-theme="dark"'* || "${ui}" == *"[data-theme=dark]"* || "${ui}" == *'data-theme*="dark"'* ]] || fail "must support manual dark override"
[[ "${ui}" == *'--bg:'* ]] || fail "must use CSS variables for theming"
[[ "${ui}" == *'localStorage'*'theme'* || "${ui}" == *'"theme"'* ]] || fail "theme choice must persist in localStorage"

# --- iOS Safari adaptations ---------------------------------------------------
[[ "${ui}" == *'viewport-fit=cover'* ]] || fail "viewport must use viewport-fit=cover"
[[ "${ui}" == *'safe-area-inset-bottom'* ]] || fail "bottom tab bar must respect the home-indicator safe area"
[[ "${ui}" == *'100dvh'* || "${ui}" == *'100svh'* ]] || fail "must use dynamic viewport height units"
[[ "${ui}" == *'apple-mobile-web-app-capable'* ]] || fail "must be add-to-homescreen capable"
[[ "${ui}" == *'tap-highlight-color'* ]] || fail "must disable tap highlight"
[[ "${ui}" == *'font-size:16px'* || "${ui}" == *'font-size: 16px'* ]] || fail "inputs must be >=16px to prevent focus zoom"

# --- responsive layout: sidebar on desktop, bottom tabs on mobile -------------
[[ "${ui}" == *'@media'*'768px'* ]] || fail "must have a 768px breakpoint"
[[ "${ui}" == *'class="tabbar"'* ]] || fail "must have a bottom tab bar"

# --- six sections + mihomo integration ----------------------------------------
for s in dashboard exits rules monitor ai settings; do
  [[ "${ui}" == *"data-section=\"${s}\""* || "${ui}" == *"id=\"sec-${s}\""* ]] || fail "missing section: ${s}"
done
[[ "${ui}" == *'/api/mihomo/overview'* ]] || fail "dashboard must load the mihomo overview card"
[[ "${ui}" == *'/mihomo/'* ]] || fail "monitor section must embed the metacubexd iframe"

# --- auth model unchanged ------------------------------------------------------
[[ "${ui}" == *'Bearer'* ]] || fail "panel must keep bearer-token auth"

echo "test_webui_policy: OK"
```

- [ ] **Step 2: 运行确认失败**

Run: `bash tests/test_webui_policy.sh`
Expected: FAIL（当前 index.html 无 `prefers-color-scheme`）

- [ ] **Step 3: 重写 index.html — 主题令牌 + 布局壳**

保留现有 `<head>` 后的全部 API 调用 JS（`api()` 函数、各 `load*()` 函数在 Task 7 迁移），先搭新壳。核心结构（完整代码在实现时写入单文件，以下为必须原样落地的关键片段）：

```html
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#f8fafc">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#0d1117">
<style>
:root{                       /* 浅色令牌（B 简洁风） */
  --bg:#f8fafc; --card:#ffffff; --border:#e2e8f0; --text:#1e293b; --sub:#64748b;
  --accent:#2563eb; --ok:#16a34a; --warn:#d97706; --danger:#dc2626; --teal:#0d9488;
  --shadow:0 1px 3px rgba(15,23,42,.08); --mono:"SF Mono",ui-monospace,Menlo,monospace;
}
[data-theme="dark"]{         /* 深色令牌（A 运维风） */
  --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --sub:#8b949e;
  --accent:#58a6ff; --ok:#3fb950; --warn:#d29922; --danger:#f85149; --teal:#58d6c9;
  --shadow:0 1px 3px rgba(1,4,9,.6);
}
@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]){ /* 同 dark 令牌 */ } }
input,select,textarea{font-size:16px}      /* 防 iOS 聚焦缩放 */
html{-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,"PingFang SC",sans-serif;height:100dvh}
/* 布局：桌面侧栏 */
.sidebar{display:flex;flex-direction:column;gap:2px;width:200px;padding:14px 10px;background:var(--card);border-right:1px solid var(--border)}
.tabbar{display:none}                      /* 移动端底部标签栏 */
@media (max-width:768px){
  .sidebar{display:none}
  .tabbar{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:50;
    background:var(--card);border-top:1px solid var(--border);
    padding:6px 2px calc(6px + env(safe-area-inset-bottom))}
  .tabbar a{flex:1;text-align:center;color:var(--sub);font-size:10px;padding:4px 0;min-height:44px}
  .tabbar a.on{color:var(--accent)}
  main{padding-bottom:calc(64px + env(safe-area-inset-bottom))}
}
</style>
```

布局 HTML：

```html
<body>
<aside class="sidebar">…导航（六个 data-section）+ 主题切换 + 登出…</aside>
<main id="main">…六个 <section id="sec-XXX">…</main>
<nav class="tabbar">
  <a data-section="dashboard" class="on">首页</a>
  <a data-section="exits">出口</a>
  <a data-section="rules">规则</a>
  <a data-section="monitor">监控</a>
  <a data-section="more">更多</a>   <!-- 弹出 AI 助手 / 设置 -->
</nav>
</body>
```

主题 JS：

```javascript
const THEME_KEY="theme";  // "system" | "light" | "dark"
function applyTheme(t){const d=t==="dark"||(t==="system"&&matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-theme",d?"dark":"light");}
applyTheme(localStorage.getItem(THEME_KEY)||"system");
matchMedia("(prefers-color-scheme: dark)").addEventListener("change",()=>applyTheme(localStorage.getItem(THEME_KEY)||"system"));
```

- [ ] **Step 4: 运行测试确认壳相关断言通过**（页面区断言在 Task 7 补齐后全绿）

- [ ] **Step 5: 提交**

```bash
git add webui/index.html tests/test_webui_policy.sh
git commit -m "feat(webui): redesign shell — dual theme tokens, mobile bottom tab bar, iOS Safari fit"
```

---

## Task 7: webui 重写 — 六个页面 + mihomo 监控

**Files:**
- Modify: `webui/index.html`

- [ ] **Step 1: 迁移六个页面**（API 调用逻辑全部沿用现有 index.html 的实现，仅重排进新壳与新样式）

逐页落地（每页为一个 `<section id="sec-XXX">`，复用现有 `api()` 辅助函数与数据流）：

1. **dashboard**：资源卡片（CPU/内存/磁盘/运行时间，来自 `/api/status`）、实时速率与连接数（`/api/live`，2s 轮询）、24h 流量与延迟曲线（`/api/traffic`、`/api/latency`，canvas 绘制，沿用现有绘图代码）、**mihomo 概览卡**（`/api/mihomo/overview`：连接数、Top5 规则命中、内存、版本；502 时显示"mihomo 离线（smart 出口未启用）"占位）。
2. **exits**：列表 + 切换/添加/编辑/删除/连通性/延迟（现有 `/api/exits*` 端点全部沿用，含 `/api/exits/edit`）。
3. **rules**：规则文本编辑、单条增删改、规则组管理（`/api/rules*`、`/api/policy*`）、域名路由测试器（`/api/route/test`）、一键定向（`/api/proxy-domain`）。
4. **monitor**：上半为自制摘要（同 overview 数据的展开 + 说明），下半/入口为 `<iframe src="/mihomo/index.html" style="width:100%;border:0;min-height:70dvh">`；iframe 内的 metacubexd 其后端指向同源 `/api/mihomo/proxy`（首次打开在其设置页填 `https://<域名>:8444/api/mihomo/proxy`，secret 留空——在页面顶部用一行提示写明）。
5. **ai**：沿用现有 `/api/ai/*` 流程（配置 base_url/key/model → 生成草案 → 确认应用）。
6. **settings**：备份下载（`/api/backup`）、恢复（`/api/restore`）、更新规则集（`/api/update-rules`）、API 地址/令牌显示与修改、主题三档（跟随系统/深色/浅色，`localStorage "theme"`）。

注意沿用现有细节：toast 反馈、确认对话框、loading 态；移动端下卡片单列堆叠、表格横向滚动（`overflow-x:auto`）、按钮 ≥44px。

- [ ] **Step 2: 运行 policy 测试确认全绿**

Run: `bash tests/test_webui_policy.sh`
Expected: PASS `test_webui_policy: OK`

- [ ] **Step 3: 人工冒烟（本地）**

Run: `python3 -m http.server 8080 -d webui &` 打开 `http://localhost:8080`，检查：双主题跟随系统切换、768px 以下出现底部标签栏、登录页可填地址令牌。（无网关时 API 会 401/失败，属预期，只看布局与主题。）

- [ ] **Step 4: 提交**

```bash
git add webui/index.html
git commit -m "feat(webui): six-section console — dashboard w/ mihomo card, exits, rules, monitor, ai, settings"
```

---

## Task 8: README + 全量验证

**Files:**
- Modify: `README.md`（网页控制台章节、端口表）

- [ ] **Step 1: README 更新**

在"网页控制台（可选）"节补充 mihomo 监控说明；端口表加一行：`| 9090 | TCP | 仅 127.0.0.1 | mihomo Clash API（回环，smart 实例；经 api-server 反代访问，不对公网开放） |`。

- [ ] **Step 2: 全量验证**

Run: `bash -n install.sh && python3 -m py_compile lib/api-server.py lib/mihomo-router-config.py && for t in tests/*.sh; do bash "$t" >/dev/null 2>&1 || echo "FAIL: $t"; done && python3 -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -1`
Expected: 仅 2 个 macOS 环境预置失败（`test_exit_proxy_types_policy.sh`、`test_sniproxy_dns_rewrite_idempotent.sh`），其余全过。

- [ ] **Step 3: 提交并推送**

```bash
git add README.md
git commit -m "docs: mihomo monitor page + loopback 9090 port note"
git push
```

---

## Self-Review 记录

- 规格覆盖：前端重写(T6/T7)、api-server 三端点(T3/T4/T5)、router 配置(T1)、install.sh(T1/T2)、测试(T1-T7 全程)、README(T8) ✅
- 类型一致性：`clash_request` 返回 `(status, ctype, bytes)` 三处定义/使用一致；`ws_relay(sock, sub, headers)` 签名一致；`static_path(sub)→str|None` 一致 ✅
- 已知风险：metacubexd 后端配置支持带路径 base URL 的前提在 T7 Step 1.4 验证，不支持时改为静态注入默认配置（spec 已注明） ✅
