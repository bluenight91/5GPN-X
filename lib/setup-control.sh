#!/usr/bin/env bash
# setup-control.sh — Client-facing control surfaces: SOCKS/MTProto/Clash-remote proxies, tgbot, API.
# Sourced by install.sh; do not execute directly. Relies on install.sh globals
# and runs under install.sh's set -euo pipefail (ShellCheck scopes below).
# shellcheck disable=SC2154,SC2034,SC2164,SC2317

install_client_socks_binary() {
    ensure_proxy_user
    mkdir -p "${BASE_DIR}/bin" "${SRC_DIR}" "${CONF_DIR}"
    [[ -f "${LIB_DIR}/client-socks.go" ]] || { err "client-socks.go missing"; return 1; }
    if ! cmp -s "${LIB_DIR}/client-socks.go" "${SRC_DIR}/client-socks.go" 2>/dev/null \
        || [[ ! -x "${CLIENT_SOCKS_BIN}" ]]; then
        info "Compiling client-socks (private SOCKS5)..."
        cp "${LIB_DIR}/client-socks.go" "${SRC_DIR}/client-socks.go"
        (
            cd "${SRC_DIR}"
            export PATH=$PATH:/usr/local/go/bin
            go build -ldflags="-s -w" -o "${CLIENT_SOCKS_BIN}" client-socks.go
        )
    fi
    cat > /etc/systemd/system/5gpn-client-socks.service <<EOF
[Unit]
Description=5GPN-X private client SOCKS5 (CIDR ACL + user/pass)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-${CLIENT_SOCKS_ENV}
ExecStart=${CLIENT_SOCKS_BIN} -l 0.0.0.0:\${SOCKS_PORT} -u \${SOCKS_USER} -P \${SOCKS_PASS} -a \${SOCKS_ALLOW_CIDR} -q
Restart=on-failure
RestartSec=3
User=${EXIT_USER}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}
client_socks_ensure_creds() {
    mkdir -p "${CONF_DIR}"
    local port user pass cidr
    port="$(cat "${CLIENT_SOCKS_PORT_FILE}" 2>/dev/null || echo "${CLIENT_SOCKS_PORT_DEFAULT}")"
    [[ "$port" =~ ^[0-9]+$ ]] || port="${CLIENT_SOCKS_PORT_DEFAULT}"
    echo "$port" > "${CLIENT_SOCKS_PORT_FILE}"
    cidr="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    if [[ -f "${CLIENT_SOCKS_ENV}" ]]; then
        # shellcheck disable=SC1090
        set -a; source "${CLIENT_SOCKS_ENV}"; set +a
    fi
    user="${SOCKS_USER:-${CLIENT_SOCKS_USER_DEFAULT}}"
    pass="${SOCKS_PASS:-}"
    if [[ -z "$pass" ]]; then
        pass="$(openssl rand -hex 12 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    umask 077
    cat > "${CLIENT_SOCKS_ENV}" <<EOF
SOCKS_PORT=${port}
SOCKS_USER=${user}
SOCKS_PASS=${pass}
SOCKS_ALLOW_CIDR=${cidr}
EOF
    chmod 600 "${CLIENT_SOCKS_ENV}"
}
client_socks_host_ip() {
    cat /etc/mosdns/.public_ip 2>/dev/null \
        || ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' \
        || echo "127.0.0.1"
}
enable_client_socks() {
    check_root
    install_client_socks_binary
    client_socks_ensure_creds
    # shellcheck disable=SC1090
    set -a; source "${CLIENT_SOCKS_ENV}"; set +a
    : > "${CLIENT_SOCKS_ENABLED}"
    chmod 644 "${CLIENT_SOCKS_ENABLED}"
    if declare -F firewall_socks_sync >/dev/null 2>&1; then
        firewall_socks_sync || { rm -f "${CLIENT_SOCKS_ENABLED}"; err "SOCKS firewall sync failed; SOCKS5 not enabled"; return 1; }
    fi
    systemctl enable --now 5gpn-client-socks.service
    systemctl restart 5gpn-client-socks.service
    local host; host="$(client_socks_host_ip)"
    ok "私网 SOCKS5 已开启"
    echo "  地址:   ${host}:${SOCKS_PORT}"
    echo "  用户:   ${SOCKS_USER}"
    echo "  密码:   ${SOCKS_PASS}"
    echo "  允许源: ${SOCKS_ALLOW_CIDR}"
    echo "  Telegram: 设置 → 代理 → SOCKS5，填以上信息"
    warn "密码仅此时完整显示；之后 status 会隐藏。需要时可 --reset-client-socks-creds"
}
disable_client_socks() {
    check_root
    systemctl disable --now 5gpn-client-socks.service 2>/dev/null || true
    rm -f "${CLIENT_SOCKS_ENABLED}"
    declare -F firewall_socks_sync >/dev/null 2>&1 && firewall_socks_sync || true
    ok "私网 SOCKS5 已关闭"
}
client_socks_status() {
    local on=0 host port user cidr
    [[ -f "${CLIENT_SOCKS_ENABLED}" ]] && on=1
    port="$(cat "${CLIENT_SOCKS_PORT_FILE}" 2>/dev/null || echo "${CLIENT_SOCKS_PORT_DEFAULT}")"
    host="$(client_socks_host_ip)"
    cidr="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    user="?"
    if [[ -f "${CLIENT_SOCKS_ENV}" ]]; then
        user="$(sed -n 's/^SOCKS_USER=//p' "${CLIENT_SOCKS_ENV}" | head -1)"
    fi
    echo "client-socks: $([[ $on -eq 1 ]] && echo enabled || echo disabled)"
    echo "listen: ${host}:${port}"
    echo "user: ${user}"
    echo "password: ***"
    echo "allow: ${cidr}"
    if [[ $on -eq 1 ]]; then
        systemctl is-active --quiet 5gpn-client-socks.service \
            && echo "service: running" || echo "service: not running"
    fi
}
reset_client_socks_creds() {
    check_root
    mkdir -p "${CONF_DIR}"
    local port user pass cidr
    port="$(cat "${CLIENT_SOCKS_PORT_FILE}" 2>/dev/null || echo "${CLIENT_SOCKS_PORT_DEFAULT}")"
    user="${CLIENT_SOCKS_USER_DEFAULT}"
    pass="$(openssl rand -hex 12 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    cidr="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    echo "$port" > "${CLIENT_SOCKS_PORT_FILE}"
    umask 077
    cat > "${CLIENT_SOCKS_ENV}" <<EOF
SOCKS_PORT=${port}
SOCKS_USER=${user}
SOCKS_PASS=${pass}
SOCKS_ALLOW_CIDR=${cidr}
EOF
    chmod 600 "${CLIENT_SOCKS_ENV}"
    if [[ -f "${CLIENT_SOCKS_ENABLED}" ]]; then
        systemctl restart 5gpn-client-socks.service 2>/dev/null || true
    fi
    local host; host="$(client_socks_host_ip)"
    ok "SOCKS5 凭据已轮换"
    echo "  地址: ${host}:${port}"
    echo "  用户: ${user}"
    echo "  密码: ${pass}"
}
# Normalize to classic 32-hex secret Telegram can paste directly.
# Accepts: 32-hex | dd+32-hex | legacy ee… FakeTLS (extracts key).
canonicalize_mtproto_secret() {
    local s="${1:-}" out=""
    [[ -n "$s" ]] || return 1
    [[ "$s" != *$'\n'* && "$s" != *' '* && "$s" != *$'\t'* ]] || return 1
    out="$(python3 - "$s" <<'PY'
import re, sys
s = sys.argv[1].strip()
if re.fullmatch(r"[0-9a-fA-F]{32}", s):
    print(s.lower()); raise SystemExit(0)
if re.fullmatch(r"[dD][dD][0-9a-fA-F]{32}", s):
    print(s[2:].lower()); raise SystemExit(0)
# Legacy mtg FakeTLS: ee + 16-byte key + hostname → reuse key as classic secret
if s.lower().startswith("ee") and len(s) >= 34 and re.fullmatch(r"[0-9a-fA-F]+", s):
    key = s[2:34].lower()
    if re.fullmatch(r"[0-9a-f]{32}", key):
        print(key); raise SystemExit(0)
raise SystemExit(1)
PY
)" || return 1
    [[ "$out" =~ ^[0-9a-f]{32}$ ]] || return 1
    printf '%s\n' "$out"
}
validate_mtproto_secret() {
    canonicalize_mtproto_secret "${1:-}" >/dev/null
}
ensure_mtprotoproxy() {
    local ver="${MTPROTOPROXY_VERSION:-${MTPROTOPROXY_VERSION_DEFAULT}}"
    local repo="${MTPROTOPROXY_REPO:-${MTPROTOPROXY_REPO_DEFAULT}}"
    local url pin
    mkdir -p "${BASE_DIR}/bin" "${CONF_DIR}"
    pin="$(cat "${MTPROTOPROXY_PIN}" 2>/dev/null || true)"
    if [[ -f "${MTPROTOPROXY_PY}" && "$pin" == "$ver" ]]; then
        return 0
    fi
    url="${repo}/${ver}/mtprotoproxy.py"
    info "Downloading mtprotoproxy ${ver}..."
    if ! curl -fsSL --max-time 60 "$url" -o "${MTPROTOPROXY_PY}.new"; then
        rm -f "${MTPROTOPROXY_PY}.new"
        err "mtprotoproxy 下载失败: $url"
        return 1
    fi
    head -n1 "${MTPROTOPROXY_PY}.new" | grep -q python || {
        rm -f "${MTPROTOPROXY_PY}.new"
        err "mtprotoproxy 内容无效"
        return 1
    }
    mv -f "${MTPROTOPROXY_PY}.new" "${MTPROTOPROXY_PY}"
    chmod 755 "${MTPROTOPROXY_PY}"
    echo "$ver" > "${MTPROTOPROXY_PIN}"
    ok "mtprotoproxy ${ver} → ${MTPROTOPROXY_PY}"
}
client_mtproto_write_conf() {
    local secret="${1:-}" backend_port
    [[ -n "$secret" ]] || return 1
    backend_port="${CLIENT_MTPROTO_BACKEND_DEFAULT##*:}"
    [[ "$backend_port" =~ ^[0-9]+$ ]] || backend_port=15753
    umask 077
    cat > "${MTPROTOPROXY_CONF}" <<EOF
# Generated by 5gpn — classic MTProto (Telegram pastes the 32-hex secret as-is).
PORT = ${backend_port}
LISTEN_ADDR_IPV4 = "127.0.0.1"
LISTEN_ADDR_IPV6 = ""
USERS = {"tg": "${secret}"}
MODES = {"classic": True, "secure": True, "tls": False}
FAST_MODE = True
USE_MIDDLE_PROXY = False
EOF
    chmod 600 "${MTPROTOPROXY_CONF}"
    chown "${EXIT_USER}:${EXIT_USER}" "${MTPROTOPROXY_CONF}" 2>/dev/null || true
}
install_client_mtproto_binary() {
    ensure_proxy_user
    mkdir -p "${BASE_DIR}/bin" "${SRC_DIR}" "${CONF_DIR}"
    ensure_mtprotoproxy || return 1
    [[ -f "${LIB_DIR}/client-mtproto.go" ]] || { err "client-mtproto.go missing"; return 1; }
    if ! cmp -s "${LIB_DIR}/client-mtproto.go" "${SRC_DIR}/client-mtproto.go" 2>/dev/null \
        || [[ ! -x "${CLIENT_MTPROTO_BIN}" ]]; then
        info "Compiling client-mtproto (CIDR ACL front)..."
        cp "${LIB_DIR}/client-mtproto.go" "${SRC_DIR}/client-mtproto.go"
        (
            cd "${SRC_DIR}"
            export PATH=$PATH:/usr/local/go/bin
            go build -ldflags="-s -w" -o "${CLIENT_MTPROTO_BIN}" client-mtproto.go
        ) || { err "client-mtproto 编译失败"; return 1; }
    fi
    [[ -x "${CLIENT_MTPROTO_BIN}" ]] || { err "client-mtproto 二进制不存在: ${CLIENT_MTPROTO_BIN}"; return 1; }
    [[ -f "${MTPROTOPROXY_PY}" ]] || { err "mtprotoproxy.py missing"; return 1; }
    chmod 755 "${CLIENT_MTPROTO_BIN}" "${MTPROTOPROXY_PY}" 2>/dev/null || true
    # Retire previous mtg unit if present (FakeTLS engine cannot serve bare hex).
    if [[ -f /etc/systemd/system/5gpn-mtg.service ]]; then
        systemctl disable --now 5gpn-mtg.service 2>/dev/null || true
        rm -f /etc/systemd/system/5gpn-mtg.service
    fi
    cat > /etc/systemd/system/5gpn-mtproxy.service <<EOF
[Unit]
Description=5GPN-X classic MTProto core (mtprotoproxy, loopback)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${CONF_DIR}
ExecStart=/usr/bin/python3 ${MTPROTOPROXY_PY} ${MTPROTOPROXY_CONF}
Restart=on-failure
RestartSec=3
User=${EXIT_USER}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONF_DIR}
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/5gpn-client-mtproto.service <<EOF
[Unit]
Description=5GPN-X private MTProto ACL front (client CIDR → mtprotoproxy)
After=network-online.target 5gpn-mtproxy.service
Wants=network-online.target
Requires=5gpn-mtproxy.service

[Service]
Type=simple
EnvironmentFile=-${CLIENT_MTPROTO_ENV}
ExecStart=${CLIENT_MTPROTO_BIN} -l 0.0.0.0:\${MTPROTO_PORT} -b \${MTPROTO_BACKEND} -a \${MTPROTO_ALLOW_CIDR} -q
Restart=on-failure
RestartSec=3
User=${EXIT_USER}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}
client_mtproto_ensure_creds() {
    mkdir -p "${CONF_DIR}"
    local port cidr secret backend raw
    port="$(cat "${CLIENT_MTPROTO_PORT_FILE}" 2>/dev/null || echo "${CLIENT_MTPROTO_PORT_DEFAULT}")"
    [[ "$port" =~ ^[0-9]+$ ]] || port="${CLIENT_MTPROTO_PORT_DEFAULT}"
    echo "$port" > "${CLIENT_MTPROTO_PORT_FILE}"
    cidr="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    backend="${CLIENT_MTPROTO_BACKEND_DEFAULT}"
    secret=""
    if [[ -f "${CLIENT_MTPROTO_ENV}" ]]; then
        # shellcheck disable=SC1090
        set -a; source "${CLIENT_MTPROTO_ENV}"; set +a
        raw="${MTPROTO_SECRET:-}"
        backend="${MTPROTO_BACKEND:-$backend}"
        if [[ -n "$raw" ]]; then
            secret="$(canonicalize_mtproto_secret "$raw" 2>/dev/null || true)"
            if [[ -z "$secret" ]]; then
                warn "已有 MTProto secret 无法转为 classic 32-hex，将重新生成"
            elif [[ "$secret" != "$raw" ]]; then
                info "已将旧 secret 规范为 classic 32-hex（Telegram 请直接填此密钥）"
            fi
        fi
    fi
    if [[ -z "$secret" ]]; then
        secret="$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        validate_mtproto_secret "$secret" || {
            err "无法生成 MTProto secret"
            return 1
        }
    fi
    umask 077
    cat > "${CLIENT_MTPROTO_ENV}" <<EOF
MTPROTO_PORT=${port}
MTPROTO_BACKEND=${backend}
MTPROTO_SECRET=${secret}
MTPROTO_ALLOW_CIDR=${cidr}
EOF
    chmod 600 "${CLIENT_MTPROTO_ENV}"
    client_mtproto_write_conf "$secret"
}
client_mtproto_host_ip() {
    client_socks_host_ip
}
enable_client_mtproto() {
    check_root
    install_client_mtproto_binary || return 1
    client_mtproto_ensure_creds || return 1
    # shellcheck disable=SC1090
    set -a; source "${CLIENT_MTPROTO_ENV}"; set +a
    : > "${CLIENT_MTPROTO_ENABLED}"
    chmod 644 "${CLIENT_MTPROTO_ENABLED}"
    if declare -F firewall_mtproto_sync >/dev/null 2>&1; then
        firewall_mtproto_sync || {
            rm -f "${CLIENT_MTPROTO_ENABLED}"
            err "MTProto firewall sync failed; MTProto not enabled"
            return 1
        }
    fi
    systemctl enable 5gpn-mtproxy.service 5gpn-client-mtproto.service >/dev/null 2>&1 || true
    systemctl restart 5gpn-mtproxy.service || true
    sleep 0.5
    systemctl restart 5gpn-client-mtproto.service || true
    if ! systemctl is-active --quiet 5gpn-mtproxy.service \
        || ! systemctl is-active --quiet 5gpn-client-mtproto.service; then
        rm -f "${CLIENT_MTPROTO_ENABLED}"
        declare -F firewall_mtproto_sync >/dev/null 2>&1 && firewall_mtproto_sync || true
        err "MTProto 服务启动失败（已回滚 enabled 标记）"
        echo "---- 5gpn-mtproxy ----"
        systemctl status 5gpn-mtproxy.service --no-pager -l 2>&1 | tail -n 40 || true
        journalctl -u 5gpn-mtproxy.service -n 40 --no-pager 2>&1 || true
        echo "---- 5gpn-client-mtproto ----"
        systemctl status 5gpn-client-mtproto.service --no-pager -l 2>&1 | tail -n 40 || true
        journalctl -u 5gpn-client-mtproto.service -n 40 --no-pager 2>&1 || true
        return 1
    fi
    local host; host="$(client_mtproto_host_ip)"
    ok "私网 MTProto 已开启（classic，Telegram 可直接填 32-hex 密钥）"
    echo "  地址:   ${host}:${MTPROTO_PORT}"
    echo "  密钥:   ${MTPROTO_SECRET}"
    echo "  允许源: ${MTPROTO_ALLOW_CIDR}"
    echo "  链接:   tg://proxy?server=${host}&port=${MTPROTO_PORT}&secret=${MTPROTO_SECRET}"
    echo "  Telegram: 设置 → 数据与存储 → 代理 → 添加代理 → MTProto"
    warn "密钥仅此时完整显示；之后 status 会隐藏。可用 --set-client-mtproto-secret 指定"
}
disable_client_mtproto() {
    check_root
    systemctl disable --now 5gpn-client-mtproto.service 5gpn-mtproxy.service 5gpn-mtg.service 2>/dev/null || true
    rm -f "${CLIENT_MTPROTO_ENABLED}"
    declare -F firewall_mtproto_sync >/dev/null 2>&1 && firewall_mtproto_sync || true
    ok "私网 MTProto 已关闭"
}
client_mtproto_status() {
    local on=0 host port cidr
    [[ -f "${CLIENT_MTPROTO_ENABLED}" ]] && on=1
    port="$(cat "${CLIENT_MTPROTO_PORT_FILE}" 2>/dev/null || echo "${CLIENT_MTPROTO_PORT_DEFAULT}")"
    host="$(client_mtproto_host_ip)"
    cidr="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    echo "client-mtproto: $([[ $on -eq 1 ]] && echo enabled || echo disabled)"
    echo "listen: ${host}:${port}"
    echo "secret: ***"
    echo "allow: ${cidr}"
    echo "engine: mtprotoproxy classic (loopback ${CLIENT_MTPROTO_BACKEND_DEFAULT})"
    if [[ $on -eq 1 ]]; then
        systemctl is-active --quiet 5gpn-mtproxy.service \
            && echo "core: running" || echo "core: not running"
        systemctl is-active --quiet 5gpn-client-mtproto.service \
            && echo "front: running" || echo "front: not running"
    fi
}
set_client_mtproto_secret() {
    check_root
    local raw="${1:-}" secret=""
    secret="$(canonicalize_mtproto_secret "$raw")" || {
        err "无效 secret（需要 32 位 hex；也可 dd+32hex，或从旧 ee… FakeTLS 提取 key）"
        return 1
    }
    if [[ "$secret" != "$raw" ]]; then
        info "已规范为 classic 32-hex；Telegram 请填: ${secret}"
    fi
    install_client_mtproto_binary || return 1
    local port cidr backend
    port="$(cat "${CLIENT_MTPROTO_PORT_FILE}" 2>/dev/null || echo "${CLIENT_MTPROTO_PORT_DEFAULT}")"
    cidr="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    backend="${CLIENT_MTPROTO_BACKEND_DEFAULT}"
    umask 077
    cat > "${CLIENT_MTPROTO_ENV}" <<EOF
MTPROTO_PORT=${port}
MTPROTO_BACKEND=${backend}
MTPROTO_SECRET=${secret}
MTPROTO_ALLOW_CIDR=${cidr}
EOF
    chmod 600 "${CLIENT_MTPROTO_ENV}"
    client_mtproto_write_conf "$secret"
    if [[ -f "${CLIENT_MTPROTO_ENABLED}" ]]; then
        systemctl restart 5gpn-mtproxy.service 5gpn-client-mtproto.service 2>/dev/null || true
        if ! systemctl is-active --quiet 5gpn-mtproxy.service \
            || ! systemctl is-active --quiet 5gpn-client-mtproto.service; then
            err "密钥已写入，但服务未就绪；journalctl -u 5gpn-mtproxy -n 40"
            return 1
        fi
    fi
    local host; host="$(client_mtproto_host_ip)"
    ok "MTProto 密钥已更新（Telegram 直接填此 32-hex）"
    echo "  地址: ${host}:${port}"
    echo "  密钥: ${secret}"
    echo "  链接: tg://proxy?server=${host}&port=${port}&secret=${secret}"
}
generate_client_mtproto_secret() {
    check_root
    local secret
    secret="$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    set_client_mtproto_secret "$secret"
}
clash_remote_normalize_extra_cidr() {
    # Allow /8../32 (incl. /32 single hosts for public admin IPs). Empty → empty.
    local raw="${1:-}" out
    raw="$(echo "$raw" | tr -d '[:space:]')"
    [[ -z "$raw" ]] && { echo ""; return 0; }
    out="$(FORCE_WIDE_CIDR=1 python3 - "$raw" <<'PY'
import ipaddress, sys
raw = sys.argv[1].strip()
out = []
for item in raw.split(","):
    item = item.strip()
    if not item:
        continue
    net = ipaddress.ip_network(item, strict=False)
    if net.version != 4 or not (8 <= net.prefixlen <= 32):
        raise SystemExit(1)
    out.append(str(net))
print(",".join(dict.fromkeys(out)))
PY
)" || return 1
    printf '%s\n' "$out"
}
clash_remote_merge_allow_cidr() {
    local client extra merged
    client="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    extra="${1:-}"
    merged="$(python3 - "$client" "$extra" <<'PY'
import ipaddress, sys
parts = []
for raw in sys.argv[1:]:
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            parts.append(str(ipaddress.ip_network(item, strict=False)))
        except Exception:
            pass
print(",".join(dict.fromkeys(parts)))
PY
)"
    [[ -n "$merged" ]] || merged="$client"
    printf '%s\n' "$merged"
}
install_clash_remote_binary() {
    ensure_proxy_user
    mkdir -p "${BASE_DIR}/bin" "${SRC_DIR}" "${CONF_DIR}"
    [[ -f "${LIB_DIR}/clash-remote.go" ]] || { err "clash-remote.go missing"; return 1; }
    if ! cmp -s "${LIB_DIR}/clash-remote.go" "${SRC_DIR}/clash-remote.go" 2>/dev/null \
        || [[ ! -x "${CLASH_REMOTE_BIN}" ]]; then
        info "Compiling clash-remote (HTTPS Clash API for third-party panels)..."
        cp "${LIB_DIR}/clash-remote.go" "${SRC_DIR}/clash-remote.go"
        (
            cd "${SRC_DIR}"
            export PATH=$PATH:/usr/local/go/bin
            go build -ldflags="-s -w" -o "${CLASH_REMOTE_BIN}" clash-remote.go
        ) || { err "clash-remote 编译失败"; return 1; }
    fi
    [[ -x "${CLASH_REMOTE_BIN}" ]] || { err "clash-remote 二进制不存在: ${CLASH_REMOTE_BIN}"; return 1; }
    chmod 755 "${CLASH_REMOTE_BIN}" 2>/dev/null || true
    cat > /etc/systemd/system/5gpn-clash-remote.service <<EOF
[Unit]
Description=5GPN-X remote Clash API HTTPS (CIDR ACL + dedicated secret)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-${CLASH_REMOTE_ENV}
ExecStart=${CLASH_REMOTE_BIN} -l 0.0.0.0:\${CLASH_REMOTE_PORT} -b \${CLASH_REMOTE_BACKEND} -s \${CLASH_REMOTE_SECRET} -f \${CLASH_REMOTE_CLASH_SECRET_FILE} -a \${CLASH_REMOTE_ALLOW_CIDR} -cert \${CLASH_REMOTE_TLS_CERT} -key \${CLASH_REMOTE_TLS_KEY} -q
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}
clash_remote_ensure_creds() {
    mkdir -p "${CONF_DIR}"
    ensure_mihomo_api_secret
    local port secret extra allow cert key backend
    port="$(cat "${CLASH_REMOTE_PORT_FILE}" 2>/dev/null || echo "${CLASH_REMOTE_PORT_DEFAULT}")"
    [[ "$port" =~ ^[0-9]+$ ]] || port="${CLASH_REMOTE_PORT_DEFAULT}"
    echo "$port" > "${CLASH_REMOTE_PORT_FILE}"
    if [[ -f "${CLASH_REMOTE_ENV}" ]]; then
        # shellcheck disable=SC1090
        set -a; source "${CLASH_REMOTE_ENV}"; set +a
    fi
    secret="${CLASH_REMOTE_SECRET:-}"
    if [[ -z "$secret" ]]; then
        secret="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    extra="$(clash_remote_normalize_extra_cidr "${CLASH_REMOTE_EXTRA_CIDR:-}" 2>/dev/null || echo "")"
    allow="$(clash_remote_merge_allow_cidr "$extra")"
    cert="${CLASH_REMOTE_TLS_CERT:-/etc/mosdns/certs/fullchain.pem}"
    key="${CLASH_REMOTE_TLS_KEY:-/etc/mosdns/certs/privkey.pem}"
    backend="${CLASH_REMOTE_BACKEND:-${CLASH_REMOTE_BACKEND_DEFAULT}}"
    umask 077
    cat > "${CLASH_REMOTE_ENV}" <<EOF
CLASH_REMOTE_PORT=${port}
CLASH_REMOTE_SECRET=${secret}
CLASH_REMOTE_EXTRA_CIDR=${extra}
CLASH_REMOTE_ALLOW_CIDR=${allow}
CLASH_REMOTE_BACKEND=${backend}
CLASH_REMOTE_TLS_CERT=${cert}
CLASH_REMOTE_TLS_KEY=${key}
CLASH_REMOTE_CLASH_SECRET_FILE=${MIHOMO_API_SECRET_FILE}
EOF
    chmod 600 "${CLASH_REMOTE_ENV}"
}
clash_remote_host_ip() {
    client_socks_host_ip
}
clash_remote_domain() {
    cat "${CONF_DIR}/.domain" 2>/dev/null || cat /etc/mosdns/.domain 2>/dev/null || echo ""
}
enable_clash_remote() {
    check_root
    install_clash_remote_binary || return 1
    clash_remote_ensure_creds
    local cert key
    # shellcheck disable=SC1090
    set -a; source "${CLASH_REMOTE_ENV}"; set +a
    cert="${CLASH_REMOTE_TLS_CERT}"
    key="${CLASH_REMOTE_TLS_KEY}"
    [[ -f "$cert" && -f "$key" ]] || {
        err "缺少 TLS 证书（${cert}）；请先完成安装或 --renew-cert"
        return 1
    }
    [[ -s "${MIHOMO_API_SECRET_FILE}" ]] || {
        err "缺少 mihomo API secret；请先 --setup-api"
        return 1
    }
    : > "${CLASH_REMOTE_ENABLED}"
    chmod 644 "${CLASH_REMOTE_ENABLED}"
    if declare -F firewall_clash_remote_sync >/dev/null 2>&1; then
        firewall_clash_remote_sync || {
            rm -f "${CLASH_REMOTE_ENABLED}"
            err "Clash remote firewall sync failed; not enabled"
            return 1
        }
    fi
    systemctl enable --now 5gpn-clash-remote.service
    systemctl restart 5gpn-clash-remote.service
    if ! systemctl is-active --quiet 5gpn-clash-remote.service; then
        rm -f "${CLASH_REMOTE_ENABLED}"
        declare -F firewall_clash_remote_sync >/dev/null 2>&1 && firewall_clash_remote_sync || true
        err "clash-remote 未启动；journalctl -u 5gpn-clash-remote -n 40"
        return 1
    fi
    local host domain
    host="$(clash_remote_host_ip)"
    domain="$(clash_remote_domain)"
    ok "远程 Clash API（HTTPS）已开启"
    echo "  地址:   ${host}:${CLASH_REMOTE_PORT}"
    if [[ -n "$domain" ]]; then
        echo "  URL:    https://${domain}:${CLASH_REMOTE_PORT}"
    else
        echo "  URL:    https://${host}:${CLASH_REMOTE_PORT}"
    fi
    echo "  密钥:   ${CLASH_REMOTE_SECRET}"
    echo "  允许源: ${CLASH_REMOTE_ALLOW_CIDR}"
    echo "  说明:   第三方面板填上述 URL，secret 填远程密钥；路径留空（根路径）"
    warn "密钥仅此时完整显示；之后 status 会隐藏。需要时可 --reset-clash-remote-secret"
}
disable_clash_remote() {
    check_root
    systemctl disable --now 5gpn-clash-remote.service 2>/dev/null || true
    rm -f "${CLASH_REMOTE_ENABLED}"
    declare -F firewall_clash_remote_sync >/dev/null 2>&1 && firewall_clash_remote_sync || true
    ok "远程 Clash API 已关闭"
}
clash_remote_status() {
    local on=0 host port domain extra allow
    [[ -f "${CLASH_REMOTE_ENABLED}" ]] && on=1
    port="$(cat "${CLASH_REMOTE_PORT_FILE}" 2>/dev/null || echo "${CLASH_REMOTE_PORT_DEFAULT}")"
    host="$(clash_remote_host_ip)"
    domain="$(clash_remote_domain)"
    extra=""
    allow="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    if [[ -f "${CLASH_REMOTE_ENV}" ]]; then
        extra="$(sed -n 's/^CLASH_REMOTE_EXTRA_CIDR=//p' "${CLASH_REMOTE_ENV}" | head -1)"
        allow="$(sed -n 's/^CLASH_REMOTE_ALLOW_CIDR=//p' "${CLASH_REMOTE_ENV}" | head -1)"
        [[ -n "$allow" ]] || allow="$(clash_remote_merge_allow_cidr "$extra")"
    fi
    echo "clash-remote: $([[ $on -eq 1 ]] && echo enabled || echo disabled)"
    echo "listen: ${host}:${port}"
    if [[ -n "$domain" ]]; then
        echo "url: https://${domain}:${port}"
    else
        echo "url: https://${host}:${port}"
    fi
    echo "secret: ***"
    echo "extra_cidr: ${extra:-"(none)"}"
    echo "allow: ${allow}"
    if [[ $on -eq 1 ]]; then
        systemctl is-active --quiet 5gpn-clash-remote.service \
            && echo "service: running" || echo "service: not running"
    fi
}
reset_clash_remote_secret() {
    check_root
    install_clash_remote_binary || return 1
    local port extra allow cert key backend secret
    port="$(cat "${CLASH_REMOTE_PORT_FILE}" 2>/dev/null || echo "${CLASH_REMOTE_PORT_DEFAULT}")"
    [[ "$port" =~ ^[0-9]+$ ]] || port="${CLASH_REMOTE_PORT_DEFAULT}"
    echo "$port" > "${CLASH_REMOTE_PORT_FILE}"
    extra=""
    if [[ -f "${CLASH_REMOTE_ENV}" ]]; then
        # shellcheck disable=SC1090
        set -a; source "${CLASH_REMOTE_ENV}"; set +a
        extra="${CLASH_REMOTE_EXTRA_CIDR:-}"
    fi
    extra="$(clash_remote_normalize_extra_cidr "$extra" 2>/dev/null || echo "")"
    allow="$(clash_remote_merge_allow_cidr "$extra")"
    cert="${CLASH_REMOTE_TLS_CERT:-/etc/mosdns/certs/fullchain.pem}"
    key="${CLASH_REMOTE_TLS_KEY:-/etc/mosdns/certs/privkey.pem}"
    backend="${CLASH_REMOTE_BACKEND:-${CLASH_REMOTE_BACKEND_DEFAULT}}"
    secret="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    ensure_mihomo_api_secret
    umask 077
    cat > "${CLASH_REMOTE_ENV}" <<EOF
CLASH_REMOTE_PORT=${port}
CLASH_REMOTE_SECRET=${secret}
CLASH_REMOTE_EXTRA_CIDR=${extra}
CLASH_REMOTE_ALLOW_CIDR=${allow}
CLASH_REMOTE_BACKEND=${backend}
CLASH_REMOTE_TLS_CERT=${cert}
CLASH_REMOTE_TLS_KEY=${key}
CLASH_REMOTE_CLASH_SECRET_FILE=${MIHOMO_API_SECRET_FILE}
EOF
    chmod 600 "${CLASH_REMOTE_ENV}"
    if [[ -f "${CLASH_REMOTE_ENABLED}" ]]; then
        systemctl restart 5gpn-clash-remote.service 2>/dev/null || true
    fi
    local host domain
    host="$(clash_remote_host_ip)"
    domain="$(clash_remote_domain)"
    ok "远程 Clash API 密钥已轮换"
    echo "  地址: ${host}:${port}"
    if [[ -n "$domain" ]]; then
        echo "  URL:  https://${domain}:${port}"
    fi
    echo "  密钥: ${secret}"
}
set_clash_remote_extra_cidr() {
    check_root
    local raw="${1:-}" extra
    if [[ -z "$raw" || "$raw" == "-" ]]; then
        extra=""
    else
        extra="$(clash_remote_normalize_extra_cidr "$raw")" || {
            err "无效额外 CIDR（IPv4 /8../32，多段用逗号）"
            return 1
        }
    fi
    install_clash_remote_binary || return 1
    clash_remote_ensure_creds
    # shellcheck disable=SC1090
    set -a; source "${CLASH_REMOTE_ENV}"; set +a
    local allow port secret cert key backend
    allow="$(clash_remote_merge_allow_cidr "$extra")"
    port="${CLASH_REMOTE_PORT}"
    secret="${CLASH_REMOTE_SECRET}"
    cert="${CLASH_REMOTE_TLS_CERT}"
    key="${CLASH_REMOTE_TLS_KEY}"
    backend="${CLASH_REMOTE_BACKEND}"
    umask 077
    cat > "${CLASH_REMOTE_ENV}" <<EOF
CLASH_REMOTE_PORT=${port}
CLASH_REMOTE_SECRET=${secret}
CLASH_REMOTE_EXTRA_CIDR=${extra}
CLASH_REMOTE_ALLOW_CIDR=${allow}
CLASH_REMOTE_BACKEND=${backend}
CLASH_REMOTE_TLS_CERT=${cert}
CLASH_REMOTE_TLS_KEY=${key}
CLASH_REMOTE_CLASH_SECRET_FILE=${MIHOMO_API_SECRET_FILE}
EOF
    chmod 600 "${CLASH_REMOTE_ENV}"
    if [[ -f "${CLASH_REMOTE_ENABLED}" ]]; then
        systemctl restart 5gpn-clash-remote.service 2>/dev/null || true
        declare -F firewall_clash_remote_sync >/dev/null 2>&1 && firewall_clash_remote_sync || true
    fi
    ok "额外允许网段已设置为 ${extra:-"(清空)"}；有效 ACL=${allow}"
}
setup_tgbot() {
    local token="${TG_BOT_TOKEN:-}"
    local ids="${TG_ADMIN_IDS:-}"
    if [[ -z "$token" && -t 0 ]]; then
        echo ""
        info "可选：配置 Telegram 控制 Bot（直接在 Telegram 上运维）"
        read -r -p "Telegram Bot Token (留空跳过): " token
    fi
    if [[ -z "$token" ]]; then
        info "未提供 Telegram Bot Token，跳过 tgbot。以后可运行: $0 --setup-tgbot"
        return 0
    fi
    if [[ -z "$ids" && -t 0 ]]; then
        read -r -p "授权的 Telegram 数字 ID（逗号分隔，可留空，稍后用 /id 获取再填）: " ids
    fi
    ids="$(printf '%s' "$ids" | tr ', ' '\n' | grep -E '^[0-9]+$' | paste -sd ',' - 2>/dev/null || true)"
    local py; py="$(command -v python3 || echo /usr/bin/python3)"
    info "Installing Telegram control bot..."
    mkdir -p "${BASE_DIR}/bin"
    if [[ ! -f "${LIB_DIR}/tgbot.py" ]]; then
        err "tgbot.py not found in ${LIB_DIR}"
        return 1
    fi
    install -m 0755 "${LIB_DIR}/tgbot.py" "${BASE_DIR}/bin/tgbot.py"
    install_mgmt_ctl
    mkdir -p "${CONF_DIR}"
    cat > "${CONF_DIR}/tgbot.env" <<EOF
TG_BOT_TOKEN=${token}
TG_ADMIN_IDS=${ids}
MGMT=${BASE_DIR}/bin/5gpn-ctl
EOF
    chmod 600 "${CONF_DIR}/tgbot.env"
    cat > /etc/systemd/system/5gpn-tgbot.service <<EOF
[Unit]
Description=Proxy Gateway Telegram control bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=LANG=C.UTF-8
Environment=PYTHONIOENCODING=utf-8
Environment=PYTHONUTF8=1
EnvironmentFile=${CONF_DIR}/tgbot.env
ExecStart=${py} ${BASE_DIR}/bin/tgbot.py
Restart=on-failure
RestartSec=5
User=root
# Root orchestrator: /etc and /usr read-only except the paths its operations
# (add/del/switch-exit, update, renew-cert, DNS/firewall sync) must write.
ProtectSystem=full
ReadWritePaths=/etc/5gpn /etc/mosdns /etc/sniproxy.conf /etc/wireguard /etc/nftables.conf /etc/letsencrypt /etc/systemd/system /usr/local/bin
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now 5gpn-tgbot.service
    if [[ -z "$ids" ]]; then
        warn "尚未设置授权 ID。给 Bot 发送 /id 获取数字 ID，填入 ${CONF_DIR}/tgbot.env 的 TG_ADMIN_IDS，然后:"
        warn "  systemctl restart 5gpn-tgbot"
    fi
    ok "Telegram bot 已安装。在 Telegram 给你的 Bot 发送 /start 开始操作。"
}
ensure_mihomo_api_secret() {
    if [[ ! -s "${MIHOMO_API_SECRET_FILE}" ]]; then
        mkdir -p /etc/5gpn; chmod 700 /etc/5gpn
        openssl rand -hex 32 2>/dev/null > "${MIHOMO_API_SECRET_FILE}" || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "${MIHOMO_API_SECRET_FILE}"
    fi
    chmod 600 "${MIHOMO_API_SECRET_FILE}"
}
install_metacubexd() {
    # Version resolution: explicit env > persisted pin > repo default.
    # setup-api / update always call this; without a pin, a newer manual
    # install would be overwritten by the default on the next update.
    local pin_file="${CONF_DIR}/metacubexd.pin"
    local ver="" explicit=0
    if [[ -n "${METACUBEXD_VERSION:-}" ]]; then
        ver="${METACUBEXD_VERSION}"
        explicit=1
    elif [[ -f "$pin_file" ]]; then
        ver="$(tr -d '[:space:]' < "$pin_file" | head -n1)"
    fi
    [[ -n "$ver" ]] || ver="${METACUBEXD_VERSION_DEFAULT}"
    local url="https://github.com/MetaCubeX/metacubexd/releases/download/v${ver}/compressed-dist.tgz"
    local tmp app_ver="" installed=""
    if [[ -f "${BASE_DIR}/webui/mihomo/.metacubexd-version" ]]; then
        installed="$(tr -d '[:space:]' < "${BASE_DIR}/webui/mihomo/.metacubexd-version" | head -n1)"
    fi
    if [[ -n "$installed" && "$installed" == "$ver" && -f "${BASE_DIR}/webui/mihomo/index.html" ]]; then
        ok "metacubexd v${ver} already installed (skip download)"
        [[ "$explicit" -eq 1 ]] && printf '%s\n' "$ver" > "$pin_file"
        return 0
    fi
    tmp="$(mktemp)"
    info "Downloading metacubexd v${ver}..."
    if ! curl -fsSL --max-time 90 "$url" -o "$tmp"; then
        rm -f "$tmp"
        if [[ "$explicit" -eq 1 ]]; then
            err "metacubexd v${ver} 下载失败: $url"
            return 1
        fi
        warn "metacubexd 下载失败（可稍后重跑 --setup-api）；mihomo 监控页暂不可用，其余功能不受影响。"
        return 0
    fi
    rm -rf "${BASE_DIR}/webui/mihomo"
    mkdir -p "${BASE_DIR}/webui/mihomo"
    if ! tar -xzf "$tmp" -C "${BASE_DIR}/webui/mihomo" 2>/dev/null && ! tar -xf "$tmp" -C "${BASE_DIR}/webui/mihomo"; then
        rm -f "$tmp"
        if [[ "$explicit" -eq 1 ]]; then
            err "metacubexd v${ver} 解压失败"
            return 1
        fi
        warn "metacubexd 解压失败（可稍后重跑 --setup-api）；其余功能不受影响。"
        return 0
    fi
    rm -f "$tmp"
    printf '%s\n' "$ver" > "${BASE_DIR}/webui/mihomo/.metacubexd-version"
    # Persist explicit pins so later `5gpn update` does not silently downgrade.
    if [[ "$explicit" -eq 1 ]]; then
        mkdir -p "${CONF_DIR}"
        printf '%s\n' "$ver" > "$pin_file"
    fi
    app_ver="$(python3 - <<'PY' "${BASE_DIR}/webui/mihomo/index.html" 2>/dev/null || true
import re, sys
try:
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
except OSError:
    raise SystemExit(0)
m = re.search(r'appVersion\s*:\s*"([^"]+)"', text)
if m:
    print(m.group(1))
PY
)"
    if [[ -n "$app_ver" && "$app_ver" != "$ver" ]]; then
        warn "解压后 index.html 的 appVersion=${app_ver}，与请求的 v${ver} 不一致"
    fi
    ok "metacubexd v${ver} installed to ${BASE_DIR}/webui/mihomo${app_ver:+ (appVersion=${app_ver})}"
    info "若浏览器仍显示旧版：清掉该站 Service Worker / 站点数据，或用无痕窗口打开 /mihomo/"
}
update_webui() {
    # Self-service metacubexd dashboard bump: 5gpn update-webui [version].
    # An explicit version is pinned (etc/metacubexd.pin); without an argument
    # the version resolves via env > pin > repo default.
    local ver="${1:-}"
    if [[ -n "$ver" ]]; then
        METACUBEXD_VERSION="${ver}" install_metacubexd
    else
        install_metacubexd
    fi
}
setup_api() {
    local token="${API_TOKEN:-}"
    local port="${API_PORT:-${API_PORT_DEFAULT}}"
    local bind="${API_BIND:-}"
    local allow_origin="${API_ALLOW_ORIGIN:-}"
    port="$(printf '%s' "$port" | tr -dc '0-9')"; [[ -n "$port" ]] || port="${API_PORT_DEFAULT}"

    # Reuse existing API settings on re-runs; explicit environment wins.
    if [[ -z "$token" && -f "${CONF_DIR}/api.env" ]]; then
        token="$(sed -n 's/^API_TOKEN=//p' "${CONF_DIR}/api.env" | head -n1)"
    fi
    if [[ -z "$bind" && -f "${CONF_DIR}/api.env" ]]; then
        bind="$(sed -n 's/^API_BIND=//p' "${CONF_DIR}/api.env" | head -n1)"
    fi
    if [[ -z "$allow_origin" && -f "${CONF_DIR}/api.env" ]]; then
        allow_origin="$(sed -n 's/^API_ALLOW_ORIGIN=//p' "${CONF_DIR}/api.env" | head -n1)"
    fi
    bind="${bind:-127.0.0.1}"
    if [[ -z "$token" ]]; then
        token="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    if [[ -z "$token" || ${#token} -lt 16 ]]; then
        err "Could not generate an API token. Set API_TOKEN and retry."; return 1
    fi

    local py; py="$(command -v python3 || echo /usr/bin/python3)"
    if [[ ! -f "${LIB_DIR}/api-server.py" ]]; then
        err "api-server.py not found in ${LIB_DIR}"; return 1
    fi
    if [[ ! -f "${LIB_DIR}/mihomo-router-config.py" ]]; then
        err "mihomo-router-config.py not found in ${LIB_DIR}"; return 1
    fi

    info "Installing HTTP control API..."
    ensure_mihomo_api_secret
    mkdir -p "${BASE_DIR}/bin" "${CONF_DIR}"
    # Refresh the installed router generator so the regen below emits the Clash API block.
    install -m 0755 "${LIB_DIR}/mihomo-router-config.py" "${MIHOMO_ROUTER_GEN}"
    install_metacubexd
    if [[ -f "${RULES_FILE}" ]]; then
        info "Rebuilding smart router config to enable the mihomo API..."
        ( regen_smart ) || warn "smart 配置重建失败；配置规则后可重跑 --setup-api"
    fi
    install -m 0755 "${LIB_DIR}/api-server.py" "${BASE_DIR}/bin/api-server.py"
    install -m 0755 "${LIB_DIR}/mihomo-router-config.py" "${MIHOMO_ROUTER_GEN}"
    install_mgmt_ctl
    if [[ -f "${SCRIPT_DIR}/webui/index.html" && "${SCRIPT_DIR}" != "${BASE_DIR}" ]]; then
        mkdir -p "${BASE_DIR}/webui"
        install -m 0644 "${SCRIPT_DIR}/webui/index.html" "${BASE_DIR}/webui/index.html"
    fi

    local domain; domain="$(cat "${CONF_DIR}/.domain" 2>/dev/null || echo "")"
    local cert="/etc/mosdns/certs/fullchain.pem" key="/etc/mosdns/certs/privkey.pem"
    [[ -f "$cert" && -f "$key" ]] || warn "TLS certs not found at ${cert} — run --renew-cert or full install first; the API needs them to start."

    cat > "${CONF_DIR}/api.env" <<EOF
API_TOKEN=${token}
API_PORT=${port}
API_BIND=${bind}
API_TLS_CERT=${cert}
API_TLS_KEY=${key}
API_ALLOW_ORIGIN=${allow_origin}
MGMT=${BASE_DIR}/bin/5gpn-ctl
CONF_DIR=${CONF_DIR}
EOF
    chmod 600 "${CONF_DIR}/api.env"
    printf '%s' "$port" > "${CONF_DIR}/.api_port"

    cat > /etc/systemd/system/5gpn-api.service <<EOF
[Unit]
Description=5GPN-X HTTP control API
After=network-online.target mosdns.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${CONF_DIR}/api.env
ExecStart=${py} ${BASE_DIR}/bin/api-server.py
Restart=on-failure
RestartSec=5
User=root
# Root orchestrator: same write-path contract as 5gpn-tgbot.service.
ProtectSystem=full
ReadWritePaths=/etc/5gpn /etc/mosdns /etc/sniproxy.conf /etc/wireguard /etc/nftables.conf /etc/letsencrypt /etc/systemd/system /usr/local/bin
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable 5gpn-api.service
    systemctl restart 5gpn-api.service   # plain restart: re-runs must pick up new code

    echo ""
    ok "HTTP 控制 API 已启用。"
    echo "  绑定地址:             ${bind}"
    echo "  地址 (API Base URL): https://${domain:-<你的域名>}:${port}"
    echo "  本机 WebUI/API:       https://127.0.0.1:${port}/"
    echo "  令牌 (API_TOKEN):    ${token}"
    echo "  健康检查:            curl -k https://${domain:-<域名>}:${port}/api/health"
    echo "  网页面板:            API 服务会同源提供 WebUI；也可打开仓库里的 webui/index.html。"
    echo "  令牌存放:            ${CONF_DIR}/api.env (chmod 600)"
    warn "API 可控制出口/分流，务必保管好令牌；只用 HTTPS 访问。"
    if [[ "$bind" == "0.0.0.0" || "$bind" == "::" ]]; then
        warn "API 已公开绑定；请确认主机防火墙只向可信来源放行 TCP ${port}，详见 docs/TROUBLESHOOTING.md。"
    else
        warn "API 默认仅绑定本机。公网访问需显式 API_BIND=0.0.0.0 并配置防火墙，详见 docs/TROUBLESHOOTING.md。"
    fi
}
# Rotate API_TOKEN in place (keeps port/bind/origin), restart the API, verify.
rotate_api_token() {
    check_root
    [[ -f "${CONF_DIR}/api.env" ]] || { err "API 未安装；先运行 --setup-api"; return 1; }
    local token port domain tmp i
    token="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    if [[ -z "$token" || ${#token} -lt 16 ]]; then
        err "Could not generate an API token."; return 1
    fi
    tmp="${CONF_DIR}/api.env.tmp"
    if grep -q '^API_TOKEN=' "${CONF_DIR}/api.env"; then
        sed "s/^API_TOKEN=.*/API_TOKEN=${token}/" "${CONF_DIR}/api.env" > "$tmp"
    else
        cat "${CONF_DIR}/api.env" > "$tmp"
        echo "API_TOKEN=${token}" >> "$tmp"
    fi
    chmod 600 "$tmp"
    mv "$tmp" "${CONF_DIR}/api.env"
    systemctl restart 5gpn-api.service

    port="$(sed -n 's/^API_PORT=//p' "${CONF_DIR}/api.env" | head -n1)"; port="${port:-8444}"
    for i in $(seq 1 10); do
        if curl -k -fsS -m 3 -H "Authorization: Bearer ${token}" \
                "https://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then
            break
        fi
        if [[ "$i" == "10" ]]; then
            warn "重启后健康检查未通过，请运行 journalctl -u 5gpn-api 排查"
        fi
        sleep 1
    done

    domain="$(cat "${CONF_DIR}/.domain" 2>/dev/null || echo "")"
    ok "API token 已轮换，5gpn-api 已重启。"
    echo "  新令牌 (API_TOKEN): ${token}"
    echo "  WebUI:              https://${domain:-<域名>}:${port}/"
    warn "旧令牌立即失效；请更新所有客户端/书签里的令牌。"
}
# --- API source allowlist (etc/api-allow.list; enforced by api-server.py) -----
api_allow_file() { printf '%s/api-allow.list' "${CONF_DIR}"; }
valid_cidr() {
    python3 - "$1" <<'PYEOF' >/dev/null 2>&1
import ipaddress
import sys
ipaddress.ip_network(sys.argv[1], strict=False)
PYEOF
}
api_allow_list() {
    local f; f="$(api_allow_file)"
    if [[ -s "$f" ]]; then
        echo "API 来源白名单 (${f}):"
        grep -v '^\s*#' "$f" | grep -v '^\s*$' || true
    else
        info "API 来源白名单为空：不限制来源（回环始终允许）。"
    fi
}
api_allow_add() {
    check_root
    local cidr="${1:-}" f
    [[ -n "$cidr" ]] || { err "Usage: $0 --api-allow add <cidr>"; exit 1; }
    valid_cidr "$cidr" || { err "Invalid CIDR: $cidr"; exit 1; }
    f="$(api_allow_file)"
    mkdir -p "${CONF_DIR}"
    touch "$f"
    chmod 600 "$f"
    if grep -qxF "$cidr" "$f"; then
        info "已在白名单中: ${cidr}"
    else
        echo "$cidr" >> "$f"
        ok "API 来源白名单已添加: ${cidr}"
    fi
    warn "HTTP 层立即生效（api-server 按 mtime 热加载）。白名单非空时，名单外来源访问 API/webui 一律 403，请确认已覆盖你的管理来源。"
}
api_allow_del() {
    check_root
    local cidr="${1:-}" f tmp
    [[ -n "$cidr" ]] || { err "Usage: $0 --api-allow del <cidr>"; exit 1; }
    f="$(api_allow_file)"
    [[ -f "$f" ]] || { info "白名单为空，无需删除。"; return 0; }
    tmp="${f}.tmp"
    grep -vxF "$cidr" "$f" > "$tmp" 2>/dev/null || true
    chmod 600 "$tmp"
    mv "$tmp" "$f"
    ok "API 来源白名单已删除: ${cidr}（剩余条目为空时恢复不限制）"
}
# --- exit failover watchdog (opt-in; invariant I11) ---------------------------
setup_failover() {
    [[ -f "${LIB_DIR}/failover.py" ]] || { err "failover.py not found in ${LIB_DIR}"; return 1; }
    mkdir -p "${BASE_DIR}/bin"
    install -m 0755 "${LIB_DIR}/failover.py" "${BASE_DIR}/bin/failover.py"
    # Root orchestrator (switches via install.sh --set-exit): same write-path
    # contract as 5gpn-tgbot.service / 5gpn-api.service (I10).
    cat > /etc/systemd/system/5gpn-failover.service <<EOF
[Unit]
Description=5GPN-X exit failover watchdog (one tick)

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${BASE_DIR}/bin/failover.py tick
ProtectSystem=full
ReadWritePaths=/etc/5gpn /etc/mosdns /etc/sniproxy.conf /etc/wireguard /etc/nftables.conf /etc/letsencrypt /etc/systemd/system /usr/local/bin
ProtectHome=true
PrivateTmp=true
EOF
    cat > /etc/systemd/system/5gpn-failover.timer <<'EOF'
[Unit]
Description=Run 5GPN-X exit failover watchdog every 60 seconds

[Timer]
OnBootSec=5min
OnUnitActiveSec=60s
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    # I11: opt-in. Units are rendered but the timer is only ever enabled by
    # `failover_ctl on` — never here.
}
failover_ctl() {
    check_root
    local action="${1:-status}"
    local py; py="$(command -v python3 || echo /usr/bin/python3)"
    case "$action" in
        on)
            setup_failover
            mkdir -p /etc/5gpn
            touch /etc/5gpn/failover.enabled
            chmod 600 /etc/5gpn/failover.enabled
            systemctl enable --now 5gpn-failover.timer
            ok "出口自愈已开启：每 60s 探测当前出口，连续失败自动切换到最优候选出口并推送 Telegram 通知。"
            info "自定义候选顺序: $0 --failover order hk,jp,us"
            ;;
        off)
            rm -f /etc/5gpn/failover.enabled
            systemctl disable --now 5gpn-failover.timer 2>/dev/null || true
            ok "出口自愈已关闭（单元保留，状态文件保留）。"
            ;;
        order)
            local order="${2:-}" item clean=()
            [[ -n "$order" ]] || { err "Usage: $0 --failover order <exit1,exit2,...>"; exit 1; }
            IFS=',' read -r -a items <<< "$order"
            for item in "${items[@]}"; do
                item="$(echo "$item" | tr -d '[:space:]')"
                [[ -z "$item" ]] && continue
                if [[ "$item" == "local" || "$item" == "smart" ]]; then
                    err "local/smart 不能作为 failover 候选"; exit 1
                fi
                exit_exists "$item" || { err "未知出口: $item（先 --add-exit 添加）"; exit 1; }
                clean+=("$item")
            done
            [[ ${#clean[@]} -gt 0 ]] || { err "候选顺序不能为空"; exit 1; }
            mkdir -p /etc/5gpn
            umask 077
            printf 'FAILOVER_ORDER="%s"\n' "$(IFS=,; echo "${clean[*]}")" > /etc/5gpn/failover.env
            chmod 600 /etc/5gpn/failover.env
            ok "failover 候选顺序: $(IFS=,; echo "${clean[*]}")"
            ;;
        status)
            if [[ -f /etc/5gpn/failover.enabled ]]; then
                echo -e "failover: ${GREEN}enabled${NC} (timer: $(systemctl is-active 5gpn-failover.timer 2>/dev/null || echo unknown))"
            else
                echo "failover: disabled（开启: $0 --failover on）"
            fi
            [[ -x "${BASE_DIR}/bin/failover.py" ]] && "$py" "${BASE_DIR}/bin/failover.py" status 2>/dev/null || true
            ;;
        *)
            err "Usage: $0 --failover [on|off|status|order <a,b,c>]"; exit 1 ;;
    esac
}
# Opt-in API + web panel during install (API_SETUP=1 / API_TOKEN set / prompt).
maybe_setup_api() {
    local want="${API_SETUP:-}"
    [[ -z "$want" && -n "${API_TOKEN:-}" ]] && want=1
    if [[ -z "$want" && -t 0 ]]; then
        echo ""
        info "可选：启用 HTTP 控制 API + 网页面板（在网页上运维，与 Telegram Bot 实时同步）"
        local ans; read -r -p "现在启用 API / 网页面板? [y/N]: " ans
        case "$ans" in y|Y|yes|YES) want=1 ;; *) want=0 ;; esac
    fi
    if [[ "$want" == "1" ]]; then
        setup_api
    else
        info "未启用 HTTP API（可选）。以后随时运行: $0 --setup-api"
    fi
}
