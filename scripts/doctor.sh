#!/usr/bin/env bash
# 5GPN-X doctor — structured read-only health check.
# Usage:
#   sudo 5gpn doctor
#   sudo bash /opt/5gpn/scripts/doctor.sh [--json] [--deep] [--quiet]
#
# Exit: 0 = no failures (warnings allowed); 1 = at least one failure.
# shellcheck disable=SC2015
set -uo pipefail

# systemd Bot/API often inherit a minimal PATH; keep sbin tools visible.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
SYSTEMCTL="$(command -v systemctl || echo /usr/bin/systemctl)"
IP="$(command -v ip || echo /usr/sbin/ip)"
NFT="$(command -v nft || echo /usr/sbin/nft)"

svc_active() {
    local unit="$1" st
    st="$("$SYSTEMCTL" show -p ActiveState --value "$unit" 2>/dev/null || true)"
    [[ "$st" == "active" || "$st" == "activating" ]]
}

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0
JSON=0; DEEP=0; QUIET=0
RESULTS=()

for arg in "$@"; do
    case "$arg" in
        --json) JSON=1 ;;
        --deep) DEEP=1 ;;
        --quiet|-q) QUIET=1 ;;
        -h|--help)
            echo "Usage: $0 [--json] [--deep] [--quiet]"
            exit 0
            ;;
    esac
done

record() { # level label detail
    local level="$1" label="$2" detail="$3"
    # Keep RESULT argv-safe for --json (no pipes/newlines in fields).
    detail="${detail//$'\r'/}"
    detail="${detail//$'\n'/ }"
    detail="${detail//'|'/-}"
    label="${label//'|'/-}"
    RESULTS+=("${level}|${label}|${detail}")
    case "$level" in
        ok)   PASS=$((PASS+1))
              if [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]]; then
                  echo -e "${GREEN}[PASS]${NC} ${label}: ${detail}"
              fi
              ;;
        fail) FAIL=$((FAIL+1))
              if [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]]; then
                  echo -e "${RED}[FAIL]${NC} ${label}: ${detail}"
              fi
              ;;
        warn) WARN=$((WARN+1))
              if [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]]; then
                  echo -e "${YELLOW}[WARN]${NC} ${label}: ${detail}"
              fi
              ;;
        info) if [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]]; then
                  echo -e "       ${label}: ${detail}"
              fi
              ;;
    esac
    return 0
}
ok()   { record ok "$1" "$2"; }
bad()  { record fail "$1" "$2"; }
note() { record warn "$1" "$2"; }

BASE_DIR="${BASE_DIR:-/opt/5gpn}"
CONF_DIR="${CONF_DIR:-${BASE_DIR}/etc}"
CURRENT="$(cat "${CONF_DIR}/current-exit" 2>/dev/null || echo local)"
CLIENT_CIDR="$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"

[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && \
    echo "===== 5GPN-X doctor $(date '+%F %T') (exit=${CURRENT}, client=${CLIENT_CIDR}) ====="

# ----- deployed revision -----
git_head=""
if [[ -d "${BASE_DIR}/.git" ]]; then
    git_head="$(git -C "${BASE_DIR}" rev-parse HEAD 2>/dev/null || true)"
    short="$(git -C "${BASE_DIR}" rev-parse --short HEAD 2>/dev/null || echo '?')"
    subj="$(git -C "${BASE_DIR}" log -1 --pretty=%s 2>/dev/null | tr -d '\n' || true)"
    ok "部署版本" "${short} ${subj}"
elif [[ -f "${CONF_DIR}/.deployed-rev" ]]; then
    short="$(awk -F= '/^short=/{print substr($0,7); exit}' "${CONF_DIR}/.deployed-rev")"
    ok "部署版本" "${short:-unknown} (recorded)"
else
    note "部署版本" "无法读取 git HEAD"
fi

# Half-update detector: code pulled but runtime refresh not finished.
if [[ -n "$git_head" && -f "${CONF_DIR}/.deployed-rev" ]]; then
    recorded="$(awk -F= '/^full=/{print substr($0,6); exit}' "${CONF_DIR}/.deployed-rev")"
    if [[ -n "$recorded" && "$git_head" != "$recorded" ]]; then
        note "运行时一致性" "git HEAD≠已部署记录，建议 sudo 5gpn update 完成刷新"
    fi
fi
if [[ -f "${BASE_DIR}/scripts/health-notify.sh" ]]; then
    if "$SYSTEMCTL" is-enabled --quiet 5gpn-health.timer 2>/dev/null \
        || svc_active 5gpn-health.timer; then
        ok "健康定时器" "enabled"
    else
        note "健康定时器" "未启用，建议 sudo 5gpn update"
    fi
fi

# ----- services -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 服务 -----"
for svc in mosdns sniproxy wa-shim quic-proxy; do
    if svc_active "$svc"; then
        ok "服务 ${svc}" "running"
    else
        bad "服务 ${svc}" "not running"
    fi
done
[[ -f "${CONF_DIR}/tgbot.env" ]] && {
    if svc_active 5gpn-tgbot; then
        ok "服务 5gpn-tgbot" "running"
    else
        bad "服务 5gpn-tgbot" "not running"
    fi
}
[[ -f "${CONF_DIR}/api.env" ]] && {
    if svc_active 5gpn-api; then
        ok "服务 5gpn-api" "running"
    else
        bad "服务 5gpn-api" "not running"
    fi
}
if [[ -f "${CONF_DIR}/client-socks.enabled" ]]; then
    if svc_active 5gpn-client-socks; then
        ok "服务 client-socks" "running"
    else
        bad "服务 client-socks" "enabled but not running"
    fi
else
    note "私网 SOCKS5" "disabled"
fi
if [[ -f "${CONF_DIR}/client-mtproto.enabled" ]]; then
    if svc_active 5gpn-mtg && svc_active 5gpn-client-mtproto; then
        ok "服务 client-mtproto" "running"
    else
        bad "服务 client-mtproto" "enabled but mtg/front not running"
    fi
else
    note "私网 MTProto" "disabled"
fi
if [[ "$CURRENT" == "smart" ]]; then
    if svc_active 5gpn-mihomo@smart; then
        ok "服务 smart" "running"
    else
        bad "服务 smart" "5gpn-mihomo@smart not running"
    fi
elif [[ "$CURRENT" != "local" ]]; then
    if svc_active "5gpn-mihomo@${CURRENT}"; then
        ok "服务出口 ${CURRENT}" "running"
    else
        note "服务出口 ${CURRENT}" "mihomo unit not running"
    fi
fi

# ----- ports -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 端口 -----"
check_listen() {
    local proto="$1" port="$2" label="$3"
    if ss -H -tln 2>/dev/null | grep -qE ":${port}( |$)" \
        || ss -H -uln 2>/dev/null | grep -qE ":${port}( |$)"; then
        ok "$label" "${proto}/${port} listening"
    else
        bad "$label" "${proto}/${port} not listening"
    fi
}
check_listen tcp 853 "DoT"
check_listen udp 53 "DNS"
check_listen tcp 443 "HTTPS/SNI"
[[ -f "${CONF_DIR}/api.env" ]] && check_listen tcp 8444 "控制 API"
if [[ -f "${CONF_DIR}/client-socks.enabled" ]]; then
    socks_port="$(cat "${CONF_DIR}/client-socks.port" 2>/dev/null || echo 38443)"
    check_listen tcp "$socks_port" "私网 SOCKS5"
fi
if [[ -f "${CONF_DIR}/client-mtproto.enabled" ]]; then
    mtproto_port="$(cat "${CONF_DIR}/client-mtproto.port" 2>/dev/null || echo 5753)"
    check_listen tcp "$mtproto_port" "私网 MTProto"
fi
if [[ "$CURRENT" == "smart" ]]; then
    if ss -H -tln 2>/dev/null | grep -q "127.0.0.1:9090"; then
        ok "Clash API" "127.0.0.1:9090"
    else
        bad "Clash API" "127.0.0.1:9090 not listening"
    fi
    if ss -H -tln 2>/dev/null | grep -qE "0\.0\.0\.0:9090|\[::\]:9090"; then
        bad "Clash API 暴露" "9090 is public"
    else
        ok "Clash API 暴露" "not public"
    fi
fi

# ----- DNS / DoT -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- DNS / DoT -----"
if command -v dig >/dev/null 2>&1; then
    dns_out="$(dig +time=3 +tries=1 @127.0.0.1 -p 53 example.com A 2>&1 || true)"
    if [[ "$dns_out" == *"status:"* ]]; then
        st="$(sed -n 's/.*status: \([A-Za-z]*\).*/\1/p' <<< "$dns_out" | head -1)"
        if [[ "$st" == "REFUSED" ]]; then
            note "mosdns UDP/53" "REFUSED (upstream ACL/rate-limit?)"
        else
            ok "mosdns UDP/53" "status=${st}"
        fi
    else
        bad "mosdns UDP/53" "no response"
    fi
else
    note "mosdns UDP/53" "dig not installed"
fi
domain="$(cat "${CONF_DIR}/.domain" 2>/dev/null || cat /etc/mosdns/.domain 2>/dev/null || true)"
if [[ -n "$domain" ]] && command -v openssl >/dev/null 2>&1; then
    tls_out="$(echo | openssl s_client -connect 127.0.0.1:853 -servername "$domain" 2>/dev/null || true)"
    if [[ "$tls_out" == *"Verify return code: 0 (ok)"* ]]; then
        ok "DoT TLS" "handshake+cert ok (${domain})"
    else
        bad "DoT TLS" "handshake/cert failed (${domain})"
    fi
fi
# client cidr vs mosdns config
if [[ -f /etc/mosdns/config.yaml ]]; then
    if grep -q "client_ip ${CLIENT_CIDR}" /etc/mosdns/config.yaml 2>/dev/null; then
        ok "客户端网段" "${CLIENT_CIDR} 已写入 mosdns"
    else
        note "客户端网段" "配置为 ${CLIENT_CIDR}，但 config.yaml 可能尚未刷新（跑 5gpn update-rules）"
    fi
fi
dd_count=0
if [[ -f /etc/mosdns/direct-domains.txt ]]; then
    # grep -c exits 1 on zero matches but still prints "0"; do not append via || echo.
    dd_count="$(grep -cE '^[A-Za-z0-9]' /etc/mosdns/direct-domains.txt 2>/dev/null || true)"
    [[ "$dd_count" =~ ^[0-9]+$ ]] || dd_count=0
fi
ok "DNS 直连名单" "${dd_count} 条"

# ----- egress path -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 出口链路 -----"
if [[ "$CURRENT" == "smart" ]]; then
    if "$IP" link show pgw-smart >/dev/null 2>&1; then
        ok "TUN pgw-smart" "exists"
        if "$IP" route show table 100 2>/dev/null | grep -q "default.*pgw-smart"; then
            ok "路由表 100" "default via pgw-smart"
        else
            bad "路由表 100" "default not via pgw-smart"
        fi
        if [[ "$DEEP" -eq 1 ]]; then
            code="$(curl -m 8 -s -o /dev/null -w '%{http_code}' --interface pgw-smart https://www.google.com 2>/dev/null || echo 000)"
            if [[ "$code" != "000" ]]; then
                ok "smart 出网" "HTTP ${code}"
            else
                bad "smart 出网" "curl failed"
            fi
        fi
    else
        bad "TUN pgw-smart" "missing"
    fi
elif [[ "$CURRENT" != "local" ]]; then
    if "$IP" link show "pgw-${CURRENT}" >/dev/null 2>&1; then
        ok "TUN pgw-${CURRENT}" "exists"
    else
        bad "TUN pgw-${CURRENT}" "missing"
    fi
else
    note "出口链路" "local 直出，跳过 TUN"
fi

# ----- policy routing -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 策略路由 -----"
fw_count="$("$IP" rule show 2>/dev/null | grep -c 'fwmark 0x1 lookup 100' || true)"
[[ "$fw_count" =~ ^[0-9]+$ ]] || fw_count=0
if [[ "$fw_count" -ge 1 ]]; then
    ok "fwmark 规则" "${fw_count} 条"
else
    bad "fwmark 规则" "missing"
fi
if "$NFT" list table inet pgw_exit >/dev/null 2>&1; then
    ok "pgw_exit 表" "present"
else
    bad "pgw_exit 表" "missing"
fi

# ----- API -----
if [[ -f "${CONF_DIR}/api.env" ]]; then
    [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- API -----"
    health="$(curl -m 5 -sk https://127.0.0.1:8444/api/health 2>/dev/null || true)"
    if [[ "$health" == *'"ok": true'* || "$health" == *'"ok":true'* ]]; then
        ok "API /health" "ok"
    else
        bad "API /health" "${health:-no response}"
    fi
fi

# ----- WLOC -----
if [[ -f /etc/systemd/system/5gpn-wloc.service ]]; then
    [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- WLOC -----"
    wloc_dir="${CONF_DIR}/wloc"
    if [[ -s "${wloc_dir}/ca.crt" && -s "${wloc_dir}/leaf.crt" && -s "${wloc_dir}/leaf.key" ]]; then
        ok "WLOC 证书" "present"
    else
        bad "WLOC 证书" "missing"
    fi
    wstate="$(cat "${wloc_dir}/modifier.state" 2>/dev/null || echo paused)"
    if [[ "$wstate" == "active" ]]; then
        if svc_active 5gpn-wloc; then
            ok "WLOC" "active+running"
        else
            bad "WLOC" "active but service down"
        fi
        if ss -H -tln 2>/dev/null | grep -q "127.0.0.1:10451"; then
            ok "WLOC 端口" "127.0.0.1:10451"
        else
            bad "WLOC 端口" "10451 not listening"
        fi
        if grep -q "gs-loc.apple.com" /etc/mosdns/wloc.txt 2>/dev/null; then
            ok "WLOC DNS 劫持" "gs-loc.apple.com present"
        else
            bad "WLOC DNS 劫持" "wloc.txt missing gs-loc.apple.com"
        fi
    else
        note "WLOC" "disabled"
    fi
fi

# ----- certs -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 证书 -----"
if [[ -s /etc/mosdns/certs/fullchain.pem && -s /etc/mosdns/certs/privkey.pem ]]; then
    ok "TLS 证书文件" "present"
    if command -v openssl >/dev/null 2>&1; then
        days=$(( ( $(date -d "$(openssl x509 -enddate -noout -in /etc/mosdns/certs/fullchain.pem | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
        if [[ "$days" -gt 14 ]]; then
            ok "证书有效期" "${days} 天"
        elif [[ "$days" -gt 0 ]]; then
            note "证书有效期" "仅剩 ${days} 天"
        else
            bad "证书有效期" "已过期或无效"
        fi
    fi
else
    bad "TLS 证书文件" "missing"
fi

# ----- deep extras -----
if [[ "$DEEP" -eq 1 ]]; then
    [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 深度检查 -----"
    if [[ -n "$domain" ]] && command -v dig >/dev/null 2>&1; then
        pub="$(dig +short +time=3 A "$domain" 2>/dev/null | head -1)"
        self="$(cat /etc/mosdns/.public_ip 2>/dev/null || true)"
        if [[ -n "$pub" && -n "$self" && "$pub" == "$self" ]]; then
            ok "DoT 域名 A 记录" "${domain} → ${pub}"
        else
            note "DoT 域名 A 记录" "${domain} → ${pub:-?} (本机 ${self:-?})"
        fi
    fi
    # Domain DoH upstream wire-format probe (catches AGH ACL / path issues).
    doh_url="$(grep -m1 -o 'https://[^ ]*' /etc/mosdns/.remote_dns 2>/dev/null || true)"
    if [[ -n "$doh_url" ]]; then
        code="$(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
            | curl -sm 8 -X POST "$doh_url" -H "content-type: application/dns-message" -H "accept: application/dns-message" \
                  --data-binary @- -o /tmp/.doh-doctor.bin -w '%{http_code}' 2>/dev/null || echo 000)"
        rm -f /tmp/.doh-doctor.bin
        if [[ "$code" == "200" ]]; then
            ok "DoH 上游" "${doh_url} HTTP 200"
        else
            note "DoH 上游" "${doh_url} HTTP ${code}"
        fi
    fi
fi

# ----- output -----
if [[ "$JSON" -eq 1 ]]; then
    # Pass RESULTS via a temp file — argv packing breaks under some locales and
    # can drop/corrupt checks when Bot/cron invoke doctor --json.
    _json_results="$(mktemp)"
    if ((${#RESULTS[@]})); then
        printf '%s\n' "${RESULTS[@]}" > "${_json_results}"
    else
        : > "${_json_results}"
    fi
    PYTHONIOENCODING=utf-8 PYTHONUTF8=1 python3 - "$PASS" "$FAIL" "$WARN" "$CURRENT" "$CLIENT_CIDR" "${_json_results}" <<'PY'
import json, os, sys
pass_n, fail_n, warn_n, current, cidr, path = sys.argv[1:7]
items = []
with open(path, encoding="utf-8") as fh:
    for raw in fh:
        raw = raw.rstrip("\n")
        if not raw:
            continue
        parts = raw.split("|", 2)
        if len(parts) < 3:
            continue
        level, label, detail = parts
        items.append({"level": level, "check": label, "detail": detail})
try:
    os.remove(path)
except OSError:
    pass
# Prefer recounting from items so output stays self-consistent.
pass_n = sum(1 for i in items if i["level"] == "ok")
fail_n = sum(1 for i in items if i["level"] == "fail")
warn_n = sum(1 for i in items if i["level"] == "warn")
payload = json.dumps({
    "ok": fail_n == 0,
    "pass": pass_n,
    "fail": fail_n,
    "warn": warn_n,
    "current_exit": current,
    "client_cidr": cidr,
    "checks": items,
}, ensure_ascii=False) + "\n"
sys.stdout.buffer.write(payload.encode("utf-8"))
PY
    rm -f "${_json_results}"
else
    [[ "$QUIET" -eq 0 ]] && echo "" && echo "===== 结果: ${PASS} 通过, ${FAIL} 失败, ${WARN} 警告 ====="
    if [[ "$DEEP" -eq 1 && "$QUIET" -eq 0 ]]; then
        echo ""
        echo "人工步骤（脚本无法代替）:"
        echo "  1. 手机连入后，浏览器开 https://www.google.com 应通（smart/代理出口下）"
        echo "  2. 开几个国内站点（baidu.com/taobao.com）应直连且速度正常"
        echo "  3. 控制台仪表盘有实时速率、24H 流量出点、mihomo 概览有连接数"
        echo "  4. 重启服务器一次：确认 current-exit 出口自动恢复"
    fi
fi

[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
