#!/usr/bin/env bash
# 5GPN-X doctor — structured read-only health check.
# Usage:
#   sudo 5gpn doctor
#   sudo bash /opt/5gpn/scripts/doctor.sh [--json] [--deep] [--quiet]
#
# Exit: 0 = no failures (warnings allowed); 1 = at least one failure.
# shellcheck disable=SC2015
set -uo pipefail

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
    RESULTS+=("${level}|${label}|${detail}")
    case "$level" in
        ok)   PASS=$((PASS+1)); [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo -e "${GREEN}[PASS]${NC} ${label}: ${detail}" ;;
        fail) FAIL=$((FAIL+1)); [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo -e "${RED}[FAIL]${NC} ${label}: ${detail}" ;;
        warn) WARN=$((WARN+1)); [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo -e "${YELLOW}[WARN]${NC} ${label}: ${detail}" ;;
        info) [[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo -e "       ${label}: ${detail}" ;;
    esac
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
    if systemctl is-enabled --quiet 5gpn-health.timer 2>/dev/null \
        || systemctl is-active --quiet 5gpn-health.timer 2>/dev/null; then
        ok "健康定时器" "enabled"
    else
        note "健康定时器" "未启用，建议 sudo 5gpn update"
    fi
fi

# ----- services -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 服务 -----"
for svc in mosdns sniproxy wa-shim quic-proxy; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "服务 ${svc}" "running"
    else
        bad "服务 ${svc}" "not running"
    fi
done
[[ -f "${CONF_DIR}/tgbot.env" ]] && {
    systemctl is-active --quiet 5gpn-tgbot 2>/dev/null && ok "服务 5gpn-tgbot" "running" || bad "服务 5gpn-tgbot" "not running"
}
[[ -f "${CONF_DIR}/api.env" ]] && {
    systemctl is-active --quiet 5gpn-api 2>/dev/null && ok "服务 5gpn-api" "running" || bad "服务 5gpn-api" "not running"
}
if [[ "$CURRENT" == "smart" ]]; then
    systemctl is-active --quiet 5gpn-mihomo@smart 2>/dev/null \
        && ok "服务 smart" "running" || bad "服务 smart" "5gpn-mihomo@smart not running"
elif [[ "$CURRENT" != "local" ]]; then
    systemctl is-active --quiet "5gpn-mihomo@${CURRENT}" 2>/dev/null \
        && ok "服务出口 ${CURRENT}" "running" || note "服务出口 ${CURRENT}" "mihomo unit not running"
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
    dd_count="$(grep -cE '^[A-Za-z0-9]' /etc/mosdns/direct-domains.txt 2>/dev/null || echo 0)"
fi
ok "DNS 直连名单" "${dd_count} 条"

# ----- egress path -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 出口链路 -----"
if [[ "$CURRENT" == "smart" ]]; then
    if ip link show pgw-smart >/dev/null 2>&1; then
        ok "TUN pgw-smart" "exists"
        if ip route show table 100 2>/dev/null | grep -q "default.*pgw-smart"; then
            ok "路由表 100" "default via pgw-smart"
        else
            bad "路由表 100" "default not via pgw-smart"
        fi
        if [[ "$DEEP" -eq 1 ]]; then
            code="$(curl -m 8 -s -o /dev/null -w '%{http_code}' --interface pgw-smart https://www.google.com 2>/dev/null || echo 000)"
            [[ "$code" != "000" ]] && ok "smart 出网" "HTTP ${code}" || bad "smart 出网" "curl failed"
        fi
    else
        bad "TUN pgw-smart" "missing"
    fi
elif [[ "$CURRENT" != "local" ]]; then
    ip link show "pgw-${CURRENT}" >/dev/null 2>&1 \
        && ok "TUN pgw-${CURRENT}" "exists" || bad "TUN pgw-${CURRENT}" "missing"
else
    note "出口链路" "local 直出，跳过 TUN"
fi

# ----- policy routing -----
[[ "$JSON" -eq 0 && "$QUIET" -eq 0 ]] && echo "----- 策略路由 -----"
fw_count="$(ip rule show 2>/dev/null | grep -c 'fwmark 0x1 lookup 100' || true)"
[[ "$fw_count" -ge 1 ]] && ok "fwmark 规则" "${fw_count} 条" || bad "fwmark 规则" "missing"
nft list table inet pgw_exit >/dev/null 2>&1 && ok "pgw_exit 表" "present" || bad "pgw_exit 表" "missing"

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
        systemctl is-active --quiet 5gpn-wloc 2>/dev/null \
            && ok "WLOC" "active+running" || bad "WLOC" "active but service down"
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
    python3 - "$PASS" "$FAIL" "$WARN" "$CURRENT" "$CLIENT_CIDR" "${RESULTS[@]}" <<'PY'
import json, sys
pass_n, fail_n, warn_n, current, cidr = sys.argv[1:6]
items = []
for raw in sys.argv[6:]:
    level, label, detail = raw.split("|", 2)
    items.append({"level": level, "check": label, "detail": detail})
print(json.dumps({
    "ok": int(fail_n) == 0,
    "pass": int(pass_n),
    "fail": int(fail_n),
    "warn": int(warn_n),
    "current_exit": current,
    "client_cidr": cidr,
    "checks": items,
}, ensure_ascii=False))
PY
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
