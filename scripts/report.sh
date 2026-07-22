#!/usr/bin/env bash
# 5GPN-X redacted diagnostic report.
# Usage: sudo bash scripts/report.sh [--full] [--out /path/file.txt]
set -euo pipefail

BASE_DIR="${BASE_DIR:-/opt/5gpn}"
CONF_DIR="${CONF_DIR:-${BASE_DIR}/etc}"
FULL=0
OUT=""

for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
        --out=*) OUT="${arg#--out=}" ;;
        --out) shift_next=1 ;;
        *)
            if [[ "${shift_next:-0}" -eq 1 ]]; then OUT="$arg"; shift_next=0; fi
            ;;
    esac
done

need_root() { [[ ${EUID:-0} -eq 0 ]] || { echo "run as root" >&2; exit 1; }; }
need_root

ts="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-/tmp/5gpn-report-${ts}.txt}"
umask 077
tmp="$(mktemp)"

redact() {
    # Strip tokens, passwords, secrets, long hex/base64-ish blobs.
    sed -E \
        -e 's/(API_TOKEN|TG_BOT_TOKEN|SOCKS_PASS|token|password|passwd|secret|uuid)=[^[:space:]]+/\1=***REDACTED***/Ig' \
        -e 's#(ss|vmess|vless|trojan|hysteria2|hy2|tuic|anytls|socks5h?|https?)://[^[:space:]]+#\1://***REDACTED***#Ig' \
        -e 's/[A-Za-z0-9_-]{32,}/***REDACTED***/g'
}

{
    echo "===== 5GPN-X diagnostic report ${ts} ====="
    echo "host=$(hostname -f 2>/dev/null || hostname)"
    echo "uname=$(uname -a)"
    echo ""
    echo "----- deployed -----"
    if [[ -d "${BASE_DIR}/.git" ]]; then
        git -C "${BASE_DIR}" log -1 --oneline 2>/dev/null || true
        git -C "${BASE_DIR}" status -sb 2>/dev/null || true
    fi
    [[ -f "${CONF_DIR}/.deployed-rev" ]] && cat "${CONF_DIR}/.deployed-rev"
    echo "current_exit=$(cat "${CONF_DIR}/current-exit" 2>/dev/null || echo local)"
    echo "domain=$(cat "${CONF_DIR}/.domain" 2>/dev/null || cat /etc/mosdns/.domain 2>/dev/null || echo '?')"
    echo "public_ip=$(cat /etc/mosdns/.public_ip 2>/dev/null || echo '?')"
    echo "client_cidr=$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo '172.22.0.0/16')"
    echo ""
    echo "----- doctor -----"
    bash "${BASE_DIR}/scripts/doctor.sh" --deep 2>&1 || true
    echo ""
    echo "----- services -----"
    systemctl is-active mosdns sniproxy wa-shim quic-proxy 5gpn-tgbot 5gpn-api 2>&1 || true
    echo ""
    echo "----- listeners -----"
    ss -tlnp 2>/dev/null | grep -E ':(53|853|80|443|8111|8444|9090)\s' || true
    ss -ulnp 2>/dev/null | grep -E ':(53|443)\s' || true
    echo ""
    echo "----- ip rule / route 100 -----"
    ip rule show 2>/dev/null | head -20 || true
    ip route show table 100 2>/dev/null || true
    echo ""
    echo "----- recent journals -----"
    for u in mosdns sniproxy wa-shim quic-proxy 5gpn-tgbot 5gpn-api; do
        echo "## $u"
        journalctl -u "$u" -n 20 --no-pager -o short-iso 2>/dev/null || true
        echo ""
    done
    if [[ "$FULL" -eq 1 ]]; then
        echo "----- mosdns config (redacted paths only head) -----"
        head -n 80 /etc/mosdns/config.yaml 2>/dev/null || true
        echo "----- rules.conf -----"
        head -n 80 /etc/5gpn/rules.conf 2>/dev/null || true
        echo "----- direct-domains -----"
        cat /etc/mosdns/direct-domains.txt 2>/dev/null || true
    fi
    echo "===== end report ====="
} > "$tmp"

if [[ "$FULL" -eq 1 ]]; then
    cp "$tmp" "$OUT"
else
    redact < "$tmp" > "$OUT"
fi
rm -f "$tmp"
chmod 600 "$OUT"
echo "report written: $OUT"
echo "$OUT"
