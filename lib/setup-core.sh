#!/usr/bin/env bash
# setup-core.sh — Core services: DNS/sniproxy/mosdns/cert install, OS detection, service startup.
# Sourced by install.sh; do not execute directly. Relies on install.sh globals
# and runs under install.sh's set -euo pipefail (ShellCheck scopes below).
# shellcheck disable=SC2154,SC2034,SC2164,SC2317

render_sniproxy_dns_nameservers() {
    local input="${1:-}"
    local dns_list=()
    local item count=0 used_loopback=0
    if [[ -z "$input" ]]; then
        dns_list=("${DEFAULT_REMOTE_DNS[@]}")
    else
        input="${input//,/ }"
        read -r -a dns_list <<< "$input"
    fi
    for item in "${dns_list[@]}"; do
        [[ -z "$item" ]] && continue
        if [[ "$item" == *://* ]]; then
            # DoH/DoT upstream: sniproxy only speaks plain DNS. Point it at the
            # local mosdns on loopback — it resolves via the full configured
            # chain (including these DoH upstreams) with caching, so sniproxy
            # gets the same answers with zero extra latency and no warnings.
            [[ "$used_loopback" == "1" ]] && continue
            used_loopback=1
            printf '    nameserver 127.0.0.1\n'
            count=$((count+1))
            continue
        elif [[ "$item" == \[*\]:* ]]; then
            item="${item#\[}"
            item="${item%%\]:*}"
        elif [[ "$item" =~ ^([0-9]+\.){3}[0-9]+:[0-9]+$ ]]; then
            item="${item%:*}"
        fi
        if [[ ! "$item" =~ ^[0-9A-Fa-f:.]+$ ]]; then
            continue
        fi
        printf '    nameserver %s\n' "$item"
        count=$((count+1))
    done
    if [[ "$count" -eq 0 ]]; then
        printf '    nameserver 127.0.0.1\n'
    fi
}
first_plain_dns() {
    local rendered
    rendered=$(render_sniproxy_dns_nameservers "${1:-}")
    awk 'NR == 1 { print $2 }' <<< "$rendered"
}
normalize_dns_list() {
    local input="${1:-}"
    local dns_list=() out=() item
    input="${input//,/ }"
    read -r -a dns_list <<< "$input"
    for item in "${dns_list[@]}"; do
        [[ -z "$item" ]] && continue
        if [[ ! "$item" =~ ^[0-9A-Fa-f:.]+$ ]]; then
            err "Invalid DNS address: $item"
            exit 1
        fi
        python3 - "$item" <<'PYEOF' || { err "Invalid DNS address: $item"; exit 1; }
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PYEOF
        out+=("$item")
    done
    [[ ${#out[@]} -gt 0 ]] || { err "DNS list cannot be empty"; exit 1; }
    printf '%s' "${out[*]}"
}
normalize_dns_upstreams() {
    local input="${1:-}"
    local dns_list=() out=() item host port
    input="${input//,/ }"
    read -r -a dns_list <<< "$input"
    for item in "${dns_list[@]}"; do
        [[ -z "$item" ]] && continue
        if [[ "$item" == *://* ]]; then
            python3 - "$item" <<'PYEOF' || { err "Invalid DNS upstream URL: $item"; exit 1; }
import ipaddress
import re
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
parsed = urlsplit(value)
if parsed.scheme not in {"https", "tls", "udp", "tcp"}:
    raise SystemExit(1)
if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
    raise SystemExit(1)
if parsed.query and parsed.scheme != "https":
    raise SystemExit(1)
try:
    ipaddress.ip_address(parsed.hostname)
except ValueError:
    # DoH/DoT endpoints may use a domain (bootstrap resolver handles it);
    # plain udp/tcp upstreams must stay IP literals.
    if parsed.scheme not in {"https", "tls"} or \
            not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*", parsed.hostname):
        raise SystemExit(1)
if parsed.port is not None and not 1 <= parsed.port <= 65535:
    raise SystemExit(1)
# DoH is just an HTTP endpoint: any path is fine (camouflaged DoH servers
# commonly hide behind custom paths like /api/<id> instead of /dns-query).
if parsed.scheme == "https" and parsed.path and not parsed.path.startswith("/"):
    raise SystemExit(1)
if parsed.scheme != "https" and parsed.path not in {"", "/"}:
    raise SystemExit(1)
PYEOF
            out+=("$item")
            continue
        fi
        if [[ "$item" == *:* ]]; then
            if python3 - "$item" <<'PYEOF' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
PYEOF
            then
                host="$item"
                port="53"
            else
                host="${item%:*}"
                port="${item##*:}"
            fi
        else
            host="$item"
            port="53"
        fi
        [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || { err "Invalid DNS upstream port: $item"; exit 1; }
        python3 - "$host" <<'PYEOF' || { err "Invalid DNS upstream IP: $item"; exit 1; }
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PYEOF
        if [[ "$port" == "53" ]]; then
            out+=("$host")
        else
            out+=("$host:$port")
        fi
    done
    [[ ${#out[@]} -gt 0 ]] || { err "DNS upstream list cannot be empty"; exit 1; }
    printf '%s' "${out[*]}"
}
rewrite_sniproxy_dns() {
    local sniproxy_dns="${1:-}" nameservers
    [[ -f /etc/sniproxy.conf ]] || return 0
    nameservers=$(render_sniproxy_dns_nameservers "$sniproxy_dns")
    python3 - /etc/sniproxy.conf "$nameservers" <<'PYEOF'
import sys

path, nameservers = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    lines = f.read().splitlines()

start = None
end = None
for idx, line in enumerate(lines):
    if line.strip() == "resolver {":
        start = idx
        break
if start is not None:
    for idx in range(start + 1, len(lines)):
        if lines[idx].strip() == "}":
            end = idx
            break
if start is None or end is None:
    raise SystemExit("resolver block not found in /etc/sniproxy.conf")

replacement = ["resolver {"] + nameservers.splitlines() + ["    mode ipv4_only", "}"]
new_lines = lines[:start] + replacement + lines[end + 1:]
with open(path, "w", encoding="utf-8") as f:
    f.write("\n".join(new_lines) + "\n")
PYEOF
}
restore_or_remove_file() {
    local old_value="${1-}" target="${2-}"
    [[ -n "$target" ]] || return 0
    if [[ -n "$old_value" ]]; then
        if ! printf '%s\n' "$old_value" > "$target"; then
            err "restore_or_remove_file: failed to restore $target"
            return 1
        fi
    else
        rm -f "$target"
    fi
}
resolve_domain_a_records() {
    local domain="${1:-}" resolver="" line=""
    local records=()
    local public_resolvers=(1.1.1.1 8.8.8.8 9.9.9.9 223.5.5.5 114.114.114.114)
    if command -v dig >/dev/null 2>&1; then
        for resolver in "${public_resolvers[@]}"; do
            while IFS= read -r line; do
                [[ "$line" =~ ^[0-9]+(\.[0-9]+){3}$ ]] && records+=("$line")
            done < <(dig +time=2 +tries=1 +short A "$domain" @"$resolver" 2>/dev/null || true)
        done
    fi
    if command -v getent >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[0-9]+(\.[0-9]+){3}$ ]] && records+=("$line")
        done < <(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' || true)
    fi
    if [[ ${#records[@]} -gt 0 ]]; then
        printf '%s\n' "${records[@]}" | awk '!seen[$0]++'
    fi
}
domain_resolves_to_public_ip() {
    local domain="${1:-}" expected_ip="${2:-}" ip=""
    [[ -n "$domain" && -n "$expected_ip" ]] || return 1
    while IFS= read -r ip; do
        [[ "$ip" == "$expected_ip" ]] && return 0
    done < <(resolve_domain_a_records "$domain")
    return 1
}
certbot_diagnostics() {
    local domain="${1:-}" resolved=""
    resolved=$(resolve_domain_a_records "$domain" | paste -sd',' - || true)
    echo "诊断: domain=${domain:-未知}"
    echo "诊断: public_ip=${PUBLIC_IP:-未知}"
    echo "诊断: resolved=${resolved:-无}"
    echo "诊断: certbot=$(command -v certbot 2>/dev/null || echo missing)"
    if command -v ss >/dev/null 2>&1; then
        echo "诊断: tcp80_listen=$(ss -H -ltnp 'sport = :80' 2>/dev/null | head -n 3 | sed 's/[[:space:]]\+/ /g' | paste -sd ';' - || true)"
    fi
}
configure_dns_upstreams() {
    local remote_selected="${REMOTE_DNS:-${DNS_UPSTREAMS:-${OVERSEAS_DNS:-${PRIVATE_OVERSEAS_DNS:-${SNIPROXY_DNS:-}}}}}"
    local local_selected="${LOCAL_DNS:-}"
    local mosdns_dir="${MOSDNS_DIR:-/etc/mosdns}"
    if [[ -z "$remote_selected" ]]; then
        remote_selected=$(cat "${mosdns_dir}/.remote_dns" 2>/dev/null || cat /etc/dnsdist/.remote_dns 2>/dev/null || true)
    fi
    if [[ -z "$local_selected" ]]; then
        local_selected=$(cat "${mosdns_dir}/.local_dns" 2>/dev/null || cat /etc/dnsdist/.local_dns 2>/dev/null || true)
    fi
    if [[ -z "$remote_selected" && -t 0 ]]; then
        echo ""
        read -r -p "国际 DNS remote [1.1.1.1,8.8.8.8,9.9.9.9]: " remote_selected
    fi
    if [[ -z "$local_selected" && -t 0 ]]; then
        read -r -p "国内 DNS local [101.226.4.6,218.30.118.6,180.76.76.76,119.29.29.29]: " local_selected
    fi
    [[ -n "$remote_selected" ]] || remote_selected="${DEFAULT_REMOTE_DNS[*]}"
    [[ -n "$local_selected" ]] || local_selected="${DEFAULT_LOCAL_DNS[*]}"
    REMOTE_DNS=$(normalize_dns_upstreams "$remote_selected")
    LOCAL_DNS=$(normalize_dns_upstreams "$local_selected")
    mkdir -p "$CONF_DIR"
    echo "$REMOTE_DNS" > "${CONF_DIR}/.remote_dns"
    echo "$LOCAL_DNS" > "${CONF_DIR}/.local_dns"
    echo "$REMOTE_DNS" > "${CONF_DIR}/.overseas_dns"
    echo "$REMOTE_DNS" > "${CONF_DIR}/.overseas_private_dns"
    echo "$REMOTE_DNS" > "${CONF_DIR}/.overseas_public_dns"
    echo "$REMOTE_DNS" > "${CONF_DIR}/.sniproxy_dns"
    info "DNS 设置: remote=$REMOTE_DNS local=$LOCAL_DNS"
}
configure_overseas_dns() { configure_dns_upstreams; }
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (use sudo)"
        exit 1
    fi
}
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        err "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    case "$OS" in
        ubuntu|debian)
            PKG_MGR="apt-get"
            ;;
        centos|rhel|rocky|almalinux|fedora)
            if command -v dnf >/dev/null 2>&1; then
                PKG_MGR="dnf"
            else
                PKG_MGR="yum"
            fi
            ;;
        *)
            err "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    info "Detected OS: $OS $VER (package manager: $PKG_MGR)"
}
detect_memory_profile() {
    MEM_TOTAL_MB=$(awk '/MemTotal/ { printf "%d", $2 / 1024 }' /proc/meminfo 2>/dev/null || echo 0)
    if [[ -n "${LOWMEM:-}" ]]; then
        case "${LOWMEM}" in
            1|yes|true|on)  LOWMEM=1 ;;
            *)              LOWMEM=0 ;;
        esac
    elif [[ "${MEM_TOTAL_MB:-0}" -le 1300 ]]; then
        LOWMEM=1
    else
        LOWMEM=0
    fi
    if [[ "$LOWMEM" == "1" ]]; then
        MAKE_JOBS=1
        PACKET_CACHE_SIZE=20000
        warn "Low-memory mode ENABLED (RAM: ${MEM_TOTAL_MB}MB). Reducing caches, sysctl, build jobs; iOS server is on-demand; swap will be checked."
    else
        MAKE_JOBS="$(nproc 2>/dev/null || echo 2)"
        PACKET_CACHE_SIZE=100000
        info "Standard memory mode (RAM: ${MEM_TOTAL_MB}MB)."
    fi
}
swap_size_to_bytes() {
    python3 -c 'import re, sys; raw = sys.argv[1].strip().upper(); raw = raw if raw.endswith("G") else (raw + "G" if raw else raw); m = re.fullmatch(r"([0-9]+(?:\\.[0-9]+)?)G", raw); print(0 if not m else int(float(m.group(1)) * 1024 * 1024 * 1024))' "$1"
}
confirm_swap_creation() {
    local input="${SWAP_ENABLE:-}"
    if [[ -z "$input" && -t 0 ]]; then
        read -r -p "检测到低内存且当前没有 swap，是否创建 swap？输入 y 开启，其它输入跳过 [y/N]: " input || true
    fi
    input="${input^^}"
    case "$input" in
        Y|YES) return 0 ;;
        *)     return 1 ;;
    esac
}
prompt_swap_size() {
    local input="${SWAP_SIZE:-}"
    if [[ -z "$input" && -t 0 ]]; then
        read -r -p "请输入 swap 大小（如 0.5/1/2 或 0.5G/1G/2G；回车默认 1）: " input || true
    fi
    input="${input:-1}"
    input="${input^^}"
    case "$input" in
        0|N|NO|SKIP)
            printf 'SKIP'
            return 0
            ;;
    esac
    if [[ "$input" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        input="${input}G"
    fi
    if [[ ! "$input" =~ ^[0-9]+(\.[0-9]+)?G$ ]]; then
        warn "无效的 swap 大小：${input}，已回退到 1G。"
        input="1G"
    fi
    printf '%s' "$input"
}
ensure_swap() {
    [[ "${LOWMEM:-0}" == "1" ]] || return 0
    if [[ "$(wc -l < /proc/swaps 2>/dev/null || echo 1)" -gt 1 ]]; then
        info "Swap already present, skipping swapfile creation."
        return 0
    fi
    [[ -e /swapfile ]] && return 0
    local swap_size swap_bytes swap_mib required_mb avail_mb
    if ! confirm_swap_creation; then
        info "Skipping swap creation by user request."
        return 0
    fi
    swap_size="$(prompt_swap_size)"
    if [[ "$swap_size" == "SKIP" ]]; then
        info "Skipping swap creation by user request."
        return 0
    fi
    swap_bytes="$(swap_size_to_bytes "$swap_size")"
    if [[ "$swap_bytes" -le 0 ]]; then
        warn "无法解析 swap 大小，已回退到 1G。"
        swap_size="1G"
        swap_bytes="$(swap_size_to_bytes "$swap_size")"
    fi
    swap_mib=$(( (swap_bytes + 1024 * 1024 - 1) / 1024 / 1024 ))
    required_mb=$(( (swap_mib * 3 + 1) / 2 ))
    avail_mb=$(df -Pm / | awk 'NR==2 {print $4}')
    if [[ -z "$avail_mb" || "$avail_mb" -lt "$required_mb" ]]; then
        warn "Not enough free disk for a ${swap_size} swapfile (${avail_mb:-?}MB free, need ~${required_mb}MB); skipping."
        return 0
    fi
    info "Creating ${swap_size} swapfile to avoid OOM on this low-memory host..."
    if ! fallocate -l "$swap_bytes" /swapfile 2>/dev/null; then
        dd if=/dev/zero of=/swapfile bs=1M count="$swap_mib" status=none 2>/dev/null || {
            warn "Failed to allocate swapfile; continuing without swap."; rm -f /swapfile; return 0; }
    fi
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1 || { warn "mkswap failed; skipping swap."; rm -f /swapfile; return 0; }
    swapon /swapfile 2>/dev/null || { warn "swapon failed; skipping swap."; rm -f /swapfile; return 0; }
    if ! grep -q '^/swapfile ' /etc/fstab 2>/dev/null; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    ok "${swap_size} swapfile active."
}
get_public_ip() {
    PUBLIC_IP=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || \
                curl -4 -s --max-time 10 https://ifconfig.me 2>/dev/null || \
                curl -4 -s --max-time 10 https://icanhazip.com 2>/dev/null || echo "")
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' || echo "")
    fi
    if [[ -z "$PUBLIC_IP" ]]; then
        err "Failed to detect public IPv4 address. Please set PUBLIC_IP manually."
        exit 1
    fi
    info "Public IP detected: $PUBLIC_IP"
}
port53_pids() {
    ss -H -lnptu 2>/dev/null | awk '$5 ~ /(^|\[|:)53$/ {print}' | grep -oP 'pid=\K[0-9]+' | sort -u || true
}
port53_owner_summary() {
    local pids pid proc unit summaries=()
    pids=$(port53_pids)
    for pid in $pids; do
        proc=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        unit=$(systemd_unit_for_pid "$pid")
        if [[ -n "$unit" ]]; then
            summaries+=("$proc (PID: $pid, unit: $unit)")
        else
            summaries+=("$proc (PID: $pid)")
        fi
    done
    (IFS=', '; echo "${summaries[*]}")
}
check_port_53() {
    info "Checking port 53 availability..."
    local pid pids proc remaining
    pids=$(port53_pids)
    if [[ -n "$pids" ]]; then
        pid=$(printf '%s\n' "$pids" | head -n1)
        proc=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        warn "Port 53 is already in use by: $(port53_owner_summary)"
        local confirm=""
        if [[ "$proc" == "dnsdist" || "$proc" == "mosdns" ]]; then
            info "Stopping the existing $proc service for DNS migration/update..."
        else
            read -r -p "Stop and disable '$proc' to free port 53? [Y/n]: " confirm
        fi
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            err "Port 53 must be free for mosdns to start. Aborting."
            exit 1
        fi
        for pid in $pids; do
            proc=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            stop_port53_owner "$pid" "$proc"
        done
        wait_for_port53_free 10
        remaining=$(port53_pids)
        if [[ -n "$remaining" ]]; then
            warn "Port 53 is still in use by: $(port53_owner_summary)"
            warn "Trying SIGTERM/SIGKILL on remaining port 53 owners..."
            for pid in $remaining; do
                kill "$pid" 2>/dev/null || true
            done
            wait_for_port53_free 5
        fi
        remaining=$(port53_pids)
        if [[ -n "$remaining" ]]; then
            for pid in $remaining; do
                kill -9 "$pid" 2>/dev/null || true
            done
            wait_for_port53_free 3
        fi
        remaining=$(port53_pids)
        if [[ -n "$remaining" ]]; then
            err "Failed to free port 53. Still in use by: $(port53_owner_summary)"
            err "Check with: ss -lnptu 'sport = :53' ; systemctl status <unit> ; journalctl -u <unit> -n 50"
            exit 1
        fi
        ok "Port 53 is now free"
    else
        ok "Port 53 is available"
    fi
}
wait_for_port53_free() {
    local timeout="${1:-10}" i
    for ((i=0; i<timeout; i++)); do
        [[ -z "$(port53_pids)" ]] && return 0
        sleep 1
    done
    [[ -z "$(port53_pids)" ]]
}
systemd_unit_for_pid() {
    local pid="${1:-}"
    [[ -z "$pid" || ! -r "/proc/$pid/cgroup" ]] && return 0
    grep -aoE '[^/]+\.service' "/proc/$pid/cgroup" | head -n1 || true
}
stop_port53_owner() {
    local pid="${1:-}"
    local proc="${2:-unknown}"
    local unit
    unit=$(systemd_unit_for_pid "$pid")
    if [[ -n "$unit" ]]; then
        stop_systemd_unit_and_socket "$unit"
    fi
    case "$proc" in
        systemd-resolve|systemd-resolved)
            info "Stopping systemd-resolved service to release DNS stub port 53"
            if [[ -L /etc/resolv.conf || -f /etc/resolv.conf ]]; then
                if ! grep -q '1.1.1.1' /etc/resolv.conf 2>/dev/null; then
                    cp -a /etc/resolv.conf /etc/resolv.conf.pgw.bak 2>/dev/null || true
                    cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF
                    info "Rewrote /etc/resolv.conf to public DNS servers for installer stability"
                fi
            fi
            stop_systemd_unit_and_socket systemd-resolved.service
            ;;
        mosdns)
            stop_systemd_unit_and_socket mosdns.service
            ;;
        dnsdist)
            stop_systemd_unit_and_socket dnsdist.service
            ;;
        dnsmasq)
            stop_systemd_unit_and_socket dnsmasq.service
            ;;
        named)
            stop_systemd_unit_and_socket named.service
            stop_systemd_unit_and_socket bind9.service
            ;;
    esac
}
stop_systemd_unit_and_socket() {
    local unit="${1:-}"
    [[ -z "$unit" ]] && return 0
    local socket="${unit%.service}.socket"
    info "Stopping systemd unit owning port 53: $unit"
    systemctl stop "$socket" 2>/dev/null || true
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" "$socket" 2>/dev/null || true
}
install_deps() {
    info "Installing system dependencies..."
    local pcre_dev_pkg="libpcre3-dev"
    if [[ "${OS:-}" == "debian" && "${VER%%.*}" -ge 13 ]]; then
        pcre_dev_pkg="libpcre2-dev"
    fi
    case "$PKG_MGR" in
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            if ! apt-get update -qq; then
                warn "apt update failed; trying a direct public DNS path for Debian mirrors..."
                if [[ -f /etc/apt/sources.list.d/debian.sources ]]; then
                    sed -i 's/^URIs: .*/URIs: http:\/\/deb.debian.org\/debian/' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true
                fi
                if [[ -f /etc/apt/sources.list ]]; then
                    sed -i 's|^[[:space:]]*deb[[:space:]]\+mirror+file:/etc/apt/mirrors/.*|deb http://deb.debian.org/debian trixie main|g' /etc/apt/sources.list 2>/dev/null || true
                fi
                apt-get update -qq
            fi
            apt-get install -y -qq \
                build-essential git wget curl ca-certificates \
                libev-dev "${pcre_dev_pkg}" libudns-dev libssl-dev \
                autoconf automake libtool pkg-config \
                certbot python3-certbot-dns-cloudflare \
                python3 python3-pip jq libcap2-bin \
                nftables qrencode wireguard-tools || true
            ;;
        dnf|yum)
            $PKG_MGR install -y -q \
                gcc gcc-c++ make git wget curl ca-certificates \
                libev-devel pcre-devel openssl-devel \
                autoconf automake libtool pkgconfig \
                certbot python3-certbot-dns-cloudflare \
                python3 python3-pip jq libcap-ng-utils \
                nftables qrencode wireguard-tools || true
            ;;
    esac
    if ! command -v go >/dev/null 2>&1; then
        info "Installing Go compiler..."
        GO_VER="1.22.4"
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64) GO_ARCH="amd64" ;;
            aarch64|arm64) GO_ARCH="arm64" ;;
            *) GO_ARCH="amd64" ;;
        esac
        wget -q "https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        # shellcheck disable=SC2016 # Write a literal profile snippet for future shells.
        printf '%s\n' 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
    fi
    ok "Go version: $(go version)"
    if command -v certbot >/dev/null 2>&1; then
        if ! certbot --version >/dev/null 2>&1; then
            warn "Certbot has compatibility issues with the current Python version. Attempting to fix..."
            pip3 install --upgrade --break-system-packages certbot josepy cryptography 2>/dev/null || \
                pip3 install --upgrade certbot josepy cryptography 2>/dev/null || true
        fi
    fi
    if ! command -v certbot >/dev/null 2>&1; then
        err "Required package 'certbot' was not installed successfully."
        err "Please check your package manager output above."
        exit 1
    fi
}
ensure_mosdns_user() {
    if ! id mosdns >/dev/null 2>&1; then
        useradd --system --home-dir /etc/mosdns --shell /usr/sbin/nologin mosdns
    fi
}
install_mosdns_binary() {
    local version="${MOSDNS_VERSION:-$MOSDNS_VERSION_DEFAULT}" arch asset url tmpdir
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) err "Unsupported mosdns architecture: $(uname -m)"; exit 1 ;;
    esac
    if command -v mosdns >/dev/null 2>&1 && mosdns version 2>/dev/null | grep -q "v${version}"; then
        info "mosdns v${version} already installed"
        return 0
    fi
    info "Installing mosdns v${version}..."
    asset="mosdns-linux-${arch}.zip"
    url="https://github.com/IrineSistiana/mosdns/releases/download/v${version}/${asset}"
    tmpdir=$(mktemp -d /tmp/mosdns.XXXXXX)
    curl -fL --retry 3 --connect-timeout 15 "$url" -o "${tmpdir}/${asset}"
    python3 - "${tmpdir}/${asset}" "$tmpdir" <<'PYEOF'
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    member = next((name for name in archive.namelist() if name.rstrip("/").endswith("mosdns")), None)
    if member is None:
        raise SystemExit("mosdns binary missing from release archive")
    with archive.open(member) as source, open(sys.argv[2] + "/mosdns", "wb") as target:
        target.write(source.read())
PYEOF
    install -m 0755 "${tmpdir}/mosdns" /usr/local/bin/mosdns
    rm -rf "$tmpdir"
    mosdns version >/dev/null
    ok "mosdns v${version} installed"
}
is_valid_domain() {
    local d="${1:-}"
    [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)+$ ]]
}
generate_domain() {
    if [[ -n "${DOMAIN:-}" ]]; then
        DOMAIN="${DOMAIN,,}"  # normalize to lowercase (certbot always lowercases)
        if ! is_valid_domain "$DOMAIN"; then
            err "Invalid DOMAIN: '$DOMAIN'. Provide a fully-qualified domain like dns.example.com"
            exit 1
        fi
        info "Using pre-configured domain: $DOMAIN"
        mkdir -p "$CONF_DIR"
        echo "$DOMAIN" > "${CONF_DIR}/.domain"
        return
    fi
    if [[ ! -t 0 ]]; then
        err "No domain provided. Set the DOMAIN environment variable (e.g. DOMAIN=dns.example.com) for non-interactive installs."
        exit 1
    fi
    echo ""
    echo "=================================================="
    echo "  请输入你自己的域名"
    echo "=================================================="
    echo "  示例: dns.example.com 或 example.com"
    echo "  该域名需要你能管理其 DNS（添加一条 A 记录指向本机）"
    echo "=================================================="
    echo ""
    local input=""
    while true; do
        read -r -p "请输入域名: " input
        input="${input## }"; input="${input%% }"
        input="${input#http://}"; input="${input#https://}"
        input="${input%/}"
        if is_valid_domain "$input"; then
            DOMAIN="$input"
            DOMAIN="${DOMAIN,,}"  # normalize to lowercase
            break
        fi
        warn "无效域名，请输入形如 dns.example.com 的完整域名"
    done
    info "Using domain: $DOMAIN"
    mkdir -p "$CONF_DIR"
    echo "$DOMAIN" > "${CONF_DIR}/.domain"
}
verify_domain_dns() {
    info "DNS 解析检查"
    info "=================================================="
    info "域名: $DOMAIN"
    info "需要的 A 记录值: $PUBLIC_IP"
    info "=================================================="
    info ""
    info "请在你自己的 DNS 服务商处添加（或确认已存在）一条 A 记录:"
    info "   Host:  ${DOMAIN%%.*}  (若是裸域则填 @ 或留空)"
    info "   Type:  A"
    info "   Value: $PUBLIC_IP"
    info "   TTL:   尽量低 (如 60-300)，便于快速生效"
    info ""
    if [[ -t 0 ]]; then
        local confirm=""
        read -r -p "完成配置后按 Enter 继续（或输入 'skip' 跳过解析验证）: " confirm
        if [[ "$confirm" == "skip" ]]; then
            warn "跳过域名解析验证，请确保 A 记录已正确配置"
            mkdir -p "$CONF_DIR"
            echo "$DOMAIN" > "${CONF_DIR}/.domain"
            return
        fi
    fi
    info "等待 DNS 解析生效（最多 120 秒）..."
    local waited=0 resolved=""
    while [[ $waited -lt 120 ]]; do
        resolved=$(resolve_domain_a_records "$DOMAIN" | paste -sd',' - || true)
        if domain_resolves_to_public_ip "$DOMAIN" "$PUBLIC_IP"; then
            ok "DNS 解析验证通过: $DOMAIN -> $PUBLIC_IP"
            mkdir -p "$CONF_DIR"
            echo "$DOMAIN" > "${CONF_DIR}/.domain"
            return
        fi
        sleep 5
        waited=$((waited + 5))
        echo -n "."
    done
    echo ""
    warn "DNS 解析未在 120 秒内生效（当前解析: ${resolved:-无}）。"
    warn "将继续安装；如后续 Let's Encrypt 证书申请失败，请确认 $DOMAIN 的 A 记录已指向 $PUBLIC_IP。"
    mkdir -p "$CONF_DIR"
    echo "$DOMAIN" > "${CONF_DIR}/.domain"
}
install_cert() {
    local certbot_cmd certbot_cmd_force
    ensure_mosdns_user
    CERTBOT_LAST_OUTPUT=""
    install_certbot_firewall_hooks
    certbot_cmd=(certbot certonly --standalone -d "$DOMAIN" \
        --agree-tos -n -m "${EMAIL:-admin@${DOMAIN}}" \
        --pre-hook /usr/local/bin/5gpn-open-cert-http.sh \
        --post-hook /usr/local/bin/5gpn-restore-firewall.sh)
    certbot_cmd_force=(certbot certonly --standalone -d "$DOMAIN" --force-renewal \
        --agree-tos -n -m "${EMAIL:-admin@${DOMAIN}}" \
        --pre-hook /usr/local/bin/5gpn-open-cert-http.sh \
        --post-hook /usr/local/bin/5gpn-restore-firewall.sh)
    local cb_cmd=()
    if [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
        info "Let's Encrypt certificate already exists for $DOMAIN, forcing renewal..."
        cb_cmd=("${certbot_cmd_force[@]}")
    else
        info "申请 Let's Encrypt 证书 for $DOMAIN..."
        cb_cmd=("${certbot_cmd[@]}")
    fi
    run_certbot() {
        prepare_certbot_standalone
        trap cleanup_certbot_standalone RETURN
        local out retry_out rc
        if out="$("${cb_cmd[@]}" 2>&1)"; then rc=0; else rc=$?; fi
        CERTBOT_LAST_OUTPUT="$out"
        printf '%s\n' "$out"
        if [[ $rc -eq 0 ]]; then
            return 0
        fi
        if grep -q "AttributeError" <<<"$out"; then
            warn "Certbot compatibility error detected. Attempting to fix Python dependencies..."
            pip3 install --upgrade --break-system-packages certbot josepy cryptography 2>/dev/null || \
                pip3 install --upgrade certbot josepy cryptography 2>/dev/null || true
            info "Retrying certificate request..."
            if retry_out="$("${cb_cmd[@]}" 2>&1)"; then rc=0; else rc=$?; fi
            CERTBOT_LAST_OUTPUT="$retry_out"
            printf '%s\n' "$retry_out"
            return $rc
        fi
        return 1
    }
    if ! run_certbot; then
        err "证书申请失败。请检查:"
        err "  1. 域名 $DOMAIN 是否正确解析到本机 ($PUBLIC_IP)"
        err "  2. 端口 80 是否被占用"
        err "  3. 防火墙是否放行 80"
        err "  4. 是否触发了 Let's Encrypt 速率限制 (同一域名 7 天内限 5 次)"
        if [[ -n "${CERTBOT_LAST_OUTPUT:-}" ]]; then
            err "certbot 最后输出:"
            printf '%s\n' "$CERTBOT_LAST_OUTPUT" | tail -n 30 >&2
        fi
        exit 1
    fi
    info "Copying certificates to /etc/mosdns/certs/ ..."
    local cert_live_dir="/etc/letsencrypt/live/${DOMAIN}"
    if [[ -d "$cert_live_dir" ]]; then
        mkdir -p /etc/mosdns/certs
        cp "${cert_live_dir}/fullchain.pem" /etc/mosdns/certs/fullchain.pem
        cp "${cert_live_dir}/privkey.pem" /etc/mosdns/certs/privkey.pem
        chown -R mosdns:mosdns /etc/mosdns/certs/
        chmod 600 /etc/mosdns/certs/*.pem
        ok "Certificates copied to /etc/mosdns/certs/"
    else
        warn "Could not find certificate live directory: $cert_live_dir"
    fi
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    if [[ -f "${LIB_DIR}/renew-hook.sh" ]]; then
        cp "${LIB_DIR}/renew-hook.sh" /etc/letsencrypt/renewal-hooks/deploy/99-reload-mosdns.sh
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/99-reload-mosdns.sh
        ok "证书已就绪，自动续期 Hook 已部署"
    else
        warn "renew-hook.sh not found in ${LIB_DIR}; keeping existing renewal hook"
        ok "证书已就绪"
    fi
}
install_sniproxy() {
    ensure_proxy_user
    if ! command -v sniproxy >/dev/null 2>&1; then
        info "Compiling sniproxy (TCP SNI proxy)..."
        mkdir -p "$SRC_DIR"
        cd "$SRC_DIR"
        if [[ ! -d sniproxy ]]; then
            git clone --depth=1 https://github.com/dlundquist/sniproxy.git
        fi
        cd sniproxy
        DEBEMAIL="root@localhost" DEBFULLNAME="root" ./autogen.sh >/dev/null
        ./configure --prefix=/usr/local --sysconfdir=/etc --enable-dns >/dev/null
        make -j"${MAKE_JOBS:-$(nproc)}" >/dev/null
        make install >/dev/null
    else
        info "sniproxy already installed"
    fi
    if [[ -f "${LIB_DIR}/sniproxy.conf" ]]; then
        local sniproxy_nameservers
        sniproxy_nameservers=$(render_sniproxy_dns_nameservers "$REMOTE_DNS")
        python3 - "${LIB_DIR}/sniproxy.conf" "$sniproxy_nameservers" /etc/sniproxy.conf <<'PYEOF'
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace("__SNIPROXY_NAMESERVERS__", sys.argv[2])
with open(sys.argv[3], "w", encoding="utf-8") as f:
    f.write(content)
PYEOF
    else
        err "sniproxy.conf not found in ${LIB_DIR}"
        exit 1
    fi
    cat > /etc/systemd/system/sniproxy.service <<'EOF'
[Unit]
Description=sniproxy (TCP SNI transparent proxy)
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/sbin/sniproxy -c /etc/sniproxy.conf -f
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root
LimitNOFILE=65535
MemoryMax=256M
# Starts as root to bind 80/443 then setuid(pxout) per /etc/sniproxy.conf;
# NoNewPrivileges is intentionally NOT set (privilege drop happens post-exec).
ProtectSystem=strict
ReadWritePaths=/var/run
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sniproxy
    ok "sniproxy installed"
}
install_whatsapp_shim() {
    local shim_dns self_ips
    info "Installing iOS WhatsApp no-SNI shim..."
    [[ -f "${LIB_DIR}/wa-shim.py" ]] || { err "wa-shim.py not found in ${LIB_DIR}"; return 1; }
    mkdir -p "${BASE_DIR}/bin" "${CONF_DIR}"
    install -m 0755 "${LIB_DIR}/wa-shim.py" "${BASE_DIR}/bin/wa-shim.py"
    mkdir -p /etc/mosdns
    touch /etc/mosdns/gfwlist-extra-local.txt
    for domain in whatsapp.net whatsapp.com; do
        grep -qxF "$domain" /etc/mosdns/gfwlist-extra-local.txt || echo "$domain" >> /etc/mosdns/gfwlist-extra-local.txt
    done
    shim_dns="${REMOTE_DNS:-$(cat "${CONF_DIR}/.remote_dns" 2>/dev/null || printf '%s ' "${DEFAULT_REMOTE_DNS[@]}")}"
    self_ips="${PUBLIC_IP:-},127.0.0.1,::1,"
    self_ips+="$(hostname -I 2>/dev/null | tr ' ' ',' | tr -d '\n')"
    cat > "${CONF_DIR}/wa-shim.env" <<EOF
WA_SHIM_LISTEN=0.0.0.0
WA_SHIM_PORT=443
WA_SHIM_BACKEND=127.0.0.1:8443
WA_SHIM_WA_HOST=g.whatsapp.net
WA_SHIM_RESOLVER=$(first_plain_dns "$shim_dns"),8.8.8.8
WA_SHIM_SELF_IPS=${self_ips}
WA_SHIM_ALLOW_CIDR=172.22.0.0/16,127.0.0.0/8
EOF
    chmod 600 "${CONF_DIR}/wa-shim.env"
    cat > /etc/systemd/system/wa-shim.service <<EOF
[Unit]
Description=5GPN-X iOS WhatsApp no-SNI shim
After=network-online.target sniproxy.service
Wants=network-online.target
Requires=sniproxy.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
EnvironmentFile=${CONF_DIR}/wa-shim.env
ExecStart=/usr/bin/python3 ${BASE_DIR}/bin/wa-shim.py
Restart=on-failure
RestartSec=5
User=${EXIT_USER}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65535
MemoryMax=128M

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable wa-shim.service 2>/dev/null || true
    ok "WhatsApp no-SNI shim installed (public :443 -> sniproxy 127.0.0.1:8443)"
}
install_quic_proxy() {
    ensure_proxy_user
    if [[ ! -x "${BASE_DIR}/bin/quic-proxy" ]]; then
        info "Compiling quic-proxy (UDP/QUIC SNI proxy)..."
        mkdir -p "${BASE_DIR}/bin"
        mkdir -p "${SRC_DIR}"
        cp "${LIB_DIR}/quic-proxy.go" "${SRC_DIR}/quic-proxy.go"
        cd "${SRC_DIR}"
        export PATH=$PATH:/usr/local/go/bin
        go build -ldflags="-s -w" -o "${BASE_DIR}/bin/quic-proxy" quic-proxy.go
    else
        info "quic-proxy already compiled"
    fi
    cat > /etc/systemd/system/quic-proxy.service <<'EOF'
[Unit]
Description=quic-proxy (UDP/QUIC SNI transparent proxy)
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/opt/5gpn/bin/quic-proxy -l 0.0.0.0:443
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=pxout
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
MemoryMax=256M
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable quic-proxy
    ok "quic-proxy installed"
}
install_mosdns() {
    info "Configuring mosdns..."
    ensure_mosdns_user
    install_mosdns_binary
    mkdir -p /etc/mosdns
    cp "${LIB_DIR}/mosdns.yaml.template" /etc/mosdns/config.yaml.template
    cp "${LIB_DIR}/update-rules.sh" /usr/local/bin/update-mosdns-rules.sh
    chmod +x /usr/local/bin/update-mosdns-rules.sh
    echo "$DOMAIN" > /etc/mosdns/.domain
    echo "$PUBLIC_IP" > /etc/mosdns/.public_ip
    echo "$REMOTE_DNS" > /etc/mosdns/.remote_dns
    echo "$LOCAL_DNS" > /etc/mosdns/.local_dns
    echo "$REMOTE_DNS" > /etc/mosdns/.overseas_dns
    echo "$REMOTE_DNS" > /etc/mosdns/.overseas_private_dns
    echo "$REMOTE_DNS" > /etc/mosdns/.overseas_public_dns
    echo "$REMOTE_DNS" > /etc/mosdns/.sniproxy_dns
    echo "${PGW_ECS:-139.226.48.0/24}" > /etc/mosdns/.ecs
    echo "${PACKET_CACHE_SIZE:-100000}" > /etc/mosdns/.cache_size
    echo "${CLIENT_CIDR:-172.22.0.0/16}" > /etc/mosdns/.client_cidr
    touch /etc/mosdns/gfwlist.txt /etc/mosdns/chinalist.txt /etc/mosdns/gfwlist-extra-local.txt /etc/mosdns/direct-domains.txt
    chown -R mosdns:mosdns /etc/mosdns
    chmod 0750 /etc/mosdns /etc/mosdns/certs
    local mosdns_memory_max="512M"
    [[ "${LOWMEM:-0}" == "1" ]] && mosdns_memory_max="256M"
    cat > /etc/systemd/system/mosdns.service <<EOF
[Unit]
Description=mosdns smart DNS and DNS-over-TLS
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/mosdns start -c /etc/mosdns/config.yaml
Restart=always
RestartSec=3
User=mosdns
Group=mosdns
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/mosdns
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65535
MemoryMax=${mosdns_memory_max}

[Install]
WantedBy=multi-user.target
EOF
    systemctl disable --now dnsdist.service update-dnsdist-rules.timer china-dns-race-proxy.service 2>/dev/null || true
    rm -rf /etc/systemd/system/dnsdist.service.d /etc/systemd/system/china-dns-race-proxy.service.d
    rm -f /etc/systemd/system/update-dnsdist-rules.{service,timer} \
        /etc/systemd/system/china-dns-race-proxy.service \
        /usr/local/bin/update-dnsdist-rules.sh \
        /etc/letsencrypt/renewal-hooks/deploy/99-reload-dnsdist.sh \
        "${BASE_DIR}/bin/china-dns-race-proxy"
    systemctl daemon-reload
    systemctl enable mosdns
    ok "mosdns configured"
}
init_rules() {
    info "Initializing GFWList and ChinaList..."
    /usr/local/bin/update-mosdns-rules.sh || warn "Rule update failed, will retry later"
}
generate_ios_profile() {
    info "Generating iOS DoT configuration profile..."
    mkdir -p "$WWW_DIR"
    local profile_path="${WWW_DIR}/ios-dot.mobileconfig"
    local profile_url="http://${DOMAIN}:${IOS_PROFILE_PORT}/ios-dot.mobileconfig"
    cat > "$profile_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>TLS</string>
                <key>ServerName</key>
                <string>${DOMAIN}</string>
                <key>ServerAddresses</key>
                <array>
                    <string>${PUBLIC_IP}</string>
                </array>
            </dict>
            <key>OnDemandRules</key>
            <array>
                <dict>
                    <key>Action</key>
                    <string>Connect</string>
                    <key>InterfaceTypeMatch</key>
                    <string>Cellular</string>
                </dict>
                <dict>
                    <key>Action</key>
                    <string>Disconnect</string>
                    <key>InterfaceTypeMatch</key>
                    <string>WiFi</string>
                </dict>
                <dict>
                    <key>Action</key>
                    <string>Disconnect</string>
                </dict>
            </array>
            <key>PayloadDescription</key>
            <string>Use ${DOMAIN} DNS over TLS only on cellular networks.</string>
            <key>PayloadDisplayName</key>
            <string>Proxy Gateway Cellular DoT</string>
            <key>PayloadIdentifier</key>
            <string>com.5gpn.${DOMAIN}.dnssettings</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Installs a DNS over TLS profile for cellular networks only.</string>
    <key>PayloadDisplayName</key>
    <string>Proxy Gateway Cellular DoT</string>
    <key>PayloadIdentifier</key>
    <string>com.5gpn.${DOMAIN}</string>
    <key>PayloadOrganization</key>
    <string>Proxy Gateway</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF
    cat > "${WWW_DIR}/index.html" <<EOF
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Proxy Gateway iOS DoT</title>
</head>
<body>
  <h1>Proxy Gateway iOS DoT</h1>
  <p><a href="/ios-dot.mobileconfig">下载 iOS 蜂窝网络 DoT 描述文件</a></p>
</body>
</html>
EOF
    local py; py="$(command -v python3 || echo /usr/bin/python3)"
    mkdir -p "${BASE_DIR}/bin"
    if [[ -f "${LIB_DIR}/ios-http.py" ]]; then
        install -m 0755 "${LIB_DIR}/ios-http.py" "${BASE_DIR}/bin/ios-http.py"
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^5gpn-ios-profile\.service'; then
        systemctl disable --now 5gpn-ios-profile.service 2>/dev/null || true
    fi
    rm -f /etc/systemd/system/5gpn-ios-profile.service
    cat > /etc/systemd/system/5gpn-ios-profile.socket <<EOF
[Unit]
Description=Proxy Gateway iOS profile HTTP socket

[Socket]
ListenStream=0.0.0.0:${IOS_PROFILE_PORT}
Accept=yes

[Install]
WantedBy=sockets.target
EOF
    cat > /etc/systemd/system/5gpn-ios-profile@.service <<EOF
[Unit]
Description=Proxy Gateway iOS profile responder (per-connection)

[Service]
Type=simple
ExecStart=${py} ${BASE_DIR}/bin/ios-http.py
Environment=WWW_DIR=${WWW_DIR}
StandardInput=socket
StandardOutput=socket
StandardError=journal
User=root
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
EOF
    systemctl daemon-reload
    systemctl enable --now 5gpn-ios-profile.socket
    echo "$profile_url" > "${WWW_DIR}/ios-profile-url.txt"
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ANSIUTF8 "$profile_url" | tee "${WWW_DIR}/ios-dot.qr.txt"
    else
        warn "qrencode is not installed; QR code skipped. Profile URL: $profile_url"
    fi
    ok "iOS profile ready: $profile_url"
}
prepare_certbot_standalone() {
    CERT_STOPPED_SNIPROXY=0
    CERT_STOPPED_WA_SHIM=0
    if systemctl is-active --quiet wa-shim 2>/dev/null; then
        info "Stopping wa-shim temporarily during certificate maintenance..."
        systemctl stop wa-shim
        CERT_STOPPED_WA_SHIM=1
    fi
    if systemctl is-active --quiet sniproxy 2>/dev/null; then
        info "Stopping sniproxy temporarily so certbot can bind TCP/80..."
        systemctl stop sniproxy
        CERT_STOPPED_SNIPROXY=1
    fi
    open_cert_http_port
}
cleanup_certbot_standalone() {
    local rc=$?
    restore_reverse_proxy_firewall
    if [[ "${CERT_STOPPED_SNIPROXY:-0}" == "1" ]]; then
        info "Starting sniproxy after certbot..."
        systemctl start sniproxy || warn "sniproxy failed to restart after certbot; run: systemctl status sniproxy"
    fi
    if [[ "${CERT_STOPPED_WA_SHIM:-0}" == "1" ]]; then
        systemctl start wa-shim || warn "wa-shim failed to restart after certbot"
    fi
    return $rc
}
install_certbot_firewall_hooks() {
    mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post
    cat > /usr/local/bin/5gpn-open-cert-http.sh <<'EOF'
#!/bin/bash
set -e
systemctl stop sniproxy 2>/dev/null || true
systemctl stop wa-shim 2>/dev/null || true
if command -v nft >/dev/null 2>&1 && nft list table inet filter >/dev/null 2>&1; then
    nft insert rule inet filter input tcp dport 80 accept comment '"5gpn-cert-http"' 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT 1 -p tcp --dport 80 -m comment --comment 5gpn-cert-http -j ACCEPT 2>/dev/null || true
fi
EOF
    cat > /usr/local/bin/5gpn-restore-firewall.sh <<'EOF'
#!/bin/bash
set -e
# Delete only the tagged temporary rule. Reloading /etc/nftables.conf here
# would be wrong when the firewall is user-managed (FIREWALL_MODE=preserve).
if command -v nft >/dev/null 2>&1 && nft list table inet filter >/dev/null 2>&1; then
    while h="$(nft --handle list chain inet filter input 2>/dev/null | awk '/5gpn-cert-http/ { print $NF; exit }')" && [ -n "$h" ]; do
        nft delete rule inet filter input handle "$h" 2>/dev/null || break
    done
fi
if command -v iptables >/dev/null 2>&1; then
    while iptables -D INPUT -p tcp --dport 80 -m comment --comment 5gpn-cert-http -j ACCEPT 2>/dev/null; do :; done
fi
systemctl start sniproxy 2>/dev/null || true
systemctl start wa-shim 2>/dev/null || true
EOF
    chmod +x /usr/local/bin/5gpn-open-cert-http.sh /usr/local/bin/5gpn-restore-firewall.sh
    cp /usr/local/bin/5gpn-open-cert-http.sh /etc/letsencrypt/renewal-hooks/pre/10-5gpn-open-http.sh
    cp /usr/local/bin/5gpn-restore-firewall.sh /etc/letsencrypt/renewal-hooks/post/90-5gpn-restore-firewall.sh
    chmod +x /etc/letsencrypt/renewal-hooks/pre/10-5gpn-open-http.sh \
        /etc/letsencrypt/renewal-hooks/post/90-5gpn-restore-firewall.sh
}
apply_lowmem_go_limits() {
    local d mihomo_limit
    for svc in quic-proxy mosdns; do
        d="/etc/systemd/system/${svc}.service.d"
        if [[ "${LOWMEM:-0}" == "1" ]]; then
            mkdir -p "$d"
            cat > "$d/lowmem.conf" <<'EOF'
[Service]
Environment=GOGC=50 GOMEMLIMIT=64MiB
EOF
        else
            rm -f "$d/lowmem.conf" 2>/dev/null || true
        fi
    done
    mihomo_limit="$(resolve_mihomo_gomemlimit)"
    d="/etc/systemd/system/5gpn-mihomo@.service.d"
    mkdir -p "$d"
    cat > "$d/gomemlimit.conf" <<EOF
[Service]
Environment=GOGC=50 GOMEMLIMIT=${mihomo_limit}
EOF
    systemctl daemon-reload
}
clamp_mosdns_cache_size() {
    local target current
    target=100000
    [[ "${LOWMEM:-0}" == "1" ]] && target=20000
    mkdir -p /etc/mosdns
    current="$(cat /etc/mosdns/.cache_size 2>/dev/null || true)"
    if [[ ! "$current" =~ ^[0-9]+$ || -z "$current" ]]; then
        echo "$target" > /etc/mosdns/.cache_size
    elif [[ "$current" -gt "$target" ]]; then
        echo "$target" > /etc/mosdns/.cache_size
    fi
}
start_services() {
    info "Starting services..."
    systemctl restart mosdns || { err "mosdns failed to start"; journalctl -u mosdns --no-pager -n 20; exit 1; }
    systemctl restart sniproxy || { err "sniproxy failed to start"; journalctl -u sniproxy --no-pager -n 20; exit 1; }
    systemctl restart wa-shim || { err "wa-shim failed to start"; journalctl -u wa-shim --no-pager -n 20; exit 1; }
    systemctl restart quic-proxy || { err "quic-proxy failed to start"; journalctl -u quic-proxy --no-pager -n 20; exit 1; }
    ok "All services started"
}
