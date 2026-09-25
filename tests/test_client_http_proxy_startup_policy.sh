#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

BASE_DIR="${tmp}/runtime"
CONF_DIR="${BASE_DIR}/etc"
SRC_DIR="${BASE_DIR}/src"
LIB_DIR="${root}/lib"
CLIENT_HTTP_PROXY_BIN="${BASE_DIR}/bin/client-http-proxy"
CLIENT_HTTP_PROXY_ENV="${CONF_DIR}/client-http-proxy.env"
CLIENT_HTTP_PROXY_ENABLED="${CONF_DIR}/client-http-proxy.enabled"
CLIENT_HTTP_PROXY_PORT_FILE="${CONF_DIR}/client-http-proxy.port"
CLIENT_HTTP_PROXY_PORT_DEFAULT=38444
CLIENT_HTTP_PROXY_USER_DEFAULT=5gpn
EXIT_USER="$(id -un)"
SYSTEMD_UNIT_DIR="${tmp}/systemd"

ensure_proxy_user() { :; }
systemctl() { [[ "$1" == daemon-reload ]]; }
info() { :; }
source "${root}/lib/setup-control.sh"

(umask 077; install_client_http_proxy_binary)
[[ "$(stat -c %a "${CLIENT_HTTP_PROXY_BIN}")" == 755 ]] || {
    echo "client-http-proxy binary must be mode 755 after restrictive umask" >&2
    exit 1
}
grep -q '^Type=notify$' "${SYSTEMD_UNIT_DIR}/5gpn-client-http-proxy.service" || {
    echo "client-http-proxy unit must wait for application readiness" >&2
    exit 1
}

install_client_http_proxy_binary() { :; }
client_http_proxy_ensure_creds() {
    mkdir -p "$CONF_DIR"
    cat > "$CLIENT_HTTP_PROXY_ENV" <<EOF
HTTP_PROXY_PORT=38444
HTTP_PROXY_USER=5gpn
HTTP_PROXY_PASS=example-pass
HTTP_PROXY_ALLOW_CIDR=172.22.0.0/16,172.31.11.94/32
EOF
}
check_root() { :; }
client_socks_host_ip() { echo 192.0.2.1; }
ok() { :; }
warn() { :; }
err() { :; }

run_failure_case() {
    local stage="$1" case_dir="${tmp}/${stage}"
    mkdir -p "$case_dir"
    CLIENT_HTTP_PROXY_ENABLED="${case_dir}/client-http-proxy.enabled"
    CLIENT_HTTP_PROXY_ENV="${case_dir}/client-http-proxy.env"
    CLIENT_HTTP_PROXY_PORT_FILE="${case_dir}/client-http-proxy.port"
    CALL_LOG="${case_dir}/calls"

    firewall_http_proxy_sync() {
        if [[ -f "$CLIENT_HTTP_PROXY_ENABLED" ]]; then
            echo "firewall:marker-present" >> "$CALL_LOG"
        else
            echo "firewall:marker-absent" >> "$CALL_LOG"
        fi
    }
    systemctl() {
        echo "systemctl:$*" >> "$CALL_LOG"
        case "$1 $2" in
            "enable --now") [[ "$stage" != start ]] ;;
            "restart 5gpn-client-http-proxy.service") [[ "$stage" != restart ]] ;;
            "is-active --quiet") [[ "$stage" != readiness ]] ;;
            "disable --now"|"stop 5gpn-client-http-proxy.service") return 0 ;;
            *) return 0 ;;
        esac
    }

    set +e
    enable_client_http_proxy >/dev/null 2>&1
    local rc=$?
    set -e
    [[ $rc -ne 0 ]] || { echo "${stage} failure unexpectedly succeeded" >&2; exit 1; }
    [[ ! -e "$CLIENT_HTTP_PROXY_ENABLED" ]] || {
        echo "${stage} failure left enabled marker behind" >&2
        exit 1
    }
    grep -q '^systemctl:disable --now 5gpn-client-http-proxy.service$' "$CALL_LOG" || {
        echo "${stage} failure did not disable/stop service" >&2
        exit 1
    }
    [[ "$(grep -c '^firewall:' "$CALL_LOG")" -eq 2 ]] \
        && grep -q '^firewall:marker-present$' "$CALL_LOG" \
        && grep -q '^firewall:marker-absent$' "$CALL_LOG" || {
        echo "${stage} failure did not re-sync firewall after marker removal" >&2
        exit 1
    }
}

run_failure_case start
run_failure_case restart
run_failure_case readiness

echo "test_client_http_proxy_startup_policy: OK"
