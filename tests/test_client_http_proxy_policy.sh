#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "$1" >&2; exit 1; }

install="$(cat "${root}/install.sh" "${root}/lib"/setup-*.sh)"
host="$(cat "${root}/lib/host-setup.sh")"
api="$(cat "${root}/lib/api-server.py")"
ui="$(cat "${root}/webui/index.html")"
bot="$(cat "${root}/lib/tgbot.py")"
doctor="$(cat "${root}/scripts/doctor.sh")"
proxy_go="$(cat "${root}/lib/client-http-proxy.go")"

[[ -f "${root}/lib/client-http-proxy.go" ]] || fail "HTTP proxy implementation must exist"
[[ -f "${root}/lib/client-http-proxy_test.go" ]] || fail "HTTP proxy unit tests must exist"
if command -v go >/dev/null 2>&1; then
    (
        cd "${root}/lib"
        go test client-http-proxy.go client-http-proxy_test.go
        go build -ldflags='-s -w' -o /tmp/client-http-proxy-test client-http-proxy.go
    ) || fail "client-http-proxy must test and compile"
    rm -f /tmp/client-http-proxy-test
else
    echo "note: go toolchain not found; skipping Go tests" >&2
fi

[[ "${install}" == *'CLIENT_HTTP_PROXY_PORT_DEFAULT=38444'* ]] \
    || fail "default HTTP proxy port must be 38444"
for command in enable disable status reset; do
    case "$command" in
        enable|disable) needle="--${command}-client-http-proxy)" ;;
        status) needle="--client-http-proxy-status)" ;;
        reset) needle="--reset-client-http-proxy-creds)" ;;
    esac
    [[ "${install}" == *"${needle}"* ]] || fail "CLI must expose ${needle}"
done
[[ "${install}" == *'5gpn-client-http-proxy.service'* ]] || fail "systemd unit required"
[[ "${install}" == *'User=${EXIT_USER}'* ]] || fail "HTTP proxy must run as pxout"
[[ "${install}" == *'ProtectSystem=strict'* && "${install}" == *'NoNewPrivileges=true'* ]] \
    || fail "HTTP proxy unit must use the non-orchestrator sandbox"
[[ "${install}" == *'firewall_http_proxy_sync ||'* \
    && "${install}" == *'HTTP proxy firewall sync failed'* ]] \
    || fail "enable must abort when firewall sync fails"

[[ "${host}" == *'__HTTP_PROXY_RULE__'* ]] || fail "managed nft must reserve HTTP proxy slot"
[[ "${host}" == *'firewall_http_proxy_sync'* ]] || fail "firewall sync required"
[[ "${host}" == *'5gpn-http-proxy'* ]] || fail "firewall rules must be tagged"
[[ "${host}" == *'client_cidr_nft_expr'* && "${host}" == *'for one in $(client_cidr_list)'* ]] \
    || fail "firewall sync must support multiple CIDRs"

[[ "${proxy_go}" == *'http.MethodConnect'* ]] || fail "HTTPS CONNECT support required"
[[ "${proxy_go}" == *'Proxy-Authorization'* ]] || fail "proxy authentication required"
[[ "${proxy_go}" == *'ConstantTimeCompare'* ]] || fail "auth comparison must be constant-time"
[[ "${proxy_go}" == *'Proxy:                 nil'* ]] \
    || fail "upstream requests must not recurse through environment proxies"

[[ "${api}" == *'/api/client-http-proxy'* ]] || fail "API endpoint required"
[[ "${ui}" == *'私网 HTTP/HTTPS 代理'* && "${ui}" == *'httpProxyAction'* ]] \
    || fail "WebUI controls required"
[[ "${bot}" == *'menu:http_proxy'* && "${bot}" == *'http_proxy:enable'* ]] \
    || fail "Telegram controls required"
[[ "${doctor}" == *'client-http-proxy'* ]] || fail "doctor integration required"

echo "test_client_http_proxy_policy: OK"
