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
socks_go="$(cat "${root}/lib/client-socks.go")"

[[ -f "${root}/lib/client-socks.go" ]] || fail "lib/client-socks.go must exist"
if command -v go >/dev/null 2>&1; then
    ( cd /tmp && cp "${root}/lib/client-socks.go" . && go build -ldflags='-s -w' -o /tmp/client-socks-test client-socks.go ) \
        || fail "client-socks.go must compile"
    rm -f /tmp/client-socks-test /tmp/client-socks.go
else
    echo "note: go toolchain not found; skipping compile check" >&2
fi

[[ "${install}" == *'API_PORT_DEFAULT=8444'* ]] || fail "API_PORT_DEFAULT=8444 must remain defined (set -u)"
[[ "${install}" == *'CLIENT_SOCKS_PORT_DEFAULT=38443'* ]] || fail "default socks port must be uncommon 38443"
[[ "${install}" == *'enable_client_socks()'* ]] || fail "install must define enable_client_socks"
[[ "${install}" == *'--enable-client-socks)'* ]] || fail "CLI must expose --enable-client-socks"
[[ "${install}" == *'--disable-client-socks)'* ]] || fail "CLI must expose --disable-client-socks"
[[ "${install}" == *'5gpn-client-socks.service'* ]] || fail "systemd unit for client-socks required"
[[ "${install}" == *'User=${EXIT_USER}'* ]] || fail "socks must run as EXIT_USER/pxout for exit following"
[[ "${install}" == *'firewall_socks_sync ||'* && "${install}" == *'SOCKS firewall sync failed'* ]] \
    || fail "enable-client-socks must abort when firewall sync fails"

[[ "${host}" == *'__SOCKS_RULE__'* ]] || fail "managed nft must reserve SOCKS rule slot"
[[ "${host}" == *'firewall_socks_sync'* ]] || fail "host-setup must sync socks firewall"
[[ "${host}" == *'5gpn-socks'* ]] || fail "socks firewall rules must be tagged"
[[ "${host}" == *'client_cidr_nft_expr'* && "${host}" == *'for one in $(client_cidr_list)'* ]] \
    || fail "socks firewall sync must support multi-CIDR nft and iptables"
[[ "${socks_go}" == *'crypto/subtle'* && "${socks_go}" == *'ConstantTimeCompare'* ]] \
    || fail "client-socks auth must use constant-time comparison"

[[ "${api}" == *'/api/client-socks'* ]] || fail "api must expose /api/client-socks"
[[ "${ui}" == *'私网 SOCKS5'* ]] || fail "webui must show SOCKS5 card"
[[ "${ui}" == *'socksAction'* ]] || fail "webui must call socks actions"
[[ "${bot}" == *'menu:socks'* ]] || fail "tgbot must expose SOCKS menu"
[[ "${bot}" == *'socks:enable'* ]] || fail "tgbot must support enable"
[[ "${doctor}" == *'client-socks'* ]] || fail "doctor must check client-socks when enabled"

echo "test_client_socks_policy: OK"
