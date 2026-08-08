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
mtproto_go="$(cat "${root}/lib/client-mtproto.go")"

[[ -f "${root}/lib/client-mtproto.go" ]] || fail "lib/client-mtproto.go must exist"
if command -v go >/dev/null 2>&1; then
    ( cd /tmp && cp "${root}/lib/client-mtproto.go" . && go build -ldflags='-s -w' -o /tmp/client-mtproto-test client-mtproto.go ) \
        || fail "client-mtproto.go must compile"
    rm -f /tmp/client-mtproto-test /tmp/client-mtproto.go
else
    echo "note: go toolchain not found; skipping compile check" >&2
fi

[[ "${install}" == *'CLIENT_MTPROTO_PORT_DEFAULT=5753'* ]] || fail "default MTProto port must be 5753"
[[ "${install}" == *'MTPROTOPROXY_VERSION_DEFAULT="v1.1.2"'* ]] || fail "mtprotoproxy must be pinned"
[[ "${install}" == *'canonicalize_mtproto_secret'* ]] || fail "must canonicalize secrets to classic 32-hex"
[[ "${install}" == *'enable_client_mtproto()'* ]] || fail "install must define enable_client_mtproto"
[[ "${install}" == *'--enable-client-mtproto)'* ]] || fail "CLI must expose --enable-client-mtproto"
[[ "${install}" == *'--set-client-mtproto-secret)'* ]] || fail "CLI must expose --set-client-mtproto-secret"
[[ "${install}" == *'5gpn-client-mtproto.service'* ]] || fail "systemd unit for client-mtproto required"
[[ "${install}" == *'5gpn-mtproxy.service'* ]] || fail "systemd unit for mtprotoproxy required"
[[ "${install}" == *'MODES = {"classic": True'* ]] || fail "classic mode required for bare Telegram secrets"
[[ "${install}" == *'LISTEN_ADDR_IPV4 = "127.0.0.1"'* ]] || fail "core must bind loopback only"
[[ "${install}" == *'firewall_mtproto_sync ||'* && "${install}" == *'MTProto firewall sync failed'* ]] \
    || fail "enable-client-mtproto must abort when firewall sync fails"

# Smoke: bare key stays bare (Telegram-pasteable)
canon_tmp="$(mktemp)"
sed -n '/^canonicalize_mtproto_secret()/,/^}/p; /^validate_mtproto_secret()/,/^}/p' \
    "${root}/lib/setup-control.sh" > "${canon_tmp}"
# shellcheck disable=SC1090
got="$(bash -c '. "$1"; canonicalize_mtproto_secret 2cf16b88a9ba60ac6aff397eafc8336c' _ "${canon_tmp}")"
rm -f "${canon_tmp}"
[[ "$got" == 2cf16b88a9ba60ac6aff397eafc8336c ]] \
    || fail "canonicalize must keep bare 32-hex for Telegram (got: ${got})"

[[ "${host}" == *'__MTPROTO_RULE__'* ]] || fail "managed nft must reserve MTProto rule slot"
[[ "${host}" == *'firewall_mtproto_sync'* ]] || fail "host-setup must sync mtproto firewall"
[[ "${host}" == *'5gpn-mtproto'* ]] || fail "mtproto firewall rules must be tagged"
[[ "${mtproto_go}" == *'0.0.0.0:5753'* ]] || fail "client-mtproto default listen must be 5753"
[[ "${mtproto_go}" == *'127.0.0.1:15753'* ]] || fail "client-mtproto default backend must be loopback 15753"

[[ "${api}" == *'/api/client-mtproto'* ]] || fail "api must expose /api/client-mtproto"
[[ "${api}" == *'5gpn-mtproxy'* ]] || fail "api must check mtproxy unit"
[[ "${ui}" == *'私网 MTProto'* ]] || fail "webui must show MTProto card"
[[ "${ui}" == *'32'* && "${ui}" == *'Telegram'* ]] || fail "webui must document Telegram 32-hex secret"
[[ "${bot}" == *'menu:mtproto'* ]] || fail "tgbot must expose MTProto menu"
[[ "${bot}" == *'mtproto_set_secret'* ]] || fail "tgbot must support manual secret input"
[[ "${doctor}" == *'5gpn-mtproxy'* ]] || fail "doctor must check mtproxy when enabled"

echo "test_client_mtproto_policy: OK"
