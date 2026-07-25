#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "$1" >&2; exit 1; }

install="$(cat "${root}/install.sh")"
host="$(cat "${root}/lib/host-setup.sh")"
api="$(cat "${root}/lib/api-server.py")"
ui="$(cat "${root}/webui/index.html")"
bot="$(cat "${root}/lib/tgbot.py")"
doctor="$(cat "${root}/scripts/doctor.sh")"
mtproto_go="$(cat "${root}/lib/client-mtproto.go")"

[[ -f "${root}/lib/client-mtproto.go" ]] || fail "lib/client-mtproto.go must exist"
( cd /tmp && cp "${root}/lib/client-mtproto.go" . && go build -ldflags='-s -w' -o /tmp/client-mtproto-test client-mtproto.go ) \
    || fail "client-mtproto.go must compile"
rm -f /tmp/client-mtproto-test /tmp/client-mtproto.go

[[ "${install}" == *'CLIENT_MTPROTO_PORT_DEFAULT=5753'* ]] || fail "default MTProto port must be 5753"
[[ "${install}" == *'MTG_VERSION_DEFAULT="2.2.8"'* ]] || fail "mtg must be pinned to 2.2.8"
[[ "${install}" == *'enable_client_mtproto()'* ]] || fail "install must define enable_client_mtproto"
[[ "${install}" == *'--enable-client-mtproto)'* ]] || fail "CLI must expose --enable-client-mtproto"
[[ "${install}" == *'--disable-client-mtproto)'* ]] || fail "CLI must expose --disable-client-mtproto"
[[ "${install}" == *'--set-client-mtproto-secret)'* ]] || fail "CLI must expose --set-client-mtproto-secret"
[[ "${install}" == *'--generate-client-mtproto-secret)'* ]] || fail "CLI must expose --generate-client-mtproto-secret"
[[ "${install}" == *'5gpn-client-mtproto.service'* ]] || fail "systemd unit for client-mtproto required"
[[ "${install}" == *'5gpn-mtg.service'* ]] || fail "systemd unit for mtg required"
[[ "${install}" == *'User=${EXIT_USER}'* ]] || fail "mtproto front must run as EXIT_USER"
[[ "${install}" == *'firewall_mtproto_sync ||'* && "${install}" == *'MTProto firewall sync failed'* ]] \
    || fail "enable-client-mtproto must abort when firewall sync fails"
[[ "${install}" == *'MTPROTO_ALLOW_CIDR='* ]] || fail "set-client-cidr must sync MTPROTO_ALLOW_CIDR"

[[ "${host}" == *'__MTPROTO_RULE__'* ]] || fail "managed nft must reserve MTProto rule slot"
[[ "${host}" == *'firewall_mtproto_sync'* ]] || fail "host-setup must sync mtproto firewall"
[[ "${host}" == *'5gpn-mtproto'* ]] || fail "mtproto firewall rules must be tagged"
[[ "${mtproto_go}" == *'0.0.0.0:5753'* ]] || fail "client-mtproto default listen must be 5753"
[[ "${mtproto_go}" == *'127.0.0.1:15753'* ]] || fail "client-mtproto default backend must be loopback 15753"

[[ "${api}" == *'/api/client-mtproto'* ]] || fail "api must expose /api/client-mtproto"
[[ "${api}" == *'set-secret'* && "${api}" == *'generate-secret'* ]] \
    || fail "api must support set-secret and generate-secret"
[[ "${ui}" == *'私网 MTProto'* ]] || fail "webui must show MTProto card"
[[ "${ui}" == *'mtprotoAction'* ]] || fail "webui must call mtproto actions"
[[ "${ui}" == *'5753'* ]] || fail "webui must mention port 5753"
[[ "${bot}" == *'menu:mtproto'* ]] || fail "tgbot must expose MTProto menu"
[[ "${bot}" == *'mtproto:enable'* ]] || fail "tgbot must support enable"
[[ "${bot}" == *'mtproto_set_secret'* ]] || fail "tgbot must support manual secret input"
[[ "${doctor}" == *'client-mtproto'* ]] || fail "doctor must check client-mtproto when enabled"

echo "test_client_mtproto_policy: OK"
