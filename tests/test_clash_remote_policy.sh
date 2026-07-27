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
renew="$(cat "${root}/lib/renew-hook.sh")"
go_src="$(cat "${root}/lib/clash-remote.go")"

[[ -f "${root}/lib/clash-remote.go" ]] || fail "lib/clash-remote.go must exist"
if command -v go >/dev/null 2>&1; then
    ( cd /tmp && cp "${root}/lib/clash-remote.go" . && go build -ldflags='-s -w' -o /tmp/clash-remote-test clash-remote.go ) \
        || fail "clash-remote.go must compile"
    rm -f /tmp/clash-remote-test /tmp/clash-remote.go
else
    echo "note: go toolchain not found; skipping compile check" >&2
fi

[[ "${install}" == *'CLASH_REMOTE_PORT_DEFAULT=9443'* ]] || fail "default clash-remote port must be 9443"
[[ "${install}" == *'enable_clash_remote()'* ]] || fail "install must define enable_clash_remote"
[[ "${install}" == *'--enable-clash-remote)'* ]] || fail "CLI must expose --enable-clash-remote"
[[ "${install}" == *'--disable-clash-remote)'* ]] || fail "CLI must expose --disable-clash-remote"
[[ "${install}" == *'--set-clash-remote-extra-cidr)'* ]] || fail "CLI must expose extra CIDR setter"
[[ "${install}" == *'5gpn-clash-remote.service'* ]] || fail "systemd unit for clash-remote required"
[[ "${install}" == *'firewall_clash_remote_sync ||'* && "${install}" == *'Clash remote firewall sync failed'* ]] \
    || fail "enable-clash-remote must abort when firewall sync fails"
[[ "${install}" == *'clash_remote_merge_allow_cidr'* ]] || fail "must merge client CIDR + extra"

[[ "${host}" == *'__CLASH_REMOTE_RULE__'* ]] || fail "managed nft must reserve clash-remote rule slot"
[[ "${host}" == *'firewall_clash_remote_sync'* ]] || fail "host-setup must sync clash-remote firewall"
[[ "${host}" == *'5gpn-clash-remote'* ]] || fail "clash-remote firewall rules must be tagged"
[[ "${host}" == *'clash_remote_allow_cidr_nft_expr'* ]] || fail "firewall must support multi-CIDR allow list"

[[ "${go_src}" == *'crypto/subtle'* && "${go_src}" == *'ConstantTimeCompare'* ]] \
    || fail "clash-remote auth must use constant-time comparison"
[[ "${go_src}" == *'tls.NewListener'* || "${go_src}" == *'tls.Config'* ]] \
    || fail "clash-remote must terminate TLS"
[[ "${go_src}" == *'Authorization'* && "${go_src}" == *'Bearer'* ]] \
    || fail "clash-remote must inject upstream Clash Bearer secret"

[[ "${api}" == *'/api/clash-remote'* ]] || fail "api must expose /api/clash-remote"
[[ "${ui}" == *'远程 Clash 面板 API'* ]] || fail "webui must show clash-remote card"
[[ "${ui}" == *'clashRemoteAction'* ]] || fail "webui must call clash-remote actions"
[[ "${bot}" == *'menu:clash_remote'* ]] || fail "tgbot must expose clash-remote menu"
[[ "${bot}" == *'clashr:enable'* ]] || fail "tgbot must support enable"
[[ "${doctor}" == *'clash-remote'* ]] || fail "doctor must check clash-remote when enabled"
[[ "${renew}" == *'5gpn-clash-remote'* ]] || fail "cert renew hook must restart clash-remote"

echo "test_clash_remote_policy: OK"
