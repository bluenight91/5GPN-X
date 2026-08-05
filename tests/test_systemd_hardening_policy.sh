#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"

fail() { echo "$1" >&2; exit 1; }

unit_block() { # unit-name → heredoc body of its unit definition in install.sh
    awk -v u="$1" '
        $0 ~ "cat > /etc/systemd/system/" u " <<" { inb=1; next }
        inb && /^EOF$/ { exit }
        inb { print }
    ' "${install}"
}

# --- sniproxy: root→setuid(pxout); sandbox but never NoNewPrivileges ---------
b="$(unit_block sniproxy.service)"
[[ "$b" == *'ProtectSystem=strict'* ]] || fail "sniproxy must get ProtectSystem=strict"
[[ "$b" == *'ReadWritePaths=/var/run'* ]] || fail "sniproxy needs /var/run for its pidfile"
[[ "$b" == *'ProtectHome=true'* && "$b" == *'PrivateTmp=true'* ]] || fail "sniproxy needs ProtectHome/PrivateTmp"
! grep -q '^NoNewPrivileges=' <<< "$b" || fail "sniproxy starts as root and drops privileges post-exec; NoNewPrivileges would break it"

# --- quic-proxy ---------------------------------------------------------------
b="$(unit_block quic-proxy.service)"
[[ "$b" == *'ProtectSystem=strict'* ]] || fail "quic-proxy must get ProtectSystem=strict"
[[ "$b" == *'CapabilityBoundingSet=CAP_NET_BIND_SERVICE'* ]] || fail "quic-proxy must be capability-bounded"
[[ "$b" == *'ProtectHome=true'* && "$b" == *'PrivateTmp=true'* ]] || fail "quic-proxy needs ProtectHome/PrivateTmp"

# --- mosdns --------------------------------------------------------------------
b="$(unit_block mosdns.service)"
[[ "$b" == *'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'* ]] || fail "mosdns must be address-family restricted"

# --- 5gpn-mihomo@: root for TUN; capability-bounded, never NoNewPrivileges ----
b="$(unit_block '5gpn-mihomo@.service')"
[[ "$b" == *'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER'* ]] \
    || fail "mihomo@ must be capability-bounded to TUN + config needs"
[[ "$b" == *'ProtectHome=true'* && "$b" == *'PrivateTmp=true'* ]] || fail "mihomo@ needs ProtectHome/PrivateTmp"
! grep -q '^NoNewPrivileges=' <<< "$b" || fail "mihomo@ must not get NoNewPrivileges"
[[ "$b" != *'ProtectSystem'* ]] || fail "mihomo@ intentionally has no ProtectSystem (apply-exit/drop-in surface too wide)"

# --- ios-profile responder ------------------------------------------------------
b="$(unit_block '5gpn-ios-profile@.service')"
[[ "$b" == *'ProtectSystem=strict'* && "$b" == *'ProtectHome=true'* && "$b" == *'PrivateTmp=true'* ]] \
    || fail "ios-profile@ must be sandboxed"

# --- root orchestrators: full /etc-/usr lockdown with an explicit whitelist ----
rw='/etc/5gpn /etc/mosdns /etc/sniproxy.conf /etc/wireguard /etc/nftables.conf /etc/letsencrypt /etc/systemd/system /usr/local/bin'
for u in 5gpn-tgbot.service 5gpn-api.service; do
    b="$(unit_block "$u")"
    [[ "$b" == *'ProtectSystem=full'* ]] || fail "$u must get ProtectSystem=full"
    [[ "$b" == *"ReadWritePaths=${rw}"* ]] || fail "$u ReadWritePaths whitelist mismatch"
    [[ "$b" == *'ProtectHome=true'* && "$b" == *'PrivateTmp=true'* ]] || fail "$u needs ProtectHome/PrivateTmp"
done
# The two orchestrators must share the identical write-path contract.
[[ "$(unit_block 5gpn-tgbot.service | grep ReadWritePaths)" == "$(unit_block 5gpn-api.service | grep ReadWritePaths)" ]] \
    || fail "tgbot and api must carry identical ReadWritePaths"

# --- do_update must re-render every hardened unit, not just restart ----------
# (Unit heredocs carry the sandbox directives; an update that only restarts
# the service leaves old unsandboxed units in place — tgbot regression.)
upd="$(awk '/^do_update\(\)/,/^}$/' "${install}")"
[[ "$upd" == *'setup_tgbot </dev/null'* ]] || fail "do_update must re-render the tgbot unit via setup_tgbot (non-interactive)"
[[ "$upd" == *'&& setup_api'* ]] || fail "do_update must re-render the api unit via setup_api"
[[ "$upd" == *'setup_exit_switching'* ]] || fail "do_update must re-render exit-switching units"

echo "systemd hardening policy OK"
