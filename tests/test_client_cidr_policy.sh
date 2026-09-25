#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ops="$(cat "${root}/lib/setup-ops.sh")"
host="$(cat "${root}/lib/host-setup.sh")"
rules="$(cat "${root}/lib/update-rules.sh")"
api="$(cat "${root}/lib/api-server.py")"
bot="$(cat "${root}/lib/tgbot.py")"
ui="$(cat "${root}/webui/index.html")"
docs="$(cat "${root}/docs/TROUBLESHOOTING.md")"
architecture="$(cat "${root}/docs/architecture.md")"

fail() { echo "$1" >&2; exit 1; }

for source in "$ops" "$host" "$rules" "$api"; do
    [[ "$source" == *'8 <= net.prefixlen <= 32'* ]] \
        || fail "all client CIDR validators must accept IPv4 /32"
done

[[ "$ops" == *'IPv4 /16../32'* ]] || fail "CLI validation message must document /32"
[[ "$ops" == *'HTTP_PROXY_ALLOW_CIDR=${cidr}'* \
    && "$ops" == *'systemctl restart 5gpn-client-http-proxy.service'* ]] \
    || fail "client CIDR updates must propagate to the HTTP proxy"
[[ "$api" == *'IPv4 /16../32 by default'* ]] || fail "API error must document /32"
[[ "$bot" == *'前缀 /8–/32'* ]] || fail "Telegram prompt must document /32"
[[ "$ui" == *'单个 IP 用 <span class="mono">/32</span>'* ]] \
    || fail "WebUI must explain single-IP /32 syntax"
[[ "$docs" == *'172.31.11.94/32'* ]] || fail "troubleshooting docs must include a /32 example"
[[ "$architecture" == *'单主机用 `/32`'* ]] || fail "architecture must define single-host CIDR behavior"

echo "client CIDR /32 policy OK"
