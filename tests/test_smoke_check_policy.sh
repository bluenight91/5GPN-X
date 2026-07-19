#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke="${root}/scripts/smoke-check.sh"
fail() { echo "$1" >&2; exit 1; }

[[ -f "${smoke}" ]] || fail "scripts/smoke-check.sh must exist"
bash -n "${smoke}" || fail "smoke-check.sh must pass bash -n"
body="$(cat "${smoke}")"

# The checks that would have caught real incidents.
[[ "${body}" == *'--interface pgw-smart'* ]] || fail "smoke must test TUN egress with curl --interface pgw-smart"
[[ "${body}" == *'https://www.google.com'* ]] || fail "smoke must probe an external site through the TUN"
[[ "${body}" == *'5gpn-mihomo@smart'* ]] || fail "smoke must check the smart instance service"
[[ "${body}" == *'127.0.0.1:9090'* ]] || fail "smoke must verify the Clash API is loopback-only"
[[ "${body}" == *'fwmark 0x1 lookup 100'* ]] || fail "smoke must verify fwmark rules exist and count them"
[[ "${body}" == *'/api/health'* ]] || fail "smoke must hit the API health endpoint"
[[ "${body}" == *'"ok": true'* ]] || fail "smoke health check must tolerate json spacing (\"ok\": true)"
[[ "${body}" == *'status:'* ]] || fail "smoke must treat any DNS status as proof of life"
[[ "${body}" == *'openssl s_client'* ]] || fail "smoke must check DoT via TLS handshake"
[[ "${body}" == *'application/dns-message'* ]] || fail "smoke must probe DoH upstreams wire-format when configured"
[[ "${body}" == *'人工步骤'* ]] || fail "smoke must end with manual verification steps"

echo "test_smoke_check_policy: OK"
