#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke="${root}/scripts/smoke-check.sh"
doctor="${root}/scripts/doctor.sh"
fail() { echo "$1" >&2; exit 1; }

[[ -f "${smoke}" ]] || fail "scripts/smoke-check.sh must exist"
[[ -f "${doctor}" ]] || fail "scripts/doctor.sh must exist"
bash -n "${smoke}" || fail "smoke-check.sh must pass bash -n"
bash -n "${doctor}" || fail "doctor.sh must pass bash -n"

smoke_body="$(cat "${smoke}")"
[[ "${smoke_body}" == *'doctor.sh'* && "${smoke_body}" == *'--deep'* ]] \
    || fail "smoke-check.sh must delegate to doctor.sh --deep"

body="$(cat "${doctor}")"

# The checks that would have caught real incidents (now live in doctor --deep).
[[ "${body}" == *'--interface pgw-smart'* ]] || fail "doctor must test TUN egress with curl --interface pgw-smart"
[[ "${body}" == *'https://www.google.com'* ]] || fail "doctor must probe an external site through the TUN"
[[ "${body}" == *'5gpn-mihomo@smart'* ]] || fail "doctor must check the smart instance service"
[[ "${body}" == *'127.0.0.1:9090'* ]] || fail "doctor must verify the Clash API is loopback-only"
[[ "${body}" == *'fwmark 0x1 lookup 100'* ]] || fail "doctor must verify fwmark rules exist and count them"
[[ "${body}" == *'/api/health'* ]] || fail "doctor must hit the API health endpoint"
[[ "${body}" == *'"ok": true'* ]] || fail "doctor health check must tolerate json spacing (\"ok\": true)"
[[ "${body}" == *'status:'* ]] || fail "doctor must treat any DNS status as proof of life"
[[ "${body}" == *'openssl s_client'* ]] || fail "doctor must check DoT via TLS handshake"
[[ "${body}" == *'application/dns-message'* ]] || fail "doctor --deep must probe DoH upstreams wire-format when configured"
[[ "${body}" == *'modifier.state'* ]] || fail "doctor must read WLOC modifier state"
[[ "${body}" == *'10451'* ]] || fail "doctor must check the WLOC interceptor port when active"
[[ "${body}" == *'gs-loc.apple.com'* ]] || fail "doctor must verify WLOC DNS hijack entries when active"
[[ "${body}" == *'人工步骤'* ]] || fail "doctor --deep must end with manual verification steps"
[[ "${body}" == *'运行时一致性'* ]] || fail "doctor must detect git HEAD vs .deployed-rev mismatch"
[[ "${body}" == *'健康定时器'* ]] || fail "doctor must check 5gpn-health.timer when health-notify exists"
[[ "${body}" == *'--json'* ]] || fail "doctor must support --json for health-notify"

echo "test_smoke_check_policy: OK"
