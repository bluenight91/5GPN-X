#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gen="$(cat "${root}/lib/mihomo-router-config.py")"
install_body="$(cat "${root}/install.sh")"
fail() { echo "$1" >&2; exit 1; }

# --- router config enables the Clash API on loopback only --------------------
[[ "${gen}" == *'external-controller'* ]] || fail "router config must set external-controller"
[[ "${gen}" == *'127.0.0.1:9090'* ]] || fail "external-controller must bind 127.0.0.1:9090"
[[ "${gen}" == *'MIHOMO_API_SECRET_FILE'* ]] || fail "router generator must read the secret file path from env"
[[ "${gen}" == *'/etc/5gpn/mihomo-api-secret'* ]] || fail "default secret file must be /etc/5gpn/mihomo-api-secret"

# --- installer creates the secret --------------------------------------------
[[ "${install_body}" == *'ensure_mihomo_api_secret() {'* ]] || fail "install.sh must define ensure_mihomo_api_secret()"
[[ "${install_body}" == *'openssl rand -hex 32'* ]] || fail "secret must be openssl rand -hex 32"
[[ "${install_body}" == *'MIHOMO_API_SECRET_FILE='/etc/5gpn/mihomo-api-secret''* ]] || fail "install.sh must define MIHOMO_API_SECRET_FILE"

echo "test_mihomo_api_policy: OK"
