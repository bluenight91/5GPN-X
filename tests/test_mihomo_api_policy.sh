#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gen="$(cat "${root}/lib/mihomo-router-config.py")"
exitgen="$(cat "${root}/lib/mihomo-exit-config.py")"
install_body="$(cat "${root}/install.sh" "${root}/lib"/setup-*.sh)"
api_body="$(cat "${root}/lib/api-server.py")"
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

# --- installer vendors metacubexd (pinned version, download at install) ------
[[ "${install_body}" == *'METACUBEXD_VERSION_DEFAULT="1.270.5"'* ]] || fail "install.sh must pin METACUBEXD_VERSION_DEFAULT"
[[ "${install_body}" == *'install_metacubexd() {'* ]] || fail "install.sh must define install_metacubexd()"
[[ "${install_body}" == *'MetaCubeX/metacubexd/releases/download/v${ver}/compressed-dist.tgz'* ]] || fail "metacubexd must come from the pinned GitHub release asset"
[[ "${install_body}" == *'${BASE_DIR}/webui/mihomo'* ]] || fail "metacubexd must unpack to \${BASE_DIR}/webui/mihomo"
[[ "${install_body}" == *'.metacubexd-version'* ]] || fail "install_metacubexd must record installed version"
[[ "${install_body}" == *'metacubexd.pin'* ]] || fail "install_metacubexd must persist an explicit version pin"
[[ "${api_body}" == *'Cache-Control'* && "${api_body}" == *'sw.js'* ]] || fail "api must send no-cache for metacubexd service worker / index"
[[ "${install_body}" == *'( regen_smart )'* ]] || fail "setup_api must rebuild the smart config in a subshell"
[[ "${install_body}" == *'install -m 0755 "${LIB_DIR}/mihomo-router-config.py" "${MIHOMO_ROUTER_GEN}"'* ]] || fail "setup_api must refresh the installed router generator before regen"

# --- mihomo configs carry an explicit dns section (system resolver is unreliable here)
for g in "${gen}" "${exitgen}"; do
  [[ "$g" == *'"dns": DNS_CONFIG'* ]] || fail "mihomo configs must include the dns section"
  [[ "$g" == *'proxy-server-nameserver'* ]] || fail "dns section must set proxy-server-nameserver"
  [[ "$g" == *'MIHOMO_DNS_LOCAL'* && "$g" == *'MIHOMO_DNS_REMOTE'* ]] || fail "dns servers must come from MIHOMO_DNS_* env"
done
[[ "${install_body}" == *'mihomo_dns_env() {'* ]] || fail "install.sh must define mihomo_dns_env()"

# --- fwmark ip rules must be deduplicated, and --update rebuilds URI exits -----
[[ "${install_body}" == *'while ip rule del fwmark "${EXIT_MARK}" table "${EXIT_TABLE}"'* ]] || fail "set_exit must dedupe fwmark ip rules"
[[ "${install_body}" == *'PGW_EXIT_OVERWRITE=1 add_exit "$n" < "$f"'* ]] || fail "do_update must rebuild URI exits from stored links"

echo "test_mihomo_api_policy: OK"
