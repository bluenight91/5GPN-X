#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
api="${root}/lib/api-server.py"
webui="${root}/webui/index.html"
install_body="$(cat "${install}")"

fail() { echo "$1" >&2; exit 1; }

# --- API server exists and is valid Python -----------------------------------
[[ -f "${api}" ]] || fail "lib/api-server.py must exist"
python3 -m py_compile "${api}" || fail "api-server.py must compile"
api_body="$(cat "${api}")"

# --- web panel is bundled ------------------------------------------------------
[[ -f "${webui}" ]] || fail "webui/index.html must exist"

# --- never run a shell on user input ------------------------------------------
[[ "${api_body}" != *'shell=True'* ]] || fail "api-server.py must never use shell=True"
[[ "${api_body}" != *'os.system'* ]] || fail "api-server.py must never use os.system"

# --- bearer auth must gate every operation except /api/health -----------------
[[ "${api_body}" == *'hmac.compare_digest'* ]] || fail "API must compare tokens with hmac.compare_digest"
[[ "${api_body}" == *'refusing to start'* ]] || fail "API must refuse to start with a short/missing token"

# --- paths must match the 5GPN-X layout ----------------------------------------
[[ "${api_body}" == *'/opt/5gpn/bin/5gpn-ctl'* ]] || fail "API must default MGMT to /opt/5gpn/bin/5gpn-ctl"
[[ "${api_body}" == *'"/etc/5gpn"'* ]] || fail "API must use /etc/5gpn as the state dir"
[[ "${api_body}" == *'/etc/mosdns/certs/fullchain.pem'* ]] || fail "API must use the mosdns TLS certs"
[[ "${api_body}" == *'/etc/mosdns/gfwlist.txt'* ]] || fail "API route tester must read the mosdns gfwlist"
[[ "${api_body}" != *'proxy-gateway'* ]] || fail "API must not reference the old proxy-gateway layout"
[[ "${api_body}" != *'dnsdist'* ]] || fail "API must not reference dnsdist"

# --- default port must avoid the sniproxy loopback listener on 8443 ------------
[[ "${api_body}" == *'"8444"'* ]] || fail "API default port must be 8444 (8443 is sniproxy on 5GPN-X)"
[[ "${api_body}" != *'"8443"'* ]] || fail "API must not default to port 8443"

# --- services it reports on must be the 5GPN-X units ---------------------------
[[ "${api_body}" == *'"mosdns", "sniproxy", "wa-shim", "quic-proxy"'* ]] || fail "API SERVICES must list 5GPN-X units"
[[ "${api_body}" == *'"5gpn-tgbot", "5gpn-api"'* ]] || fail "API SERVICES must list the bot and the API itself"

# --- exit names follow install.sh's validator (Chinese names allowed) ----------
[[ "${api_body}" == *'{1,16}'* ]] || fail "API exit-name rule must allow 1-16 chars like install.sh"

# --- installer wires the API up -------------------------------------------------
[[ "${install_body}" == *'setup_api() {'* ]] || fail "install.sh must define setup_api()"
[[ "${install_body}" == *'maybe_setup_api() {'* ]] || fail "install.sh must define maybe_setup_api()"
[[ "${install_body}" == *'--setup-api)'* ]] || fail "install.sh must dispatch --setup-api"
[[ "${install_body}" == *'5gpn-api.service'* ]] || fail "install.sh must install a 5gpn-api.service unit"
[[ "${install_body}" == *'systemctl restart 5gpn-api.service'* ]] || fail "setup_api must restart the api service so upgrades take effect"
[[ "${install_body}" == *'s/^API_TOKEN=//p'* ]] || fail "setup_api must reuse an existing API token on re-run"
[[ "${install_body}" == *'s/^API_BIND=//p'* ]] || fail "setup_api must reuse an existing API_BIND on re-run"
[[ "${install_body}" == *'bind="${bind:-127.0.0.1}"'* ]] || fail "setup_api must default API_BIND to loopback"
[[ "${install_body}" == *'API_ALLOW_ORIGIN=${allow_origin}'* ]] || fail "setup_api must not default CORS to wildcard"
[[ "${install_body}" == *'API_BIND=0.0.0.0'* ]] || fail "setup_api warning/help must document explicit public bind"
[[ "${api_body}" == *'"UP", "DOWN", "n/a", "udp"'* ]] || fail "api parse_check must accept the udp state"

# --- security hardening (borrowed from moooyo/5gpn review) ---------------------
[[ "${api_body}" == *'def _sec_headers'* && "${api_body}" == *'Strict-Transport-Security'* && "${api_body}" == *'X-Frame-Options'* ]] || fail "api must send security headers (HSTS/XFO/nosniff)"
[[ "${api_body}" == *'Content-Security-Policy'* && "${api_body}" == *"frame-ancestors 'self'"* ]] || fail "static hosting must send CSP"
[[ "${api_body}" == *'def rate_ok('* && "${api_body}" == *'429'* ]] || fail "api must rate-limit per source ip"
[[ "${install_body}" == *'API_PORT_DEFAULT=8444'* ]] || fail "install.sh must default API_PORT_DEFAULT=8444"
[[ "${install_body}" == *'${BASE_DIR}/bin/5gpn-ctl'* ]] || fail "api.env must point MGMT at 5gpn-ctl"
[[ "${install_body}" == *'/etc/mosdns/certs/fullchain.pem'* ]] || fail "setup_api must use the mosdns certs"

# --- --edit-exit (used by the panel's edit endpoint) -----------------------------
[[ "${install_body}" == *'edit_exit() {'* ]] || fail "install.sh must define edit_exit()"
[[ "${install_body}" == *'--edit-exit)'* ]] || fail "install.sh must dispatch --edit-exit"
[[ "${install_body}" == *'PGW_EXIT_OVERWRITE=1 add_exit'* ]] || fail "edit_exit must re-add with overwrite enabled"
[[ "${install_body}" == *'PGW_EXIT_OVERWRITE:-0'* ]] || fail "add_exit must honor the overwrite flag"
[[ "${api_body}" == *'"--edit-exit"'* ]] || fail "api-server must call --edit-exit for edits"

echo "test_api_setup_policy: OK"
