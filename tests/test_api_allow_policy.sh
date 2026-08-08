#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "${root}/install.sh")"
api_body="$(cat "${root}/lib/api-server.py")"
tgbot_body="$(cat "${root}/lib/tgbot.py")"

fail() { echo "$1" >&2; exit 1; }

# --- api-server: allowlist enforcement ----------------------------------------
[[ "${api_body}" == *'ALLOW_FILE = os.environ.get("API_ALLOW_FILE", CONF_DIR + "/api-allow.list")'* ]] \
    || fail "api-server must read etc/api-allow.list (env-overridable)"
[[ "${api_body}" == *'def source_allowed(ip_str):'* ]] || fail "api-server must define source_allowed"
[[ "${api_body}" == *'if ip.is_loopback:
        return True'* ]] || fail "loopback must always be allowed"
count="$(grep -c 'if not source_allowed(self.client_address\[0\]):' <<<"${api_body}")"
[[ "${count}" -ge 3 ]] || fail "source check must gate do_GET, do_POST and _dispatch (found ${count})"

# --- install.sh: management CLI -------------------------------------------------
[[ "${install_body}" == *'--api-allow)'* ]] || fail "install.sh must wire --api-allow"
[[ "${install_body}" == *'api_allow_add() {'* ]] || fail "install.sh must define api_allow_add"
[[ "${install_body}" == *'api_allow_del() {'* ]] || fail "install.sh must define api_allow_del"
[[ "${install_body}" == *'ipaddress.ip_network(sys.argv[1], strict=False)'* ]] \
    || fail "CIDR validation must go through python ipaddress"
[[ "${install_body}" == *'chmod 600 "$f"'* ]] || fail "allow list file must be chmod 600"
[[ "${install_body}" == *'--api-allow [list|add <cidr>|del <cidr>]'* ]] || fail "--api-allow must be in help"

# --- no firewall-template tampering (I1): restriction lives in the app layer ---
[[ "${install_body}" != *'5gpn-api-allow'* ]] || fail "no ephemeral firewall tag: the operator's own broad ACCEPT would defeat it; app layer is the enforcement"

# --- tgbot: menu + prompt flow ---------------------------------------------------
[[ "${tgbot_body}" == *'"🛡 API 白名单", "callback_data": "menu:api_allow"'* ]] \
    || fail "tgbot ops menu must offer the API allowlist"
[[ "${tgbot_body}" == *'"action": "api_allow_add"'* ]] || fail "tgbot must prompt for add"
[[ "${tgbot_body}" == *'"action": "api_allow_del"'* ]] || fail "tgbot must prompt for del"
[[ "${tgbot_body}" == *'"--api-allow", "add"'* ]] || fail "tgbot add must call the CLI"
[[ "${tgbot_body}" == *'"--api-allow", "del"'* ]] || fail "tgbot del must call the CLI"
[[ "${tgbot_body}" == *'名单外来源访问 API/webui 会立即 403'* ]] \
    || fail "tgbot add prompt must warn about lockout"

echo "PASS: api allowlist policy"
