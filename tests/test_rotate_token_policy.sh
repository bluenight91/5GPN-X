#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "${root}/install.sh" "${root}/lib"/setup-*.sh)"
tgbot_body="$(cat "${root}/lib/tgbot.py")"

fail() { echo "$1" >&2; exit 1; }

# --- install.sh: rotate_api_token + CLI wiring --------------------------------
[[ "${install_body}" == *'rotate_api_token() {'* ]] || fail "install.sh must define rotate_api_token"
[[ "${install_body}" == *'--rotate-token)'* ]] || fail "install.sh must wire --rotate-token"
[[ "${install_body}" == *'--rotate-token Rotate API_TOKEN'* ]] || fail "--rotate-token must be in help"
[[ "${install_body}" == *'openssl rand -hex 24'* ]] || fail "token must be generated with 24 hex bytes (>=16 chars)"
[[ "${install_body}" == *'chmod 600 "$tmp"
    mv "$tmp" "${CONF_DIR}/api.env"'* ]] || fail "api.env rewrite must stay chmod 600 and atomic (tmp+mv)"
[[ "${install_body}" == *'systemctl restart 5gpn-api.service'* ]] || fail "rotation must restart 5gpn-api"
[[ "${install_body}" == *'Authorization: Bearer ${token}'* ]] \
    || fail "rotation must verify /api/health with the NEW token"
[[ "${install_body}" == *'旧令牌立即失效'* ]] || fail "rotation output must warn that the old token dies"

# --- tgbot: ops menu button + confirm step + handler ---------------------------
[[ "${tgbot_body}" == *'"🔑 轮换 API 令牌", "callback_data": "act:rotate_token"'* ]] \
    || fail "tgbot ops menu must offer token rotation"
[[ "${tgbot_body}" == *'act:rotate_token!'* ]] || fail "tgbot rotation must require a confirm tap"
[[ "${tgbot_body}" == *'run2(["bash", MGMT, "--rotate-token"], timeout=120)'* ]] \
    || fail "tgbot rotation must call install.sh --rotate-token"
[[ "${tgbot_body}" == *'旧令牌立即失效；本消息含新令牌，复制后建议删除。'* ]] \
    || fail "tgbot result must advise deleting the token-bearing message"

echo "PASS: rotate-token policy"
