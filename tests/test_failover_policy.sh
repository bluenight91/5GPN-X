#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "${root}/install.sh" "${root}/lib"/setup-*.sh)"
tgbot_body="$(cat "${root}/lib/tgbot.py")"

fail() { echo "$1" >&2; exit 1; }

# --- install.sh: units + CLI wiring --------------------------------------------
[[ "${install_body}" == *'setup_failover() {'* ]] || fail "install.sh must define setup_failover"
[[ "${install_body}" == *'install -m 0755 "${LIB_DIR}/failover.py" "${BASE_DIR}/bin/failover.py"'* ]] \
    || fail "setup_failover must install failover.py into BASE_DIR/bin"
[[ "${install_body}" == *'failover_ctl() {'* ]] || fail "install.sh must define failover_ctl"
[[ "${install_body}" == *'--failover)'* ]] || fail "install.sh must wire --failover"
[[ "${install_body}" == *'--failover [on|off|status|order <a,b,c>]'* ]] || fail "--failover must be in help"
[[ "${install_body}" == *'setup_failover || warn'* ]] \
    || fail "setup_schedules must render the failover units (install and update paths)"
[[ "${install_body}" == *'systemctl enable --now 5gpn-failover.timer'* ]] \
    || fail "failover_ctl on must enable the timer"
[[ "${install_body}" == *'systemctl disable --now 5gpn-failover.timer'* ]] \
    || fail "failover_ctl off must disable the timer"
[[ "${install_body}" == *'exit_exists "$item" || {'* ]] \
    || fail "--failover order must validate candidate names against existing exits"
[[ "${install_body}" == *'OnUnitActiveSec=60s'* ]] || fail "failover timer must tick every 60s"

# --- order config lives in /etc/5gpn/failover.env with tight perms --------------
grep -qF 'FAILOVER_ORDER=' <<<"${install_body}" || fail "failover.env must carry FAILOVER_ORDER"
[[ "${install_body}" == *'chmod 600 /etc/5gpn/failover.env'* ]] || fail "failover.env must be chmod 600"
[[ "${install_body}" == *'chmod 600 /etc/5gpn/failover.enabled'* ]] || fail "failover.enabled must be chmod 600"

# --- tgbot: 运维 menu entry + actions --------------------------------------------
[[ "${tgbot_body}" == *'"🩹 出口自愈", "callback_data": "menu:failover"'* ]] \
    || fail "tgbot ops menu must offer failover"
[[ "${tgbot_body}" == *'"--failover", "status"'* ]] || fail "tgbot must read failover status"
[[ "${tgbot_body}" == *'op_failover_ctl("on")'* ]] || fail "tgbot must enable failover"
[[ "${tgbot_body}" == *'op_failover_ctl("off")'* ]] || fail "tgbot must disable failover"
[[ "${tgbot_body}" == *'"action": "failover_order"'* ]] || fail "tgbot must prompt for the order"
[[ "${tgbot_body}" == *'"--failover", "order", order_text.strip()'* ]] \
    || fail "tgbot order must call the CLI"

echo "PASS: failover wiring policy"
