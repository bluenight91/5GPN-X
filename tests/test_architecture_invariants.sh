#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
hostsetup="${root}/lib/host-setup.sh"
archdoc="${root}/docs/architecture.md"
install_body="$(cat "${install}" "${root}/lib"/setup-*.sh)"
hostsetup_body="$(cat "${hostsetup}")"

fail() { echo "$1" >&2; exit 1; }

# --- the normative architecture doc must exist and carry every invariant -----
[[ -f "${archdoc}" ]] || fail "docs/architecture.md must exist (normative architecture doc)"
for anchor in I1 I2 I3 I4 I5 I6 I7 I8 I9 I10; do
    grep -q "\*\*${anchor} " "${archdoc}" || fail "docs/architecture.md must define invariant ${anchor}"
done

# --- I1: no global flush ruleset outside the uninstall disaster fallback -----
# The managed template recreates only its own tables. The uninstall emergency
# fallback writes the flush via printf with an escaped \n, so a literal
# newline-flush must not appear anywhere in either file.
combined="${install_body}
${hostsetup_body}"
[[ "${combined}" != *$'\nflush ruleset\n'* ]] || fail "I1: no literal global 'flush ruleset' outside the uninstall printf fallback"
[[ "${hostsetup_body}" == *'delete table inet filter'* ]] || fail "I1: managed template must recreate only its own inet filter table"

# --- I2: mihomo Clash API binds loopback only --------------------------------
[[ "${install_body}" != *'external-controller: 0.0.0.0'* ]] || fail "I2: external-controller must not bind 0.0.0.0"
grep -q 'external-controller.*127\.0\.0\.1:9090' "${root}/lib/mihomo-router-config.py" \
    || fail "I2: router config must bind external-controller to 127.0.0.1:9090"

# --- I4: secrets permissions ---------------------------------------------------
[[ "${install_body}" == *'chmod 700 "${EXITS_DIR}"'* ]] || fail "I4: EXITS_DIR must be chmod 700"
[[ "${install_body}" == *'chmod 600 "${CONF_DIR}/tgbot.env"'* ]] || fail "I4: tgbot.env must be chmod 600"
[[ "${install_body}" == *'chmod 600 "${CONF_DIR}/api.env"'* ]] || fail "I4: api.env must be chmod 600"

# --- I6: deterministic TUN naming, bash and python in lockstep -----------------
[[ "${install_body}" == *"printf 'pgw-%s\\n' \"\$(printf '%s' \"\$name\" | sha256sum | cut -c1-11)\""* ]] \
    || fail "I6: bash TUN name derivation (sha256[:11]) missing"
grep -q 'hexdigest()\[:11\]' "${root}/lib/mihomo-exit-config.py" \
    || fail "I6: python TUN name derivation (hexdigest[:11]) missing"

# --- I8: validate-then-publish for generated mihomo configs --------------------
[[ "${install_body}" == *'-t -f "${yaml}.tmp"'* ]] || fail "I8: generated mihomo configs must be validated with -t before publish"

# --- I9: no real secrets/domains in the public repo ----------------------------
if grep -rnE '258364448\.xyz' "${root}" --exclude-dir=.git --exclude="$(basename "${BASH_SOURCE[0]}")" >/dev/null 2>&1; then
    fail "I9: real operator domain must never appear in the repo"
fi

# --- I11: failover is opt-in and only ever switches via set_exit ---------------
fo_body="$(cat "${root}/lib/failover.py")"
[[ "${install_body}" == *'cat > /etc/systemd/system/5gpn-failover.timer'* ]] \
    || fail "I11: failover timer unit must be rendered"
setup_fo="$(sed -n '/^setup_failover() {/,/^}/p' "${root}/lib/setup-control.sh")"
[[ "${setup_fo}" != *'enable --now 5gpn-failover.timer'* ]] \
    || fail "I11: setup_failover must never enable the timer (opt-in via failover_ctl on)"
[[ "${install_body}" == *'touch /etc/5gpn/failover.enabled'* ]] \
    || fail "I11: failover_ctl on must create the enabled marker"
[[ "${fo_body}" == *'os.path.isfile(ENABLED_FILE)'* ]] \
    || fail "I11: a tick must no-op without the enabled marker"
[[ "${fo_body}" == *'"--set-exit", name'* ]] \
    || fail "I11: switching must go through install.sh --set-exit"
for forbidden in 'ip route' 'ip rule' 'nft ' 'iptables'; do
    [[ "${fo_body}" != *"${forbidden}"* ]] \
        || fail "I11: failover.py must not touch routing/firewall directly (${forbidden})"
done
[[ "${fo_body}" == *'COOLDOWN_SEC'* && "${fo_body}" == *'MAX_SWITCHES_PER_HOUR'* \
    && "${fo_body}" == *'GRACE_SEC'* && "${fo_body}" == *'FAIL_AFTER'* ]] \
    || fail "I11: anti-flap guards (threshold/cooldown/hourly cap/grace) are mandatory"
[[ "${fo_body}" == *'SKIP_EXITS = ("local", "smart")'* ]] \
    || fail "I11: local/smart must be excluded from failover"

echo "architecture invariants policy OK"
