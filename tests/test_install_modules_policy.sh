#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
# Policy: install.sh is split into sourced modules under lib/ (pure code motion).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "$1" >&2; exit 1; }

modules=(core exit control ops)

# --- (a) install.sh sources all four modules ----------------------------------
install_body="$(cat "${root}/install.sh")"
[[ "${install_body}" == *'source "${LIB_DIR}/setup-${_m}.sh"'* ]] \
    || fail "install.sh must source modules via the LIB_DIR loop"
for m in "${modules[@]}"; do
    [[ "${install_body}" == *"setup-${m}.sh"* ]] \
        || fail "install.sh must source lib/setup-${m}.sh"
done

# --- (b) modules exist; all five files pass bash -n ---------------------------
bash -n "${root}/install.sh" || fail "bash -n install.sh failed"
for m in "${modules[@]}"; do
    f="${root}/lib/setup-${m}.sh"
    [[ -f "$f" ]] || fail "lib/setup-${m}.sh must exist"
    bash -n "$f" || fail "bash -n lib/setup-${m}.sh failed"
done

# --- (c) key functions live in the expected module, not in install.sh ---------
check_fn() { # <function> <module>
    local fn="$1" mod="$2"
    grep -qE "^${fn}\(\) *\{" "${root}/lib/setup-${mod}.sh" \
        || fail "${fn} must be defined in lib/setup-${mod}.sh"
    if grep -qE "^${fn}\(\) *\{" "${root}/install.sh"; then
        fail "${fn} must not remain defined in install.sh"
    fi
}
check_fn install_mosdns core
check_fn check_port_53 core
check_fn set_exit exit
check_fn regen_smart exit
check_fn setup_api control
check_fn enable_client_socks control
check_fn do_update ops
check_fn main_install ops

# --- (d) no function name defined in more than one of the five files ----------
# Exception: exit_iface intentionally appears twice inside lib/setup-exit.sh —
# the real top-level definition and a second one inside the heredoc that
# generates /usr/local/bin/5gpn-apply-exit.sh (bash last-wins / verbatim heredoc).
decls="$(grep -hoE '^[a-zA-Z_][a-zA-Z0-9_]*\(\) *\{' \
    "${root}/install.sh" "${root}/lib"/setup-*.sh | sed -E 's/\(\) *\{//' | sort)"
while read -r count name; do
    [[ -n "${name:-}" ]] || continue
    if [[ "$name" == "exit_iface" ]]; then
        [[ "$count" -eq 2 ]] || fail "exit_iface must appear exactly twice (def + helper heredoc)"
        [[ "$(grep -cE '^exit_iface\(\) *\{' "${root}/lib/setup-exit.sh")" -eq 2 ]] \
            || fail "both exit_iface definitions must live in lib/setup-exit.sh"
        continue
    fi
    [[ "$count" -eq 1 ]] || fail "function ${name} defined ${count} times across install.sh and lib/setup-*.sh"
done < <(uniq -c <<<"$decls")

echo "install modules policy OK"
