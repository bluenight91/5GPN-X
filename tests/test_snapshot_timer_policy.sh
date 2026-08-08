#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "${root}/install.sh")"

fail() { echo "$1" >&2; exit 1; }

# --- daily snapshot service + timer are rendered by setup_schedules ----------
[[ "${install_body}" == *'cat > /etc/systemd/system/5gpn-snapshot.service'* ]] \
    || fail "setup_schedules must render 5gpn-snapshot.service"
[[ "${install_body}" == *'cat > /etc/systemd/system/5gpn-snapshot.timer'* ]] \
    || fail "setup_schedules must render 5gpn-snapshot.timer"
[[ "${install_body}" == *'ExecStart=/bin/bash ${BASE_DIR}/scripts/snapshot.sh create auto'* ]] \
    || fail "snapshot service must call snapshot.sh create auto"
[[ "${install_body}" == *'OnCalendar='* ]] || fail "snapshot timer must be calendar-based"
[[ "${install_body}" == *'systemctl enable --now 5gpn-snapshot.timer'* ]] \
    || fail "snapshot timer must be enabled"

# --- retention is explicit and operator-tunable -------------------------------
[[ "${install_body}" == *'Environment=SNAP_KEEP=7'* ]] \
    || fail "snapshot service must set SNAP_KEEP (default 7)"

# --- I10 sandbox: oneshot writes only /var/lib/5gpn ---------------------------
[[ "${install_body}" == *'ProtectSystem=strict
ReadWritePaths=/var/lib/5gpn
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true'* ]] \
    || fail "snapshot service must carry the I10 sandbox (strict + ReadWritePaths=/var/lib/5gpn)"

# --- snapshot.sh already enforces retention on create -------------------------
snap_body="$(cat "${root}/scripts/snapshot.sh")"
[[ "${snap_body}" == *'KEEP="${SNAP_KEEP:-5}"'* ]] || fail "snapshot.sh must honor SNAP_KEEP"
[[ "${snap_body}" == *'if [[ "$count" -gt "$KEEP" ]]'* ]] \
    || fail "snapshot.sh must prune snapshots beyond KEEP"

echo "PASS: snapshot timer policy"
