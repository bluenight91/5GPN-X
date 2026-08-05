#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
doctor="${root}/scripts/doctor.sh"
install_body="$(cat "${install}")"
doctor_body="$(cat "${doctor}")"

fail() { echo "$1" >&2; exit 1; }

# --- doctor already carries machine-readable output + failing exit code ------
[[ "${doctor_body}" == *'--json'* ]] || fail "doctor.sh must support --json"
[[ "${doctor_body}" == *'[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1'* ]] \
    || fail "doctor.sh must exit non-zero when any check fails"

# --- verify_installation exists and drives doctor --deep --json --------------
[[ "${install_body}" == *'verify_installation() {'* ]] || fail "install.sh must define verify_installation"
[[ "${install_body}" == *'bash "${doctor}" --deep --json'* ]] \
    || fail "verify_installation must probe via doctor --deep --json"

# --- tiered classification: core surfaces vs advisory ------------------------
[[ "${install_body}" == *'CORE_LABELS = {"DoT", "DNS", "HTTPS/SNI", "控制 API",'* ]] \
    || fail "readiness probe must treat ports/control-API as core"
[[ "${install_body}" == *'"Clash API", "Clash API 暴露", "API /health"}'* ]] \
    || fail "readiness probe must treat Clash/API health as core"
[[ "${install_body}" == *'CORE_PREFIXES = ("服务 ",)'* ]] \
    || fail "readiness probe must treat service state as core"
[[ "${install_body}" == *'就绪探测(非核心)'* ]] || fail "non-core failures must be advisory warnings"
[[ "${install_body}" == *'就绪探测(核心)'* ]] || fail "core failures must be reported as errors"

# --- wired into the main install flow before the success banner --------------
[[ "${install_body}" == *'if ! verify_installation; then
        err "核心就绪探测失败，请运行 sudo 5gpn doctor --deep 排查后重试"
        exit 1
    fi
    echo ""
    echo "=========================================="
    echo "         部署完成 — 下一步清单"'* ]] \
    || fail "main install flow must gate the success banner on verify_installation"

# --- wired into do_update after the ERR rollback trap is disarmed ------------
[[ "${install_body}" == *'trap - ERR
    if ! verify_installation; then
        err "更新后核心就绪探测失败'* ]] \
    || fail "do_update must verify after disarming the rollback trap (no auto-rollback on probe failure)"

# --- no automatic rollback on probe failure -----------------------------------
[[ "${install_body}" == *'sudo 5gpn rollback ${snap_id:-latest}'* ]] \
    || fail "update probe failure must point at the manual rollback path"

echo "readiness probe policy OK"
