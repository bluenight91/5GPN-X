#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "$1" >&2; exit 1; }

for f in doctor.sh snapshot.sh report.sh health-notify.sh smoke-check.sh; do
    [[ -f "${root}/scripts/${f}" ]] || fail "scripts/${f} must exist"
    bash -n "${root}/scripts/${f}" || fail "scripts/${f} must pass bash -n"
done

install="$(cat "${root}/install.sh")"
host="$(cat "${root}/lib/host-setup.sh")"
template="$(cat "${root}/lib/mosdns.yaml.template")"
rules="$(cat "${root}/lib/update-rules.sh")"

[[ "${install}" == *'--doctor)'* ]] || fail "install.sh must expose --doctor"
[[ "${install}" == *'--report)'* ]] || fail "install.sh must expose --report"
[[ "${install}" == *'--snapshot)'* ]] || fail "install.sh must expose --snapshot"
[[ "${install}" == *'--rollback)'* ]] || fail "install.sh must expose --rollback"
[[ "${install}" == *'--set-client-cidr)'* ]] || fail "install.sh must expose --set-client-cidr"
[[ "${install}" == *'--detect-client-cidr)'* ]] || fail "install.sh must expose --detect-client-cidr"
[[ "${install}" == *'PGW_UPDATE_SNAPSHOT'* ]] || fail "update must carry a rollback snapshot id"
[[ "${install}" == *'install_repo_script()'* ]] || fail "install must define install_repo_script"
[[ "${install}" == *'"$src" -ef "$dest"'* || "${install}" == *"\$src\" -ef \"\$dest\""* ]] \
    || fail "install_repo_script must skip same-file (in-place /opt/5gpn) copies"
[[ "${install}" == *'install_repo_script "${SCRIPT_DIR}/scripts/${f}"'* ]] \
    || fail "update/schedules must install ops scripts via install_repo_script"
[[ "${install}" == *'5gpn-health.timer'* ]] || fail "schedules must install 5gpn-health.timer"
[[ "${install}" == *'5gpn-health.service'* ]] || fail "uninstall must remove 5gpn-health units"
[[ "${install}" == *'set_client_cidr()'* ]] || fail "install.sh must define set_client_cidr"
[[ "${install}" == *'detect_client_cidr()'* ]] || fail "install.sh must define detect_client_cidr"

[[ "${template}" == *'client_ip __CLIENT_CIDR__'* ]] \
    || fail "mosdns template must substitute client CIDR"
[[ "${rules}" == *'__CLIENT_CIDR__'* ]] || fail "update-rules must render __CLIENT_CIDR__"
[[ "${rules}" == *'.client_cidr'* ]] || fail "update-rules must read .client_cidr"

[[ "${host}" == *'__CLIENT_CIDR__'* ]] || fail "nft managed firewall must use __CLIENT_CIDR__ placeholder"
[[ "${host}" == *'client_cidr="$(cat /etc/mosdns/.client_cidr'* ]] \
    || fail "iptables managed firewall must read .client_cidr"

snap="$(cat "${root}/scripts/snapshot.sh")"
[[ "${snap}" == *'/var/lib/5gpn/snapshots'* ]] || fail "snapshots live under /var/lib/5gpn/snapshots"
[[ "${snap}" == *'create_snapshot'* || "${snap}" == *'create)'* ]] || fail "snapshot must support create"
[[ "${snap}" == *'restore'* ]] || fail "snapshot must support restore"

report="$(cat "${root}/scripts/report.sh")"
[[ "${report}" == *'REDACTED'* ]] || fail "report must redact secrets"
[[ "${report}" == *'doctor.sh'* ]] || fail "report must include doctor output"

notify="$(cat "${root}/scripts/health-notify.sh")"
[[ "${notify}" == *'tgbot.env'* ]] || fail "health-notify must read tgbot.env"
[[ "${notify}" == *'doctor.sh'* && "${notify}" == *'--json'* ]] \
    || fail "health-notify must run doctor --json"

doctor="$(cat "${root}/scripts/doctor.sh")"
[[ "${doctor}" == *'stdout.buffer.write'* ]] \
    || fail "doctor --json must write UTF-8 via stdout.buffer"
[[ "${doctor}" == *'PYTHONIOENCODING=utf-8'* ]] \
    || fail "doctor --json must set PYTHONIOENCODING=utf-8"
[[ "${doctor}" == *'_json_results'* || "${doctor}" == *'mktemp'* ]] \
    || fail "doctor --json must pass RESULTS via temp file (not argv)"
[[ "${doctor}" == *"dd_count=\"\$(grep -cE"* || "${doctor}" == *'dd_count="$(grep -cE'* ]] \
    || fail "doctor must count direct-domains with grep -cE"
# Zero-match grep -c must not use `|| echo 0` (duplicates the 0 on stdout).
if grep -nE 'grep -cE.*\|\|[[:space:]]*echo[[:space:]]+0' "${root}/scripts/doctor.sh" >/dev/null; then
    fail "doctor must not use grep -c || echo 0 (double-counts zero matches)"
fi

# Smoke: --json must succeed with Chinese labels even when stdout is ASCII.
tmpd="$(mktemp -d)"
mkdir -p "${tmpd}/etc"
export BASE_DIR="$tmpd" CONF_DIR="${tmpd}/etc"
echo local > "${CONF_DIR}/current-exit"
set +e
out="$(PYTHONUTF8=0 LANG=C LC_ALL=C bash "${root}/scripts/doctor.sh" --json 2>"${tmpd}/err")"
rc=$?
set -e
if ! printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "checks" in d'; then
    echo "doctor --json under LANG=C must print parseable UTF-8 JSON (rc=${rc})" >&2
    echo "stdout: $out" >&2
    echo "stderr: $(cat "${tmpd}/err")" >&2
    rm -rf "$tmpd"
    exit 1
fi
rm -rf "$tmpd"
unset BASE_DIR CONF_DIR

echo "test_ops_doctor_policy: OK"
