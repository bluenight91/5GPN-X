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

echo "test_ops_doctor_policy: OK"
