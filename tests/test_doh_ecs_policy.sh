#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "${root}/install.sh" "${root}/lib"/setup-*.sh)"
rules="$(cat "${root}/lib/update-rules.sh")"
tpl="$(cat "${root}/lib/mosdns.yaml.template")"
gen="$(cat "${root}/lib/mihomo-router-config.py")"
exitgen="$(cat "${root}/lib/mihomo-exit-config.py")"
fail() { echo "$1" >&2; exit 1; }

# --- DoH by domain: validation allows https/tls hostnames ----------------------
[[ "${install_body}" == *'parsed.scheme not in {"https", "tls"}'* ]] || fail "normalize must special-case https/tls"
[[ "${install_body}" == *'plain udp/tcp upstreams must stay IP literals'* ]] || fail "normalize must keep udp/tcp IP-only"
[[ "${install_body}" != *'parsed.path != "/dns-query"'* ]] || fail "https DoH must allow camouflaged paths, not just /dns-query"

# --- bootstrap resolver for hostname upstreams ----------------------------------
[[ "${rules}" == *'bootstrap: {bootstrap}'* ]] || fail "yaml_upstreams must emit bootstrap for hostname URLs"

# --- ECS configurable ------------------------------------------------------------
[[ "${tpl}" == *'__ECS_HOST__'* ]] || fail "mosdns template must take ECS from a placeholder"
[[ "${tpl}" != *'139.226.48.1'* ]] || fail "ECS must not be hardcoded in the template"
[[ "${rules}" == *'$BASE_DIR/.ecs'* ]] || fail "render_config must read .ecs"
[[ "${rules}" == *'touch "$BASE_DIR/wloc.txt"'* ]] || fail "render_config must ensure wloc.txt exists (template requires it)"
[[ "${install_body}" == *'PGW_ECS:-139.226.48.0/24'* ]] || fail "install must default .ecs to 139.226.48.0/24"
[[ "${install_body}" == *'set_ecs() {'* && "${install_body}" == *'--set-ecs)'* ]] || fail "install.sh must provide --set-ecs"

# --- mihomo bootstrap for DoH hostnames ------------------------------------------
[[ "${gen}" == *'default-nameserver'* ]] || fail "router dns must set default-nameserver (bootstrap)"
[[ "${exitgen}" == *'default-nameserver'* ]] || fail "exit dns must set default-nameserver (bootstrap)"
[[ "${gen}" == *'_pure_ips(DNS_LOCAL)'* && "${exitgen}" == *'_pure_ips(DNS_LOCAL)'* ]] \
    || fail "default-nameserver must filter DoH URLs out (mihomo requires pure IPs)"

echo "test_doh_ecs_policy: OK"
