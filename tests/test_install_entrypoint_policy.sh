#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell snippets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
install_body="$(cat "${install}")"

if [[ ! -x "${install}" ]]; then
    echo "install.sh must be executable after cloning the repository." >&2
    exit 1
fi

# The documented one-liner downloads the script to a file first
# (`curl -fsSL ... -o /tmp/5gpnx-install.sh && sudo bash ...`), so there is no
# single-argument size limit (the old `bash -c "$(curl ...)"` form capped us at
# 128 KiB MAX_ARG_STRLEN). No size assertion needed.

first_three="$(head -c 3 "${install}" | od -An -tx1 | tr -d ' \n')"
if [[ "${first_three}" == "efbbbf" ]]; then
    echo "install.sh must not start with a UTF-8 BOM; it breaks the shebang when executed directly." >&2
    exit 1
fi

first_line="$(head -n 1 "${install}")"
if [[ "${first_line}" != "#!/usr/bin/env bash" && "${first_line}" != "#!/bin/bash" ]]; then
    echo "install.sh must start with a plain bash shebang." >&2
    exit 1
fi

if [[ "${install_body}" != *'systemd_unit_for_pid()'* ]]; then
    echo "install.sh must resolve the systemd unit that owns port 53 before stopping it." >&2
    exit 1
fi

if [[ "${install_body}" != *'port53_pids()'* || "${install_body}" != *'wait_for_port53_free 10'* ]]; then
    echo "install.sh must enumerate all port 53 owners and wait for the port to be released." >&2
    exit 1
fi

if [[ "${install_body}" != *'stop_systemd_unit_and_socket()'* || "${install_body}" != *'${unit%.service}.socket'* ]]; then
    echo "install.sh must stop matching systemd sockets when freeing port 53." >&2
    exit 1
fi

if [[ "${install_body}" != *'Still in use by: $(port53_owner_summary)'* ]]; then
    echo "install.sh must report the remaining port 53 owner when cleanup fails." >&2
    exit 1
fi

if [[ "${install_body}" != *'systemd-resolved.service'* ]]; then
    echo "install.sh must handle systemd-resolved when it owns port 53 as systemd-resolve." >&2
    exit 1
fi

if [[ "${install_body}" != *'ensure_repo_checkout() {'* || "${install_body}" != *'git reset --hard -q origin/main'* ]]; then
    echo "install.sh must turn BASE_DIR into a git checkout for in-place upgrades." >&2
    exit 1
fi

if [[ "${install_body}" != *'ensure_repo_checkout'* ]]; then
    echo "install.sh must call ensure_repo_checkout so /opt/5gpn becomes a repo." >&2
    exit 1
fi

if [[ "${install_body}" != *'do_update() {'* || "${install_body}" != *'--update)'* ]]; then
    echo "install.sh must provide --update for one-command upgrades." >&2
    exit 1
fi

if [[ "${install_body}" != *'G5PNX_UPDATED'* || "${install_body}" != *'exec bash "${BASE_DIR}/install.sh" --update'* ]]; then
    echo "--update must self-update the checkout and re-exec once on the new code." >&2
    exit 1
fi

if [[ "${install_body}" != *'REMOTE_DNS="$cur_ns" install_sniproxy'* ]]; then
    echo "--update must re-render sniproxy.conf with the user's current DNS, not defaults." >&2
    exit 1
fi

update_body="$(sed -n '/^do_update()/,/^}/p' "${install}")"
if [[ "${update_body}" != *'detect_os'* || "${update_body}" != *'detect_memory_profile'* ]]; then
    echo "do_update must run detect_os/detect_memory_profile before install_deps (PKG_MGR et al)." >&2
    exit 1
fi
if [[ "${update_body}" != *'get_public_ip'* || "${update_body}" != *'DOMAIN="${DOMAIN:-$(cat'* ]]; then
    echo "do_update must restore PUBLIC_IP/DOMAIN for generate_ios_profile." >&2
    exit 1
fi
if [[ "${update_body}" != *'systemctl reset-failed'* ]]; then
    echo "do_update must reset-failed services before restart (start-limit-hit after crash loops)." >&2
    exit 1
fi
if [[ "${update_body}" != *'install_wloc'* ]]; then
    echo "do_update must install the WLOC runtime as well (else /wloc reports not installed)." >&2
    exit 1
fi

uninstall_body="$(sed -n '/^do_uninstall()/,/^}/p' "${install}")"
if [[ "${uninstall_body}" != *'5gpn-wloc'* || "${uninstall_body}" != *'userdel wloc'* ]]; then
    echo "do_uninstall must clean up the WLOC service and user." >&2
    exit 1
fi

echo "install entrypoint policy OK"
