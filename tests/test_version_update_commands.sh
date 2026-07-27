#!/usr/bin/env bash
# Policy: `5gpn update-webui [ver]` / `5gpn update-mihomo [ver]` self-service
# version bumps for the vendored dashboard and the mihomo TUN engine.
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "${root}/install.sh")"
fail() { echo "$1" >&2; exit 1; }

# --- subcommands are dispatched ----------------------------------------------
[[ "${install_body}" == *'--update-webui)'* ]] || fail "install.sh must dispatch --update-webui"
[[ "${install_body}" == *'--update-mihomo)'* ]] || fail "install.sh must dispatch --update-mihomo"
[[ "${install_body}" == *'update_webui() {'* ]] || fail "install.sh must define update_webui()"
[[ "${install_body}" == *'update_mihomo() {'* ]] || fail "install.sh must define update_mihomo()"

# --- update-webui reuses the pinned metacubexd installer ----------------------
[[ "${install_body}" == *'METACUBEXD_VERSION="${ver}" install_metacubexd'* ]] \
    || fail "update_webui must pass the explicit version into install_metacubexd"

# --- mihomo version pin (env > pin > default), like metacubexd ---------------
[[ "${install_body}" == *'mihomo.pin'* ]] || fail "install.sh must persist an explicit mihomo version pin"
[[ "${install_body}" == *'.mihomo-version'* ]] || fail "ensure_mihomo must record the installed version"
[[ "${install_body}" == *'ensure_mihomo() {'* ]] || fail "install.sh must define ensure_mihomo()"
[[ "${install_body}" == *'ver="${MIHOMO_VERSION}"'* ]] \
    || fail "ensure_mihomo must resolve an explicit env override first"
[[ "${install_body}" == *'pin_file="${CONF_DIR}/mihomo.pin"'* ]] \
    || fail "ensure_mihomo must fall back to the persisted pin before the default"

# --- updating mihomo restarts running exit instances --------------------------
[[ "${install_body}" == *"systemctl list-units --all --no-legend --no-pager '5gpn-mihomo@*.service'"* ]] \
    || fail "update_mihomo must enumerate running mihomo instances"
[[ "${install_body}" == *'systemctl restart "$u"'* ]] \
    || fail "update_mihomo must restart each mihomo instance"

# --- usage() documents both commands ------------------------------------------
[[ "${install_body}" == *'--update-webui [version]'* ]] || fail "usage() must document --update-webui"
[[ "${install_body}" == *'--update-mihomo [version]'* ]] || fail "usage() must document --update-mihomo"

echo "version update commands policy OK"
