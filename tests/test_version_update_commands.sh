#!/usr/bin/env bash
# Policy: `5gpn update-webui [ver]` / `5gpn update-mihomo [ver]` self-service
# version bumps for the vendored dashboard and the mihomo TUN engine.
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "${root}/install.sh")"
api_body="$(cat "${root}/lib/api-server.py")"
bot_body="$(cat "${root}/lib/tgbot.py")"
ui_body="$(cat "${root}/webui/index.html")"
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

# --- API exposes version query + update endpoints ------------------------------
[[ "${api_body}" == *'/api/component/versions'* ]] || fail "api must expose GET /api/component/versions"
[[ "${api_body}" == *'/api/component/update'* ]] || fail "api must expose POST /api/component/update"
[[ "${api_body}" == *'COMPONENT_VERSION_RE'* ]] || fail "api must validate component versions"
[[ "${api_body}" == *'def github_latest('* ]] || fail "api must fetch upstream latest releases"
[[ "${api_body}" == *'def component_versions('* ]] || fail "api must aggregate component versions"

# --- TG bot exposes the same flow under ops -> components ----------------------
[[ "${bot_body}" == *'"🧩 组件版本", "callback_data": "menu:components"'* ]] || fail "ops menu must link the components submenu"
[[ "${bot_body}" == *'def components_menu()'* ]] || fail "bot must define components_menu()"
[[ "${bot_body}" == *'def op_update_component('* ]] || fail "bot must define op_update_component()"
[[ "${bot_body}" == *'def components_view('* ]] || fail "bot must define components_view()"
[[ "${bot_body}" == *'comp:up:mihomo'* ]] || fail "bot must confirm before a mihomo engine upgrade"
[[ "${bot_body}" == *'COMP_VERSION_RE'* ]] || fail "bot must validate manual versions"

# --- WebUI settings card wires both endpoints ----------------------------------
[[ "${ui_body}" == *'id="comp_webui"'* && "${ui_body}" == *'id="comp_mihomo"'* ]] \
    || fail "webui must show both component versions"
[[ "${ui_body}" == *'/api/component/versions'* ]] || fail "webui must query component versions"
[[ "${ui_body}" == *'/api/component/update'* ]] || fail "webui must call the component update endpoint"
[[ "${ui_body}" == *'function updateComponent('* ]] || fail "webui must define updateComponent()"
[[ "${ui_body}" == *'loadComponents()'* ]] || fail "webui must load component versions on settings entry"

echo "version update commands policy OK"
