#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "${root}/install.sh")"
template="$(cat "${root}/lib/mosdns.yaml.template")"
rules="$(cat "${root}/lib/update-rules.sh")"
api="$(cat "${root}/lib/api-server.py")"
bot="$(cat "${root}/lib/tgbot.py")"
ui="$(cat "${root}/webui/index.html")"
readme="$(cat "${root}/README.md")"

fail() { echo "$1" >&2; exit 1; }
has() { [[ "$1" == *"$2"* ]] || fail "$3"; }

# --- mosdns / update-rules ----------------------------------------------------
has "$template" 'tag: direct_domains' "mosdns template must define direct_domains set"
has "$template" '/etc/mosdns/direct-domains.txt' "mosdns must load direct-domains.txt"
has "$template" 'qname $direct_domains' "private_client must match direct_domains"
has "$template" 'exec: goto remote_resolve' "direct domains must use remote_resolve"
has "$rules" 'direct-domains.txt' "update-rules must ensure direct-domains.txt exists"

# --- install.sh CLI -----------------------------------------------------------
for cmd in list-direct-domains add-direct-domain del-direct-domain set-direct-domains; do
  has "$install_body" "--${cmd}" "install.sh must expose --${cmd}"
done
has "$install_body" 'apply_direct_domains()' "install.sh must reload mosdns after list changes"
has "$install_body" 'DIRECT_DOMAINS_FILE="/etc/mosdns/direct-domains.txt"' \
  "install.sh must persist the list under /etc/mosdns"
has "$install_body" 'touch /etc/mosdns/direct-domains.txt' \
  "install/update must create direct-domains.txt"

# Function smoke: normalize + validate without touching the host firewall.
eval "$(awk '/^normalize_direct_domain\(\)/,/^}/' "${root}/install.sh")"
eval "$(awk '/^valid_direct_domain\(\)/,/^}/' "${root}/install.sh")"
[[ "$(normalize_direct_domain 'HTTPS://Box2.Example.com/path#x')" == "box2.example.com" ]] \
  || fail "normalize_direct_domain must strip scheme/path and lowercase"
valid_direct_domain "box2.example.com" || fail "valid_direct_domain must accept FQDNs"
valid_direct_domain "bad" && fail "valid_direct_domain must reject bare labels" || true

# --- API ----------------------------------------------------------------------
has "$api" '/api/direct-domains' "api-server must expose /api/direct-domains"
has "$api" '/api/direct-domains/add' "api-server must expose add endpoint"
has "$api" '/api/direct-domains/del' "api-server must expose del endpoint"
has "$api" '/api/client-cidr' "api-server must expose /api/client-cidr"
has "$api" 'get_client_cidr' "api-server must read client CIDR"
has "$api" 'direct_bypass' "route tester must report direct_bypass"
has "$api" 'etc/mosdns/direct-domains.txt' "backup/restore must include the list"
python3 -m py_compile "${root}/lib/api-server.py" || fail "api-server.py must compile"

# --- webui --------------------------------------------------------------------
has "$ui" 'DNS 直连域名' "webui settings must show DNS direct-domains card"
has "$ui" '/api/direct-domains' "webui must call the direct-domains API"
has "$ui" '客户端网段' "webui settings must show client CIDR card"
has "$ui" '/api/client-cidr' "webui must call the client-cidr API"
has "$ui" 'addDirectDomain' "webui must support adding a domain"
has "$ui" 'saveDirectDomains' "webui must support replacing the whole list"

# --- telegram bot -------------------------------------------------------------
has "$bot" 'menu:direct' "tgbot must expose DNS direct-domains menu"
has "$bot" 'menu:cidr' "tgbot must expose client CIDR menu"
has "$bot" 'dd:add' "tgbot must support adding direct domains"
has "$bot" 'dd:set' "tgbot must support replacing the direct-domains list"
has "$bot" 'cidr:set' "tgbot must support setting client CIDR"
has "$bot" 'op_add_direct_domain' "tgbot must call --add-direct-domain"
has "$bot" 'DNS 直连域名' "dot menu must link to direct-domains"
has "$bot" '客户端网段' "dot menu must link to client CIDR"
python3 -m py_compile "${root}/lib/tgbot.py" || fail "tgbot.py must compile"

python3 - "${root}/lib/tgbot.py" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("tgbot", sys.argv[1])
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)
kb = bot.dot_menu()
assert any(b.get("callback_data") == "menu:direct" for row in kb for b in row), kb
assert any(b.get("callback_data") == "menu:cidr" for row in kb for b in row), kb
assert bot.direct_domains_menu()[-1][0]["callback_data"] == "menu:dot"
assert bot.client_cidr_menu()[-1][0]["callback_data"] == "menu:dot"
assert bot.op_add_direct_domain("not a domain").startswith("域名格式无效")
PY

# --- docs ---------------------------------------------------------------------
has "$readme" '/etc/mosdns/direct-domains.txt' "README must document the direct-domains path"
has "$readme" 'list-direct-domains' "README must mention the CLI"

echo "direct-domains policy OK"
