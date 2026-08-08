#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell variables.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
gen="${root}/lib/mihomo-exit-config.py"
install_body="$(cat "${install}" "${root}/lib"/setup-*.sh)"

fail() { echo "$1" >&2; exit 1; }

[[ -f "${gen}" ]] || fail "mihomo-exit-config.py must exist"
python3 -m py_compile "${gen}" || fail "mihomo-exit-config.py must compile"

out="$(python3 "${gen}" us 'socks5://u:p@1.2.3.4:1080')"
python3 - "$out" <<'PY'
import json, sys
c = json.loads(sys.argv[1])
assert c["tun"]["enable"] and c["tun"]["device"] == "pgw-us"
assert c["tun"]["stack"] == "gvisor"
assert c["tun"]["auto-route"] is False and c["tun"]["auto-redirect"] is False
p = c["proxies"][0]
assert p["type"] == "socks5" and p["username"] == "u" and p["password"] == "p"
assert c["rules"] == ["MATCH,out"]
assert "sniffer" not in c
PY

name='澳大利亚-EXETEL-2X'
out="$(python3 "${gen}" "$name" 'socks5://u:p@1.2.3.4:1080')"
python3 - "$name" "$out" <<'PY'
import hashlib, json, re, sys
name, raw = sys.argv[1:3]
device = json.loads(raw)["tun"]["device"]
expected = "pgw-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:11]
assert device == expected
assert len(device.encode("ascii")) <= 15
assert re.fullmatch(r"pgw-[0-9a-f]{11}", device)
PY

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
WG_DIR="${tmpdir}/wg"
EXITS_DIR="${tmpdir}/exits"
mkdir -p "$WG_DIR" "$EXITS_DIR"
eval "$(awk '/^exit_conf_path\(\)/{copy=1} copy{if ($0 ~ /^ensure_mihomo\(\)/) exit; print}' "${root}/lib/setup-exit.sh")"
printf '{"tun":{"device":"pgw-%s"}}\n' "$name" > "${EXITS_DIR}/${name}.yaml"
ensure_mihomo_exit_iface "$name"
python3 - "$name" "${EXITS_DIR}/${name}.yaml" <<'PY'
import hashlib, json, sys
name, path = sys.argv[1:3]
with open(path, encoding="utf-8") as f:
    device = json.load(f)["tun"]["device"]
assert device == "pgw-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:11]
PY
unit="$(exit_mihomo_unit "$name")"
[[ "$unit" == 5gpn-mihomo@*.service && "$unit" != *"$name"* ]] || fail "Unicode mihomo unit must be escaped"

# WireGuard runtime aliases (symlinks) must not surface as phantom exits.
printf '[Interface]\n' > "${WG_DIR}/pgw-${name}.conf"
ln -sf "${WG_DIR}/pgw-${name}.conf" "${WG_DIR}/$(exit_iface "$name").conf"
listed="$(list_exit_names)"
[[ "$listed" == "$name" ]] || fail "list_exit_names must skip runtime iface symlinks (got: $listed)"
rm -f "${WG_DIR}/pgw-${name}.conf" "${WG_DIR}/$(exit_iface "$name").conf"

# Passwords are parsed from the rightmost @ and JSON-escaped verbatim.
out="$(python3 "${gen}" us 'socks5://myuser:p@ss:w/r#d?x %z@198.51.100.7:1080')"
python3 - "$out" <<'PY'
import json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert p["server"] == "198.51.100.7"
assert p["username"] == "myuser" and p["password"] == "p@ss:w/r#d?x %z"
PY
out="$(PGW_USER='bob' PGW_PASS='p@ss:w/rd#1?' python3 "${gen}" us 'socks5://1.2.3.4:1080')"
python3 - "$out" <<'PY'
import json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert p["username"] == "bob" and p["password"] == "p@ss:w/rd#1?"
PY
[[ "${install_body}" == *'PGW_USER="$px_user" PGW_PASS="$px_pass"'* ]] || fail "add_exit must pass out-of-band credentials"

ui="$(printf 'aes-256-gcm:pw' | base64)"
out="$(python3 "${gen}" hk "ss://${ui}@5.6.7.8:8388")"
python3 - "$out" <<'PY'
import json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert p["type"] == "ss" and p["cipher"] == "aes-256-gcm"
PY
out="$(python3 "${gen}" sg 'ss://2022-blake3-aes-128-gcm:GsEqQ8x6m1bF9o2k3J4mNQ==@9.9.9.9:443')"
grep -q '"cipher": "2022-blake3-aes-128-gcm"' <<<"$out" || fail "SS2022 cipher must be parsed"

out="$(python3 "${gen}" us 'socks5h://1.2.3.4:1080')"
python3 - "$out" <<'PY'
import json, sys
s = json.loads(sys.argv[1])["sniffer"]
assert s["enable"] and s["override-destination"]
PY
out="$(PGW_REMOTE_DNS=on python3 "${gen}" us 'socks5://1.2.3.4:1080')"
grep -q '"sniffer"' <<<"$out" || fail "PGW_REMOTE_DNS must enable sniffing"
[[ "${install_body}" == *'PGW_REMOTE_DNS="$px_rdns"'* ]] || fail "add_exit must pass remote DNS toggle"

for uri in \
  "trojan://pw@example.com:443?sni=example.com" \
  "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&sni=example.com" \
  "hysteria2://pw@example.com:443?sni=example.com" \
  "tuic://00000000-0000-0000-0000-000000000000:pw@example.com:443?sni=example.com" \
  "anytls://pw@example.com:443?sni=example.com" \
  "http://u:p@example.com:8080"; do
  out="$(python3 "${gen}" us "$uri")"
  grep -q '"server": "example.com"' <<<"$out" || fail "URI must parse server: $uri"
done
vmess_payload='eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInRscyI6InRscyIsInNuaSI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii9wIn0='
out="$(python3 "${gen}" us "vmess://${vmess_payload}")"
grep -q '"type": "vmess"' <<<"$out" || fail "vmess URI must yield a vmess proxy"

# --- masque outbound (masque:// URI and YAML paste) --------------------------
priv="$(printf '0123456789abcdef0123456789abcdef' | base64)"
pub="$(printf 'abcdef0123456789abcdef0123456789' | base64)"
out="$(python3 "${gen}" warp "masque://${priv}@warp.example.com:443?public-key=${pub}&ip=172.16.0.2/32&ipv6=fd00::2/128&mtu=1280&udp=true&network=h2")"
python3 - "$out" "$priv" "$pub" <<'PY'
import json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert p["type"] == "masque", p
assert p["server"] == "warp.example.com" and p["port"] == 443
assert p["private-key"] == sys.argv[2] and p["public-key"] == sys.argv[3]
assert p["ip"] == "172.16.0.2/32" and p["ipv6"] == "fd00::2/128"
assert p["mtu"] == 1280 and p["udp"] is True and p["network"] == "h2"
PY
out="$(python3 "${gen}" warp "masque://${priv}@warp.example.com?public-key=${pub}&ip=172.16.0.2/32")"
python3 - "$out" <<'PY'
import json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert p["type"] == "masque" and p["port"] == 443
assert p["udp"] is True and "network" not in p and "ipv6" not in p and "mtu" not in p
PY
# URL-safe base64 keys must be normalized to standard base64.
priv_us="$(printf '%s' "$priv" | tr '+/' '-_' | tr -d '=')"
out="$(python3 "${gen}" warp "masque://${priv_us}@warp.example.com:443?public-key=${pub}&ip=172.16.0.2/32")"
python3 - "$out" "$priv" <<'PY'
import base64, json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert base64.b64decode(p["private-key"]) == base64.b64decode(sys.argv[2])
PY
# YAML paste mode: mihomo-docs-style block, comments, quotes, list prefix.
out="$(python3 "${gen}" warp --yaml <<YAML
# masque exit, pasted from the mihomo wiki
- name: "warp"
  type: masque
  server: "warp.example.com"
  port: 443
  private-key: ${priv}
  public-key: '${pub}'
  ip: 172.16.0.2/32
  udp: true
  network: h2
YAML
)"
python3 - "$out" "$priv" "$pub" <<'PY'
import json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert p["type"] == "masque", p
assert p["server"] == "warp.example.com" and p["port"] == 443
assert p["private-key"] == sys.argv[2] and p["public-key"] == sys.argv[3]
assert p["ip"] == "172.16.0.2/32" and p["network"] == "h2"
PY
# YAML paste mode: clash-style 'proxies:' wrapper, bare ip/ipv6, sni passthrough.
out="$(python3 "${gen}" warp --yaml <<YAML
proxies:
- name: "WARP"
  type: masque
  server: 162.159.197.2
  port: 443
  sni: www.example.com
  private-key: "${priv}"
  public-key: ${pub}
  ip: 100.96.0.5
  ipv6: fd00::5
  mtu: 1280
  udp: true
YAML
)"
python3 - "$out" <<'PY'
import json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert p["type"] == "masque", p
assert p["server"] == "162.159.197.2" and p["sni"] == "www.example.com"
assert p["ip"] == "100.96.0.5/32" and p["ipv6"] == "fd00::5/128" and p["mtu"] == 1280
PY
# iOS paste artifacts: fullwidth colon and trailing inline comments must parse.
out="$(python3 "${gen}" warp --yaml <<YAML
name：warp
type：masque
server: warp.example.com  # 节点地址
private-key: ${priv}
public-key: ${pub}
ip: 172.16.0.2/32
YAML
)"
python3 - "$out" <<'PY'
import json, sys
p = json.loads(sys.argv[1])["proxies"][0]
assert p["type"] == "masque" and p["server"] == "warp.example.com", p
PY
# masque negatives: missing/invalid fields must be rejected in both modes.
if python3 "${gen}" warp "masque://${priv}@warp.example.com:443?ip=172.16.0.2/32" >/dev/null 2>&1; then fail "masque requires public-key"; fi
if python3 "${gen}" warp "masque://${priv}@warp.example.com:443?public-key=${pub}" >/dev/null 2>&1; then fail "masque requires ip"; fi
if python3 "${gen}" warp "masque://${priv}@warp.example.com:443?public-key=${pub}&ip=172.16.0.2/32&network=quic3" >/dev/null 2>&1; then fail "masque network must be quic or h2"; fi
if python3 "${gen}" warp "masque://not-valid-b64!!@warp.example.com:443?public-key=${pub}&ip=172.16.0.2/32" >/dev/null 2>&1; then fail "masque keys must be base64"; fi
if python3 "${gen}" warp "masque://${priv}@warp.example.com:443?public-key=${pub}&ip=999.1.2.3" >/dev/null 2>&1; then fail "masque ip must be a valid address"; fi
if printf 'type: hysteria2\nserver: x\n' | python3 "${gen}" warp --yaml >/dev/null 2>&1; then fail "yaml mode must reject non-masque type"; fi
if printf 'type: masque\nws-opts:\n  path: /\n' | python3 "${gen}" warp --yaml >/dev/null 2>&1; then fail "yaml mode must reject nested structures"; fi
if python3 "${gen}" us 'ftp://x' >/dev/null 2>&1; then fail "generator must reject unsupported URIs"; fi
if python3 "${gen}" us 'socks5://1.2.3.4:70000' >/dev/null 2>&1; then fail "generator must reject out-of-range ports"; fi
if python3 "${gen}" us 'trojan://pw@:443' >/dev/null 2>&1; then fail "generator must reject missing server hosts"; fi

for m in 'ensure_mihomo()' 'exit_type()' 'exit_up()' 'exit_down()' 'install_mihomo_unit()' 'exit_wait_device()' 'migrate_singbox_exits()'; do
    [[ "${install_body}" == *"${m}"* ]] || fail "install.sh missing function: ${m}"
done
[[ "${install_body}" == *'MIHOMO_VERSION_DEFAULT="1.19.28"'* ]] || fail "mihomo version must be locked"
[[ "${install_body}" == *'5gpn-mihomo@'* ]] || fail "mihomo systemd template missing"
[[ "${install_body}" == *'mihomo-exit-config.py'* ]] || fail "mihomo generator wiring missing"
[[ "${install_body}" == *'systemd-escape --template=5gpn-mihomo@.service'* ]] || fail "mihomo instance names must be escaped"
[[ "${install_body}" == *'systemctl start "${unit}"'* ]] || fail "apply-exit must start escaped mihomo units"
[[ "${install_body}" == *'systemctl show -p ActiveState --value "${unit}"'* ]] || fail "apply-exit must check ActiveState before starting mihomo units"
[[ "${install_body}" == *'"${state}" != "active" && "${state}" != "activating"'* ]] || fail "apply-exit must not re-start an activating unit (ExecStartPost self-deadlock)"
[[ "${install_body}" == *'TimeoutStartSec=180'* ]] || fail "mihomo unit must allow slow TUN creation in ExecStartPost"
[[ "${install_body}" == *'ExecStart=${MIHOMO_BIN} -d ${CONF_DIR}/mihomo/%I -f ${EXITS_DIR}/%I.yaml'* ]] || fail "mihomo unit must use the unescaped instance for config paths"
[[ "${install_body}" == *'ip route replace default dev'* ]] || fail "exit must route through pgw device"
[[ "${install_body}" != *'SINGBOX_VERSION_DEFAULT'* ]] || fail "sing-box runtime must be removed"
[[ "${install_body}" != *'ensure_singbox()'* ]] || fail "sing-box runtime function must be removed"
for scheme in vmess trojan vless hysteria2 tuic anytls socks http masque; do
    [[ "${install_body}" == *"$scheme"* ]] || fail "install help/runtime must document $scheme exits"
done
[[ "${install_body}" == *'masque://*)             type=masque ;;'* ]] || fail "add_exit must map masque:// to type masque"
[[ "${install_body}" == *'type[[:space:]]*[:：][[:space:]]*"?masque"?([[:space:]#]|$)'* ]] || fail "add_exit must detect pasted masque YAML"
# add/del-exit must refresh the smart router or new exits never appear in metacubexd.
add_fn="$(awk '/^add_exit\(\)/,/^}/' "${root}/lib/setup-exit.sh")"
[[ "$(grep -c 'regen_smart' <<<"${add_fn}")" -eq 2 ]] || fail "add_exit must regen smart on both add paths (URI/YAML and WireGuard)"
del_fn="$(awk '/^del_exit\(\)/,/^}/' "${root}/lib/setup-exit.sh")"
[[ "$(grep -c 'regen_smart' <<<"${del_fn}")" -eq 1 ]] || fail "del_exit must regen smart after removal"
# pipefail: a no-match grep in the URI extraction pipeline must not kill add_exit silently.
uri_line="$(grep -F 'ss|vmess|trojan|vless' <<<"${install_body}" | grep -F '|| true')" || fail "add_exit URI grep pipeline must end with || true (pipefail silent-exit)"
[[ -n "${uri_line}" ]] || fail "add_exit URI grep pipeline must end with || true (pipefail silent-exit)"
[[ "${install_body}" == *'"${MIHOMO_CFG_GEN}" "$name" --yaml'* ]] || fail "add_exit must wire generator --yaml mode"
[[ "${install_body}" == *'[[ $current_removed -eq 1 ]]'* ]] || fail "migration must preserve an active WireGuard exit"

# --- check_exits must not TCP-probe UDP transports (hysteria2/tuic/masque) ---
[[ "${install_body}" == *'"$typ" == "hysteria2" || "$typ" == "tuic" || "$typ" == "masque"'* ]] || fail "check_exits must skip TCP probe for hysteria2/tuic/masque"
[[ "${install_body}" == *'state="udp"'* ]] || fail "UDP exits must report state udp instead of DOWN"
# --- preflight_exit must not TCP-probe UDP transports either ------------------
[[ "${install_body}" == *'hysteria2|tuic|masque) return 0'* ]] || fail "preflight_exit must skip TCP probe for UDP transports"

echo "exit proxy types policy OK"
