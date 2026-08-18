#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ui="$(cat "${root}/webui/index.html")"
fail() { echo "$1" >&2; exit 1; }

# --- dual theme via CSS variables + system preference -------------------------
[[ "${ui}" == *'prefers-color-scheme'* ]] || fail "must follow system color scheme"
[[ "${ui}" == *'data-theme="dark"'* || "${ui}" == *"[data-theme=dark]"* || "${ui}" == *'data-theme*="dark"'* ]] || fail "must support manual dark override"
[[ "${ui}" == *'--bg:'* ]] || fail "must use CSS variables for theming"
[[ "${ui}" == *'localStorage'*'theme'* || "${ui}" == *'"theme"'* ]] || fail "theme choice must persist in localStorage"

# --- iOS Safari adaptations ---------------------------------------------------
[[ "${ui}" == *'viewport-fit=cover'* ]] || fail "viewport must use viewport-fit=cover"
[[ "${ui}" == *'safe-area-inset-bottom'* ]] || fail "bottom tab bar must respect the home-indicator safe area"
[[ "${ui}" == *'100dvh'* || "${ui}" == *'100svh'* ]] || fail "must use dynamic viewport height units"
[[ "${ui}" == *'apple-mobile-web-app-capable'* ]] || fail "must be add-to-homescreen capable"
[[ "${ui}" == *'tap-highlight-color'* ]] || fail "must disable tap highlight"
[[ "${ui}" == *'font-size:16px'* || "${ui}" == *'font-size: 16px'* ]] || fail "inputs must be >=16px to prevent focus zoom"
# textarea 的 mono 规则不得把字号覆盖回 <16px（iOS 聚焦缩放回归）
[[ "${ui}" != *'font-family:var(--mono); font-size:14px'* && "${ui}" != *'font-family:var(--mono);font-size:14px'* && "${ui}" != *'font-family: var(--mono); font-size: 14px'* && "${ui}" != *'font-family:var(--mono); font-size:13px'* && "${ui}" != *'font-family:var(--mono);font-size:13px'* ]] || fail "textarea must stay 16px on iOS"

# --- responsive layout: sidebar on desktop, bottom tabs on mobile -------------
[[ "${ui}" == *'@media'*'768px'* ]] || fail "must have a 768px breakpoint"
[[ "${ui}" == *'class="tabbar"'* ]] || fail "must have a bottom tab bar"

# --- six sections + mihomo integration ----------------------------------------
for s in dashboard exits rules monitor ai settings; do
  [[ "${ui}" == *"data-section=\"${s}\""* || "${ui}" == *"id=\"sec-${s}\""* ]] || fail "missing section: ${s}"
done
[[ "${ui}" == *'/api/mihomo/overview'* ]] || fail "dashboard must load the mihomo overview card"
[[ "${ui}" == *'chartRange'* && "${ui}" == *'CHART_RANGES'* ]] || fail "dashboard charts must expose a time-range selector"
[[ "${ui}" == *'/mihomo/'* ]] || fail "monitor section must embed the metacubexd iframe"
[[ "${ui}" == *'DNS 直连域名'* ]] || fail "settings must expose DNS direct-domains management"
[[ "${ui}" == *'/api/direct-domains'* ]] || fail "settings must call /api/direct-domains"
[[ "${ui}" == *'id="dd_fold"'* || "${ui}" == *"id='dd_fold'"* ]] || fail "direct-domains list must be foldable"
[[ "${ui}" == *'已有 '* || "${ui}" == *'setDirectDomainSummary'* ]] || fail "fold summary must show domain count"
[[ "${ui}" == *'客户端网段'* ]] || fail "settings must expose client CIDR management"
[[ "${ui}" == *'/api/client-cidr'* ]] || fail "settings must call /api/client-cidr"
[[ "${ui}" == *'saveClientCidr'* ]] || fail "settings must support saving client CIDR"
[[ "${ui}" == *'私网 SOCKS5'* ]] || fail "settings must expose private SOCKS5 card"
[[ "${ui}" == *'/api/client-socks'* ]] || fail "settings must call /api/client-socks"
[[ "${ui}" == *'socksAction'* ]] || fail "settings must support SOCKS enable/disable"
[[ "${ui}" == *'私网 MTProto'* ]] || fail "settings must expose private MTProto card"
[[ "${ui}" == *'/api/client-mtproto'* ]] || fail "settings must call /api/client-mtproto"
[[ "${ui}" == *'mtprotoAction'* ]] || fail "settings must support MTProto enable/secret"
[[ "${ui}" == *'5753'* ]] || fail "settings must document MTProto port 5753"
[[ "${ui}" == *'/api/doctor'* ]] || fail "settings must expose doctor"
[[ "${ui}" == *'renderDoctor('* ]] || fail "doctor results must use structured renderDoctor()"
[[ "${ui}" == *'d.pass'* || "${ui}" == *'Number(d.pass'* ]] || fail "doctor summary must use pass count, not boolean ok"
[[ "${ui}" == *'/api/report'* ]] || fail "settings must expose report generation"
[[ "${ui}" == *'/api/snapshots'* ]] || fail "settings must expose runtime snapshots"
[[ "${ui}" == *'deleteSnapshot('* ]] || fail "settings must expose snapshot delete"
[[ "${ui}" == *'轻量配置包'* && "${ui}" == *'运行时快照'* ]] || fail "backup UI must distinguish config packages and snapshots"

# --- auth model unchanged ------------------------------------------------------
[[ "${ui}" == *'Bearer'* ]] || fail "panel must keep bearer-token auth"
[[ "${ui}" == *'sessionStorage.setItem("pgw_token"'* ]] || fail "API token must be stored in sessionStorage"
[[ "${ui}" != *'localStorage.setItem("pgw_token"'* ]] || fail "API token must not be stored in localStorage"

# --- mobile tabbar: auto-hide on scroll down + horizontal overflow scroll -------
[[ "${ui}" == *'.tabbar.hide'* ]] || fail "tabbar must support auto-hide"
[[ "${ui}" == *'passive:true'* ]] || fail "tabbar scroll listener must be passive for iOS"
[[ "${ui}" == *'overflow-x:auto'* ]] || fail "tabbar must allow horizontal overflow scrolling"

# --- UDP transports (hysteria2/tuic/masque) are not connectivity failures -------
[[ "${ui}" == *'x.state==="DOWN").length'* ]] || fail "connectivity check must only count DOWN exits as unreachable (udp is N/A, not bad)"
[[ "${ui}" == *'x.state==="UP"||x.state==="udp"'* ]] || fail "udp state must render as an ok pill"

# --- daily rollup traffic chart: plot daily volume (bytes/day), never rate ----
# 回归锁：日汇总点是一天总字节，除以 86400 会显示成几百 Kbps 的假速率。
[[ "${ui}" == *'daily=iv>=86400'* ]] || fail "traffic chart must detect daily rollup data"
[[ "${ui}" == *'daily ? (x=>Array.isArray(x)?x[0]+x[1]:null)'* ]] || fail "daily traffic chart must plot raw daily bytes"
[[ "${ui}" == *'fmtBytes(b)+"/天"'* ]] || fail "daily traffic Y axis must be labeled as bytes per day"
[[ "${ui}" == *'流量=每日总量'* ]] || fail "daily view note must state traffic shows daily totals"

# --- inline script must parse (a stray '*/' inside a JS comment once killed
#     every handler on the page; node is available on GitHub runners) ----------
if command -v node >/dev/null 2>&1; then
  tmp_js="$(mktemp /tmp/webui-inline.XXXXXX.js)"
  python3 - "${root}/webui/index.html" "${tmp_js}" <<'PYEOF'
import re, sys
html = open(sys.argv[1], encoding="utf-8").read()
scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
assert scripts, "no inline <script> found"
open(sys.argv[2], "w").write("\n;\n".join(scripts))
PYEOF
  node --check "${tmp_js}" || fail "webui inline script has a JS syntax error"
  rm -f "${tmp_js}"
else
  echo "test_webui_policy: WARN node not found, skipping JS syntax check"
fi

echo "test_webui_policy: OK"
