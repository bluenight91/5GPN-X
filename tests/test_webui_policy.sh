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

echo "test_webui_policy: OK"
