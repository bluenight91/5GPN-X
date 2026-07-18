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

# --- responsive layout: sidebar on desktop, bottom tabs on mobile -------------
[[ "${ui}" == *'@media'*'768px'* ]] || fail "must have a 768px breakpoint"
[[ "${ui}" == *'class="tabbar"'* ]] || fail "must have a bottom tab bar"

# --- six sections + mihomo integration ----------------------------------------
for s in dashboard exits rules monitor ai settings; do
  [[ "${ui}" == *"data-section=\"${s}\""* || "${ui}" == *"id=\"sec-${s}\""* ]] || fail "missing section: ${s}"
done
[[ "${ui}" == *'/api/mihomo/overview'* ]] || fail "dashboard must load the mihomo overview card"
[[ "${ui}" == *'/mihomo/'* ]] || fail "monitor section must embed the metacubexd iframe"

# --- auth model unchanged ------------------------------------------------------
[[ "${ui}" == *'Bearer'* ]] || fail "panel must keep bearer-token auth"

echo "test_webui_policy: OK"
