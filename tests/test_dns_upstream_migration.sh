#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034 # Extracted functions consume globals dynamically via eval.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "$1" >&2; exit 1; }
info() { :; }
warn() { :; }
err() { echo "$*" >&2; }
DEFAULT_REMOTE_DNS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
DEFAULT_LOCAL_DNS=("101.226.4.6" "218.30.118.6" "180.76.76.76" "119.29.29.29")
CONF_DIR="${tmp}/conf"
MOSDNS_DIR="$CONF_DIR"
mkdir -p "$CONF_DIR"

eval "$(sed -n '/^normalize_dns_upstreams() {/,/^}/p' "$install")"
eval "$(sed -n '/^configure_dns_upstreams() {/,/^}/p' "$install")"

# 1. Empty config -> use defaults (4 China servers, 3 overseas).
unset REMOTE_DNS LOCAL_DNS DNS_UPSTREAMS OVERSEAS_DNS PRIVATE_OVERSEAS_DNS SNIPROXY_DNS
configure_dns_upstreams </dev/null
[[ "$REMOTE_DNS" == "1.1.1.1 8.8.8.8 9.9.9.9" ]] \
    || fail "default international pool was not applied (got: $REMOTE_DNS)"
[[ "$LOCAL_DNS" == "101.226.4.6 218.30.118.6 180.76.76.76 119.29.29.29" ]] \
    || fail "default domestic pool was not applied (got: $LOCAL_DNS)"

# 2. Saved config from previous install should be preserved.
printf '9.9.9.9 1.0.0.1\n' > "${CONF_DIR}/.remote_dns"
printf '223.5.5.5 119.29.29.29\n' > "${CONF_DIR}/.local_dns"
unset REMOTE_DNS LOCAL_DNS DNS_UPSTREAMS OVERSEAS_DNS PRIVATE_OVERSEAS_DNS SNIPROXY_DNS
configure_dns_upstreams </dev/null
[[ "$REMOTE_DNS" == "9.9.9.9 1.0.0.1" ]] || fail "saved remote DNS was changed"
[[ "$LOCAL_DNS" == "223.5.5.5 119.29.29.29" ]] || fail "saved local DNS was changed"

# 3. Explicit user override takes priority.
REMOTE_DNS="1.0.0.1 8.8.4.4"
LOCAL_DNS="180.76.76.76 114.114.114.114"
configure_dns_upstreams </dev/null
[[ "$REMOTE_DNS" == "1.0.0.1 8.8.4.4" ]] || fail "explicit international DNS was changed"
[[ "$LOCAL_DNS" == "180.76.76.76 114.114.114.114" ]] || fail "explicit domestic DNS was changed"

# 4. DoH URLs are still accepted and validated.
REMOTE_DNS="https://1.1.1.1/dns-query"
LOCAL_DNS="https://223.5.5.5/dns-query"
configure_dns_upstreams </dev/null
[[ "$REMOTE_DNS" == "https://1.1.1.1/dns-query" ]] || fail "DoH URL not preserved (got: $REMOTE_DNS)"

# 5. Camouflaged DoH paths are accepted; malformed URLs must fail closed.
(normalize_dns_upstreams "https://example.com/api/camo1") >/dev/null 2>&1 \
    || fail "camouflaged DoH path was rejected"
for bad_url in "https://user:pass@example.com/dns-query" "https://example.com/dns-query#frag" "ftp://example.com/x" "udp://dns.example.com"; do
    if (normalize_dns_upstreams "$bad_url") >/dev/null 2>&1; then
        fail "invalid URL was accepted: $bad_url"
    fi
done

# 6. sniproxy nameserver rendering: DoH/DoT upstreams resolve via loopback mosdns.
eval "$(sed -n '/^render_sniproxy_dns_nameservers() {/,/^}/p' "$install")"

# DoH-only upstreams -> nameserver 127.0.0.1 (local mosdns), exactly once, no warnings.
out="$(render_sniproxy_dns_nameservers "https://doh-a.example.com/api/camo1 https://doh-b.example.com/api/camo1")"
[[ "$out" == *'nameserver 127.0.0.1'* ]] \
    || fail "DoH upstreams must use loopback mosdns (got: $out)"
[[ "$(grep -c 'nameserver 127.0.0.1' <<< "$out")" -eq 1 ]] \
    || fail "loopback nameserver must appear exactly once (got: $out)"
[[ "$out" != *'[WARN]'* ]] || fail "rendered output must not contain warnings (got: $out)"

# plain IP input is preserved.
out="$(render_sniproxy_dns_nameservers "9.9.9.9")"
[[ "$out" == *'nameserver 9.9.9.9'* && "$out" != *'127.0.0.1'* ]] \
    || fail "plain IP nameserver not preserved (got: $out)"

# mixed: plain IP kept + loopback added once.
out="$(render_sniproxy_dns_nameservers "https://doh-a.example.com/api/camo1 8.8.8.8")"
[[ "$out" == *'nameserver 8.8.8.8'* && "$out" == *'nameserver 127.0.0.1'* ]] \
    || fail "mixed upstreams must keep plain IP plus loopback (got: $out)"

echo "DNS upstream configuration and URL validation OK"
