#!/usr/bin/env bash
# Top-level constants and globals are consumed by the sourced lib/setup-*.sh
# modules, so they appear unused to ShellCheck in this file alone.
# shellcheck disable=SC2034
set -euo pipefail
REPO_URL="https://github.com/bluenight91/5GPN-X.git"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
BASE_DIR="/opt/5gpn"
CONF_DIR="${BASE_DIR}/etc"
SRC_DIR="${BASE_DIR}/src"
WWW_DIR="${BASE_DIR}/www"
IOS_PROFILE_PORT=8111
API_PORT_DEFAULT=8444
CLIENT_SOCKS_PORT_DEFAULT=38443
CLIENT_SOCKS_USER_DEFAULT=5gpn
CLIENT_MTPROTO_PORT_DEFAULT=5753
CLIENT_MTPROTO_BACKEND_DEFAULT=127.0.0.1:15753
CLASH_REMOTE_PORT_DEFAULT=9443
CLASH_REMOTE_BACKEND_DEFAULT=127.0.0.1:9090
# Classic MTProto (bare 32-hex secrets Telegram can paste directly).
# mtg v2 FakeTLS cannot accept bare hex client secrets.
MTPROTOPROXY_VERSION_DEFAULT="v1.1.2"
MTPROTOPROXY_REPO_DEFAULT="https://raw.githubusercontent.com/alexbers/mtprotoproxy"
EXIT_USER="pxout"
EXIT_MARK="0x1"
EXIT_TABLE="100"
WG_DIR="/etc/wireguard"
EXITS_DIR="/etc/5gpn/exits"
MIHOMO_API_SECRET_FILE=/etc/5gpn/mihomo-api-secret
RULES_FILE="/etc/5gpn/rules.conf"
POLICY_MAP="/etc/5gpn/policy-map.conf"
KEEP_FILE="/etc/5gpn/keep-categories"
DIRECT_FILE="/etc/5gpn/direct-categories"
RULES_DEFAULT="/etc/5gpn/rules-default.conf"
RULESET_CACHE="/etc/5gpn/rulesets"
MIHOMO_BIN="/opt/5gpn/bin/mihomo"
MIHOMO_VERSION_FILE="/opt/5gpn/bin/.mihomo-version"
MIHOMO_CFG_GEN="/opt/5gpn/bin/mihomo-exit-config.py"
MIHOMO_ROUTER_GEN="/opt/5gpn/bin/mihomo-router-config.py"
RULES_IMPORT="/opt/5gpn/bin/rules-import.py"
MIHOMO_VERSION_DEFAULT="1.19.28"
METACUBEXD_VERSION_DEFAULT="1.270.5"
MOSDNS_VERSION_DEFAULT="5.3.4"
DEFAULT_REMOTE_DNS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
DEFAULT_LOCAL_DNS=("101.226.4.6" "218.30.118.6" "180.76.76.76" "119.29.29.29")
bootstrap_from_repo_if_needed() {
    local required=(
        install.sh
        lib/setup-core.sh lib/setup-exit.sh lib/setup-control.sh lib/setup-ops.sh
        lib/renew-hook.sh lib/sniproxy.conf lib/quic-proxy.go lib/client-socks.go
        lib/client-mtproto.go lib/clash-remote.go
        lib/mosdns.yaml.template lib/update-rules.sh lib/ios-http.py lib/tgbot.py
        lib/wa-shim.py lib/rules-import.py lib/mihomo-exit-config.py
        lib/mihomo-router-config.py lib/rules-default.conf lib/host-setup.sh
        lib/wloc-interceptor.py lib/wloc-rewrite.py lib/wloc-wifitile.py
    )
    local missing=0 f tmpdir
    for f in "${required[@]}"; do
        [[ -f "${SCRIPT_DIR}/${f}" ]] || { missing=1; break; }
    done
    if [[ $missing -eq 0 ]]; then
        return 0
    fi
    if [[ -n "${G5PNX_BOOTSTRAPPED:-}" ]]; then
        return 0
    fi
    tmpdir="$(mktemp -d /tmp/5gpnx-src.XXXXXX)"
    if git clone --depth=1 --branch main "$REPO_URL" "$tmpdir" >/dev/null 2>&1; then
        export G5PNX_BOOTSTRAPPED=1
        exec bash "$tmpdir/install.sh" "$@"
    fi
    echo "[ERR]  无法自动获取完整源码树。请用 git clone 后再运行 install.sh。" >&2
    exit 1
}
bootstrap_from_repo_if_needed "$@"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC}  $*" >&2; }

# Copy a repo script into BASE_DIR. No-op when source and dest are the same
# inode (normal for /opt/5gpn in-place updates) — GNU install errors on that.
install_repo_script() {
    local src="$1" dest="$2" mode="${3:-0755}"
    [[ -f "$src" ]] || return 0
    mkdir -p "$(dirname "$dest")"
    if [[ "$src" -ef "$dest" ]] 2>/dev/null || [[ "$src" == "$dest" ]]; then
        chmod "$mode" "$dest" 2>/dev/null || true
        return 0
    fi
    install -m "$mode" "$src" "$dest"
}
ensure_repo_checkout() {
    [[ -d "${BASE_DIR}/.git" ]] && return 0
    command -v git >/dev/null 2>&1 || return 0
    mkdir -p "${BASE_DIR}"
    ( cd "${BASE_DIR}"
      git init -q -b main 2>/dev/null || git init -q
      git remote add origin "${REPO_URL}" 2>/dev/null || git remote set-url origin "${REPO_URL}"
      git fetch -q --depth 1 origin main
      git reset --hard -q origin/main
      git branch --set-upstream-to=origin/main main 2>/dev/null || true
    ) || warn "无法把 ${BASE_DIR} 初始化为 git 仓库（不影响本次运行）"
}
ensure_repo_checkout

for _m in core exit control ops; do
    # shellcheck source=/dev/null
    source "${LIB_DIR}/setup-${_m}.sh"
done

usage() {
    cat <<EOF
Usage: $0 [OPTION]

Options:
  (none)         Full interactive installation
  --status       Show service status
  --update       Self-update from git and redeploy the runtime (config kept)
  --smoke        Run the read-only post-deploy smoke check (alias of doctor --deep)
  --doctor       Structured health check (--json / --deep supported via scripts/doctor.sh)
  --report       Write a redacted diagnostic report under /tmp
  --snapshot [list|restore [id]|delete [id]|label]
                 List / restore / delete snapshots, or save a config snapshot
                 (also done automatically before --update)
  --rollback [id]
                 Restore the latest (or named) config snapshot
  --set-client-cidr <cidr>
                 Set private-client source CIDR(s) for mosdns hijack
                 (default 172.22.0.0/16; comma-separated multi-CIDR supported)
  --detect-client-cidr
                 Detect a private-client CIDR from local interfaces and apply it
  --update-rules Update GFWList/ChinaList and reload mosdns
  --renew-cert   Force renew certificates and reload services
  --set-dot-domain <domain>
                 Change DoT domain, issue certificate, reload mosdns
  --set-dot-domain-force <domain>
                 Force-change DoT domain without issuing a certificate first
  --set-dns <remote-dns> [local-dns]
                 Set primary/fallback DNS upstreams and reload mosdns/sniproxy.
                 remote is used for international/proxy-side resolution; local
                 is used for ChinaList direct resolution. https/tls upstreams
                 may use domains (e.g. your own DoH server).
  --set-ecs <a.b.c.d[/24]>
                 Set the ECS subnet carried in China-chain DNS queries
                 (default 139.226.48.0/24; takes effect immediately).
  --list-exits   List configured egress exits and which one is active
  --check-exits  Test reachability of each exit's upstream node (UP/DOWN)
  --add-exit <name> [wg.conf | proxy-uri]
                 Register an egress exit. Accepts a WireGuard client config
                 (file/stdin/paste), ss/vmess/trojan/vless/hysteria2/tuic/
                 anytls/masque/socks/http URI, or a mihomo-style masque YAML
                 proxy block (usque/wiki format). URI types use the locked
                 mihomo TUN engine (auto-installed).
  --rename-exit <old> <new>
                 Rename a configured exit safely, including references in the
                 active selection and smart-routing policy/rules when needed.
  --set-exit <name|local|smart>
                 Switch proxy egress to <name>, 'local' for direct egress, or
                 'smart' for rule-based per-domain routing (see --set-rules).
  --del-exit <name>
                 Remove a configured exit.
  --edit-exit <name>
                 Replace an exit's config in place (reads new wg.conf / proxy
                 URI from stdin; validates before replacing, re-activates if active).
  --set-rules [file]
                 Install routing rules (file/stdin/paste) for the
                 'smart' exit: route domains to exits / direct / block, with
                 local lists, remote rule-set URLs, geosite/geoip.
  --show-rules   Print the current smart-routing rules.
  --add-rule <rule>
                 Add one top-priority smart rule and rebuild atomically.
  --add-ruleset <url|path> <exit|category|direct|block>
                 Add a mihomo rule-provider source and rebuild atomically.
  --import-rules <rule-list-file>
                 Convert a rule list into smart rules (categories),
                 seed the category->exit policy map, and rebuild the router.
  --set-policy <category> <exit|direct|block>
                 Map a rule category (group) to an egress target, then rebuild.
  --del-policy <category>      Remove a rule group from the policy map.
  --rename-policy <old> <new>  Rename a rule group (updates rules + map).
  --proxy-domain <domain> <exit|direct|block>
                 One-click: hijack a domain into the gateway AND route it.
  --list-direct-domains
                 List DNS direct-resolve domains (private clients skip hijack).
  --add-direct-domain <domain>
                 Add a domain so private clients get its real A record
                 (for SSH hostnames and other non-SNI services).
  --del-direct-domain <domain>
                 Remove a domain from the DNS direct-resolve list.
  --set-direct-domains [file]
                 Replace the whole DNS direct-resolve list (file/stdin/paste).
  --show-policy  Print the category -> target policy map.
  --setup-tgbot  Install/enable the Telegram control bot (uses TG_BOT_TOKEN /
                 TG_ADMIN_IDS env vars, or prompts interactively).
  --setup-api    Install/enable the HTTP control API + web panel (env API_TOKEN
                 / API_PORT, or generates a token; reuses existing token).
  --rotate-token Rotate API_TOKEN (keeps port/bind), restart the API, print the
                 new token once. Old tokens stop working immediately.
  --api-allow [list|add <cidr>|del <cidr>]
                 Manage the API/webui source allowlist (etc/api-allow.list).
                 Empty list = unrestricted (loopback always allowed); once any
                 CIDR is present, every other source gets HTTP 403. Enforced
                 inside 5gpn-api, hot-reloaded on file change.
  --failover [on|off|status|order <a,b,c>]
                 Exit failover watchdog (opt-in, off by default). When on,
                 probes the active exit every 60s through its TUN device;
                 after 3 consecutive failures switches to the best healthy
                 candidate (order via 'order', else last-known latency) and
                 sends a Telegram notification. Anti-flap: 10min cooldown,
                 max 3 switches/hour, 5min grace after a manual switch.
  --update-webui [version]
                 Update the metacubexd web dashboard. An explicit version is
                 pinned (etc/metacubexd.pin) so later updates keep it.
  --update-mihomo [version]
                 Update the mihomo TUN engine and restart running exits.
                 An explicit version is pinned (etc/mihomo.pin).
  --enable-client-socks
                 Enable private SOCKS5 (user/pass; only client CIDR; default TCP 38443)
  --disable-client-socks
                 Disable the private SOCKS5 proxy
  --client-socks-status
                 Show SOCKS5 status (password omitted)
  --reset-client-socks-creds
                 Rotate SOCKS5 username/password (prints once)
  --enable-client-mtproto
                 Enable private MTProto proxy (classic; only client CIDR; TCP 5753)
  --disable-client-mtproto
                 Disable the private MTProto proxy
  --client-mtproto-status
                 Show MTProto status (secret omitted)
  --set-client-mtproto-secret <secret>
                 Set classic 32-hex secret (Telegram pastes this as-is; optional dd prefix OK)
  --generate-client-mtproto-secret
                 Generate a new random 32-hex secret
  --enable-clash-remote
                 Enable HTTPS Clash API for third-party panels (default TCP 9443;
                 client CIDR + optional extra CIDR; dedicated remote secret)
  --disable-clash-remote
                 Disable the remote Clash API endpoint
  --clash-remote-status
                 Show remote Clash API status (secret omitted)
  --reset-clash-remote-secret
                 Rotate the remote panel secret (prints once)
  --set-clash-remote-extra-cidr <cidr[,cidr…]>
                 Extra source CIDRs allowed beyond client CIDR (empty to clear)
  --setup-whatsapp
                 Install/repair the iOS WhatsApp no-SNI TCP/443 shim.
  --uninstall    Remove all installed components
  -ios          Regenerate iOS DoT profile and QR code
  -h, --help     Show this help

When invoked through the global 5gpn command, the leading dashes of the
first subcommand are optional: '5gpn update' works like '5gpn --update'.

Environment variables (for non-interactive use):
  DOMAIN         Your own fully-qualified domain (e.g. dns.example.com).
                 When set, the interactive domain prompt is skipped.
                 You must point its A record at this host's public IP.
  REMOTE_DNS     International/proxy-side DNS upstreams, IP[:port] list
  LOCAL_DNS      Domestic ChinaList DNS upstreams, IP[:port] list
  DNS_UPSTREAMS / OVERSEAS_DNS / PRIVATE_OVERSEAS_DNS / SNIPROXY_DNS
                 Backward-compatible aliases for REMOTE_DNS
  EMAIL          Email for Let's Encrypt
  TG_BOT_TOKEN   Telegram bot token; enables the control bot when set
  TG_ADMIN_IDS   Comma-separated Telegram numeric IDs allowed to operate the bot
  CLIENT_CIDR    Initial private-client CIDR(s), comma-separated
  FORCE_WIDE_CIDR=1
                 Allow/confirm wide client CIDR prefixes below /16
  API_BIND       API listen address (default 127.0.0.1; public bind needs 0.0.0.0 + firewall)
  API_ALLOW_ORIGIN
                 CORS origin (default empty/same-origin; set * explicitly for wildcard)
  API_TOKEN/API_PORT
                 API token/listen port for --setup-api or first install
  MIHOMO_VERSION Override the locked mihomo version (default: ${MIHOMO_VERSION_DEFAULT};
                 explicit use pins it via etc/mihomo.pin)
  METACUBEXD_VERSION
                 Override the locked metacubexd dashboard version
                 (default: ${METACUBEXD_VERSION_DEFAULT}; pins via etc/metacubexd.pin)
  FIREWALL_MODE  preserve (default) | auto | managed.
                 preserve keeps the existing host firewall untouched and only
                 manages the project's own egress-marking rules; auto adds the
                 needed allow rules to UFW/firewalld/nft/iptables without
                 flushing anything; managed fully owns the INPUT firewall
                 (always allowing every detected SSH port). Hosts upgraded from
                 older releases that already managed the firewall stay managed.
  PGW_TUNING     essential (default) | performance. essential applies only the
                 sysctls the gateway needs (ip_forward, rp_filter, BBR when
                 available); performance applies the legacy aggressive tuning.
                 Hosts upgraded from older releases keep the performance profile.
EOF
}


# ----- private client SOCKS5 (opt-in; uncommon port; pxout egress) -----
CLIENT_SOCKS_BIN="${BASE_DIR}/bin/client-socks"
CLIENT_SOCKS_ENV="${CONF_DIR}/client-socks.env"
CLIENT_SOCKS_ENABLED="${CONF_DIR}/client-socks.enabled"
CLIENT_SOCKS_PORT_FILE="${CONF_DIR}/client-socks.port"


# ----- private client MTProto (classic mtprotoproxy + CIDR ACL; TCP 5753) -----
CLIENT_MTPROTO_BIN="${BASE_DIR}/bin/client-mtproto"
CLIENT_MTPROTO_ENV="${CONF_DIR}/client-mtproto.env"
CLIENT_MTPROTO_ENABLED="${CONF_DIR}/client-mtproto.enabled"
CLIENT_MTPROTO_PORT_FILE="${CONF_DIR}/client-mtproto.port"
MTPROTOPROXY_PY="${BASE_DIR}/bin/mtprotoproxy.py"
MTPROTOPROXY_CONF="${CONF_DIR}/mtprotoproxy.conf.py"
MTPROTOPROXY_PIN="${CONF_DIR}/mtprotoproxy.pin"


# ----- remote Clash API HTTPS (third-party panels; CIDR ACL + dedicated secret) -----
CLASH_REMOTE_BIN="${BASE_DIR}/bin/clash-remote"
CLASH_REMOTE_ENV="${CONF_DIR}/clash-remote.env"
CLASH_REMOTE_ENABLED="${CONF_DIR}/clash-remote.enabled"
CLASH_REMOTE_PORT_FILE="${CONF_DIR}/clash-remote.port"

# Host firewall & kernel tuning helpers live in lib/host-setup.sh to keep this
# script below the 128 KiB single-argument limit of `bash -c "$(curl ...)"`.
if [[ -f "${LIB_DIR}/host-setup.sh" ]]; then
    # shellcheck source=lib/host-setup.sh
    . "${LIB_DIR}/host-setup.sh"
else
    err "lib/host-setup.sh not found next to this script; run from a full git clone or the documented installer."
    exit 1
fi

DIRECT_DOMAINS_FILE="/etc/mosdns/direct-domains.txt"

case "${1:-}" in
    --status)
        get_public_ip 2>/dev/null || true
        show_status
        ;;
    --update)
        do_update
        ;;
    --smoke)
        check_root
        exec bash "${SCRIPT_DIR}/scripts/doctor.sh" --deep
        ;;
    --doctor)
        check_root
        shift
        exec bash "${SCRIPT_DIR}/scripts/doctor.sh" "$@"
        ;;
    --report)
        check_root
        shift
        exec bash "${SCRIPT_DIR}/scripts/report.sh" "$@"
        ;;
    --snapshot)
        check_root
        case "${2:-}" in
            list) bash "${SCRIPT_DIR}/scripts/snapshot.sh" list ;;
            restore) bash "${SCRIPT_DIR}/scripts/snapshot.sh" restore "${3:-latest}" ;;
            delete|rm|remove) bash "${SCRIPT_DIR}/scripts/snapshot.sh" delete "${3:-}" ;;
            *) bash "${SCRIPT_DIR}/scripts/snapshot.sh" create "${2:-manual}" ;;
        esac
        ;;
    --rollback)
        check_root
        bash "${SCRIPT_DIR}/scripts/snapshot.sh" restore "${2:-latest}"
        ;;
    --set-client-cidr)
        check_root
        set_client_cidr "${2:-}"
        ;;
    --detect-client-cidr)
        check_root
        detect_client_cidr
        ;;
    --update-rules)
        /usr/local/bin/update-mosdns-rules.sh
        ;;
    --renew-cert)
        force_renew_cert
        ;;
    --set-dot-domain)
        check_root
        set_dot_domain "${2:-}"
        ;;
    --set-dot-domain-force)
        check_root
        force_set_dot_domain "${2:-}"
        ;;
    --set-dns)
        check_root
        set_custom_dns "${2:-}" "${3:-}" "${4:-}"
        ;;
    --set-ecs)
        check_root
        set_ecs "${2:-}"
        ;;
    --setup-whatsapp)
        check_root
        get_public_ip
        ensure_proxy_user
        install_whatsapp_shim
        systemctl restart sniproxy wa-shim
        ;;
    --list-exits)
        list_exits
        ;;
    --add-exit)
        check_root
        add_exit "${2:-}" "${3:-}"
        ;;
    --rename-exit)
        check_root
        rename_exit "${2:-}" "${3:-}"
        ;;
    --del-exit)
        check_root
        del_exit "${2:-}"
        ;;
    --edit-exit)
        check_root
        edit_exit "${2:-}"
        ;;
    --set-exit)
        check_root
        set_exit "${2:-}"
        ;;
    --set-rules)
        check_root
        set_rules "${2:-}"
        ;;
    --add-rule)
        check_root
        add_rule "${2:-}"
        ;;
    --add-ruleset)
        check_root
        add_ruleset "${2:-}" "${3:-}"
        ;;
    --import-rules)
        check_root
        import_rules "${2:-}"
        ;;
    --set-policy)
        check_root
        set_policy "${2:-}" "${3:-}"
        ;;
    --del-policy)
        check_root
        del_policy "${2:-}"
        ;;
    --rename-policy)
        check_root
        rename_policy "${2:-}" "${3:-}"
        ;;
    --proxy-domain)
        check_root
        proxy_domain "${2:-}" "${3:-}"
        ;;
    --list-direct-domains)
        list_direct_domains
        ;;
    --add-direct-domain)
        check_root
        add_direct_domain "${2:-}"
        ;;
    --del-direct-domain)
        check_root
        del_direct_domain "${2:-}"
        ;;
    --set-direct-domains)
        check_root
        set_direct_domains "${2:-}"
        ;;
    --show-policy)
        show_policy
        ;;
    --check-exits)
        check_exits
        ;;
    --show-rules)
        show_rules
        ;;
    --setup-tgbot)
        check_root
        setup_tgbot
        ;;
    --setup-api)
        check_root
        setup_api
        ;;
    --rotate-token)
        check_root
        rotate_api_token
        ;;
    --api-allow)
        case "${2:-list}" in
            list) api_allow_list ;;
            add) api_allow_add "${3:-}" ;;
            del|remove|rm) api_allow_del "${3:-}" ;;
            *) err "Usage: $0 --api-allow [list|add <cidr>|del <cidr>]"; exit 1 ;;
        esac
        ;;
    --failover)
        failover_ctl "${2:-status}" "${3:-}"
        ;;
    --update-webui)
        check_root
        update_webui "${2:-}"
        ;;
    --update-mihomo)
        check_root
        update_mihomo "${2:-}"
        ;;
    --enable-client-socks)
        enable_client_socks
        ;;
    --disable-client-socks)
        disable_client_socks
        ;;
    --client-socks-status)
        client_socks_status
        ;;
    --reset-client-socks-creds)
        reset_client_socks_creds
        ;;
    --enable-client-mtproto)
        enable_client_mtproto
        ;;
    --disable-client-mtproto)
        disable_client_mtproto
        ;;
    --client-mtproto-status)
        client_mtproto_status
        ;;
    --set-client-mtproto-secret)
        set_client_mtproto_secret "${2:-}"
        ;;
    --generate-client-mtproto-secret)
        generate_client_mtproto_secret
        ;;
    --enable-clash-remote)
        enable_clash_remote
        ;;
    --disable-clash-remote)
        disable_clash_remote
        ;;
    --clash-remote-status)
        clash_remote_status
        ;;
    --reset-clash-remote-secret)
        reset_clash_remote_secret
        ;;
    --set-clash-remote-extra-cidr)
        set_clash_remote_extra_cidr "${2:-}"
        ;;
    --uninstall)
        do_uninstall
        ;;
    -ios)
        regenerate_ios_profile
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        main_install
        ;;
esac
