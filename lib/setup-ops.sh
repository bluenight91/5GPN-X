#!/usr/bin/env bash
# setup-ops.sh — Ops & lifecycle: CLI install, status, update, uninstall, domain/DNS setters, main flow.
# Sourced by install.sh; do not execute directly. Relies on install.sh globals
# and runs under install.sh's set -euo pipefail (ShellCheck scopes below).
# shellcheck disable=SC2154,SC2034,SC2164,SC2317

install_cli() {
    # Global `5gpn` command. A symlink would break SCRIPT_DIR resolution and
    # trigger the bootstrap clone on every call, so use a tiny wrapper instead.
    cat > /usr/local/bin/5gpn <<'EOF'
#!/bin/bash
# Accept bare subcommands: `5gpn update` ≡ `5gpn --update`. Only the first
# argument is translated; everything after it is passed through verbatim.
if [[ $# -gt 0 && "$1" != -* ]]; then
    set -- "--$1" "${@:2}"
fi
exec /opt/5gpn/install.sh "$@"
EOF
    chmod 0755 /usr/local/bin/5gpn
    install_mgmt_ctl
}
install_mgmt_ctl() {
    # Bot/API call ${BASE_DIR}/bin/5gpn-ctl. Never place a full copy of install.sh
    # here: SCRIPT_DIR would become /opt/5gpn/bin, missing lib/, and every call
    # would git-clone a bootstrap tree (slow, flaky doctor/API ops).
    mkdir -p "${BASE_DIR}/bin"
    cat > "${BASE_DIR}/bin/5gpn-ctl" <<'EOF'
#!/bin/bash
if [[ $# -gt 0 && "$1" != -* ]]; then
    set -- "--$1" "${@:2}"
fi
exec /opt/5gpn/install.sh "$@"
EOF
    chmod 0755 "${BASE_DIR}/bin/5gpn-ctl"
}
setup_schedules() {
    info "Setting up automatic updates..."
    cat > /etc/systemd/system/update-mosdns-rules.timer <<'EOF'
[Unit]
Description=Weekly mosdns rules update

[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    cat > /etc/systemd/system/update-mosdns-rules.service <<'EOF'
[Unit]
Description=Update mosdns GFWList/ChinaList rules

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-mosdns-rules.sh
EOF
    # Periodic doctor → Telegram alert (no-op when tgbot.env is absent).
    mkdir -p "${BASE_DIR}/scripts"
    for f in doctor.sh snapshot.sh report.sh health-notify.sh smoke-check.sh; do
        install_repo_script "${SCRIPT_DIR}/scripts/${f}" "${BASE_DIR}/scripts/${f}"
    done
    cat > /etc/systemd/system/5gpn-health.service <<EOF
[Unit]
Description=5GPN-X periodic health check (alert on state change)

[Service]
Type=oneshot
ExecStart=/bin/bash ${BASE_DIR}/scripts/health-notify.sh
EOF
    cat > /etc/systemd/system/5gpn-health.timer <<'EOF'
[Unit]
Description=Run 5GPN-X health check every 20 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=20min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    # Daily config snapshot (configs only; retention via SNAP_KEEP).
    cat > /etc/systemd/system/5gpn-snapshot.service <<EOF
[Unit]
Description=5GPN-X daily config snapshot

[Service]
Type=oneshot
Environment=SNAP_KEEP=7
ExecStart=/bin/bash ${BASE_DIR}/scripts/snapshot.sh create auto
ProtectSystem=strict
ReadWritePaths=/var/lib/5gpn
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
EOF
    cat > /etc/systemd/system/5gpn-snapshot.timer <<'EOF'
[Unit]
Description=Run 5GPN-X config snapshot daily

[Timer]
OnCalendar=*-*-* 04:17:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now update-mosdns-rules.timer
    systemctl enable --now 5gpn-health.timer 2>/dev/null || true
    systemctl enable --now 5gpn-snapshot.timer 2>/dev/null || true
    setup_failover || warn "failover 单元渲染失败；可稍后重跑 $0 --failover on"
    install_certbot_firewall_hooks
    systemctl enable --now certbot.timer 2>/dev/null || true
    ok "Schedules configured (rules: weekly, health: 20m, snapshot: daily, cert: auto)"
}
show_status() {
    echo "=========================================="
    echo "      Proxy Gateway Status"
    echo "=========================================="
    local deploy_line
    deploy_line="$(deployed_revision_line)"
    [[ -n "$deploy_line" ]] && echo -e "Deployed: ${GREEN}${deploy_line}${NC}"
    for svc in mosdns sniproxy wa-shim quic-proxy; do
        status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        if [[ "$status" == "active" ]]; then
            echo -e "$svc: ${GREEN}running${NC}"
        else
            echo -e "$svc: ${RED}$status${NC}"
        fi
    done
    ios_status=$(systemctl is-active 5gpn-ios-profile.socket 2>/dev/null || echo "unknown")
    if [[ "$ios_status" == "active" ]]; then
        echo -e "5gpn-ios-profile.socket: ${GREEN}listening${NC}"
    else
        echo -e "5gpn-ios-profile.socket: ${RED}$ios_status${NC}"
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^5gpn-tgbot\.service'; then
        tg_status=$(systemctl is-active 5gpn-tgbot 2>/dev/null || echo "unknown")
        echo -e "5gpn-tgbot: $([[ "$tg_status" == active ]] && echo "${GREEN}running${NC}" || echo "${RED}$tg_status${NC}")"
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^5gpn-api\.service'; then
        api_status=$(systemctl is-active 5gpn-api 2>/dev/null || echo "unknown")
        echo -e "5gpn-api: $([[ "$api_status" == active ]] && echo "${GREEN}running${NC}" || echo "${RED}$api_status${NC}")"
    fi
    echo ""
    if [[ -f "${CONF_DIR}/.domain" ]]; then
        echo "Domain: $(cat "${CONF_DIR}/.domain")"
    fi
    echo "Public IP: ${PUBLIC_IP:-N/A}"
    local cur_exit="local"
    [[ -f "${CONF_DIR}/current-exit" ]] && cur_exit="$(cat "${CONF_DIR}/current-exit" 2>/dev/null || echo local)"
    echo "Egress exit: ${cur_exit}"
    if [[ -f /etc/5gpn/failover.enabled ]]; then
        echo -e "Failover: ${GREEN}on${NC} (timer: $(systemctl is-active 5gpn-failover.timer 2>/dev/null || echo unknown))"
    fi
    if [[ -f /etc/mosdns/.cache_size ]]; then
        local cs; cs="$(cat /etc/mosdns/.cache_size 2>/dev/null || echo '?')"
        echo "Mem profile: $([[ "$cs" -le 50000 ]] 2>/dev/null && echo low-memory || echo standard) (mosdns cache=${cs})"
    fi
    echo "=========================================="
}
# Record / display the git revision currently deployed under /opt/5gpn.
repo_head_full() {
    git -C "${BASE_DIR}" rev-parse HEAD 2>/dev/null || true
}
repo_origin_main_full() {
    # Prefer the remote-tracking ref; fall back to FETCH_HEAD from an explicit
    # `git fetch origin main` (some shallow clones only update FETCH_HEAD).
    local rev
    rev="$(git -C "${BASE_DIR}" rev-parse origin/main 2>/dev/null || true)"
    if [[ -z "$rev" || "$rev" == *'needed'* ]]; then
        rev="$(git -C "${BASE_DIR}" rev-parse FETCH_HEAD 2>/dev/null || true)"
    fi
    printf '%s' "$rev"
}
record_deployed_revision() {
    local full short subject branch file="${CONF_DIR}/.deployed-rev"
    mkdir -p "${CONF_DIR}"
    full="$(repo_head_full)"
    [[ -n "$full" ]] || return 0
    short="$(git -C "${BASE_DIR}" rev-parse --short HEAD 2>/dev/null || echo "${full:0:7}")"
    subject="$(git -C "${BASE_DIR}" log -1 --pretty=%s 2>/dev/null | tr '\n' ' ' || true)"
    branch="$(git -C "${BASE_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
    {
        echo "full=${full}"
        echo "short=${short}"
        echo "branch=${branch}"
        echo "subject=${subject}"
        echo "recorded_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$file"
    chmod 0644 "$file" 2>/dev/null || true
}
deployed_revision_line() {
    local full short subject branch dirty="" file="${CONF_DIR}/.deployed-rev"
    if [[ -d "${BASE_DIR}/.git" ]]; then
        full="$(repo_head_full)"
        if [[ -n "$full" ]]; then
            short="$(git -C "${BASE_DIR}" rev-parse --short HEAD 2>/dev/null || echo "${full:0:7}")"
            subject="$(git -C "${BASE_DIR}" log -1 --pretty=%s 2>/dev/null | tr '\n' ' ' || true)"
            branch="$(git -C "${BASE_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
            if [[ -n "$(git -C "${BASE_DIR}" status --porcelain 2>/dev/null || true)" ]]; then
                dirty=" (dirty)"
            fi
            printf '%s %s [%s]%s' "$short" "$subject" "$branch" "$dirty"
            return 0
        fi
    fi
    if [[ -f "$file" ]]; then
        short="$(awk -F= '/^short=/{print substr($0,7); exit}' "$file")"
        subject="$(awk -F= '/^subject=/{print substr($0,9); exit}' "$file")"
        branch="$(awk -F= '/^branch=/{print substr($0,8); exit}' "$file")"
        [[ -n "$short" ]] || return 0
        printf '%s %s [%s] (recorded)' "$short" "${subject:-?}" "${branch:-?}"
        return 0
    fi
    return 0
}
# Fetch origin/main into the checkout and hard-reset onto it. Returns 0 when
# HEAD moved, 1 when already current, 2 on fetch failure.
sync_repo_to_origin_main() {
    local before after remote_rev
    command -v git >/dev/null 2>&1 || return 2
    [[ -d "${BASE_DIR}/.git" ]] || return 2

    before="$(repo_head_full)"
    # Force-update the remote-tracking ref (works for shallow clones and avoids
    # relying on a possibly stale origin/main after plain `git pull`).
    if ! git -C "${BASE_DIR}" fetch --prune origin \
            "+refs/heads/main:refs/remotes/origin/main" 2>/dev/null; then
        # Fallback for older git / odd remotes.
        if ! git -C "${BASE_DIR}" fetch --depth 1 origin main 2>/dev/null; then
            return 2
        fi
    fi
    remote_rev="$(repo_origin_main_full)"
    if [[ -z "$remote_rev" ]]; then
        return 2
    fi
    if [[ "$before" == "$remote_rev" ]]; then
        return 1
    fi
    # Detach/feature-branch safe: recreate local main on origin/main.
    git -C "${BASE_DIR}" checkout -B main "$remote_rev" >/dev/null 2>&1 \
        || git -C "${BASE_DIR}" reset --hard "$remote_rev" >/dev/null 2>&1 \
        || return 2
    git -C "${BASE_DIR}" reset --hard "$remote_rev" >/dev/null 2>&1 || return 2
    git -C "${BASE_DIR}" branch --set-upstream-to=origin/main main >/dev/null 2>&1 || true
    after="$(repo_head_full)"
    if [[ -z "$after" || "$after" == "$before" ]]; then
        # remote_rev differed but reset didn't move HEAD — treat as failure.
        [[ "$after" == "$remote_rev" ]] && return 1
        return 2
    fi
    info "代码已更新: ${before:0:7} → ${after:0:7} ($(git -C "${BASE_DIR}" log -1 --pretty=%s 2>/dev/null || true))"
    return 0
}
# Post-deploy readiness probe: "service started" is not "service usable".
# Runs doctor --deep --json once and classifies failures by surface:
#   core     — services / listening ports / control API → deploy fails
#   advisory — DNS answers, egress path, certs → warn only (domain
#              propagation and cert issuance are legitimately transient)
# Never rolls back automatically: fail-before-publish, report the stage.
verify_installation() {
    local doctor="${BASE_DIR}/scripts/doctor.sh" out classified rc line tag msg
    [[ -f "${doctor}" ]] || { warn "doctor.sh 不存在，跳过就绪探测"; return 0; }
    command -v python3 >/dev/null 2>&1 || { warn "python3 不存在，跳过就绪探测"; return 0; }
    # Services were (re)started seconds ago; on low-memory hosts mosdns needs
    # a while to load rulesets and bind 53/853. Wait for the core listeners
    # before probing, otherwise a slow start is misreported as a core failure.
    local i
    for i in $(seq 1 30); do
        ss -H -tln 2>/dev/null | grep -qE ':853( |$)' \
            && ss -H -uln 2>/dev/null | grep -qE ':53( |$)' && break
        sleep 2
    done
    info "就绪探测 (doctor --deep)..."
    out="$(bash "${doctor}" --deep --json 2>/dev/null || true)"
    [[ -n "${out}" ]] || { warn "就绪探测无输出，跳过判定"; return 0; }
    if classified="$(OUT="${out}" python3 - <<'PY'
import json, os, sys
try:
    data = json.loads(os.environ.get("OUT", "") or "{}")
except ValueError:
    sys.exit(2)
CORE_PREFIXES = ("服务 ",)
CORE_LABELS = {"DoT", "DNS", "HTTPS/SNI", "控制 API",
               "Clash API", "Clash API 暴露", "API /health"}
core = 0
for c in data.get("checks", []):
    if c.get("level") != "fail":
        continue
    label = c.get("check", "")
    tag = "CORE" if (label.startswith(CORE_PREFIXES) or label in CORE_LABELS) else "ADVISORY"
    core += (tag == "CORE")
    print(f"{tag}\t{label}: {c.get('detail', '')}")
sys.exit(1 if core else 0)
PY
)"; then rc=0; else rc=$?; fi
    if [[ $rc -eq 2 ]]; then
        warn "就绪探测输出无法解析，跳过判定"
        return 0
    fi
    while IFS=$'\t' read -r tag msg; do
        [[ -n "${tag}" ]] || continue
        if [[ "${tag}" == "CORE" ]]; then
            err "就绪探测(核心): ${msg}"
        else
            warn "就绪探测(非核心): ${msg}"
        fi
    done <<< "${classified}"
    [[ $rc -eq 0 ]] && ok "就绪探测通过"
    return $rc
}
do_update() {
    check_root
    detect_os
    detect_memory_profile
    get_public_ip 2>/dev/null || true
    DOMAIN="${DOMAIN:-$(cat "${CONF_DIR}/.domain" 2>/dev/null || cat /etc/mosdns/.domain 2>/dev/null || true)}"
    PUBLIC_IP="${PUBLIC_IP:-$(cat /etc/mosdns/.public_ip 2>/dev/null || true)}"
    info "更新 5GPN-X（保留全部配置）..."

    local snap_id="${PGW_UPDATE_SNAPSHOT:-}"
    mkdir -p "${BASE_DIR}/scripts"
    for f in doctor.sh snapshot.sh report.sh health-notify.sh smoke-check.sh; do
        install_repo_script "${SCRIPT_DIR}/scripts/${f}" "${BASE_DIR}/scripts/${f}"
    done

    # Always keep a rollback point before mutating runtime (including the
    # first upgrade onto this feature when G5PNX_UPDATED was set by old code).
    if [[ -z "$snap_id" && -x "${BASE_DIR}/scripts/snapshot.sh" ]]; then
        info "更新前创建配置快照..."
        snap_id="$(bash "${BASE_DIR}/scripts/snapshot.sh" create pre-update 2>/dev/null | tail -1 || true)"
        if [[ -z "$snap_id" || "$snap_id" == *ERR* ]]; then
            err "创建更新前快照失败；已中止更新（避免无回滚点）"
            exit 1
        fi
        export PGW_UPDATE_SNAPSHOT="$snap_id"
        ok "快照: ${snap_id}"
    fi

    if [[ -z "${G5PNX_UPDATED:-}" ]]; then
        info "拉取最新代码 (origin/main)..."
        local sync_rc=0
        sync_repo_to_origin_main || sync_rc=$?
        case "$sync_rc" in
            0)
                export G5PNX_UPDATED=1
                export PGW_UPDATE_SNAPSHOT="${snap_id}"
                exec bash "${BASE_DIR}/install.sh" --update
                ;;
            1)
                ok "代码已是最新 ($(git -C "${BASE_DIR}" rev-parse --short HEAD 2>/dev/null || echo unknown))"
                ;;
            *)
                warn "git fetch 失败（网络问题？），将使用当前代码更新运行时"
                warn "也可手动: cd ${BASE_DIR} && git fetch origin main && git reset --hard origin/main"
                ;;
        esac
    fi

    _pgw_update_rollback() {
        local rc=$?
        trap - ERR
        if [[ "$rc" -ne 0 && -n "${snap_id:-}" ]]; then
            err "更新失败 (exit ${rc})，正在回滚快照 ${snap_id} ..."
            bash "${BASE_DIR}/scripts/snapshot.sh" restore "$snap_id" || warn "自动回滚失败，请手动: 5gpn rollback ${snap_id}"
        fi
        exit "$rc"
    }
    trap _pgw_update_rollback ERR

    install_deps
    cur_ns="$(cat /etc/mosdns/.remote_dns 2>/dev/null || cat "${CONF_DIR}/.remote_dns" 2>/dev/null || echo "${DEFAULT_REMOTE_DNS[*]}")"
    REMOTE_DNS="$cur_ns" install_sniproxy
    install_whatsapp_shim
    # One-time cleanup for upgrades from releases that shipped WLOC (removed
    # after Apple blocked gs-loc interception via certificate pinning):
    # disable the old unit and delete its runtime files. Best-effort.
    if [[ -f /etc/systemd/system/5gpn-wloc.service || -d "${CONF_DIR}/wloc" ]]; then
        info "Removing leftover WLOC runtime from a previous install..."
        systemctl disable --now 5gpn-wloc.service 2>/dev/null || true
        rm -f /etc/systemd/system/5gpn-wloc.service
        rm -rf "${CONF_DIR}/wloc" /var/lib/5gpn/wloc
        rm -f /etc/mosdns/wloc.txt
        rm -f "${BASE_DIR}/bin/wloc-interceptor.py" "${BASE_DIR}/bin/wloc_rewrite.py" "${BASE_DIR}/bin/wloc_wifitile.py"
        userdel wloc 2>/dev/null || true; groupdel wloc 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    fi
    cmp -s "${LIB_DIR}/quic-proxy.go" "${SRC_DIR}/quic-proxy.go" 2>/dev/null || rm -f "${BASE_DIR}/bin/quic-proxy"
    install_quic_proxy
    cmp -s "${LIB_DIR}/client-socks.go" "${SRC_DIR}/client-socks.go" 2>/dev/null || rm -f "${BASE_DIR}/bin/client-socks"
    install_client_socks_binary
    if [[ -f "${CLIENT_SOCKS_ENABLED}" ]]; then
        client_socks_ensure_creds
        systemctl restart 5gpn-client-socks.service 2>/dev/null || true
        declare -F firewall_socks_sync >/dev/null 2>&1 && firewall_socks_sync || true
    fi
    cmp -s "${LIB_DIR}/client-mtproto.go" "${SRC_DIR}/client-mtproto.go" 2>/dev/null || rm -f "${BASE_DIR}/bin/client-mtproto"
    install_client_mtproto_binary || warn "client-mtproto 二进制安装失败（可稍后手动 enable-client-mtproto）"
    if [[ -f "${CLIENT_MTPROTO_ENABLED}" ]]; then
        client_mtproto_ensure_creds || warn "MTProto 凭据同步失败"
        systemctl restart 5gpn-mtproxy.service 5gpn-client-mtproto.service 2>/dev/null || true
        declare -F firewall_mtproto_sync >/dev/null 2>&1 && firewall_mtproto_sync || true
    fi
    cmp -s "${LIB_DIR}/clash-remote.go" "${SRC_DIR}/clash-remote.go" 2>/dev/null || rm -f "${BASE_DIR}/bin/clash-remote"
    install_clash_remote_binary || warn "clash-remote 二进制安装失败（可稍后手动 enable-clash-remote）"
    if [[ -f "${CLASH_REMOTE_ENABLED}" ]]; then
        clash_remote_ensure_creds || warn "clash-remote 凭据同步失败"
        systemctl restart 5gpn-clash-remote.service 2>/dev/null || true
        declare -F firewall_clash_remote_sync >/dev/null 2>&1 && firewall_clash_remote_sync || true
    fi
    install_mosdns_binary
    cp "${LIB_DIR}/mosdns.yaml.template" /etc/mosdns/config.yaml.template
    install -m 0755 "${LIB_DIR}/update-rules.sh" /usr/local/bin/update-mosdns-rules.sh
    clamp_mosdns_cache_size
    touch /etc/mosdns/direct-domains.txt 2>/dev/null || true
    [[ -f /etc/mosdns/.client_cidr ]] || echo "${CLIENT_CIDR:-172.22.0.0/16}" > /etc/mosdns/.client_cidr
    # The live config is rendered from the template only by update-mosdns-rules.sh
    # (weekly timer / --update-rules). If a release changes the template, the
    # rendered config must be refreshed here too — a stale config once kept the
    # removed WLOC plugin and crash-looped mosdns after wloc.txt was cleaned up.
    # render_config validates before publishing, so a failure leaves the old
    # config in place and only warns.
    /usr/local/bin/update-mosdns-rules.sh >/dev/null 2>&1 || warn "mosdns 配置重渲染失败，请手动运行 5gpn update-rules"
    setup_exit_switching
    generate_ios_profile
    apply_lowmem_go_limits
    setup_schedules
    install_cli
    local f n cur_exit
    shopt -s nullglob
    for f in "${EXITS_DIR}"/*.uri; do
        n="$(basename "$f" .uri)"
        ( PGW_EXIT_OVERWRITE=1 add_exit "$n" < "$f" ) >/dev/null 2>&1 \
            || warn "重建出口 $n 失败，可手动 --edit-exit $n"
    done
    shopt -u nullglob
    cur_exit="$(cat "${CONF_DIR}/current-exit" 2>/dev/null || echo local)"
    [[ -f "${CONF_DIR}/api.env" ]] && setup_api
    if [[ -f "${CONF_DIR}/tgbot.env" ]]; then
        # Re-render the unit too (hardening directives land via setup_tgbot);
        # reusing the existing env keeps tokens/IDs untouched. stdin is pinned
        # away from the tty so setup_tgbot never prompts mid-update.
        local tg_token tg_ids
        tg_token="$(sed -n 's/^TG_BOT_TOKEN=//p' "${CONF_DIR}/tgbot.env" | head -n1)"
        tg_ids="$(sed -n 's/^TG_ADMIN_IDS=//p' "${CONF_DIR}/tgbot.env" | head -n1)"
        if [[ -n "$tg_token" ]]; then
            TG_BOT_TOKEN="$tg_token" TG_ADMIN_IDS="$tg_ids" setup_tgbot </dev/null
        else
            install -m 0755 "${LIB_DIR}/tgbot.py" "${BASE_DIR}/bin/tgbot.py"
        fi
        # Keep Bot UTF-8-safe under systemd LANG=C (doctor --json / Chinese UI).
        mkdir -p /etc/systemd/system/5gpn-tgbot.service.d
        cat > /etc/systemd/system/5gpn-tgbot.service.d/locale.conf <<'EOF'
[Service]
Environment=LANG=C.UTF-8
Environment=PYTHONIOENCODING=utf-8
Environment=PYTHONUTF8=1
EOF
        systemctl daemon-reload
        systemctl restart 5gpn-tgbot 2>/dev/null || true
    fi
    [[ -f "${RULES_FILE}" ]] && { ( regen_smart ) || warn "smart 配置重建失败；可稍后手动 --set-rules"; }
    if [[ "$cur_exit" != "local" && "$cur_exit" != "smart" ]]; then
        systemctl reset-failed "5gpn-mihomo@${cur_exit}.service" 2>/dev/null || true
        systemctl restart "5gpn-mihomo@${cur_exit}.service" 2>/dev/null || true
    fi
    systemctl reset-failed mosdns sniproxy wa-shim quic-proxy 2>/dev/null || true
    systemctl restart mosdns sniproxy wa-shim quic-proxy
    record_deployed_revision
    trap - ERR
    if ! verify_installation; then
        err "更新后核心就绪探测失败；请运行 sudo 5gpn doctor --deep 排查，必要时 sudo 5gpn rollback ${snap_id:-latest}"
        exit 1
    fi
    ok "更新完成 ($(deployed_revision_line))；回滚点: ${snap_id:-none}"
}
do_uninstall() {
    warn "This will remove sniproxy, quic-proxy, mosdns configs, and rules."
    read -r -p "Are you sure? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "Uninstall cancelled"; exit 0; }
    set_exit local 2>/dev/null || true
    ip rule del fwmark "${EXIT_MARK}" table "${EXIT_TABLE}" 2>/dev/null || true
    ip route flush table "${EXIT_TABLE}" 2>/dev/null || true
    shopt -s nullglob
    for f in "${WG_DIR}"/pgw-*.conf; do
        wg-quick down "$(basename "$f" .conf)" 2>/dev/null || true
    done
    for f in "${EXITS_DIR}"/*.type; do
        systemctl stop "$(exit_mihomo_unit "$(basename "$f" .type)")" 2>/dev/null || true
        systemctl stop "5gpn-singbox@$(basename "$f" .type).service" 2>/dev/null || true
    done
    shopt -u nullglob
    systemctl stop mosdns dnsdist sniproxy wa-shim quic-proxy china-dns-race-proxy 5gpn-ios-profile.socket 5gpn-ios-profile 5gpn-exit 5gpn-tgbot 5gpn-api 5gpn-health.timer 5gpn-health.service 5gpn-client-socks 5gpn-client-mtproto 5gpn-mtproxy 5gpn-mtg 5gpn-clash-remote 2>/dev/null || true
    systemctl disable mosdns dnsdist sniproxy wa-shim quic-proxy china-dns-race-proxy 5gpn-ios-profile.socket 5gpn-ios-profile 5gpn-exit 5gpn-tgbot 5gpn-api 5gpn-health.timer 5gpn-health.service 5gpn-client-socks 5gpn-client-mtproto 5gpn-mtproxy 5gpn-mtg 5gpn-clash-remote 2>/dev/null || true
    rm -f /etc/systemd/system/{mosdns,sniproxy,wa-shim,quic-proxy,china-dns-race-proxy,5gpn-ios-profile,update-mosdns-rules,5gpn-exit,5gpn-tgbot}.*
    rm -f /etc/systemd/system/5gpn-api.*
    rm -f /etc/systemd/system/5gpn-health.service /etc/systemd/system/5gpn-health.timer
    rm -f /etc/systemd/system/5gpn-client-socks.service
    rm -f /etc/systemd/system/5gpn-client-mtproto.service /etc/systemd/system/5gpn-mtproxy.service /etc/systemd/system/5gpn-mtg.service
    rm -f /etc/systemd/system/5gpn-clash-remote.service
    declare -F firewall_socks_remove_rules >/dev/null 2>&1 && firewall_socks_remove_rules || true
    declare -F firewall_mtproto_remove_rules >/dev/null 2>&1 && firewall_mtproto_remove_rules || true
    declare -F firewall_clash_remote_remove_rules >/dev/null 2>&1 && firewall_clash_remote_remove_rules || true
    rm -f /usr/local/bin/5gpn
    rm -f /etc/systemd/system/5gpn-ios-profile@.service \
        /etc/systemd/system/5gpn-mihomo@.service \
        /etc/systemd/system/5gpn-singbox@.service
    rm -rf /etc/systemd/system/quic-proxy.service.d /etc/systemd/system/mosdns.service.d \
        /etc/systemd/system/dnsdist.service.d /etc/systemd/system/china-dns-race-proxy.service.d
    systemctl daemon-reload
    rm -rf "$BASE_DIR" /etc/sniproxy.conf /etc/mosdns /etc/dnsdist /usr/local/bin/update-mosdns-rules.sh
    rm -f /usr/local/bin/update-dnsdist-rules.sh /usr/local/bin/mosdns
    rm -f /usr/local/sbin/sniproxy
    rm -f /usr/local/bin/5gpn-apply-exit.sh
    rm -f "${WG_DIR}"/pgw-*.conf
    # Repair the host firewall BEFORE removing /etc/5gpn, otherwise a
    # managed /etc/nftables.conf would keep a dangling include and fail to load
    # on reboot (leaving the host with no firewall). Also clears auto-mode
    # persistence and the managed marker.
    firewall_cleanup_on_uninstall
    rm -rf /etc/5gpn
    rm -f /etc/letsencrypt/renewal-hooks/deploy/99-reload-mosdns.sh
    rm -f /etc/sysctl.d/99-5gpn.conf
    rm -f /etc/profile.d/go.sh
    if [[ -f /etc/nftables.conf.pgw-backup ]]; then
        warn "Pre-install firewall backup kept at /etc/nftables.conf.pgw-backup (restore manually if wanted)."
    fi
    userdel "${EXIT_USER}" 2>/dev/null || true
    userdel mosdns 2>/dev/null || true
    rm -rf /var/lib/5gpn
    warn "SSL certificates in /etc/letsencrypt/live/ are kept. Remove manually if needed."
    if [[ -e /swapfile ]]; then
        warn "Swapfile /swapfile is kept. To remove: swapoff /swapfile && rm -f /swapfile && sed -i '/^\\/swapfile /d' /etc/fstab"
    fi
    ok "Uninstall completed"
}
force_renew_cert() {
    ensure_mosdns_user
    if [[ -f "${CONF_DIR}/.domain" ]]; then
        DOMAIN=$(cat "${CONF_DIR}/.domain")
    fi
    if [[ -z "${DOMAIN:-}" ]]; then
        err "No domain found. Cannot renew."
        exit 1
    fi
    get_public_ip
    certbot_diagnostics "$DOMAIN"
    if ! command -v certbot >/dev/null 2>&1; then
        err "certbot 不存在，无法签发/续期证书。请重新运行安装脚本安装依赖。"
        exit 1
    fi
    local certbot_cmd=()
    if [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
        certbot_cmd=(certbot certonly --standalone -d "$DOMAIN" --force-renewal \
            --agree-tos -n -m "${EMAIL:-admin@${DOMAIN}}" \
            --pre-hook /usr/local/bin/5gpn-open-cert-http.sh \
            --post-hook /usr/local/bin/5gpn-restore-firewall.sh)
    else
        certbot_cmd=(certbot certonly --standalone -d "$DOMAIN" \
            --agree-tos -n -m "${EMAIL:-admin@${DOMAIN}}" \
            --pre-hook /usr/local/bin/5gpn-open-cert-http.sh \
            --post-hook /usr/local/bin/5gpn-restore-firewall.sh)
    fi
    prepare_certbot_standalone
    trap cleanup_certbot_standalone RETURN
    local out retry_out rc
    if out="$("${certbot_cmd[@]}" 2>&1)"; then rc=0; else rc=$?; fi
    printf '%s\n' "$out"
    if [[ $rc -ne 0 ]]; then
        if grep -q "AttributeError" <<<"$out"; then
            warn "Certbot compatibility error detected. Attempting to fix Python dependencies..."
            pip3 install --upgrade --break-system-packages certbot josepy cryptography 2>/dev/null || \
                pip3 install --upgrade certbot josepy cryptography 2>/dev/null || true
            info "Retrying certificate renewal..."
            if retry_out="$("${certbot_cmd[@]}" 2>&1)"; then rc=0; else rc=$?; fi
            printf '%s\n' "$retry_out"
            if [[ $rc -ne 0 ]]; then
                err "证书续期/签发失败。certbot 最后输出:"
                if [[ -n "$retry_out" ]]; then
                    printf '%s\n' "$retry_out" | tail -n 30 >&2
                else
                    err "certbot 没有输出；请检查端口 80 是否被其他服务占用，以及防火墙是否允许外部访问 80。"
                fi
                exit 1
            fi
        else
            err "证书续期/签发失败。certbot 最后输出:"
            if [[ -n "$out" ]]; then
                printf '%s\n' "$out" | tail -n 30 >&2
            else
                err "certbot 没有输出；请检查端口 80 是否被其他服务占用，以及防火墙是否允许外部访问 80。"
            fi
            exit 1
        fi
    fi
    local cert_live_dir="/etc/letsencrypt/live/${DOMAIN}"
    if [[ -d "$cert_live_dir" ]]; then
        mkdir -p /etc/mosdns/certs
        cp "${cert_live_dir}/fullchain.pem" /etc/mosdns/certs/fullchain.pem
        cp "${cert_live_dir}/privkey.pem" /etc/mosdns/certs/privkey.pem
        chown -R mosdns:mosdns /etc/mosdns/certs/
        chmod 600 /etc/mosdns/certs/*.pem
    fi
    if systemctl is-active --quiet mosdns; then
        systemctl restart mosdns && ok "Certificate renewed and mosdns reloaded"
    else
        systemctl start mosdns && ok "Certificate renewed and mosdns started"
    fi
}
regenerate_ios_profile() {
    if [[ -f "${CONF_DIR}/.domain" ]]; then
        DOMAIN=$(cat "${CONF_DIR}/.domain")
    elif [[ -f /etc/mosdns/.domain ]]; then
        DOMAIN=$(cat /etc/mosdns/.domain)
    fi
    if [[ -f /etc/mosdns/.public_ip ]]; then
        PUBLIC_IP=$(cat /etc/mosdns/.public_ip)
    else
        get_public_ip
    fi
    if [[ -z "${DOMAIN:-}" ]]; then
        err "No domain found. Cannot generate iOS profile."
        exit 1
    fi
    generate_ios_profile
}
set_dot_domain() {
    local new_domain="${1:-}" resolved="" old_conf_domain="" old_mosdns_domain="" old_cert_basename=""
    [[ -n "$new_domain" ]] || { err "Usage: $0 --set-dot-domain <domain>"; exit 1; }
    if ! is_valid_domain "$new_domain"; then
        err "Invalid domain: '$new_domain'. Provide a fully-qualified domain like dns.example.com"
        exit 1
    fi
    get_public_ip
    info "DNS 解析检查"
    info "域名: $new_domain"
    info "需要的 A 记录值: $PUBLIC_IP"
    resolved=$(resolve_domain_a_records "$new_domain" | paste -sd',' - || true)
    if ! domain_resolves_to_public_ip "$new_domain" "$PUBLIC_IP"; then
        err "$new_domain 当前解析到 ${resolved:-无}，不是本机 $PUBLIC_IP"
        err "请先把 A 记录指向本机公网 IP 后重试。"
        exit 1
    fi
    old_conf_domain=$(cat "${CONF_DIR}/.domain" 2>/dev/null || true)
    old_mosdns_domain=$(cat /etc/mosdns/.domain 2>/dev/null || true)
    old_cert_basename=$(cat "${CONF_DIR}/.cert_basename" 2>/dev/null || true)
    DOMAIN="$new_domain"
    install_cert
    mkdir -p "$CONF_DIR" /etc/mosdns
    echo "$DOMAIN" > "${CONF_DIR}/.domain"
    echo "$DOMAIN" > /etc/mosdns/.domain
    rm -f "${CONF_DIR}/.cert_basename"
    if [[ -f /usr/local/bin/update-mosdns-rules.sh ]]; then
        if ! /usr/local/bin/update-mosdns-rules.sh; then
            restore_or_remove_file "$old_conf_domain" "${CONF_DIR}/.domain"
            restore_or_remove_file "$old_mosdns_domain" /etc/mosdns/.domain
            restore_or_remove_file "$old_cert_basename" "${CONF_DIR}/.cert_basename"
            /usr/local/bin/update-mosdns-rules.sh >/dev/null 2>&1 || true
            err "mosdns config update failed; DoT domain rolled back"
            exit 1
        fi
    elif ! systemctl restart mosdns; then
        restore_or_remove_file "$old_conf_domain" "${CONF_DIR}/.domain"
        restore_or_remove_file "$old_mosdns_domain" /etc/mosdns/.domain
        restore_or_remove_file "$old_cert_basename" "${CONF_DIR}/.cert_basename"
        err "mosdns restart failed; DoT domain rolled back"
        exit 1
    fi
    regenerate_ios_profile || warn "iOS profile regeneration failed"
    ok "DoT domain updated: $DOMAIN"
}
force_set_dot_domain() {
    local new_domain="${1:-}" resolved="" old_conf_domain="" old_mosdns_domain="" old_cert_basename=""
    [[ -n "$new_domain" ]] || { err "Usage: $0 --set-dot-domain-force <domain>"; exit 1; }
    if ! is_valid_domain "$new_domain"; then
        err "Invalid domain: '$new_domain'. Provide a fully-qualified domain like dns.example.com"
        exit 1
    fi
    get_public_ip
    resolved=$(resolve_domain_a_records "$new_domain" | paste -sd',' - || true)
    if ! domain_resolves_to_public_ip "$new_domain" "$PUBLIC_IP"; then
        warn "$new_domain 当前解析到 ${resolved:-无}，不是本机 $PUBLIC_IP；按强制模式继续。"
    fi
    old_conf_domain=$(cat "${CONF_DIR}/.domain" 2>/dev/null || true)
    old_mosdns_domain=$(cat /etc/mosdns/.domain 2>/dev/null || true)
    old_cert_basename=$(cat "${CONF_DIR}/.cert_basename" 2>/dev/null || true)
    DOMAIN="$new_domain"
    mkdir -p "$CONF_DIR" /etc/mosdns
    echo "$DOMAIN" > "${CONF_DIR}/.domain"
    echo "$DOMAIN" > /etc/mosdns/.domain
    rm -f "${CONF_DIR}/.cert_basename"
    if [[ -f /usr/local/bin/update-mosdns-rules.sh ]]; then
        if ! /usr/local/bin/update-mosdns-rules.sh; then
            restore_or_remove_file "$old_conf_domain" "${CONF_DIR}/.domain"
            restore_or_remove_file "$old_mosdns_domain" /etc/mosdns/.domain
            restore_or_remove_file "$old_cert_basename" "${CONF_DIR}/.cert_basename"
            /usr/local/bin/update-mosdns-rules.sh >/dev/null 2>&1 || true
            err "mosdns config update failed; DoT domain rolled back"
            exit 1
        fi
    elif ! systemctl restart mosdns; then
        restore_or_remove_file "$old_conf_domain" "${CONF_DIR}/.domain"
        restore_or_remove_file "$old_mosdns_domain" /etc/mosdns/.domain
        restore_or_remove_file "$old_cert_basename" "${CONF_DIR}/.cert_basename"
        err "mosdns restart failed; DoT domain rolled back"
        exit 1
    fi
    regenerate_ios_profile || warn "iOS profile regeneration failed"
    warn "DoT domain forcibly updated without issuing a new certificate. Run --renew-cert after fixing certbot/port 80 issues."
    ok "DoT domain forcibly updated: $DOMAIN"
}
set_ecs() {
    local ecs="${1:-}"
    [[ -n "$ecs" ]] || { err "Usage: $0 --set-ecs <a.b.c.d[/24]>"; exit 1; }
    python3 - "$ecs" <<'PY' || { err "无效的 ECS（需为 IPv4 地址或 IPv4/前缀，如 112.96.54.0/24）"; exit 1; }
import ipaddress
import sys
value = sys.argv[1]
if "/" in value:
    net = ipaddress.ip_network(value, strict=False)
    if net.version != 4 or net.prefixlen > 30:
        raise SystemExit(1)
else:
    ipaddress.ip_address(value)
PY
    mkdir -p /etc/mosdns
    echo "$ecs" > /etc/mosdns/.ecs
    /usr/local/bin/update-mosdns-rules.sh >/dev/null 2>&1 || warn "配置刷新失败，请手动运行 $0 --update-rules"
    ok "ECS 已设置为 $ecs 并生效"
}
set_client_cidr() {
    local cidr="${1:-}"
    [[ -n "$cidr" ]] || { err "Usage: $0 --set-client-cidr <a.b.c.0/16[,10.0.0.0/16...]>"; exit 1; }
    if ! cidr="$(FORCE_WIDE_CIDR="${FORCE_WIDE_CIDR:-0}" python3 - "$cidr" <<'PY'
import ipaddress, os, sys
raw = sys.argv[1].replace(";", ",").replace(" ", ",")
parts = [p.strip() for p in raw.split(",") if p.strip()]
if not parts:
    raise SystemExit(1)
force = os.environ.get("FORCE_WIDE_CIDR", "0") == "1"
out = []
for p in parts:
    net = ipaddress.ip_network(p, strict=False)
    if net.version != 4 or not (8 <= net.prefixlen <= 30):
        raise SystemExit(1)
    if net.prefixlen < 16 and not force:
        raise SystemExit(1)
    out.append(str(net))
print(",".join(out))
PY
)"; then
        err "无效 CIDR（IPv4 /16../30，多段用逗号；宽网段需 FORCE_WIDE_CIDR=1）"; exit 1
    fi
    [[ -n "$cidr" ]] || { err "无效 CIDR"; exit 1; }
    mkdir -p /etc/mosdns "$CONF_DIR"
    echo "$cidr" > /etc/mosdns/.client_cidr
    echo "$cidr" > "${CONF_DIR}/.client_cidr"
    # Keep wa-shim allow list in sync when present.
    if [[ -f "${CONF_DIR}/wa-shim.env" ]]; then
        if grep -q '^WA_SHIM_ALLOW_CIDR=' "${CONF_DIR}/wa-shim.env"; then
            sed -i -E "s#^WA_SHIM_ALLOW_CIDR=.*#WA_SHIM_ALLOW_CIDR=${cidr},127.0.0.0/8#" "${CONF_DIR}/wa-shim.env"
        else
            echo "WA_SHIM_ALLOW_CIDR=${cidr},127.0.0.0/8" >> "${CONF_DIR}/wa-shim.env"
        fi
        systemctl restart wa-shim 2>/dev/null || true
    fi
    if [[ -f "${CLIENT_SOCKS_ENV}" ]]; then
        if grep -q '^SOCKS_ALLOW_CIDR=' "${CLIENT_SOCKS_ENV}"; then
            sed -i -E "s#^SOCKS_ALLOW_CIDR=.*#SOCKS_ALLOW_CIDR=${cidr}#" "${CLIENT_SOCKS_ENV}"
        else
            echo "SOCKS_ALLOW_CIDR=${cidr}" >> "${CLIENT_SOCKS_ENV}"
        fi
        [[ -f "${CLIENT_SOCKS_ENABLED}" ]] && systemctl restart 5gpn-client-socks.service 2>/dev/null || true
    fi
    if [[ -f "${CLIENT_MTPROTO_ENV}" ]]; then
        if grep -q '^MTPROTO_ALLOW_CIDR=' "${CLIENT_MTPROTO_ENV}"; then
            sed -i -E "s#^MTPROTO_ALLOW_CIDR=.*#MTPROTO_ALLOW_CIDR=${cidr}#" "${CLIENT_MTPROTO_ENV}"
        else
            echo "MTPROTO_ALLOW_CIDR=${cidr}" >> "${CLIENT_MTPROTO_ENV}"
        fi
        [[ -f "${CLIENT_MTPROTO_ENABLED}" ]] && systemctl restart 5gpn-client-mtproto.service 2>/dev/null || true
    fi
    if [[ -f "${CLASH_REMOTE_ENV}" ]]; then
        local extra_cr allow_cr
        extra_cr="$(sed -n 's/^CLASH_REMOTE_EXTRA_CIDR=//p' "${CLASH_REMOTE_ENV}" | head -1)"
        allow_cr="$(clash_remote_merge_allow_cidr "$extra_cr")"
        if grep -q '^CLASH_REMOTE_ALLOW_CIDR=' "${CLASH_REMOTE_ENV}"; then
            sed -i -E "s#^CLASH_REMOTE_ALLOW_CIDR=.*#CLASH_REMOTE_ALLOW_CIDR=${allow_cr}#" "${CLASH_REMOTE_ENV}"
        else
            echo "CLASH_REMOTE_ALLOW_CIDR=${allow_cr}" >> "${CLASH_REMOTE_ENV}"
        fi
        [[ -f "${CLASH_REMOTE_ENABLED}" ]] && systemctl restart 5gpn-clash-remote.service 2>/dev/null || true
    fi
    /usr/local/bin/update-mosdns-rules.sh >/dev/null 2>&1 || warn "mosdns 刷新失败，请手动 --update-rules"
    if [[ -f /etc/5gpn/.firewall-managed ]] && declare -F firewall_managed_apply >/dev/null 2>&1; then
        local ssh_ports tcp_ports tcp_ports_ipt
        ssh_ports="$(detect_ssh_ports 2>/dev/null || echo 22)"
        tcp_ports_ipt="${ssh_ports},8111"
        tcp_ports="${tcp_ports_ipt//,/, }"
        firewall_managed_apply "$tcp_ports" "$tcp_ports_ipt" >/dev/null 2>&1 \
            || warn "托管防火墙未自动刷新；请重跑安装或手动放行 ${cidr}"
    else
        info "若使用自管防火墙，请自行放行来源 ${cidr} 的 53/80/443"
    fi
    declare -F firewall_socks_sync >/dev/null 2>&1 && firewall_socks_sync || true
    declare -F firewall_mtproto_sync >/dev/null 2>&1 && firewall_mtproto_sync || true
    declare -F firewall_clash_remote_sync >/dev/null 2>&1 && firewall_clash_remote_sync || true
    ok "客户端网段已设置为 ${cidr}"
}
confirm_client_cidr_choice() {
    # Interactive confirm for a guessed/env CIDR. Wide nets (/8../15) need FORCE_WIDE_CIDR=1
    # or an explicit typed confirmation of the same CIDR.
    local cidr="$1" ans=""
    local plen
    plen="$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False).prefixlen)' "$cidr" 2>/dev/null || echo 0)"
    if [[ "${plen:-0}" -lt 16 ]]; then
        if [[ "${FORCE_WIDE_CIDR:-0}" == "1" ]]; then
            warn "宽网段 ${cidr}（</16）已由 FORCE_WIDE_CIDR=1 放行"
        elif [[ -t 0 ]]; then
            warn "检测到宽网段 ${cidr}（前缀 < /16）。误配会扩大劫持/放行面。"
            read -r -p "确认使用该宽网段？请再次输入完整 CIDR 以确认: " ans || true
            [[ "$ans" == "$cidr" ]] || { err "未确认宽网段；请改用 /16../30，或 FORCE_WIDE_CIDR=1"; return 1; }
        else
            err "宽网段 ${cidr}（</16）在非交互安装需 FORCE_WIDE_CIDR=1 显式确认"
            return 1
        fi
    fi
    if [[ -t 0 && -z "${CLIENT_CIDR_CONFIRMED:-}" ]]; then
        echo ""
        info "客户端网段候选: ${cidr}"
        read -r -p "使用该网段？[Y/n] 或输入其他 CIDR: " ans || true
        ans="${ans## }"; ans="${ans%% }"
        if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then
            :
        elif [[ "$ans" =~ ^[Nn]$ ]]; then
            read -r -p "请输入客户端 CIDR (IPv4 /16../30，宽网段需再确认): " ans || true
            [[ -n "$ans" ]] || { err "未提供客户端网段"; return 1; }
            cidr="$ans"
            CLIENT_CIDR_CONFIRMED=1 confirm_client_cidr_choice "$cidr" || return 1
            return 0
        else
            cidr="$ans"
            CLIENT_CIDR_CONFIRMED=1 confirm_client_cidr_choice "$cidr" || return 1
            return 0
        fi
    fi
    export CLIENT_CIDR="$cidr"
    set_client_cidr "$cidr"
}
prompt_client_cidr_install() {
    # First-install CIDR: interactive detect+confirm; non-interactive uses CLIENT_CIDR env.
    if [[ -n "${CLIENT_CIDR:-}" ]]; then
        info "使用预置 CLIENT_CIDR=${CLIENT_CIDR}"
        confirm_client_cidr_choice "${CLIENT_CIDR}" || exit 1
        return 0
    fi
    if [[ -t 0 ]]; then
        local guessed
        guessed="$(python3 <<'PY'
import ipaddress, subprocess, re
out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True, stderr=subprocess.DEVNULL)
default_if = ""
try:
    rt = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
    m = re.search(r"dev\s+(\S+)", rt)
    if m:
        default_if = m.group(1)
except Exception:
    pass
cands = []
for line in out.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    iface, cidr = parts[1], parts[3]
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        continue
    if not net.is_private or net.is_loopback or net.prefixlen > 30:
        continue
    score = 0
    if iface != default_if:
        score += 10
    if net.prefixlen == 16:
        score += 3
    elif 16 < net.prefixlen <= 24:
        score += 2
    if ipaddress.ip_address(str(net.network_address)) in ipaddress.ip_network("172.16.0.0/12"):
        score += 5
    cands.append((score, str(net), iface))
cands.sort(reverse=True)
if cands:
    print(cands[0][1])
PY
)" || true
        if [[ -n "$guessed" ]]; then
            confirm_client_cidr_choice "$guessed" || exit 1
        else
            local ans=""
            read -r -p "未能自动探测；请输入客户端 CIDR [172.22.0.0/16]: " ans || true
            ans="${ans:-172.22.0.0/16}"
            confirm_client_cidr_choice "$ans" || exit 1
        fi
    else
        export CLIENT_CIDR="${CLIENT_CIDR:-172.22.0.0/16}"
        confirm_client_cidr_choice "${CLIENT_CIDR}" || exit 1
    fi
}
detect_client_cidr() {
    # Prefer RFC1918 addresses on non-default-route interfaces (typical NPN NIC).
    local guessed
    guessed="$(python3 <<'PY'
import ipaddress, subprocess, re
out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True, stderr=subprocess.DEVNULL)
default_if = ""
try:
    rt = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
    m = re.search(r"dev\s+(\S+)", rt)
    if m:
        default_if = m.group(1)
except Exception:
    pass
cands = []
for line in out.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    iface, cidr = parts[1], parts[3]
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        continue
    if not net.is_private or net.is_loopback or net.prefixlen > 30:
        continue
    # Prefer non-default-route NIC (NPN data path), else any private /16-/24.
    score = 0
    if iface != default_if:
        score += 10
    if net.prefixlen == 16:
        score += 3
    elif 16 < net.prefixlen <= 24:
        score += 2
    # Prefer classic 172.16/12 NPN ranges
    if ipaddress.ip_address(str(net.network_address)) in ipaddress.ip_network("172.16.0.0/12"):
        score += 5
    cands.append((score, str(net), iface))
cands.sort(reverse=True)
if cands:
    print(cands[0][1])
PY
)"
    if [[ -z "$guessed" ]]; then
        err "未能从本机网卡识别私网客户端段；请手动: $0 --set-client-cidr 172.22.0.0/16"
        exit 1
    fi
    confirm_client_cidr_choice "$guessed" || exit 1
}
set_custom_dns() {
    local remote_dns local_dns backup_dir sniproxy_backup=""
    [[ -n "${1:-}" ]] || { err "Usage: $0 --set-dns <remote-dns> [local-dns]"; exit 1; }
    remote_dns=$(normalize_dns_upstreams "$1")
    local_dns=$(normalize_dns_upstreams "${2:-$(cat /etc/mosdns/.local_dns 2>/dev/null || printf '%s' "${DEFAULT_LOCAL_DNS[*]}")}")
    mkdir -p "$CONF_DIR" /etc/mosdns
    backup_dir=$(mktemp -d)
    for f in \
        "${CONF_DIR}/.remote_dns" \
        "${CONF_DIR}/.local_dns" \
        "${CONF_DIR}/.overseas_dns" \
        "${CONF_DIR}/.overseas_private_dns" \
        "${CONF_DIR}/.overseas_public_dns" \
        "${CONF_DIR}/.sniproxy_dns" \
        "${CONF_DIR}/wa-shim.env" \
        /etc/mosdns/.remote_dns \
        /etc/mosdns/.local_dns \
        /etc/mosdns/.overseas_dns \
        /etc/mosdns/.overseas_private_dns \
        /etc/mosdns/.overseas_public_dns \
        /etc/mosdns/.sniproxy_dns; do
        [[ -f "$f" ]] && cp -a "$f" "${backup_dir}/${f//\//__}"
    done
    if [[ -f /etc/sniproxy.conf ]]; then
        sniproxy_backup="${backup_dir}/sniproxy.conf"
        cp -a /etc/sniproxy.conf "$sniproxy_backup"
    fi
    restore_dns_backup() {
        local f b
        for f in \
            "${CONF_DIR}/.remote_dns" \
            "${CONF_DIR}/.local_dns" \
            "${CONF_DIR}/.overseas_dns" \
            "${CONF_DIR}/.overseas_private_dns" \
            "${CONF_DIR}/.overseas_public_dns" \
            "${CONF_DIR}/.sniproxy_dns" \
            "${CONF_DIR}/wa-shim.env" \
            /etc/mosdns/.remote_dns \
            /etc/mosdns/.local_dns \
            /etc/mosdns/.overseas_dns \
            /etc/mosdns/.overseas_private_dns \
            /etc/mosdns/.overseas_public_dns \
            /etc/mosdns/.sniproxy_dns; do
            b="${backup_dir}/${f//\//__}"
            if [[ -f "$b" ]]; then
                cp -a "$b" "$f"
            else
                rm -f "$f"
            fi
        done
        if [[ -n "$sniproxy_backup" && -f "$sniproxy_backup" ]]; then
            cp -a "$sniproxy_backup" /etc/sniproxy.conf
        fi
    }
    echo "$remote_dns" > "${CONF_DIR}/.remote_dns"
    echo "$local_dns" > "${CONF_DIR}/.local_dns"
    echo "$remote_dns" > "${CONF_DIR}/.overseas_dns"
    echo "$remote_dns" > "${CONF_DIR}/.overseas_private_dns"
    echo "$remote_dns" > "${CONF_DIR}/.overseas_public_dns"
    echo "$remote_dns" > "${CONF_DIR}/.sniproxy_dns"
    echo "$remote_dns" > /etc/mosdns/.remote_dns
    echo "$local_dns" > /etc/mosdns/.local_dns
    echo "$remote_dns" > /etc/mosdns/.overseas_dns
    echo "$remote_dns" > /etc/mosdns/.overseas_private_dns
    echo "$remote_dns" > /etc/mosdns/.overseas_public_dns
    echo "$remote_dns" > /etc/mosdns/.sniproxy_dns
    if [[ -f "${CONF_DIR}/wa-shim.env" ]]; then
        sed -i -E "s#^WA_SHIM_RESOLVER=.*#WA_SHIM_RESOLVER=$(first_plain_dns "$remote_dns"),8.8.8.8#" "${CONF_DIR}/wa-shim.env"
    fi
    if ! rewrite_sniproxy_dns "$remote_dns"; then
        restore_dns_backup
        rm -rf "$backup_dir"
        err "sniproxy config update failed; DNS upstreams rolled back"
        exit 1
    fi
    if [[ -f /usr/local/bin/update-mosdns-rules.sh ]]; then
        if ! /usr/local/bin/update-mosdns-rules.sh; then
            restore_dns_backup
            /usr/local/bin/update-mosdns-rules.sh >/dev/null 2>&1 || true
            rm -rf "$backup_dir"
            err "mosdns config update failed; DNS upstreams rolled back"
            exit 1
        fi
    else
        if ! systemctl restart mosdns; then
            restore_dns_backup
            rm -rf "$backup_dir"
            err "mosdns restart failed; DNS upstreams rolled back"
            exit 1
        fi
    fi
    systemctl restart sniproxy 2>/dev/null || true
    systemctl restart wa-shim 2>/dev/null || true
    rm -rf "$backup_dir"
    ok "DNS upstreams updated"
    echo "Remote DNS: $remote_dns"
    echo "Local DNS: $local_dns"
}
main_install() {
    check_root
    detect_os
    detect_memory_profile
    ensure_swap
    get_public_ip
    echo ""
    echo "=========================================="
    echo "  高性能反代系统一键部署"
    echo "=========================================="
    echo ""
    install_deps
    check_port_53
    generate_domain
    verify_domain_dns
    ensure_mosdns_user
    install_cert
    configure_dns_upstreams
    install_sniproxy
    install_whatsapp_shim
    install_quic_proxy
    install_client_socks_binary
    install_client_mtproto_binary || warn "client-mtproto 预装失败（可稍后 enable-client-mtproto）"
    install_clash_remote_binary || warn "clash-remote 预装失败（可稍后 enable-clash-remote）"
    prompt_client_cidr_install
    install_mosdns
    init_rules
    system_tuning
    setup_firewall
    setup_exit_switching
    generate_ios_profile
    apply_lowmem_go_limits
    start_services
    setup_schedules
    setup_tgbot
    maybe_setup_api
    install_cli
    record_deployed_revision
    if ! verify_installation; then
        err "核心就绪探测失败，请运行 sudo 5gpn doctor --deep 排查后重试"
        exit 1
    fi
    echo ""
    echo "=========================================="
    echo "         部署完成 — 下一步清单"
    echo "=========================================="
    echo ""
    echo "版本:     $(deployed_revision_line)"
    echo "DoT 地址:  tls://${DOMAIN}:853"
    echo "TCP 代理:  ${PUBLIC_IP}:80, ${PUBLIC_IP}:443 (sniproxy)"
    echo "UDP 代理:  ${PUBLIC_IP}:443 (quic-proxy)"
    echo "DNS 查询:  ${PUBLIC_IP}:53"
    echo "客户端网段: $(cat /etc/mosdns/.client_cidr 2>/dev/null || echo "${CLIENT_CIDR:-172.22.0.0/16}")"
    echo "iOS 描述文件: http://${DOMAIN}:${IOS_PROFILE_PORT}/ios-dot.mobileconfig"
    echo ""
    echo "推荐收尾（按需）:"
    echo "  5gpn doctor                     # 结构化自检"
    echo "  5gpn detect-client-cidr         # 再确认客户端网段"
    echo "  5gpn setup-api                  # HTTP 控制 API + WebUI（默认仅本机绑定）"
    echo "  5gpn setup-tgbot                # Telegram 控制 Bot"
    echo "  5gpn add-exit <name> <wg|uri>   # 添加出口后可 set-exit / smart"
    echo ""
    echo "排查手册: docs/TROUBLESHOOTING.md"
    echo "  （规则组名 rules.conf → policy-map → mihomo 最终出口）"
    echo ""
    echo "客户端配置示例 (Android 私人 DNS): ${DOMAIN}"
    echo "iOS 扫码安装:"
    if [[ -f "${WWW_DIR}/ios-dot.qr.txt" ]]; then
        cat "${WWW_DIR}/ios-dot.qr.txt"
    fi
    echo ""
    echo "其他常用: 5gpn status | update-rules | renew-cert | list-exits | uninstall"
    echo "=========================================="
}
