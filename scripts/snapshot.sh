#!/usr/bin/env bash
# 5GPN-X config snapshot / rollback helpers.
# Usage:
#   sudo bash scripts/snapshot.sh create [label]
#   sudo bash scripts/snapshot.sh list
#   sudo bash scripts/snapshot.sh restore [id|latest]
#   sudo bash scripts/snapshot.sh path   # print SNAP_DIR
set -euo pipefail

BASE_DIR="${BASE_DIR:-/opt/5gpn}"
CONF_DIR="${CONF_DIR:-${BASE_DIR}/etc}"
SNAP_ROOT="${SNAP_ROOT:-/var/lib/5gpn/snapshots}"
KEEP="${SNAP_KEEP:-5}"

info() { echo "[INFO] $*"; }
ok()   { echo "[OK]   $*"; }
err()  { echo "[ERR]  $*" >&2; }

need_root() {
    [[ ${EUID:-0} -eq 0 ]] || { err "run as root"; exit 1; }
}

snap_paths() {
    # Paths that matter for a working runtime (configs only; not large caches).
    cat <<'EOF'
/etc/5gpn
/etc/mosdns
/opt/5gpn/etc
/etc/sniproxy.conf
EOF
    # WireGuard pgw profiles if present
    if [[ -d /etc/wireguard ]]; then
        find /etc/wireguard -maxdepth 1 -type f -name 'pgw-*.conf' 2>/dev/null || true
    fi
}

create_snapshot() {
    need_root
    local label="${1:-manual}" ts id dir meta
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    id="${ts}-$(echo "$label" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-32)"
    dir="${SNAP_ROOT}/${id}"
    mkdir -p "$dir/tree"
    meta="${dir}/meta.env"
    {
        echo "id=${id}"
        echo "label=${label}"
        echo "created_at=${ts}"
        echo "git_head=$(git -C "${BASE_DIR}" rev-parse HEAD 2>/dev/null || true)"
        echo "git_short=$(git -C "${BASE_DIR}" rev-parse --short HEAD 2>/dev/null || true)"
        echo "current_exit=$(cat "${CONF_DIR}/current-exit" 2>/dev/null || echo local)"
        echo "client_cidr=$(cat /etc/mosdns/.client_cidr 2>/dev/null || echo 172.22.0.0/16)"
    } > "$meta"

    local p rel
    while IFS= read -r p; do
        [[ -z "$p" || ! -e "$p" ]] && continue
        rel="${p#/}"
        mkdir -p "$dir/tree/$(dirname "$rel")"
        if [[ -d "$p" ]]; then
            # Skip bulky ruleset caches / geodata.
            tar -C / -cf - \
                --exclude='etc/5gpn/rulesets' \
                --exclude='etc/mosdns/*.raw' \
                --exclude='etc/mosdns/config.validate.*' \
                "$rel" 2>/dev/null | tar -C "$dir/tree" -xf - 2>/dev/null || true
        else
            cp -a "$p" "$dir/tree/${rel}" 2>/dev/null || true
        fi
    done < <(snap_paths)

    # Mark success only when at least mosdns/5gpn config landed.
    if [[ ! -e "$dir/tree/etc/mosdns" && ! -e "$dir/tree/opt/5gpn/etc" ]]; then
        rm -rf "$dir"
        err "snapshot empty; nothing to save"
        exit 1
    fi
    ln -sfn "$id" "${SNAP_ROOT}/latest"
    # prune old
    local count=0
    while IFS= read -r old; do
        count=$((count + 1))
        if [[ "$count" -gt "$KEEP" ]]; then
            rm -rf "${SNAP_ROOT}/${old}"
        fi
    done < <(find "$SNAP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r)
    ok "snapshot saved: ${id}"
    echo "$id"
}

list_snapshots() {
    need_root
    mkdir -p "$SNAP_ROOT"
    local latest id
    latest="$(readlink "${SNAP_ROOT}/latest" 2>/dev/null || true)"
    printf '%-28s  %-10s  %s\n' "ID" "GIT" "LABEL"
    find "$SNAP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r | while read -r id; do
        local git_short label mark=""
        git_short="$(awk -F= '/^git_short=/{print substr($0,11); exit}' "${SNAP_ROOT}/${id}/meta.env" 2>/dev/null || echo '?')"
        label="$(awk -F= '/^label=/{print substr($0,7); exit}' "${SNAP_ROOT}/${id}/meta.env" 2>/dev/null || echo '?')"
        [[ "$id" == "$latest" ]] && mark=" *"
        printf '%-28s  %-10s  %s%s\n' "$id" "$git_short" "$label" "$mark"
    done
}

restore_snapshot() {
    need_root
    local want="${1:-latest}" id dir
    if [[ "$want" == "latest" ]]; then
        id="$(readlink "${SNAP_ROOT}/latest" 2>/dev/null || true)"
    else
        id="$want"
    fi
    dir="${SNAP_ROOT}/${id}"
    [[ -d "$dir/tree" ]] || { err "snapshot not found: ${want}"; exit 1; }
    info "restoring snapshot ${id} ..."

    # Restore tree onto /
    if [[ -d "$dir/tree/etc/5gpn" ]]; then
        mkdir -p /etc/5gpn
        rsync -a --delete --exclude='rulesets' "$dir/tree/etc/5gpn/" /etc/5gpn/ 2>/dev/null \
            || cp -a "$dir/tree/etc/5gpn/." /etc/5gpn/
    fi
    if [[ -d "$dir/tree/etc/mosdns" ]]; then
        mkdir -p /etc/mosdns
        rsync -a --exclude='*.raw' --exclude='config.validate.*' "$dir/tree/etc/mosdns/" /etc/mosdns/ 2>/dev/null \
            || cp -a "$dir/tree/etc/mosdns/." /etc/mosdns/
    fi
    if [[ -d "$dir/tree/opt/5gpn/etc" ]]; then
        mkdir -p "${CONF_DIR}"
        rsync -a "$dir/tree/opt/5gpn/etc/" "${CONF_DIR}/" 2>/dev/null \
            || cp -a "$dir/tree/opt/5gpn/etc/." "${CONF_DIR}/"
    fi
    [[ -f "$dir/tree/etc/sniproxy.conf" ]] && cp -a "$dir/tree/etc/sniproxy.conf" /etc/sniproxy.conf
    if [[ -d "$dir/tree/etc/wireguard" ]]; then
        mkdir -p /etc/wireguard
        cp -a "$dir/tree/etc/wireguard/." /etc/wireguard/ 2>/dev/null || true
    fi

    # Optionally reset git checkout to snapshotted HEAD (best-effort).
    local git_head
    git_head="$(awk -F= '/^git_head=/{print substr($0,10); exit}' "${dir}/meta.env" 2>/dev/null || true)"
    if [[ -n "$git_head" && -d "${BASE_DIR}/.git" ]]; then
        if git -C "${BASE_DIR}" cat-file -e "${git_head}^{commit}" 2>/dev/null; then
            git -C "${BASE_DIR}" checkout -B main "$git_head" >/dev/null 2>&1 || true
            git -C "${BASE_DIR}" reset --hard "$git_head" >/dev/null 2>&1 || true
            info "git HEAD restored to ${git_head:0:7}"
        else
            info "git object ${git_head:0:7} not in local repo; configs restored, code unchanged"
        fi
    fi

    systemctl reset-failed mosdns sniproxy wa-shim quic-proxy 5gpn-tgbot 5gpn-api 2>/dev/null || true
    systemctl restart mosdns sniproxy wa-shim quic-proxy 2>/dev/null || true
    [[ -f "${CONF_DIR}/tgbot.env" ]] && systemctl restart 5gpn-tgbot 2>/dev/null || true
    [[ -f "${CONF_DIR}/api.env" ]] && systemctl restart 5gpn-api 2>/dev/null || true
    local cur
    cur="$(cat "${CONF_DIR}/current-exit" 2>/dev/null || echo local)"
    if [[ "$cur" == "smart" || ( "$cur" != "local" && -n "$cur" ) ]]; then
        systemctl reset-failed "5gpn-mihomo@${cur}.service" 2>/dev/null || true
        systemctl restart "5gpn-mihomo@${cur}.service" 2>/dev/null || true
    fi
    # Re-apply exit routing if helper exists
    [[ -x /usr/local/bin/5gpn-apply-exit.sh ]] && /usr/local/bin/5gpn-apply-exit.sh 2>/dev/null || true
    ok "restored snapshot ${id}"
}

cmd="${1:-}"
case "$cmd" in
    create) shift; create_snapshot "${1:-manual}" ;;
    list) list_snapshots ;;
    restore) shift; restore_snapshot "${1:-latest}" ;;
    path) echo "$SNAP_ROOT" ;;
    *)
        echo "Usage: $0 {create [label]|list|restore [id|latest]|path}" >&2
        exit 2
        ;;
esac
