#!/usr/bin/env bash
# 5GPN-X 部署后冒烟检查（只读，不改任何状态）
# 用法: sudo bash /opt/5gpn/scripts/smoke-check.sh
# 每次安装/更新后花一分钟跑一遍，把"单测全绿但部署坏了"的问题挡在当天。
# shellcheck disable=SC2015 # A && ok || bad 是有意的检查结果报告，不是 if-else
set -uo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0
ok()   { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
bad()  { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
note() { echo -e "${YELLOW}[NOTE]${NC} $1"; WARN=$((WARN+1)); }

BASE_DIR=/opt/5gpn
CONF_DIR="${BASE_DIR}/etc"
CURRENT="$(cat "${CONF_DIR}/current-exit" 2>/dev/null || echo local)"

echo "===== 5GPN-X 冒烟检查 $(date '+%F %T') (当前出口: ${CURRENT}) ====="

# ---------- 1. 核心服务 ----------
echo "----- 服务状态 -----"
for svc in mosdns sniproxy wa-shim quic-proxy; do
    if systemctl is-active --quiet "$svc"; then ok "服务 $svc 运行中"; else bad "服务 $svc 未运行: systemctl status $svc"; fi
done
[[ -f "${CONF_DIR}/tgbot.env" ]] && { systemctl is-active --quiet 5gpn-tgbot && ok "服务 5gpn-tgbot 运行中" || bad "服务 5gpn-tgbot 未运行"; }
[[ -f "${CONF_DIR}/api.env" ]] && { systemctl is-active --quiet 5gpn-api && ok "服务 5gpn-api 运行中" || bad "服务 5gpn-api 未运行"; }
if [[ "$CURRENT" == "smart" ]]; then
    systemctl is-active --quiet 5gpn-mihomo@smart && ok "smart 路由实例运行中" || bad "5gpn-mihomo@smart 未运行（smart 模式下分流将全灭）"
elif [[ "$CURRENT" != "local" ]]; then
    systemctl is-active --quiet "5gpn-mihomo@${CURRENT}" && ok "出口实例 ${CURRENT} 运行中" || note "5gpn-mihomo@${CURRENT} 未运行"
fi

# ---------- 2. 端口监听 ----------
echo "----- 端口监听 -----"
check_listen() { # proto port desc
    if ss -tln 2>/dev/null | grep -q ":$2 " || ss -uln 2>/dev/null | grep -q ":$2 "; then
        ok "$3 ($1/$2 在监听)"
    else
        bad "$3 ($1/$2 未监听)"
    fi
}
check_listen tcp 853 "DoT 入口"
check_listen udp 53  "DNS 入口"
check_listen tcp 443 "SNI 透明代理"
[[ -f "${CONF_DIR}/api.env" ]] && check_listen tcp 8444 "HTTP 控制 API"
if [[ "$CURRENT" == "smart" ]]; then
    ss -tln 2>/dev/null | grep -q "127.0.0.1:9090 " && ok "mihomo Clash API 仅回环监听" || bad "mihomo Clash API (127.0.0.1:9090) 未监听"
    ss -tln 2>/dev/null | grep -qE "0\.0\.0\.0:9090 |:::9090 " && bad "mihomo Clash API 暴露到公网了！" || ok "mihomo Clash API 未暴露公网"
fi

# ---------- 3. DNS 应答 ----------
echo "----- DNS 应答 -----"
if command -v dig >/dev/null 2>&1; then
    a_answer="$(dig +time=3 +tries=1 +short @127.0.0.1 -p 53 example.com A 2>/dev/null | head -1)"
    [[ -n "$a_answer" ]] && ok "mosdns UDP/53 应答正常 ($a_answer)" || bad "mosdns UDP/53 无应答"
    dot_answer="$(dig +time=3 +tries=1 +tls +short @"$(cat "${CONF_DIR}/.domain" 2>/dev/null || echo 127.0.0.1)" -p 853 example.com A 2>/dev/null | head -1)"
    [[ -n "$dot_answer" ]] && ok "DoT 853 应答正常 ($dot_answer)" || note "DoT 853 无应答（域名/证书问题？）"
else
    note "无 dig 命令，跳过 DNS 应答检查"
fi

# ---------- 4. 出口链路（当初 smart DNS 事故就该被这条拦住） ----------
echo "----- 出口链路 -----"
if [[ "$CURRENT" == "smart" ]]; then
    if ip link show pgw-smart >/dev/null 2>&1; then
        ok "TUN 设备 pgw-smart 存在"
        if ip route show table 100 2>/dev/null | grep -q "default.*pgw-smart"; then
            ok "表 100 默认路由指向 pgw-smart"
        else
            bad "表 100 默认路由未指向 pgw-smart: $(ip route show table 100)"
        fi
        code="$(curl -m 8 -s -o /dev/null -w '%{http_code}' --interface pgw-smart https://www.google.com 2>/dev/null || echo 000)"
        [[ "$code" != "000" ]] && ok "mihomo TUN 出网正常 (google HTTP $code)" || bad "mihomo TUN 出网失败（检查 smart.yaml 的 dns 段与出口连通性）"
    else
        bad "TUN 设备 pgw-smart 不存在"
    fi
elif [[ "$CURRENT" != "local" ]]; then
    ip link show "pgw-${CURRENT}" >/dev/null 2>&1 && ok "TUN 设备 pgw-${CURRENT} 存在" || bad "TUN 设备 pgw-${CURRENT} 不存在"
else
    note "当前为 local 直出，跳过 TUN 链路检查"
fi

# ---------- 5. 打标与路由规则健康 ----------
echo "----- 策略路由健康 -----"
fw_count="$(ip rule show 2>/dev/null | grep -c 'fwmark 0x1 lookup 100' || true)"
[[ "$fw_count" -ge 1 ]] && ok "fwmark 规则存在 ($fw_count 条)" || bad "fwmark 规则缺失"
[[ "$fw_count" -gt 1 ]] && note "fwmark 规则重复 ($fw_count 条，新版本已去重，可忽略)"
nft list table inet pgw_exit >/dev/null 2>&1 && ok "pgw_exit 打标表存在" || bad "pgw_exit 打标表缺失"

# ---------- 6. 控制 API ----------
if [[ -f "${CONF_DIR}/api.env" ]]; then
    echo "----- 控制 API -----"
    health="$(curl -m 5 -sk https://127.0.0.1:8444/api/health 2>/dev/null || true)"
    [[ "$health" == *'"ok":true'* ]] && ok "API 健康检查通过" || bad "API 健康检查失败: ${health:-无响应}"
    sec="$(sudo cat /etc/5gpn/mihomo-api-secret 2>/dev/null || true)"
    if [[ -n "$sec" ]]; then
        ver="$(curl -m 5 -s -H "Authorization: Bearer $sec" http://127.0.0.1:9090/version 2>/dev/null || true)"
        [[ "$ver" == *'"version"'* ]] && ok "mihomo Clash API 应答正常" || note "mihomo Clash API 无应答（smart 未启用时正常）"
    fi
fi

# ---------- 7. 证书与域名 ----------
echo "----- 证书 -----"
[[ -s /etc/mosdns/certs/fullchain.pem && -s /etc/mosdns/certs/privkey.pem ]] && ok "TLS 证书就位" || bad "TLS 证书缺失"
if command -v openssl >/dev/null 2>&1 && [[ -s /etc/mosdns/certs/fullchain.pem ]]; then
    days=$(( ( $(date -d "$(openssl x509 -enddate -noout -in /etc/mosdns/certs/fullchain.pem | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
    [[ "$days" -gt 14 ]] && ok "证书剩余 $days 天" || note "证书仅剩 $days 天，留意续期"
fi

# ---------- 汇总 ----------
echo ""
echo "===== 结果: ${PASS} 通过, ${FAIL} 失败, ${WARN} 提示 ====="
echo ""
echo "人工步骤（脚本无法代替）:"
echo "  1. 手机连入后，浏览器开 https://www.google.com 应通（smart/代理出口下）"
echo "  2. 开几个国内站点（baidu.com/taobao.com）应直连且速度正常"
echo "  3. 控制台仪表盘有实时速率、24H 流量出点、mihomo 概览有连接数"
echo "  4. 重启服务器一次：确认 current-exit 出口自动恢复"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
