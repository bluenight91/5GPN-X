#!/usr/bin/env bash
# Periodic health check → Telegram alert on failure (or recovery).
set -euo pipefail

BASE_DIR="${BASE_DIR:-/opt/5gpn}"
CONF_DIR="${CONF_DIR:-${BASE_DIR}/etc}"
STATE_DIR="${CONF_DIR}/health"
STATE_FILE="${STATE_DIR}/last.json"
BOT_ENV="${CONF_DIR}/tgbot.env"

mkdir -p "$STATE_DIR"
umask 077

[[ -f "$BOT_ENV" ]] || exit 0
# shellcheck disable=SC1090
set -a; source "$BOT_ENV"; set +a
TOKEN="${TG_BOT_TOKEN:-}"
ADMINS="${TG_ADMIN_IDS:-}"
[[ -n "$TOKEN" && -n "$ADMINS" ]] || exit 0

json_out="$(mktemp)"
bash "${BASE_DIR}/scripts/doctor.sh" --json >"$json_out" 2>/dev/null || true

text="$(python3 - "$json_out" "$STATE_FILE" <<'PY'
import html, json, os, sys

path, state_path = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(path, encoding="utf-8"))
except Exception:
    d = {"fail": 99, "warn": 0, "checks": []}

fail_n = int(d.get("fail", 0) or 0)
warn_n = int(d.get("warn", 0) or 0)
prev_fail = 0
if os.path.isfile(state_path):
    try:
        prev_fail = int(json.load(open(state_path, encoding="utf-8")).get("fail", 0) or 0)
    except Exception:
        prev_fail = 0

text = ""
if fail_n > 0 and fail_n != prev_fail:
    lines = []
    for item in d.get("checks") or []:
        if item.get("level") == "fail":
            lines.append("%s: %s" % (item.get("check", "?"), item.get("detail", "")))
    body = "\n".join(lines[:8])
    text = "🔴 <b>5GPN 健康检查失败</b>\n失败 %d / 警告 %d" % (fail_n, warn_n)
    if body:
        text += "\n<pre>%s</pre>" % html.escape(body[:1500])
    text += "\n请打开 Bot「运维 → 自检 doctor / 诊断报告」查看详情"
elif fail_n == 0 and prev_fail > 0:
    text = "🟢 <b>5GPN 健康检查已恢复</b>\n警告 %d" % warn_n
print(text)
PY
)"

cp "$json_out" "$STATE_FILE"
rm -f "$json_out"
[[ -n "$text" ]] || exit 0

IFS=',' read -r -a ids <<< "$ADMINS"
for id in "${ids[@]}"; do
    id="$(echo "$id" | tr -d '[:space:]')"
    [[ -z "$id" ]] && continue
    curl -fsS -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${id}" \
        --data-urlencode "text=${text}" \
        --data "parse_mode=HTML" \
        --data "disable_web_page_preview=true" >/dev/null 2>&1 || true
done
exit 0
