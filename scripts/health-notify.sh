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

eval "$(python3 - "$json_out" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print("fail_n=%d" % int(d.get("fail", 0)))
    print("warn_n=%d" % int(d.get("warn", 0)))
except Exception:
    print("fail_n=99")
    print("warn_n=0")
PY
)"

prev_fail=0
if [[ -f "$STATE_FILE" ]]; then
    prev_fail="$(python3 -c 'import json,sys;print(int(json.load(open(sys.argv[1])).get("fail",0)))' "$STATE_FILE" 2>/dev/null || echo 0)"
fi
cp "$json_out" "$STATE_FILE"
rm -f "$json_out"

text=""
if [[ "$fail_n" -gt 0 && "$fail_n" != "$prev_fail" ]]; then
    text="🔴 <b>5GPN 健康检查失败</b>
失败 ${fail_n} / 警告 ${warn_n}
请执行: <code>sudo 5gpn doctor</code> 或 <code>sudo 5gpn report</code>"
elif [[ "$fail_n" -eq 0 && "$prev_fail" -gt 0 ]]; then
    text="🟢 <b>5GPN 健康检查已恢复</b>
警告 ${warn_n}"
fi
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
