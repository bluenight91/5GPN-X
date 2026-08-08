#!/usr/bin/env python3
"""5GPN-X exit failover watchdog — one tick per invocation (timer-driven).

Invariant I11 (docs/architecture.md):
  * opt-in: a tick is a no-op unless /etc/5gpn/failover.enabled exists;
  * every switch goes through `install.sh --set-exit` — this program never
    touches routing tables, fwmarks or the firewall itself;
  * anti-flap guards are mandatory: consecutive-failure threshold, switch
    cooldown, per-hour switch cap, and a grace period after a manual switch.

Probe = real HTTP through the current exit's TUN device. Candidates come from
FAILOVER_ORDER in /etc/5gpn/failover.env, or (unset) the last known latencies
recorded by the API server (latency.json), ascending.
"""
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

PGW_DIR = os.environ.get("PGW_DIR", "/etc/5gpn")
EXITS_DIR = PGW_DIR + "/exits"
WG_DIR = os.environ.get("WG_DIR", "/etc/wireguard")
CONF_DIR = os.environ.get("CONF_DIR", "/opt/5gpn/etc")
STATE_FILE = os.environ.get("FAILOVER_STATE", PGW_DIR + "/health/failover.json")
ENV_FILE = PGW_DIR + "/failover.env"
ENABLED_FILE = PGW_DIR + "/failover.enabled"
CUR_EXIT_FILE = PGW_DIR + "/current-exit"
LATENCY_FILE = os.environ.get("LATENCY_FILE", CONF_DIR + "/latency.json")
MGMT = os.environ.get("MGMT", "/opt/5gpn/install.sh")
TGBOT_ENV = os.environ.get("TGBOT_ENV", CONF_DIR + "/tgbot.env")
PROBE_URL = os.environ.get("FAILOVER_PROBE_URL", "http://www.gstatic.com/generate_204")

FAIL_AFTER = int(re.sub(r"\D", "", os.environ.get("FAILOVER_FAIL_AFTER", "3")) or "3")
COOLDOWN_SEC = int(re.sub(r"\D", "", os.environ.get("FAILOVER_COOLDOWN_SEC", "600")) or "600")
MAX_SWITCHES_PER_HOUR = int(re.sub(r"\D", "", os.environ.get("FAILOVER_MAX_SWITCHES_PER_HOUR", "3")) or "3")
GRACE_SEC = int(re.sub(r"\D", "", os.environ.get("FAILOVER_GRACE_SEC", "300")) or "300")
PROBE_TIMEOUT = int(re.sub(r"\D", "", os.environ.get("FAILOVER_PROBE_TIMEOUT", "8")) or "8")

SKIP_EXITS = ("local", "smart")


def exit_iface(name):
    """TUN device name (I6): short plain names pass through, everything else
    is sha256(name)[:11]. Must match install.sh exit_iface() exactly."""
    if re.fullmatch(r"[A-Za-z0-9_-]{1,11}", name):
        return f"pgw-{name}"
    return "pgw-" + hashlib.sha256(name.encode()).hexdigest()[:11]


def read_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def current_exit():
    return read_file(CUR_EXIT_FILE).strip() or "local"


def list_exits():
    names = set()
    try:
        for f in os.listdir(EXITS_DIR):
            if f.endswith(".type"):
                names.add(f[:-5])
    except OSError:
        pass
    try:
        for f in os.listdir(WG_DIR):
            if f.startswith("pgw-") and f.endswith(".conf"):
                names.add(f[4:-5])
    except OSError:
        pass
    return sorted(n for n in names if n not in SKIP_EXITS)


def failover_order():
    for line in read_file(ENV_FILE).splitlines():
        line = line.strip()
        if line.startswith("FAILOVER_ORDER="):
            raw = line[len("FAILOVER_ORDER="):].strip().strip('"').strip("'")
            return [x.strip() for x in raw.split(",") if x.strip()]
    return []


def last_latencies():
    """exit -> ms from the newest latency.json sample (None when unknown)."""
    try:
        data = json.loads(read_file(LATENCY_FILE))
        pts = data.get("points") or []
        return dict((pts[-1] if pts else {}).get("v") or {})
    except Exception:  # noqa: BLE001
        return {}


def candidates(cur):
    existing = list_exits()
    order = [n for n in failover_order() if n in existing and n != cur]
    if order:
        rest = [n for n in existing if n != cur and n not in order]
        lat = last_latencies()
        rest.sort(key=lambda n: (lat.get(n) is None, lat.get(n) or 0, n))
        return order + rest
    lat = last_latencies()
    rest = [n for n in existing if n != cur]
    rest.sort(key=lambda n: (lat.get(n) is None, lat.get(n) or 0, n))
    return rest


def load_state():
    try:
        st = json.loads(read_file(STATE_FILE))
        if isinstance(st, dict):
            return st
    except Exception:  # noqa: BLE001, S110
        pass
    return {}


def save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass


def probe(iface):
    """True when an HTTP request through the exit device succeeds."""
    try:
        rc = subprocess.run(
            ["curl", "--interface", iface, "-m", str(PROBE_TIMEOUT), "-sf",
             "-o", "/dev/null", PROBE_URL],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=PROBE_TIMEOUT + 4, check=False).returncode
        return rc == 0
    except Exception:  # noqa: BLE001
        return False


def switch(name):
    """The ONLY switching path (I11): install.sh --set-exit."""
    try:
        return subprocess.run(
            ["bash", MGMT, "--set-exit", name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=180, check=False).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def notify_tg(text):
    """Best-effort Telegram alert using the tgbot credentials (HTML parse)."""
    token = admin_ids = ""
    for line in read_file(TGBOT_ENV).splitlines():
        if line.startswith("TG_BOT_TOKEN="):
            token = line.split("=", 1)[1].strip()
        elif line.startswith("TG_ADMIN_IDS="):
            admin_ids = line.split("=", 1)[1].strip()
    if not token or not admin_ids:
        return
    for chat_id in (x.strip() for x in admin_ids.split(",")):
        if not chat_id:
            continue
        try:
            body = json.dumps({"chat_id": chat_id, "text": text,
                               "parse_mode": "HTML",
                               "disable_web_page_preview": True}).encode()
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception:  # noqa: BLE001, S110
            pass


def tick(now=None, probe_fn=probe, switch_fn=switch, notify_fn=notify_tg):
    """One watchdog iteration. Returns a dict describing what happened."""
    now = time.time() if now is None else now
    if not os.path.isfile(ENABLED_FILE):
        return {"action": "disabled"}
    cur = current_exit()
    st = load_state()
    if cur in SKIP_EXITS:
        if st.get("fails"):
            st["fails"] = 0
            save_state(st)
        return {"action": "skip", "exit": cur}

    # Grace after a manual switch: the operator just changed current-exit;
    # give the new exit time to stabilize before judging it.
    if st.get("exit") != cur:
        st = {"exit": cur, "fails": 0,
              "last_switch": st.get("last_switch", 0),
              "switches": st.get("switches", [])}
        save_state(st)
    try:
        if now - os.path.getmtime(CUR_EXIT_FILE) < GRACE_SEC:
            return {"action": "grace", "exit": cur}
    except OSError:
        pass

    if probe_fn(exit_iface(cur)):
        if st.get("fails"):
            st["fails"] = 0
            save_state(st)
        return {"action": "ok", "exit": cur}

    st["fails"] = int(st.get("fails", 0)) + 1
    save_state(st)
    if st["fails"] < FAIL_AFTER:
        return {"action": "fail", "exit": cur, "fails": st["fails"]}

    if now - float(st.get("last_switch", 0)) < COOLDOWN_SEC:
        return {"action": "cooldown", "exit": cur}
    switches = [t for t in st.get("switches", []) if now - float(t) < 3600]
    if len(switches) >= MAX_SWITCHES_PER_HOUR:
        st["switches"] = switches
        save_state(st)
        return {"action": "capped", "exit": cur}

    for cand in candidates(cur):
        if switch_fn(cand) and probe_fn(exit_iface(cand)):
            switches.append(now)
            st.update({"exit": cand, "fails": 0, "last_switch": now,
                       "switches": switches})
            save_state(st)
            lat = last_latencies().get(cand)
            lat_s = f"（延迟 {lat} ms）" if isinstance(lat, (int, float)) else ""
            notify_fn(f"🔀 <b>5GPN 出口自动切换</b>\n出口 <code>{html.escape(cur)}</code> "
                      f"连续 {FAIL_AFTER} 次探测不可达，已切换到 "
                      f"<code>{html.escape(cand)}</code>{lat_s}。\n"
                      f"切回：<code>5gpn set-exit {html.escape(cur)}</code>")
            return {"action": "switched", "from": cur, "to": cand}

    st["last_switch"] = now   # failed attempts also honor the cooldown
    save_state(st)
    notify_fn(f"🔴 <b>5GPN 出口自愈失败</b>\n出口 <code>{html.escape(cur)}</code> "
              f"连续 {FAIL_AFTER} 次探测不可达，且没有可用的候选出口。\n"
              f"请检查节点状态：<code>5gpn --check-exits</code>")
    return {"action": "stuck", "exit": cur}


def status():
    st = load_state()
    return {
        "enabled": os.path.isfile(ENABLED_FILE),
        "current_exit": current_exit(),
        "order": failover_order(),
        "candidates": candidates(current_exit()),
        "state": st,
        "config": {"fail_after": FAIL_AFTER, "cooldown_sec": COOLDOWN_SEC,
                   "max_switches_per_hour": MAX_SWITCHES_PER_HOUR,
                   "grace_sec": GRACE_SEC, "probe_url": PROBE_URL},
    }


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "tick"
    if cmd == "tick":
        print(json.dumps(tick(), ensure_ascii=False))
    elif cmd == "status":
        print(json.dumps(status(), ensure_ascii=False, indent=2))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
