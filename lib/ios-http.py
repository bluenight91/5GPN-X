#!/usr/bin/env python3
"""
Tiny inetd-style HTTP responder for the iOS DoT profile.

Invoked once per connection by systemd socket activation (Accept=yes), with the
client socket wired to stdin/stdout. Serves a couple of static files from
WWW_DIR. Zero processes when idle.

A stalled peer (a scanner that connects and never sends a request) is cut off
with SIGALRM. The handler hard-exits 0: SystemExit raised from a signal
handler is not a reliable wait status, and a signalled death marks this
per-connection unit failed. One failed instance makes
``systemctl is-system-running`` report degraded.
"""
import os
import signal
import sys

WWW_DIR = os.environ.get("WWW_DIR", "/opt/5gpn/www")


def _request_timeout():
    """Seconds a peer may stall before the connection is closed successfully."""
    raw = os.environ.get("IOS_HTTP_TIMEOUT", "")
    if not raw:
        return 10
    try:
        timeout = int(raw)
    except ValueError:
        return 10
    if timeout < 1 or timeout > 60:
        return 10
    return timeout


def _expire(_signum, _frame):
    # os._exit skips interpreter shutdown. sys.exit() only raises SystemExit,
    # which a signal handler may fail to turn into status 0; the process then
    # dies by SIGALRM and systemd fails the instance.
    os._exit(0)


ROUTES = {
    "/ios-dot.mobileconfig": ("ios-dot.mobileconfig", "application/x-apple-aspen-config"),
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
}


def write(out, status, ctype, body):
    head = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    out.write(head)
    out.write(body)
    out.flush()


def main():
    # Never let a stalled/half-open connection linger as a live process.
    signal.signal(signal.SIGALRM, _expire)
    signal.alarm(_request_timeout())

    inp = sys.stdin.buffer
    out = sys.stdout.buffer

    line = inp.readline(8192).decode("latin1", "replace")
    parts = line.split()
    if len(parts) < 2 or parts[0] != "GET":
        write(out, "400 Bad Request", "text/plain", b"bad request\n")
        return
    path = parts[1].split("?", 1)[0]

    route = ROUTES.get(path)
    if not route:
        write(out, "404 Not Found", "text/plain", b"not found\n")
        return

    filename, ctype = route
    full = os.path.join(WWW_DIR, filename)
    try:
        with open(full, "rb") as f:
            body = f.read()
    except OSError:
        write(out, "404 Not Found", "text/plain", b"not found\n")
        return
    write(out, "200 OK", ctype, body)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        sys.exit(0)
