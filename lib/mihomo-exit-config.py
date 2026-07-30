#!/usr/bin/env python3
"""Generate a standalone mihomo TUN config from one proxy share URI.

The emitted document is JSON, which is valid YAML 1.2. This keeps the helper
stdlib-only while safely quoting credentials and other user-controlled values.
"""
import base64
import hashlib
import ipaddress
import json
import os
import re
import sys
from urllib.parse import parse_qs, unquote, urlparse


def die(message):
    sys.stderr.write(message.rstrip() + "\n")
    raise SystemExit(1)


def _dns_servers(env_name, default):
    raw = os.environ.get(env_name, default).replace(",", " ")
    return [x for x in raw.split() if x]


def _pure_ips(values):
    out = []
    for value in values:
        try:
            ipaddress.ip_address(value)
            out.append(value)
        except ValueError:
            continue
    return out


# mihomo's internal DNS client is strict about refused/ip-version answers and
# breaks against the gateway's own AAAA-rejecting resolver path; give it real
# upstreams instead of relying on the system resolver.
DNS_LOCAL = _dns_servers("MIHOMO_DNS_LOCAL", "223.5.5.5 119.29.29.29 180.76.76.76")
DNS_REMOTE = _dns_servers("MIHOMO_DNS_REMOTE", "1.1.1.1 8.8.8.8 9.9.9.9")
# default-nameserver bootstraps DoH/DoT hostname resolution; mihomo requires
# it to be PURE IPs, so DoH URLs from the pool must be filtered out.
DNS_BOOTSTRAP = _pure_ips(DNS_LOCAL)[:2] or ["223.5.5.5", "119.29.29.29"]
DNS_CONFIG = {"enable": True, "ipv6": False,
              "nameserver": DNS_LOCAL + DNS_REMOTE, "fallback": DNS_REMOTE,
              "default-nameserver": DNS_BOOTSTRAP,
              "proxy-server-nameserver": DNS_LOCAL + DNS_REMOTE}


def b64decode_any(value):
    value = value.strip()
    pad = "=" * (-len(value) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(value + pad).decode("utf-8")
        except Exception:  # noqa: BLE001, S110
            pass
    raise ValueError("not base64")


def parse_hostport(value):
    value = re.split(r"[/?#]", value.strip(), 1)[0].strip()
    match = re.match(r"^\[(.+)\]:(\d+)$", value) or re.match(r"^(.+):(\d+)$", value)
    if not match:
        die(f"cannot parse host:port from {value!r}")
    return require_host(match.group(1)), valid_port(match.group(2))


def require_host(value):
    if not value:
        die("proxy URI missing server host")
    return value


def valid_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        die("proxy URI port must be an integer")
    if not 1 <= port <= 65535:
        die(f"proxy URI port out of range: {value}")
    return port


def parsed_port(parsed, default):
    try:
        return valid_port(parsed.port or default)
    except ValueError as exc:
        die(f"invalid proxy URI port: {exc}")


def query_map(parsed):
    return {key: values[0] for key, values in parse_qs(parsed.query).items()}


def truthy(value):
    return str(value or "").lower() in ("1", "true", "yes", "on")


def tls_fields(proxy, servername, insecure=False):
    proxy["tls"] = True
    if servername:
        proxy["servername"] = servername
    if insecure:
        proxy["skip-cert-verify"] = True


def transport_fields(proxy, network, host=None, path=None, service=None):
    network = (network or "tcp").lower()
    if network in ("ws", "websocket"):
        proxy["network"] = "ws"
        opts = {"path": unquote(path or "/")}
        if host:
            opts["headers"] = {"Host": host}
        proxy["ws-opts"] = opts
    elif network == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": unquote(service or (path or "").lstrip("/"))}
    elif network in ("http", "h2"):
        proxy["network"] = "h2"
        proxy["h2-opts"] = {"path": unquote(path or "/"), "host": [host] if host else []}


def decode_ss_userinfo(value):
    try:
        decoded = b64decode_any(value)
        if ":" in decoded and re.match(r"^[a-z0-9-]+$", decoded.split(":", 1)[0]):
            method, password = decoded.split(":", 1)
            return method, unquote(password)
    except ValueError:
        pass
    value = unquote(value)
    if ":" not in value:
        die("cannot parse ss:// credentials")
    method, password = value.split(":", 1)
    return method, unquote(password)


def parse_ss(uri):
    rest = uri[5:].split("#", 1)[0].split("?", 1)[0]
    if "@" in rest:
        userinfo, server = rest.rsplit("@", 1)
        method, password = decode_ss_userinfo(userinfo)
        host, port = parse_hostport(server)
    else:
        try:
            decoded = b64decode_any(rest)
        except ValueError:
            die("invalid ss:// payload")
        if "@" not in decoded or ":" not in decoded:
            die("invalid legacy ss:// payload")
        creds, server = decoded.rsplit("@", 1)
        method, password = creds.split(":", 1)
        host, port = parse_hostport(server)
    return {"name": "out", "type": "ss", "server": host, "port": port,
            "cipher": method, "password": password, "udp": True}


def parse_socks(uri):
    rest = re.sub(r"^socks(?:5h|5)?://", "", uri, flags=re.IGNORECASE)
    userinfo, hostport = rest.rsplit("@", 1) if "@" in rest else ("", rest)
    host, port = parse_hostport(hostport)
    proxy = {"name": "out", "type": "socks5", "server": host, "port": port, "udp": True}
    if userinfo:
        user, password = userinfo.split(":", 1) if ":" in userinfo else (userinfo, "")
        proxy["username"] = user
        if password:
            proxy["password"] = password
    return proxy


def parse_vmess(uri):
    try:
        data = json.loads(b64decode_any(uri[8:]))
    except Exception as exc:  # noqa: BLE001
        die(f"invalid vmess:// payload: {exc}")
    host, port = require_host(data.get("add")), valid_port(data.get("port") or 443)
    proxy = {"name": "out", "type": "vmess", "server": host, "port": port,
             "uuid": data.get("id", ""), "alterId": int(data.get("aid", 0) or 0),
             "cipher": data.get("scy") or "auto", "udp": True}
    if str(data.get("tls", "")).lower() in ("tls", "true", "1"):
        tls_fields(proxy, data.get("sni") or data.get("host") or host)
    transport_fields(proxy, data.get("net"), data.get("host"), data.get("path"))
    return proxy


def parse_trojan(uri):
    parsed, proxy = urlparse(uri), {"name": "out", "type": "trojan", "udp": True}
    query = query_map(parsed)
    proxy.update(server=require_host(parsed.hostname), port=parsed_port(parsed, 443), password=unquote(parsed.username or ""))
    tls_fields(proxy, query.get("sni") or query.get("peer") or parsed.hostname,
               truthy(query.get("allowInsecure")))
    transport_fields(proxy, query.get("type"), query.get("host"), query.get("path"),
                     query.get("serviceName") or query.get("service_name"))
    return proxy


def parse_vless(uri):
    parsed = urlparse(uri)
    query = query_map(parsed)
    proxy = {"name": "out", "type": "vless", "server": require_host(parsed.hostname),
             "port": parsed_port(parsed, 443), "uuid": unquote(parsed.username or ""), "udp": True}
    if query.get("flow"):
        proxy["flow"] = query["flow"]
    security = (query.get("security") or "tls").lower()
    if security in ("tls", "reality"):
        tls_fields(proxy, query.get("sni") or parsed.hostname, truthy(query.get("allowInsecure")))
    if security == "reality":
        public_key = query.get("pbk") or query.get("public_key")
        if not public_key:
            die("vless reality URI missing public key (pbk)")
        proxy["reality-opts"] = {"public-key": public_key,
                                  "short-id": query.get("sid") or query.get("short_id", "")}
        proxy["client-fingerprint"] = query.get("fp") or "chrome"
    transport_fields(proxy, query.get("type") or query.get("transport"), query.get("host"),
                     query.get("path"), query.get("serviceName") or query.get("service_name"))
    return proxy


def parse_hysteria2(uri):
    parsed, query = urlparse(uri), query_map(urlparse(uri))
    host = require_host(parsed.hostname)
    proxy = {"name": "out", "type": "hysteria2", "server": host,
             "port": parsed_port(parsed, 443), "password": unquote(parsed.username or ""), "udp": True,
             "sni": query.get("sni") or host,
             "skip-cert-verify": truthy(query.get("insecure"))}
    if query.get("obfs"):
        proxy["obfs"] = query["obfs"]
        proxy["obfs-password"] = query.get("obfs-password") or query.get("obfs_password", "")
    return proxy


def parse_tuic(uri):
    parsed, query = urlparse(uri), query_map(urlparse(uri))
    raw_user = unquote(parsed.username or "")
    uuid, password = raw_user.split(":", 1) if ":" in raw_user else (raw_user, unquote(parsed.password or ""))
    host = require_host(parsed.hostname)
    return {"name": "out", "type": "tuic", "server": host,
            "port": parsed_port(parsed, 443), "uuid": uuid, "password": password, "udp": True,
            "sni": query.get("sni") or host,
            "skip-cert-verify": truthy(query.get("allow_insecure")),
            "udp-relay-mode": query.get("udp_relay_mode") or "native",
            "congestion-controller": query.get("congestion_control") or "bbr"}


def parse_anytls(uri):
    parsed, query = urlparse(uri), query_map(urlparse(uri))
    host = require_host(parsed.hostname)
    return {"name": "out", "type": "anytls", "server": host,
            "port": parsed_port(parsed, 443), "password": unquote(parsed.username or ""), "udp": True,
            "sni": query.get("sni") or host,
            "skip-cert-verify": truthy(query.get("insecure"))}


def normalize_b64_key(value, field):
    """Validate a base64 key; accept URL-safe alphabets and PEM-ish wrapping.

    usque and the mihomo wiki hand out keys either bare or inside PEM armor;
    normalize to standard padded base64 for the emitted config.
    """
    if not value:
        die(f"masque proxy missing {field}")
    key = re.sub(r"-----[A-Z ]+-----", "", str(value))
    key = re.sub(r"\s+", "", key).replace("-", "+").replace("_", "/")
    key += "=" * (-len(key) % 4)
    try:
        base64.b64decode(key, validate=True)
    except ValueError:
        die(f"masque {field} is not valid base64")
    return key


def valid_cidr(value, field, version=None):
    if not value:
        die(f"masque proxy missing {field} (CIDR)")
    value = str(value)
    if "/" not in value:
        # usque and the mihomo wiki examples often hand out a bare address;
        # normalize to a host route (/32 or /128).
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            die(f"masque {field} must be CIDR notation: {value}")
        value = f"{addr}/{32 if addr.version == 4 else 128}"
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        die(f"masque {field} must be CIDR notation: {value}")
    if version and network.version != version:
        die(f"masque {field} must be IPv{version}: {value}")
    return value


def parse_masque_fields(fields):
    """Build the masque proxy dict from validated input fields (URI or YAML)."""
    proxy = {"name": "out", "type": "masque",
             "server": require_host(fields.get("server")),
             "port": valid_port(fields.get("port") or 443),
             "private-key": normalize_b64_key(fields.get("private-key"), "private-key"),
             "public-key": normalize_b64_key(fields.get("public-key"), "public-key"),
             "ip": valid_cidr(fields.get("ip"), "ip", version=4),
             "udp": True}
    if fields.get("sni"):
        proxy["sni"] = str(fields["sni"]).strip()
    if fields.get("ipv6"):
        proxy["ipv6"] = valid_cidr(fields["ipv6"], "ipv6", version=6)
    mtu = fields.get("mtu")
    if mtu not in (None, ""):
        try:
            mtu = int(mtu)
        except (TypeError, ValueError):
            die(f"masque mtu must be an integer: {mtu}")
        if not 576 <= mtu <= 1500:
            die(f"masque mtu out of range (576-1500): {mtu}")
        proxy["mtu"] = mtu
    if str(fields.get("udp", "")).strip() != "":
        proxy["udp"] = truthy(fields.get("udp"))
    network = str(fields.get("network") or "").lower()
    if network:
        if network not in ("quic", "h2"):
            die(f"masque network must be quic or h2: {network}")
        if network != "quic":  # quic is the mihomo default; keep config minimal
            proxy["network"] = network
    return proxy


def parse_masque(uri):
    parsed, query = urlparse(uri), query_map(urlparse(uri))
    try:
        port = parsed.port
    except ValueError as exc:
        die(f"invalid masque URI port: {exc}")
    fields = {"server": parsed.hostname, "port": port,
              "private-key": unquote(parsed.username or "")}
    fields.update(query)
    return parse_masque_fields(fields)


def parse_flat_yaml(text):
    """Minimal flat key: value YAML reader (stdlib-only).

    Only supports the single-level proxy blocks usque / the mihomo wiki hand
    out: optional '- ' list prefix, '#' comments, single/double quoted scalars.
    Nested structures are rejected rather than misparsed.
    """
    fields = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        match = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if not match:
            die(f"unsupported YAML line: {line!r}")
        key, value = match.group(1), match.group(2).strip()
        if key == "proxies" and value == "":
            continue  # clash-style 'proxies:' wrapper around the list item
        if value[:1] in ("\"", "'"):
            quote = value[0]
            end = value.find(quote, 1)
            if end < 0:
                die(f"unterminated quoted scalar: {line!r}")
            value = value[1:end]
        else:
            value = value.split(" #", 1)[0].strip()
        if value == "":
            die(f"nested YAML structures are not supported: {line!r}")
        fields[key] = value
    return fields


def parse_masque_yaml(text):
    fields = parse_flat_yaml(text)
    ptype = fields.pop("type", "").lower()
    if ptype != "masque":
        die(f"YAML proxy type must be masque, got: {ptype or '(missing)'}")
    fields.pop("name", None)
    return parse_masque_fields(fields)


def parse_http(uri):
    parsed = urlparse(uri)
    host = require_host(parsed.hostname)
    proxy = {"name": "out", "type": "http", "server": host,
             "port": parsed_port(parsed, 443 if parsed.scheme.lower() == "https" else 80)}
    if parsed.username:
        proxy["username"] = unquote(parsed.username)
    if parsed.password:
        proxy["password"] = unquote(parsed.password)
    if parsed.scheme.lower() == "https":
        tls_fields(proxy, host)
    return proxy


def parse_proxy_uri(uri):
    low = uri.lower()
    parsers = (("ss://", parse_ss), ("vmess://", parse_vmess), ("trojan://", parse_trojan),
               ("vless://", parse_vless), ("hysteria2://", parse_hysteria2), ("hy2://", parse_hysteria2),
               ("tuic://", parse_tuic), ("anytls://", parse_anytls), ("masque://", parse_masque),
               ("socks5h://", parse_socks), ("socks5://", parse_socks), ("socks://", parse_socks),
               ("http://", parse_http), ("https://", parse_http))
    for prefix, parser in parsers:
        if low.startswith(prefix):
            return parser(uri)
    die("unsupported URI scheme")


def interface_name(name):
    if re.fullmatch(r"[A-Za-z0-9_-]{1,11}", name):
        return "pgw-" + name
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:11]
    return "pgw-" + digest


def main():
    if len(sys.argv) != 3:
        die("usage: mihomo-exit-config.py <name> <uri>|--yaml")
    name, source = sys.argv[1], sys.argv[2].strip()
    if name in ("local", "smart") or not re.match(r"^[\w\-\u4e00-\u9fff]{1,16}$", name, re.UNICODE):
        die("invalid exit name")
    if source == "--yaml":
        proxy = parse_masque_yaml(sys.stdin.read())
        uri = "masque://"
    else:
        proxy = parse_proxy_uri(source)
        uri = source
    if proxy["type"] in ("socks5", "http"):
        if os.environ.get("PGW_USER"):
            proxy["username"] = os.environ["PGW_USER"]
        if os.environ.get("PGW_PASS"):
            proxy["password"] = os.environ["PGW_PASS"]
    remote_dns = truthy(os.environ.get("PGW_REMOTE_DNS")) or uri.lower().startswith("socks5h://")
    try:
        mtu = int(os.environ.get("MIHOMO_MTU", "1400"))
    except ValueError:
        die("MIHOMO_MTU must be an integer")
    config = {
        "mode": "rule", "log-level": "warning", "ipv6": False, "find-process-mode": "off",
        "tun": {"enable": True, "stack": os.environ.get("MIHOMO_STACK", "gvisor"),
                "device": interface_name(name), "auto-route": False, "auto-redirect": False,
                "strict-route": False, "mtu": mtu},
        "proxies": [proxy], "rules": ["MATCH,out"], "dns": DNS_CONFIG,
    }
    if remote_dns:
        config["sniffer"] = {"enable": True, "force-dns-mapping": True, "parse-pure-ip": True,
                             "override-destination": True,
                             "sniff": {"TLS": {"ports": [443, 8443]}, "HTTP": {"ports": [80, "8080-8880"]}}}
    sys.stdout.write(json.dumps(config, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
