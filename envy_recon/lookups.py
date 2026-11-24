"""Public-source infrastructure lookups. Each returns a plain dict ready to render or export.

Sources: DNS (your system resolver), RDAP via rdap.org, Team Cymru's IP-to-ASN DNS
service, crt.sh certificate-transparency search, the Wayback Machine CDX API, and the
target itself (HTTP headers, TLS certificate). No API keys, no accounts.
"""

from __future__ import annotations

import collections
import datetime as dt
import ipaddress
import re
import urllib.parse

from . import validate
from .net import Net, ReconError

DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy")


# --- DNS --------------------------------------------------------------------

def _resolve(net: Net, name: str, rtype: str):
    import dns.exception
    import dns.resolver
    try:
        return [r.to_text() for r in net.resolver.resolve(name, rtype)]
    except dns.resolver.NXDOMAIN:
        raise ReconError(f"{name} does not exist (NXDOMAIN)") from None
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        raise ReconError(f"DNS timed out for {name} {rtype}") from None


def dns_records(net: Net, target: str, types=DNS_TYPES) -> dict:
    name = validate.domain(target)
    net.require_online(f"DNS {name} ({', '.join(types)})")
    records = {}
    for rtype in types:
        found = _resolve(net, name, rtype)
        if found:
            records[rtype] = sorted(found)
    return {"domain": name, "records": records,
            "spf": next((t.strip('"') for t in records.get("TXT", []) if "v=spf1" in t), None)}


def reverse_dns(net: Net, address: str) -> list:
    import dns.reversename
    addr = validate.ip(address)
    net.require_online(f"DNS PTR {addr}")
    return sorted(n.rstrip(".") for n in _resolve(net, dns.reversename.from_address(addr).to_text(), "PTR"))


def _cymru_query(ip_obj) -> str:
    if ip_obj.version == 4:
        return ".".join(reversed(str(ip_obj).split("."))) + ".origin.asn.cymru.com"
    nibbles = ip_obj.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_cymru(origin_txt: str, as_txt: str | None) -> dict:
    """Parse Team Cymru answers: '15169 | 8.8.8.0/24 | US | arin | 2023-12-28'."""
    fields = [f.strip() for f in origin_txt.strip('"').split("|")]
    out = {"asn": fields[0].split()[0] if fields[0] else None,
           "prefix": fields[1] if len(fields) > 1 else None,
           "country": fields[2] if len(fields) > 2 else None,
           "registry": fields[3] if len(fields) > 3 else None,
           "allocated": fields[4] if len(fields) > 4 else None}
    if as_txt:
        parts = [f.strip() for f in as_txt.strip('"').split("|")]
        out["as_name"] = parts[-1] if parts else None
    return out


def asn(net: Net, address: str) -> dict:
    ip_obj = ipaddress.ip_address(validate.ip(address))
    if not ip_obj.is_global:
        return {"ip": str(ip_obj), "note": "Private or reserved address — no public ASN."}
    net.require_online(f"DNS TXT Team Cymru ASN for {ip_obj}")
    origin = _resolve(net, _cymru_query(ip_obj), "TXT")
    if not origin:
        return {"ip": str(ip_obj), "note": "No ASN found."}
    info = parse_cymru(origin[0], None)
    if info["asn"]:
        names = _resolve(net, f"AS{info['asn']}.asn.cymru.com", "TXT")
        info = parse_cymru(origin[0], names[0] if names else None)
    return {"ip": str(ip_obj), **info}


# --- RDAP (modern WHOIS) ------------------------------------------------------

def _vcard_name(entity: dict) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] in ("fn", "org") and item[-1]:
            return str(item[-1])
    return entity.get("handle")


def _entities(obj: dict) -> dict:
    roles = collections.defaultdict(list)
    for ent in obj.get("entities") or []:
        name = _vcard_name(ent)
        for role in ent.get("roles") or ["unknown"]:
            if name and name not in roles[role]:
                roles[role].append(name)
    return dict(roles)


def _events(obj: dict) -> dict:
    return {e.get("eventAction"): e.get("eventDate") for e in obj.get("events") or [] if e.get("eventAction")}


def parse_rdap_domain(data: dict) -> dict:
    return {"domain": (data.get("ldhName") or "").lower(),
            "status": data.get("status") or [],
            "events": _events(data),
            "nameservers": sorted((ns.get("ldhName") or "").lower() for ns in data.get("nameservers") or []),
            "dnssec": (data.get("secureDNS") or {}).get("delegationSigned"),
            "entities": _entities(data)}


def parse_rdap_ip(data: dict) -> dict:
    return {"network": data.get("name"), "handle": data.get("handle"),
            "range": f"{data.get('startAddress')} – {data.get('endAddress')}",
            "type": data.get("type"), "country": data.get("country"),
            "events": _events(data), "entities": _entities(data)}


def whois(net: Net, target: str) -> dict:
    """RDAP lookup for a domain or an IP address (RDAP replaced port-43 WHOIS)."""
    if validate.is_ip(target):
        addr = validate.ip(target)
        data = net.json(f"https://rdap.org/ip/{addr}", accept="application/rdap+json, application/json")
        if data is None:
            raise ReconError(f"No RDAP record for {addr}")
        return {"query": addr, **parse_rdap_ip(data)}
    name = validate.domain(target)
    data = net.json(f"https://rdap.org/domain/{name}", accept="application/rdap+json, application/json")
    if data is None:
        raise ReconError(f"No RDAP record for {name} (unregistered, or its registry has no RDAP)")
    return {"query": name, **parse_rdap_domain(data)}


def ip_info(net: Net, address: str) -> dict:
    addr = validate.ip(address)
    out = {"ip": addr}
    for key, fn in (("reverse_dns", reverse_dns), ("asn", asn), ("rdap", whois)):
        try:
            out[key] = fn(net, addr)
        except ReconError as exc:
            out[key] = {"error": str(exc)}
    return out


# --- Certificate transparency -----------------------------------------------

def parse_crtsh(rows: list, domain: str) -> dict:
    names, issuers, first, last = set(), collections.Counter(), None, None
    for row in rows or []:
        for n in str(row.get("name_value", "")).lower().split("\n"):
            n = n.strip().removeprefix("*.")
            if n == domain or n.endswith("." + domain):
                names.add(n)
        issuer = re.search(r"O=([^,]+)", str(row.get("issuer_name", "")))
        issuers[issuer.group(1).strip('"') if issuer else str(row.get("issuer_name", "?"))] += 1
        nb = str(row.get("not_before", ""))[:10]
        if nb:
            first = nb if first is None or nb < first else first
            last = nb if last is None or nb > last else last
    return {"domain": domain, "certificates": len(rows or []), "first_seen": first, "last_seen": last,
            "hostnames": sorted(names), "top_issuers": dict(issuers.most_common(5))}


def certs(net: Net, target: str) -> dict:
    """Hostnames seen in public certificate-transparency logs (via crt.sh)."""
    name = validate.domain(target)
    rows = net.json(f"https://crt.sh/?q={urllib.parse.quote('%.' + name)}&output=json", retries=2)
    return parse_crtsh(rows or [], name)


# --- Wayback Machine --------------------------------------------------------

def _cdx_stamps(rows: list) -> list:
    data = rows[1:] if rows and rows[0] and rows[0][0] == "timestamp" else (rows or [])
    return sorted(r[0] for r in data if r and str(r[0])[:4].isdigit())


def _iso(s):
    return f"{s[:4]}-{s[4:6]}-{s[6:8]}" if s else None


def parse_cdx(month_rows: list, latest_rows: list | None = None) -> dict:
    """Summarise a month-collapsed CDX listing, plus an optional latest-snapshot query."""
    stamps = _cdx_stamps(month_rows)
    latest = _cdx_stamps(latest_rows or [])
    years = collections.Counter(s[:4] for s in stamps)
    last = max([s for s in (stamps[-1:] + latest[-1:])], default=None)
    return {"months_with_snapshots": len(stamps), "first": _iso(stamps[0]) if stamps else None,
            "last": _iso(last), "months_by_year": dict(sorted(years.items()))}


def wayback(net: Net, target: str) -> dict:
    """When and how often a domain or URL was archived (first/last snapshot, months per year)."""
    t = target.strip()
    if "://" not in t:
        t = validate.domain(t)
    base = "https://web.archive.org/cdx/search/cdx?"
    months = net.json(base + urllib.parse.urlencode(
        {"url": t, "output": "json", "fl": "timestamp", "collapse": "timestamp:6", "limit": "2000"}), retries=1)
    latest = net.json(base + urllib.parse.urlencode(
        {"url": t, "output": "json", "fl": "timestamp", "limit": "-1", "fastLatest": "true"}), retries=1)
    return {"target": t, **parse_cdx(months or [], latest or []),
            "browse": f"https://web.archive.org/web/*/{t}"}


# --- The target itself: HTTP + TLS ------------------------------------------

def _hget(headers, name):
    return next((v for k, v in headers if k.lower() == name), None)


def _cookie_flags(headers) -> list:
    out = []
    for k, v in headers:
        if k.lower() != "set-cookie":
            continue
        name = v.split("=", 1)[0].strip()
        low = v.lower()
        out.append({"name": name, "secure": "secure" in low, "httponly": "httponly" in low,
                    "samesite": (re.search(r"samesite=(\w+)", low) or [None, None])[1]})
    return out


def headers(net: Net, target: str, max_hops: int = 10) -> dict:
    """Fetch a URL, following redirects hop by hop, and summarise what the server reveals."""
    url = validate.url(target)
    chain = []
    for _ in range(max_hops):
        status, hdrs, body, _ = net.request(url, follow=False, max_bytes=256 * 1024)
        chain.append({"url": url, "status": status})
        loc = _hget(hdrs, "location")
        if status in (301, 302, 303, 307, 308) and loc:
            nxt = urllib.parse.urljoin(url, loc)
            if urllib.parse.urlsplit(nxt).scheme not in ("http", "https"):
                break
            url = nxt
            continue
        break
    else:
        raise ReconError(f"More than {max_hops} redirects")
    text = body.decode("utf-8", "replace")
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', text, re.I)
    return {"final_url": url, "status": chain[-1]["status"], "redirects": chain[:-1],
            "server": _hget(hdrs, "server"), "powered_by": _hget(hdrs, "x-powered-by"),
            "title": re.sub(r"\s+", " ", title.group(1)).strip()[:200] if title else None,
            "generator": gen.group(1) if gen else None,
            "security_headers": {h: (_hget(hdrs, h) is not None) for h in SECURITY_HEADERS},
            "cookies": _cookie_flags(hdrs),
            "headers": {k: v for k, v in hdrs if k.lower() != "set-cookie"}}


def _name(rdn_seq, key):
    for rdn in rdn_seq or ():
        for k, v in rdn:
            if k == key:
                return v
    return None


def parse_peer_cert(cert: dict, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    fmt = "%b %d %H:%M:%S %Y %Z"
    nb = dt.datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=dt.timezone.utc)
    na = dt.datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=dt.timezone.utc)
    return {"subject": _name(cert.get("subject"), "commonName"),
            "issuer": _name(cert.get("issuer"), "organizationName") or _name(cert.get("issuer"), "commonName"),
            "valid_from": nb.date().isoformat(), "valid_to": na.date().isoformat(),
            "days_left": (na - now).days,
            "alt_names": sorted(v for k, v in cert.get("subjectAltName", ()) if k == "DNS")}


def tls(net: Net, target: str, port: int = 443) -> dict:
    host = target.strip()
    if "://" in host:
        host = urllib.parse.urlsplit(host).hostname or ""
    host = host if validate.is_ip(host) else validate.domain(host)
    cert, version, cipher = net.tls_handshake(host, port)
    return {"host": host, "port": port, "protocol": version, "cipher": cipher, **parse_peer_cert(cert)}


# --- Everything for a domain --------------------------------------------------

def domain_report(net: Net, target: str) -> dict:
    """Run every domain lookup; one failing section never stops the others."""
    name = validate.domain(target)
    report = {"domain": name}
    steps = (("dns", lambda: dns_records(net, name)), ("whois", lambda: whois(net, name)),
             ("tls", lambda: tls(net, name)), ("http", lambda: headers(net, name)),
             ("certs", lambda: certs(net, name)), ("wayback", lambda: wayback(net, name)))
    for key, fn in steps:
        try:
            report[key] = fn()
        except ReconError as exc:
            report[key] = {"error": str(exc)}
    addrs = (report.get("dns") or {}).get("records", {}).get("A", [])[:3]
    report["addresses"] = {}
    for a in addrs:
        try:
            report["addresses"][a] = asn(net, a)
        except ReconError as exc:
            report["addresses"][a] = {"error": str(exc)}
    return report
