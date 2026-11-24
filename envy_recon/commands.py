"""The single command table shared by the interactive shell and the one-shot CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import lookups, metadata, validate
from .net import Net, ReconError


@dataclass(frozen=True)
class Command:
    name: str
    usage: str
    summary: str
    run: Callable[[Net, str], dict]
    online: bool = True


def _tls(net: Net, arg: str) -> dict:
    host, port = arg.strip(), 443
    # host:port, but leave bare IPv6 addresses (several colons) alone
    if host.count(":") == 1 and not host.startswith("["):
        host, _, p = host.partition(":")
        if not p.isdigit() or not 0 < int(p) < 65536:
            raise ReconError(f"Not a valid port: {p!r}")
        port = int(p)
    return lookups.tls(net, host, port)


def _ip(net: Net, arg: str) -> dict:
    return lookups.ip_info(net, validate.ip(arg))


COMMANDS = {c.name: c for c in (
    Command("domain", "domain <example.com>", "Everything for a domain: DNS, WHOIS, TLS, HTTP, certificates, archive",
            lookups.domain_report),
    Command("dns", "dns <example.com>", "DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA) and SPF",
            lookups.dns_records),
    Command("whois", "whois <domain or IP>", "Registration data via RDAP (registrar, dates, nameservers, network)",
            lookups.whois),
    Command("ip", "ip <address>", "Reverse DNS, ASN / owner and RDAP network for an IP address", _ip),
    Command("certs", "certs <example.com>", "Hostnames and issuers from certificate-transparency logs (crt.sh)",
            lookups.certs),
    Command("wayback", "wayback <domain or URL>", "Wayback Machine snapshot history", lookups.wayback),
    Command("headers", "headers <URL>", "Redirect chain, server, security headers and cookie flags",
            lookups.headers),
    Command("tls", "tls <host[:port]>", "TLS certificate: issuer, validity, alt names, protocol", _tls),
    Command("meta", "meta <file>", "Offline: hashes, EXIF and GPS, PDF info, Office document properties",
            lambda _net, arg: metadata.file_meta(arg), online=False),
)}


def run(net: Net, name: str, arg: str) -> dict:
    cmd = COMMANDS.get(name)
    if cmd is None:
        raise ReconError(f"Unknown command: {name}. Type 'help' for the list.")
    if not arg.strip():
        raise ReconError(f"Usage: {cmd.usage}")
    return cmd.run(net, arg.strip())
