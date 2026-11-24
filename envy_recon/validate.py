"""Strict input checks so every lookup gets a well-formed domain, IP or URL."""

from __future__ import annotations

import ipaddress
import re
import urllib.parse

from .net import ReconError

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def domain(value: str) -> str:
    """Normalise a domain name (lower-case, IDNA, no scheme/path/trailing dot)."""
    v = (value or "").strip().lower()
    if "://" in v:
        v = urllib.parse.urlsplit(v).hostname or ""
    v = v.split("/")[0].rstrip(".")
    if v.startswith("*."):
        v = v[2:]
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        raise ReconError(f"Not a valid domain name: {value!r}") from None
    labels = v.split(".")
    if len(v) > 253 or len(labels) < 2 or not all(_LABEL.match(l) for l in labels) or labels[-1].isdigit():
        raise ReconError(f"Not a valid domain name: {value!r}")
    return v


def ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise ReconError(f"Not a valid IP address: {value!r}") from None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def url(value: str) -> str:
    """Accept 'example.com' or a full http(s) URL; return a full URL."""
    v = (value or "").strip()
    if "://" not in v:
        v = "https://" + v
    parts = urllib.parse.urlsplit(v)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ReconError(f"Not a valid http(s) URL: {value!r}")
    host = parts.hostname
    if not is_ip(host):
        domain(host)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
