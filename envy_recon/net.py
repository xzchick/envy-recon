"""Transparent networking: every request is announced, and offline mode blocks all of it.

Recon talks only to public services (RDAP, DNS, crt.sh, the Wayback Machine and the
target you name). Nothing else is contacted: no telemetry, no update checks.
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

USER_AGENT = f"envy-recon/{__version__} (+https://github.com/xzchick/envy-recon)"
MAX_BODY = 16 * 1024 * 1024


class ReconError(Exception):
    """A user-facing problem: bad input, a failed lookup, or blocked network."""


class NetworkDisabled(ReconError):
    """Raised when a lookup needs the network but offline mode is on."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Net:
    """All outbound access goes through here so it can be shown and switched off."""

    def __init__(self, offline: bool = False, log=None, timeout: float = 20.0):
        self.offline = offline
        self.timeout = timeout
        self.history: list[str] = []
        self._log = log
        self._resolver = None

    @staticmethod
    def _sleep(seconds: float) -> None:
        import time
        time.sleep(seconds)

    # -- bookkeeping ---------------------------------------------------------
    def note(self, line: str) -> None:
        self.history.append(line)
        if self._log:
            self._log(line)

    def require_online(self, what: str) -> None:
        if self.offline:
            raise NetworkDisabled(f"Offline mode is on — not running: {what}. "
                                  "Turn it off with 'offline off' (or drop --offline).")
        self.note(what)

    # -- HTTP ----------------------------------------------------------------
    def request(self, url: str, *, method: str = "GET", follow: bool = True,
                max_bytes: int = MAX_BODY, accept: str | None = None):
        """Fetch ``url``; returns (status, headers list, body bytes, final url)."""
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ReconError(f"Only http(s) URLs are allowed, not {scheme or 'none'}://")
        self.require_online(f"{method} {url}")
        headers = {"User-Agent": USER_AGENT}
        if accept:
            headers["Accept"] = accept
        req = urllib.request.Request(url, method=method, headers=headers)
        opener = (urllib.request.build_opener() if follow
                  else urllib.request.build_opener(_NoRedirect))
        try:
            resp = opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read(max_bytes) if exc.fp else b""
            return exc.code, list(exc.headers.items()), body, url
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ReconError(f"Could not reach {urllib.parse.urlsplit(url).netloc}: {reason}") from None
        with resp:
            body = resp.read(max_bytes) if method != "HEAD" else b""
            return resp.status, list(resp.headers.items()), body, resp.geturl()

    def json(self, url: str, *, accept: str = "application/json", retries: int = 0, backoff: float = 2.0):
        """GET JSON. ``retries`` re-tries 5xx answers (busy free services) with backoff."""
        for attempt in range(retries + 1):
            status, _, body, final = self.request(url, accept=accept)
            if status < 500 or attempt == retries:
                break
            self.note(f"(HTTP {status}, retrying in {backoff * (attempt + 1):.0f}s)")
            self._sleep(backoff * (attempt + 1))
        host = urllib.parse.urlsplit(final).netloc
        if status == 404:
            return None
        if status >= 500:
            raise ReconError(f"{host} is busy or down (HTTP {status}) — it's a free public service; try again shortly")
        if status >= 400:
            raise ReconError(f"{host} answered HTTP {status}")
        try:
            return json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            raise ReconError(f"{urllib.parse.urlsplit(final).netloc} did not return JSON "
                             "(the service may be busy — try again)") from None

    # -- DNS -----------------------------------------------------------------
    @property
    def resolver(self):
        if self._resolver is None:
            import dns.resolver
            r = dns.resolver.Resolver()
            r.lifetime = min(self.timeout, 10.0)
            self._resolver = r
        return self._resolver

    @resolver.setter
    def resolver(self, value):
        self._resolver = value

    # -- TLS -----------------------------------------------------------------
    def tls_handshake(self, host: str, port: int = 443):
        """Return (peer cert dict, TLS version, cipher name) for a verified connection."""
        self.require_online(f"TLS {host}:{port}")
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    return tls.getpeercert(), tls.version(), (tls.cipher() or ("",))[0]
        except ssl.SSLCertVerificationError as exc:
            raise ReconError(f"Certificate did not verify: {exc.verify_message}") from None
        except (OSError, ssl.SSLError) as exc:
            raise ReconError(f"TLS connection to {host}:{port} failed: {exc}") from None
