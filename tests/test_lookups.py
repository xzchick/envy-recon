"""Lookup parsing and orchestration with faked network services (no real traffic)."""
import datetime as dt
import unittest

from envy_recon import lookups, validate
from envy_recon.net import Net, NetworkDisabled, ReconError


class FakeAnswer:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class FakeResolver:
    def __init__(self, table):
        self.table = table

    def resolve(self, name, rtype):
        import dns.resolver
        key = (name.rstrip("."), rtype)
        if key not in self.table:
            raise dns.resolver.NoAnswer()
        val = self.table[key]
        if val == "NXDOMAIN":
            raise dns.resolver.NXDOMAIN()
        return [FakeAnswer(v) for v in val]


class FakeNet(Net):
    """Serves canned HTTP responses; records what was asked for."""

    def __init__(self, routes=None, dns_table=None, offline=False):
        super().__init__(offline=offline)
        self.routes = routes or {}
        self.resolver = FakeResolver(dns_table or {})
        self.slept = []

    def _sleep(self, seconds):
        self.slept.append(seconds)

    def request(self, url, *, method="GET", follow=True, max_bytes=0, accept=None):
        self.require_online(f"{method} {url}")
        for prefix, resp in self.routes.items():
            if url.startswith(prefix):
                if isinstance(resp, list):
                    resp = resp.pop(0) if len(resp) > 1 else resp[0]
                status, headers, body = resp
                return status, headers, body if isinstance(body, bytes) else body.encode(), url
        return 404, [], b"", url


class ValidateTests(unittest.TestCase):
    def test_domains(self):
        self.assertEqual(validate.domain("HTTPS://Example.COM/path"), "example.com")
        self.assertEqual(validate.domain("*.example.org."), "example.org")
        self.assertEqual(validate.domain("münchen.de"), "xn--mnchen-3ya.de")
        for bad in ("", "localhost", "exa mple.com", "-bad.com", "1.2.3.4", "a..com"):
            with self.assertRaises(ReconError, msg=bad):
                validate.domain(bad)

    def test_ips_and_urls(self):
        self.assertEqual(validate.ip(" 2001:DB8::1 "), "2001:db8::1")
        self.assertTrue(validate.is_ip("8.8.8.8"))
        self.assertEqual(validate.url("example.com"), "https://example.com/")
        with self.assertRaises(ReconError):
            validate.url("ftp://example.com")
        with self.assertRaises(ReconError):
            validate.ip("999.1.1.1")


class DnsTests(unittest.TestCase):
    def test_records_and_spf(self):
        net = FakeNet(dns_table={("example.com", "A"): ["93.184.215.14"],
                                 ("example.com", "TXT"): ['"v=spf1 -all"', '"hello"'],
                                 ("example.com", "MX"): ["10 mail.example.com."]})
        out = lookups.dns_records(net, "example.com")
        self.assertEqual(out["records"]["A"], ["93.184.215.14"])
        self.assertEqual(out["spf"], "v=spf1 -all")
        self.assertNotIn("AAAA", out["records"])
        self.assertIn("DNS example.com", net.history[0])

    def test_nxdomain(self):
        net = FakeNet(dns_table={("nope.example", "A"): "NXDOMAIN"})
        with self.assertRaises(ReconError):
            lookups.dns_records(net, "nope.example", types=("A",))

    def test_asn_via_cymru(self):
        net = FakeNet(dns_table={("8.8.8.8.origin.asn.cymru.com", "TXT"): ['"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
                                 ("AS15169.asn.cymru.com", "TXT"): ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"']})
        out = lookups.asn(net, "8.8.8.8")
        self.assertEqual((out["asn"], out["prefix"], out["as_name"]), ("15169", "8.8.8.0/24", "GOOGLE - Google LLC, US"))

    def test_private_ip_has_no_asn_and_makes_no_query(self):
        net = FakeNet()
        self.assertIn("Private", lookups.asn(net, "192.168.1.10")["note"])
        self.assertEqual(net.history, [])

    def test_ipv6_cymru_name(self):
        import ipaddress
        name = lookups._cymru_query(ipaddress.ip_address("2001:db8::1"))
        self.assertTrue(name.endswith(".origin6.asn.cymru.com"))
        self.assertTrue(name.startswith("1.0.0.0."))


RDAP_DOMAIN = """{"ldhName":"EXAMPLE.COM","status":["client transfer prohibited"],
 "events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"}],
 "nameservers":[{"ldhName":"B.IANA-SERVERS.NET"},{"ldhName":"A.IANA-SERVERS.NET"}],
 "secureDNS":{"delegationSigned":true},
 "entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-IANA"]]]}]}"""


class HttpServiceTests(unittest.TestCase):
    def test_rdap_domain(self):
        net = FakeNet({"https://rdap.org/domain/": (200, [], RDAP_DOMAIN)})
        out = lookups.whois(net, "example.com")
        self.assertEqual(out["nameservers"], ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertEqual(out["entities"], {"registrar": ["RESERVED-IANA"]})
        self.assertTrue(out["dnssec"])

    def test_rdap_missing(self):
        with self.assertRaises(ReconError):
            lookups.whois(FakeNet(), "example.com")

    def test_crtsh_parsing_and_retry_on_busy(self):
        rows = """[{"name_value":"example.com\\n*.example.com","issuer_name":"C=US, O=\\"DigiCert Inc\\", CN=x","not_before":"2020-01-02T00:00:00"},
                   {"name_value":"www.example.com\\nevil.com","issuer_name":"C=US, O=Let's Encrypt, CN=R3","not_before":"2024-05-06T00:00:00"}]"""
        net = FakeNet({"https://crt.sh/": [(502, [], ""), (200, [], rows)]})
        out = lookups.certs(net, "example.com")
        self.assertEqual(out["hostnames"], ["example.com", "www.example.com"])  # evil.com filtered
        self.assertEqual((out["first_seen"], out["last_seen"]), ("2020-01-02", "2024-05-06"))
        self.assertEqual(out["top_issuers"], {"DigiCert Inc": 1, "Let's Encrypt": 1})
        self.assertEqual(net.slept, [2.0])

    def test_busy_service_gives_clear_error(self):
        net = FakeNet({"https://crt.sh/": [(503, [], "")]})
        with self.assertRaisesRegex(ReconError, "busy or down"):
            lookups.certs(net, "example.com")

    def test_wayback_first_last_and_months(self):
        months = '[["timestamp"],["20020120000000"],["20020301000000"],["20210105000000"]]'
        latest = '[["timestamp"],["20261124031500"]]'
        net = FakeNet({"https://web.archive.org/cdx/search/cdx?url=example.com&output=json&fl=timestamp&collapse": (200, [], months),
                       "https://web.archive.org/cdx/search/cdx?url=example.com&output=json&fl=timestamp&limit=-1": (200, [], latest)})
        out = lookups.wayback(net, "example.com")
        self.assertEqual((out["first"], out["last"]), ("2002-01-20", "2026-11-24"))
        self.assertEqual(out["months_by_year"], {"2002": 2, "2021": 1})

    def test_headers_follow_redirects_and_flag_security(self):
        net = FakeNet({
            "http://example.com/": (301, [("Location", "https://example.com/")], ""),
            "https://example.com/": (200, [("Server", "nginx"), ("Strict-Transport-Security", "max-age=1"),
                                           ("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")],
                                     "<html><title> Hi\n there </title><meta name='generator' content='WordPress 6.5'>"),
        })
        out = lookups.headers(net, "http://example.com")
        self.assertEqual(out["final_url"], "https://example.com/")
        self.assertEqual(out["redirects"], [{"url": "http://example.com/", "status": 301}])
        self.assertEqual((out["server"], out["title"], out["generator"]), ("nginx", "Hi there", "WordPress 6.5"))
        self.assertTrue(out["security_headers"]["strict-transport-security"])
        self.assertFalse(out["security_headers"]["content-security-policy"])
        self.assertEqual(out["cookies"], [{"name": "sid", "secure": True, "httponly": True, "samesite": "lax"}])
        self.assertNotIn("Set-Cookie", out["headers"])  # cookie values are never stored

    def test_redirect_to_other_scheme_stops(self):
        net = FakeNet({"https://example.com/": (302, [("Location", "file:///etc/passwd")], "")})
        out = lookups.headers(net, "example.com")
        self.assertEqual(out["final_url"], "https://example.com/")


class TlsTests(unittest.TestCase):
    def test_parse_peer_cert(self):
        cert = {"subject": ((("commonName", "example.com"),),),
                "issuer": ((("organizationName", "DigiCert Inc"),), (("commonName", "DigiCert TLS"),)),
                "notBefore": "Jan 13 00:00:00 2026 GMT", "notAfter": "Feb  1 23:59:59 2027 GMT",
                "subjectAltName": (("DNS", "www.example.com"), ("DNS", "example.com"))}
        out = lookups.parse_peer_cert(cert, now=dt.datetime(2026, 11, 24, tzinfo=dt.timezone.utc))
        self.assertEqual((out["subject"], out["issuer"]), ("example.com", "DigiCert Inc"))
        self.assertEqual(out["alt_names"], ["example.com", "www.example.com"])
        self.assertEqual(out["days_left"], 69)


class OfflineTests(unittest.TestCase):
    def test_offline_blocks_every_lookup(self):
        net = FakeNet(offline=True)
        for fn, arg in ((lookups.dns_records, "example.com"), (lookups.whois, "example.com"),
                        (lookups.certs, "example.com"), (lookups.headers, "example.com"),
                        (lookups.wayback, "example.com")):
            with self.assertRaises(NetworkDisabled, msg=fn.__name__):
                fn(net, arg)
        self.assertEqual(net.history, [])

    def test_domain_report_survives_failing_sections(self):
        net = FakeNet({"https://rdap.org/domain/": (200, [], RDAP_DOMAIN)},
                      dns_table={("example.com", "A"): ["10.0.0.1"]})
        net.tls_handshake = lambda host, port: (_ for _ in ()).throw(ReconError("no tls"))
        out = lookups.domain_report(net, "example.com")
        self.assertEqual(out["dns"]["records"]["A"], ["10.0.0.1"])
        self.assertEqual(out["tls"], {"error": "no tls"})
        self.assertEqual(out["certs"]["certificates"], 0)   # not found → empty, not a crash
        self.assertEqual(out["http"]["status"], 404)
        self.assertIn("Private", out["addresses"]["10.0.0.1"]["note"])


if __name__ == "__main__":
    unittest.main()


class TlsContextTests(unittest.TestCase):
    def test_context_verifies_with_bundled_roots(self):
        import ssl
        from envy_recon.net import tls_context
        ctx = tls_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertGreater(ctx.cert_store_stats()["x509_ca"], 50)
