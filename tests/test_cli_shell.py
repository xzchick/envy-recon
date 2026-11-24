"""The one-shot CLI and the interactive shell, driven without a terminal."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from envy_recon import __version__, cli
from envy_recon.render import render
from envy_recon.session import Session
from envy_recon.shell import ReconShell
from envy_recon.net import Net, ReconError


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_version(self):
        code, out, _ = run_cli("--version")
        self.assertEqual((code, out.strip()), (0, f"envy-recon {__version__}"))

    def test_meta_json_works_offline(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.txt"; p.write_text("x")
            code, out, _ = run_cli("meta", str(p), "--json", "--offline")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["type"], "unknown")

    def test_network_command_blocked_offline_exits_2(self):
        code, out, err = run_cli("dns", "example.com", "--offline")
        self.assertEqual(code, 2)
        self.assertIn("Offline mode is on", err)

    def test_bad_input_exits_1(self):
        code, _, err = run_cli("dns", "not a domain", "--offline")
        self.assertEqual(code, 1)
        self.assertIn("Not a valid domain", err)


class ShellTests(unittest.TestCase):
    def make(self):
        out = io.StringIO()
        return ReconShell(Net(offline=True), out=out, color=False), out

    def test_help_lists_every_command(self):
        sh, out = self.make()
        sh.onecmd("help")
        for name in ("domain", "dns", "whois", "ip", "certs", "wayback", "headers", "tls", "meta", "save"):
            self.assertIn(name, out.getvalue())

    def test_offline_lookup_and_meta_then_save(self):
        sh, out = self.make()
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "evidence.txt"; f.write_text("hi")
            sh.onecmd("dns example.com")
            self.assertIn("Offline mode is on", out.getvalue())
            sh.onecmd(f'meta {f}')
            self.assertIn("sha256", out.getvalue())
            report = Path(d) / "report.md"
            sh.onecmd(f"save {report}")
            text = report.read_text()
            self.assertIn("# ENVY Recon report", text)
            self.assertIn("`meta", text)
            self.assertIn("SHA-256", out.getvalue())
            sh.onecmd(f"save {report}")  # never overwrites
            self.assertIn("already exists", out.getvalue())

    def test_offline_toggle_and_unknown(self):
        sh, out = self.make()
        sh.onecmd("offline off")
        self.assertFalse(sh.net.offline)
        sh.onecmd("frobnicate x")
        self.assertIn("Unknown command", out.getvalue())
        self.assertTrue(sh.onecmd("exit"))


class SessionAndRenderTests(unittest.TestCase):
    def test_export_json_includes_network_log(self):
        s = Session(); s.add("dns", "example.com", {"records": {}})
        with tempfile.TemporaryDirectory() as d:
            res = s.export(str(Path(d) / "r.json"), ["DNS example.com"])
            data = json.loads(Path(res["path"]).read_text())
        self.assertEqual(data["network_requests"], ["DNS example.com"])
        self.assertEqual(len(res["sha256"]), 64)

    def test_export_empty_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ReconError):
            Session().export(str(Path(d) / "r.json"), [])

    def test_render_plain(self):
        text = render("t", {"a": True, "b": None, "error": "boom", "items": list(range(70))}, color=False)
        self.assertIn("a: yes", text)
        self.assertIn("✗ boom", text)
        self.assertIn("10 more", text)
        self.assertNotIn("\x1b[", text)


if __name__ == "__main__":
    unittest.main()
