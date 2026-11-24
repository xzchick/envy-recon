"""The interactive ENVY Recon terminal. Works in Windows Terminal/PowerShell/cmd, macOS
Terminal and any Linux shell; line editing uses readline only where it exists."""

from __future__ import annotations

import cmd
import json
import shlex
import sys

from . import __version__
from .commands import COMMANDS, run
from .net import Net, NetworkDisabled, ReconError
from .render import AMBER, CYAN, DIM, GREEN, LAVENDER, PINK, Painter, banner, enable_windows_ansi, render
from .session import Session

NOTICE = ("Lookups query public services and the target you name; each request is shown as it happens. "
          "Use only on targets you're entitled to research. 'offline on' blocks all network access.")


class ReconShell(cmd.Cmd):
    def __init__(self, net: Net | None = None, out=None, color: bool | None = None):
        super().__init__(stdout=out or sys.stdout)
        self.p = Painter(color)
        self.net = net or Net()
        self.net._log = self._show_request
        self.session = Session()
        self.last = None
        self._refresh_prompt()

    # -- output helpers --------------------------------------------------------
    def say(self, text=""):
        self.stdout.write(f"{text}\n")

    def _show_request(self, line):
        self.say(self.p(f"  ↳ {line}", DIM))

    def _refresh_prompt(self):
        mode = self.p(" offline", AMBER) if self.net.offline else ""
        self.prompt = self.p("recon", PINK, bold=True) + mode + self.p(" ▸ ", CYAN)

    def preloop(self):
        enable_windows_ansi()
        self.say(banner(self.p))
        self.say(self.p(f"  ENVY Recon v{__version__} · OSINT terminal · type 'help'", LAVENDER))
        self.say(self.p(f"  {NOTICE}", DIM))
        self.say()

    def emptyline(self):
        return False

    # -- lookups -------------------------------------------------------------
    def _lookup(self, name, arg):
        try:
            result = run(self.net, name, arg)
        except NetworkDisabled as exc:
            self.say(self.p(f"! {exc}", AMBER)); return
        except ReconError as exc:
            self.say(self.p(f"✗ {exc}", PINK)); return
        self.session.add(name, arg.strip(), result)
        self.last = result
        self.say(render(f"{name} {arg.strip()}", result, color=self.p.color))

    def default(self, line):
        name, _, arg = line.strip().partition(" ")
        if name in COMMANDS:
            return self._lookup(name, arg)
        self.say(self.p(f"✗ Unknown command '{name}'. Type 'help'.", PINK))

    def completenames(self, text, *ignored):
        names = list(COMMANDS) + ["offline", "requests", "history", "save", "json", "clear", "help", "exit"]
        return [n for n in names if n.startswith(text)]

    # -- session commands ------------------------------------------------------
    def do_offline(self, arg):
        """offline [on|off]  Block or allow all network access."""
        a = arg.strip().lower()
        if a in ("on", "off"):
            self.net.offline = a == "on"
        self._refresh_prompt()
        state = "ON — no network access" if self.net.offline else "off — lookups may use the network"
        self.say(self.p(f"Offline mode {state}.", AMBER if self.net.offline else GREEN))

    def do_requests(self, arg):
        """requests  Every network request made this session."""
        if not self.net.history:
            self.say(self.p("No network requests yet.", DIM)); return
        for i, line in enumerate(self.net.history, 1):
            self.say(f"{self.p(f'{i:>3}', DIM)}  {line}")

    def do_history(self, arg):
        """history  Lookups run this session."""
        if not self.session.entries:
            self.say(self.p("No lookups yet.", DIM)); return
        for i, e in enumerate(self.session.entries, 1):
            self.say(f"{self.p(f'{i:>3}', DIM)}  {self.p(e['utc'], DIM)}  {e['command']} {e['target']}")

    def do_json(self, arg):
        """json  Show the last result as JSON."""
        self.say(json.dumps(self.last, indent=2, ensure_ascii=False) if self.last is not None
                 else self.p("No result yet.", DIM))

    def do_save(self, arg):
        """save <file.json|file.md>  Export this session's lookups and requests (never overwrites)."""
        try:
            parts = shlex.split(arg, posix=(sys.platform != "win32"))
        except ValueError as exc:
            self.say(self.p(f"✗ {exc}", PINK)); return
        if not parts:
            self.say(self.p("Usage: save <file.json|file.md>", AMBER)); return
        path = parts[0].strip('"')
        try:
            res = self.session.export(path, self.net.history)
        except ReconError as exc:
            self.say(self.p(f"✗ {exc}", PINK)); return
        self.say(self.p(f"Saved {res['lookups']} lookup(s) → {res['path']}", GREEN))
        self.say(self.p(f"SHA-256 {res['sha256']}  (log it in ENVY Evidence Vault to fix it in time)", DIM))

    def do_clear(self, arg):
        """clear  Clear the screen."""
        self.stdout.write("\x1b[2J\x1b[H" if self.p.color else "\n" * 3)

    def do_help(self, arg):
        """help  This list."""
        self.say(self.p("Lookups", PINK, bold=True))
        for c in COMMANDS.values():
            tag = self.p(" offline", GREEN) if not c.online else ""
            self.say(f"  {self.p(c.usage.ljust(26), CYAN)}{c.summary}{tag}")
        self.say(self.p("Session", PINK, bold=True))
        for name in ("offline", "requests", "history", "json", "save", "clear", "exit"):
            doc = (getattr(self, f"do_{name}").__doc__ or "").split("  ", 1)
            self.say(f"  {self.p(doc[0].ljust(26), CYAN)}{doc[1] if len(doc) > 1 else ''}")

    def do_exit(self, arg):
        """exit  Leave ENVY Recon."""
        self.say(self.p("Session closed. Nothing was stored unless you saved it.", DIM))
        return True

    do_quit = do_exit

    def do_EOF(self, arg):
        self.say()
        return self.do_exit(arg)


def run_shell(offline: bool = False) -> int:
    shell = ReconShell(Net(offline=offline))
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        shell.say()
        shell.do_exit("")
    return 0
