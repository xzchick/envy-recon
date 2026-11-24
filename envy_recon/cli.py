"""envy-recon: interactive OSINT terminal (no arguments) or one-shot lookups."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .commands import COMMANDS, run
from .net import Net, NetworkDisabled, ReconError
from .render import Painter, enable_windows_ansi, render


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="envy-recon",
        description="ENVY Recon — an OSINT terminal for infrastructure and file metadata. "
                    "Run with no arguments for the interactive terminal.")
    parser.add_argument("--version", action="version", version=f"envy-recon {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("shell", help="open the interactive terminal").add_argument(
        "--offline", action="store_true", help="block all network access")
    for c in COMMANDS.values():
        sp = sub.add_parser(c.name, help=c.summary, description=c.summary)
        sp.add_argument("target", help=c.usage.split(" ", 1)[1])
        sp.add_argument("--json", action="store_true", help="print raw JSON instead of formatted output")
        sp.add_argument("--offline", action="store_true", help="block all network access")
        sp.add_argument("--quiet", action="store_true", help="don't print each network request")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in (None, "shell"):
        if args.command is None and not sys.stdin.isatty():
            parser.print_help()
            return 0
        from .shell import run_shell
        return run_shell(offline=getattr(args, "offline", False))

    enable_windows_ansi()
    p = Painter(None if not args.json else False)
    log = None if (args.json or args.quiet) else (lambda line: print(p(f"  ↳ {line}", (111, 120, 152)), file=sys.stderr))
    net = Net(offline=args.offline, log=log)
    try:
        result = run(net, args.command, args.target)
    except NetworkDisabled as exc:
        print(f"envy-recon: {exc}", file=sys.stderr)
        return 2
    except ReconError as exc:
        print(f"envy-recon: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render(f"{args.command} {args.target}", result))
    return 0
