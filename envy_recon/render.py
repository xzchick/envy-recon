"""Terminal rendering in the ENVY palette. Honours NO_COLOR and plain (piped) output."""

from __future__ import annotations

import os
import sys

PINK, CYAN, LAVENDER, AMBER, GREEN, DIM, INK = (
    (255, 61, 180), (53, 232, 255), (172, 140, 255), (255, 179, 71), (73, 227, 166), (111, 120, 152), (242, 244, 255))


def color_enabled(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def enable_windows_ansi() -> None:
    """Make Windows behave like macOS/Linux: VT colour codes on, and UTF-8 output even when
    redirected to a file or pipe (the legacy code page can't encode ↳ ━ and friends)."""
    if os.name != "nt":
        return
    os.system("")  # turns on VT escape processing in the Windows console
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


class Painter:
    def __init__(self, color: bool | None = None):
        self.color = color_enabled() if color is None else color

    def __call__(self, text, rgb, bold=False) -> str:
        if not self.color:
            return str(text)
        r, g, b = rgb
        return f"\x1b[{'1;' if bold else ''}38;2;{r};{g};{b}m{text}\x1b[0m"


BANNER = r"""
 ███████╗███╗   ██╗██╗   ██╗██╗   ██╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔════╝████╗  ██║██║   ██║╚██╗ ██╔╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 █████╗  ██╔██╗ ██║██║   ██║ ╚████╔╝     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝  ╚██╔╝      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ███████╗██║ ╚████║ ╚████╔╝    ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚══════╝╚═╝  ╚═══╝  ╚═══╝     ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"""


def banner(p: Painter) -> str:
    rows = BANNER.strip("\n").split("\n")
    stops = [PINK, LAVENDER, CYAN]
    out = []
    for i, row in enumerate(rows):
        t = i / max(len(rows) - 1, 1)
        a, b = (stops[0], stops[1]) if t < 0.5 else (stops[1], stops[2])
        u = t * 2 if t < 0.5 else (t - 0.5) * 2
        out.append(p(row, tuple(int(a[k] + (b[k] - a[k]) * u) for k in range(3)), bold=True))
    return "\n".join(out)


def _scalar(p, v):
    if v is True:
        return p("yes", GREEN)
    if v is False:
        return p("no", AMBER)
    if v is None:
        return p("—", DIM)
    return p(v, INK)


def render(title: str, data, color: bool | None = None, max_items: int = 60) -> str:
    p = Painter(color)
    lines = [p(f"━━ {title} ", PINK, bold=True) + p("━" * max(4, 50 - len(title)), DIM)]

    def walk(obj, indent):
        pad = "  " * indent
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = str(k)
                if key == "error":
                    lines.append(f"{pad}{p('✗ ' + str(v), PINK)}")
                elif key in ("warning", "note"):
                    lines.append(f"{pad}{p('! ' + str(v), AMBER)}")
                elif isinstance(v, (dict, list)) and v:
                    lines.append(f"{pad}{p(key, LAVENDER, bold=True)}")
                    walk(v, indent + 1)
                elif isinstance(v, (dict, list)):
                    lines.append(f"{pad}{p(key, LAVENDER)}: {p('none', DIM)}")
                else:
                    lines.append(f"{pad}{p(key, LAVENDER)}: {_scalar(p, v)}")
        elif isinstance(obj, list):
            for item in obj[:max_items]:
                if isinstance(item, dict):
                    lines.append(f"{pad}{p('-', CYAN)}")
                    walk(item, indent + 1)
                else:
                    lines.append(f"{pad}{p('•', CYAN)} {_scalar(p, item)}")
            if len(obj) > max_items:
                lines.append(f"{pad}{p(f'… {len(obj) - max_items} more (use save/--json for all)', DIM)}")
        else:
            lines.append(f"{pad}{_scalar(p, obj)}")

    walk(data, 0)
    return "\n".join(lines)
