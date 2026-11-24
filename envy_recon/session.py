"""A session records every lookup and every network request, and exports them as a report."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from . import __version__
from .net import ReconError


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Session:
    def __init__(self):
        self.started = utc_now()
        self.entries: list[dict] = []

    def add(self, command: str, target: str, result) -> None:
        self.entries.append({"utc": utc_now(), "command": command, "target": target, "result": result})

    def as_dict(self, network_log: list[str]) -> dict:
        return {"tool": f"envy-recon {__version__}", "started_utc": self.started, "exported_utc": utc_now(),
                "lookups": self.entries, "network_requests": list(network_log),
                "basis": "Results reflect public sources at lookup time; they can be incomplete, stale or wrong."}

    def export(self, path: str, network_log: list[str], fmt: str | None = None) -> dict:
        """Write a new report file (never overwrites). Returns its path and SHA-256."""
        target = Path(path).expanduser()
        fmt = fmt or ("md" if target.suffix.lower() in (".md", ".markdown") else "json")
        if fmt not in ("json", "md"):
            raise ReconError("Report format must be json or md")
        if not self.entries:
            raise ReconError("Nothing to save yet — run a lookup first.")
        data = self.as_dict(network_log)
        if fmt == "json":
            text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        else:
            parts = [f"# ENVY Recon report\n",
                     f"- Tool: {data['tool']}\n- Session started: {data['started_utc']}\n"
                     f"- Exported: {data['exported_utc']}\n\n> {data['basis']}\n"]
            for i, e in enumerate(self.entries, 1):
                parts.append(f"\n## {i}. `{e['command']} {e['target']}` — {e['utc']}\n\n"
                             f"```json\n{json.dumps(e['result'], indent=2, ensure_ascii=False)}\n```\n")
            parts.append("\n## Network requests\n\n" + "".join(f"- `{r}`\n" for r in network_log))
            text = "".join(parts)
        try:
            with target.open("x", encoding="utf-8") as fh:
                fh.write(text)
        except FileExistsError:
            raise ReconError(f"{target} already exists — choose a new file name.") from None
        except OSError as exc:
            raise ReconError(f"Could not write {target}: {exc}") from None
        return {"path": str(target), "format": fmt, "lookups": len(self.entries),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
