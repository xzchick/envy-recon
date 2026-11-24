"""Launch the freshly built standalone binary and check it really works on this OS.

1. ``envy-recon --version`` prints the version.
2. ``meta <file> --json`` runs the offline metadata path end to end (dnspython,
   Pillow and pypdf all load inside the bundle) on a real PNG and PDF.
3. ``dns example.com --offline`` is refused with exit code 2 (offline mode holds).
No network is used.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = "envy-recon"


def run(binary, *args, expect=0):
    result = subprocess.run([str(binary), *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=120)
    if result.returncode != expect:
        raise SystemExit(f"{' '.join(args)} exited {result.returncode} (wanted {expect}):\n"
                         f"{result.stdout}\n{result.stderr}")
    return result


def main():
    binary = ROOT / "dist" / "standalone" / APP / (APP + (".exe" if os.name == "nt" else ""))
    if not binary.exists():
        raise SystemExit(f"standalone binary not found: {binary}")

    out = run(binary, "--version").stdout.strip()
    print(out)
    if APP not in out or not re.search(r"\d+\.\d+\.\d+", out):
        raise SystemExit(f"unexpected --version output: {out!r}")

    from PIL import Image
    from pypdf import PdfWriter
    with tempfile.TemporaryDirectory() as d:
        png = Path(d) / "probe.png"
        Image.new("RGB", (8, 6), "cyan").save(png)
        pdf = Path(d) / "probe.pdf"
        w = PdfWriter(); w.add_blank_page(width=100, height=100); w.add_metadata({"/Author": "smoke"})
        with pdf.open("wb") as fh:
            w.write(fh)
        img = json.loads(run(binary, "meta", str(png), "--json", "--offline").stdout)
        assert img["type"] == "png" and img["metadata"]["dimensions"] == "8x6", img
        doc = json.loads(run(binary, "meta", str(pdf), "--json", "--offline").stdout)
        assert doc["metadata"]["info"]["Author"] == "smoke", doc

    blocked = run(binary, "dns", "example.com", "--offline", expect=2)
    assert "Offline mode is on" in blocked.stderr, blocked.stderr
    print("standalone smoke test passed")


if __name__ == "__main__":
    main()
