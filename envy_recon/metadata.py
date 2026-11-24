"""Offline file metadata: hashes, type, EXIF (incl. GPS), PDF info and Office document properties.

Nothing here touches the network. Files are only read, never modified.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from .net import ReconError

MAX_XML = 2 * 1024 * 1024
_NS = {"cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
       "dc": "http://purl.org/dc/elements/1.1/",
       "dcterms": "http://purl.org/dc/terms/",
       "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}


def _hashes(path: Path) -> dict:
    hs = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for h in hs.values():
                h.update(chunk)
    return {k: h.hexdigest() for k, h in hs.items()}


def sniff(head: bytes, path: Path) -> str:
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(path) as z:
                names = set(z.namelist())
            if "[Content_Types].xml" in names:
                return "ooxml"
            return "zip"
        except zipfile.BadZipFile:
            return "unknown"
    return "unknown"


# --- images -----------------------------------------------------------------

def _ratio(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError, ZeroDivisionError):
        num, den = v
        return float(num) / float(den)


def gps_to_decimal(gps: dict) -> dict | None:
    """Convert an EXIF GPS IFD (tags 1-4, optional 6) to decimal degrees."""
    try:
        def dms(vals):
            d, m, s = (_ratio(x) for x in vals)
            return d + m / 60 + s / 3600
        lat, lon = dms(gps[2]), dms(gps[4])
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None
    if str(gps.get(1, "N")).upper().startswith("S"):
        lat = -lat
    if str(gps.get(3, "E")).upper().startswith("W"):
        lon = -lon
    out = {"latitude": round(lat, 6), "longitude": round(lon, 6),
           "map": f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}"}
    if 6 in gps:
        try:
            out["altitude_m"] = round(_ratio(gps[6]), 1)
        except (TypeError, ValueError, ZeroDivisionError):
            pass
    return out


def _clean(v):
    if isinstance(v, bytes):
        v = v.rstrip(b"\x00")
        return v.decode("utf-8", "replace") if len(v) <= 256 else f"<{len(v)} bytes>"
    if isinstance(v, tuple):
        return [_clean(x) for x in v]
    if isinstance(v, (int, float, str)) or v is None:
        return v.strip("\x00 ") if isinstance(v, str) else v
    try:
        return float(v)
    except (TypeError, ValueError):
        return str(v)


def image_meta(path: Path) -> dict:
    from PIL import ExifTags, Image
    try:
        with Image.open(path) as img:
            out = {"format": img.format, "dimensions": f"{img.width}x{img.height}", "mode": img.mode}
            exif = img.getexif()
            tags = {}
            for tag, val in exif.items():
                if tag in (0x8769, 0x8825, 0x927C):  # IFD pointers / MakerNote
                    continue
                tags[ExifTags.TAGS.get(tag, f"0x{tag:04x}")] = _clean(val)
            for tag, val in exif.get_ifd(ExifTags.IFD.Exif).items():
                if tag == 0x927C:
                    continue
                tags[ExifTags.TAGS.get(tag, f"0x{tag:04x}")] = _clean(val)
            if tags:
                out["exif"] = dict(sorted(tags.items()))
            gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
            if gps:
                out["gps"] = gps_to_decimal(dict(gps)) or {"note": "GPS block present but incomplete"}
            text = {k: v for k, v in (img.info or {}).items() if isinstance(v, str) and len(v) < 2000}
            if text:
                out["embedded_text"] = text
            return out
    except Image.DecompressionBombError:
        raise ReconError("Image is too large to open safely (possible decompression bomb)") from None
    except OSError as exc:
        raise ReconError(f"Could not read image: {exc}") from None


# --- PDF --------------------------------------------------------------------

def pdf_meta(path: Path) -> dict:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError
    try:
        reader = PdfReader(str(path))
        out = {"pages": None, "encrypted": reader.is_encrypted}
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                out["note"] = "Encrypted; metadata may be unavailable without the password."
        try:
            out["pages"] = len(reader.pages)
        except Exception:
            pass
        info = reader.metadata or {}
        out["info"] = {str(k).lstrip("/"): _clean(str(v)) for k, v in info.items()}
        return out
    except PdfReadError as exc:
        raise ReconError(f"Could not read PDF: {exc}") from None


# --- Office (docx/xlsx/pptx) -------------------------------------------------

def _safe_xml(z: zipfile.ZipFile, name: str):
    try:
        info = z.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_XML:
        raise ReconError(f"{name} is unusually large; refusing to parse")
    raw = z.read(name)
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ReconError(f"{name} declares a DTD/entities; refusing to parse")
    return ElementTree.fromstring(raw)


def ooxml_meta(path: Path) -> dict:
    out = {}
    with zipfile.ZipFile(path) as z:
        core = _safe_xml(z, "docProps/core.xml")
        if core is not None:
            for key, tag in (("title", "dc:title"), ("subject", "dc:subject"), ("creator", "dc:creator"),
                             ("last_modified_by", "cp:lastModifiedBy"), ("revision", "cp:revision"),
                             ("created", "dcterms:created"), ("modified", "dcterms:modified"),
                             ("keywords", "cp:keywords"), ("description", "dc:description")):
                el = core.find(tag, _NS)
                if el is not None and (el.text or "").strip():
                    out[key] = el.text.strip()
        app = _safe_xml(z, "docProps/app.xml")
        if app is not None:
            for key, tag in (("application", "ep:Application"), ("app_version", "ep:AppVersion"),
                             ("company", "ep:Company"), ("template", "ep:Template"),
                             ("total_edit_minutes", "ep:TotalTime"), ("pages", "ep:Pages"),
                             ("words", "ep:Words"), ("slides", "ep:Slides")):
                el = app.find(tag, _NS)
                if el is not None and (el.text or "").strip():
                    out[key] = el.text.strip()
        names = z.namelist()
    kind = ("Word document" if any(n.startswith("word/") for n in names) else
            "Excel workbook" if any(n.startswith("xl/") for n in names) else
            "PowerPoint deck" if any(n.startswith("ppt/") for n in names) else "Office file")
    return {"kind": kind, "properties": out}


# --- entry point --------------------------------------------------------------

def file_meta(target: str) -> dict:
    path = Path(target).expanduser()
    if not path.is_file():
        raise ReconError(f"Not a file: {target}")
    with path.open("rb") as fh:
        head = fh.read(16)
    kind = sniff(head, path)
    out = {"file": str(path), "size_bytes": path.stat().st_size, "type": kind, "hashes": _hashes(path)}
    handler = {"jpeg": image_meta, "png": image_meta, "tiff": image_meta, "gif": image_meta,
               "webp": image_meta, "pdf": pdf_meta, "ooxml": ooxml_meta}.get(kind)
    if handler:
        try:
            out["metadata"] = handler(path)
        except ReconError as exc:
            out["metadata"] = {"error": str(exc)}
    else:
        out["metadata"] = {"note": "No embedded-metadata reader for this file type; hashes only."}
    if "latitude" in (out["metadata"].get("gps") or {}):
        out["warning"] = "This file contains GPS coordinates."
    return out
