"""Offline metadata extraction against real files built on the fly."""
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from envy_recon import metadata
from envy_recon.net import ReconError


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_jpeg_exif_and_gps(self):
        from PIL import Image
        exif = Image.Exif()
        exif[0x010F] = "ENVY Camera Co"   # Make
        exif[0x0110] = "Model X"          # Model
        exif[0x8825] = {1: "N", 2: (37.0, 46.0, 30.0), 3: "W", 4: (122.0, 25.0, 9.6), 6: 12.5}
        path = self.root / "photo.jpg"
        Image.new("RGB", (40, 30), "magenta").save(path, exif=exif)
        out = metadata.file_meta(str(path))
        self.assertEqual(out["type"], "jpeg")
        self.assertEqual(out["metadata"]["dimensions"], "40x30")
        self.assertEqual(out["metadata"]["exif"]["Make"], "ENVY Camera Co")
        gps = out["metadata"]["gps"]
        self.assertAlmostEqual(gps["latitude"], 37.775, places=3)
        self.assertAlmostEqual(gps["longitude"], -122.4193, places=3)
        self.assertEqual(gps["altitude_m"], 12.5)
        self.assertIn("openstreetmap.org", gps["map"])
        self.assertEqual(out["warning"], "This file contains GPS coordinates.")

    def test_png_text_chunks(self):
        from PIL import Image, PngImagePlugin
        info = PngImagePlugin.PngInfo(); info.add_text("Author", "Jane Analyst")
        path = self.root / "img.png"
        Image.new("RGB", (5, 5)).save(path, pnginfo=info)
        out = metadata.file_meta(str(path))
        self.assertEqual(out["metadata"]["embedded_text"]["Author"], "Jane Analyst")
        self.assertNotIn("warning", out)

    def test_pdf_info(self):
        from pypdf import PdfWriter
        w = PdfWriter(); w.add_blank_page(width=200, height=200)
        w.add_metadata({"/Author": "Jane Analyst", "/Producer": "ENVY Test", "/Title": "Brief"})
        path = self.root / "doc.pdf"
        with path.open("wb") as fh:
            w.write(fh)
        out = metadata.file_meta(str(path))
        self.assertEqual(out["type"], "pdf")
        self.assertEqual(out["metadata"]["pages"], 1)
        self.assertEqual(out["metadata"]["info"]["Author"], "Jane Analyst")

    def _docx(self, core_xml):
        path = self.root / "memo.docx"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", "<w:document/>")
            z.writestr("docProps/core.xml", core_xml)
            z.writestr("docProps/app.xml",
                       '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
                       "<Application>Microsoft Office Word</Application><Company>ACME</Company><TotalTime>42</TotalTime></Properties>")
        return path

    def test_docx_properties(self):
        core = ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
                "<dc:creator>Jane Analyst</dc:creator><cp:lastModifiedBy>John Editor</cp:lastModifiedBy>"
                "<dcterms:created>2026-01-02T03:04:05Z</dcterms:created><cp:revision>7</cp:revision></cp:coreProperties>")
        out = metadata.file_meta(str(self._docx(core)))
        self.assertEqual(out["type"], "ooxml")
        props = out["metadata"]["properties"]
        self.assertEqual(out["metadata"]["kind"], "Word document")
        self.assertEqual((props["creator"], props["last_modified_by"], props["revision"]), ("Jane Analyst", "John Editor", "7"))
        self.assertEqual((props["company"], props["total_edit_minutes"]), ("ACME", "42"))

    def test_docx_with_dtd_is_refused(self):
        evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>'
        out = metadata.file_meta(str(self._docx(evil)))
        self.assertIn("DTD", out["metadata"]["error"])

    def test_unknown_file_gets_hashes(self):
        path = self.root / "notes.txt"; path.write_bytes(b"hello")
        out = metadata.file_meta(str(path))
        self.assertEqual(out["hashes"]["sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertIn("hashes only", out["metadata"]["note"])

    def test_corrupt_image_reports_error_not_crash(self):
        path = self.root / "broken.jpg"; path.write_bytes(b"\xff\xd8\xff\xe0garbage")
        out = metadata.file_meta(str(path))
        self.assertIn("error", out["metadata"])

    def test_missing_file(self):
        with self.assertRaises(ReconError):
            metadata.file_meta(str(self.root / "nope.bin"))


if __name__ == "__main__":
    unittest.main()
