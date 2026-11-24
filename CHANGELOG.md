# Changelog

All notable changes to this project. This project adheres to semantic versioning.

## v0.1.0 — 2026-11-24

- Initial release: interactive OSINT terminal and one-shot CLI
- Lookups: `domain`, `dns`, `whois` (RDAP), `ip` (reverse DNS, ASN, RDAP), `certs` (crt.sh),
  `wayback`, `headers`, `tls`
- Offline `meta`: hashes, EXIF and GPS, PDF info, Office document properties
- Every network request is shown; `--offline` / `offline on` blocks all of them
- Session export to JSON or Markdown with the report's SHA-256
- Standalone bundles for macOS, Windows and Linux; Sigstore-signed checksums and a CycloneDX SBOM
