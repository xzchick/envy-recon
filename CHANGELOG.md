# Changelog

All notable changes to this project. This project adheres to semantic versioning.

## Unreleased

- A container image, `ghcr.io/xzchick/envy-recon` (amd64 + arm64), tested in CI (offline metadata,
  a real HTTPS request, non-root user), published with provenance and an SBOM, and signed with Sigstore

## v0.1.1 — 2026-11-24

- Fix: the macOS standalone build couldn't verify any HTTPS certificate
  (`CERTIFICATE_VERIFY_FAILED`), so every web lookup failed. Recon now ships
  certifi's root certificates in every bundle and uses them for HTTPS and `tls`.
- The release smoke test now makes a real HTTPS request from the built bundle on
  each OS, so this can't regress unnoticed.

## v0.1.0 — 2026-11-24

- Initial release: interactive OSINT terminal and one-shot CLI
- Lookups: `domain`, `dns`, `whois` (RDAP), `ip` (reverse DNS, ASN, RDAP), `certs` (crt.sh),
  `wayback`, `headers`, `tls`
- Offline `meta`: hashes, EXIF and GPS, PDF info, Office document properties
- Every network request is shown; `--offline` / `offline on` blocks all of them
- Session export to JSON or Markdown with the report's SHA-256
- Standalone bundles for macOS, Windows and Linux; Sigstore-signed checksums and a CycloneDX SBOM
