<p align="center"><b>ENVY RECON</b><br />An OSINT terminal for domains, IPs, certificates, web archives and file metadata.</p>

<p align="center">
  <a href="https://github.com/xzchick/envy-recon/actions/workflows/tests.yml"><img src="https://github.com/xzchick/envy-recon/actions/workflows/tests.yml/badge.svg" alt="Cross-platform build" /></a>
</p>
<p align="center">
  <img src="https://img.shields.io/badge/macOS-supported-ff3db4?style=for-the-badge&logo=apple&logoColor=white&labelColor=050713" alt="macOS supported" />
  <img src="https://img.shields.io/badge/Windows-supported-35e8ff?style=for-the-badge&logo=windows&logoColor=white&labelColor=050713" alt="Windows supported" />
  <img src="https://img.shields.io/badge/Linux-supported-ac8cff?style=for-the-badge&logo=linux&logoColor=white&labelColor=050713" alt="Linux supported" /><br />
  <img src="https://img.shields.io/badge/no_API_keys-public_sources-ff3db4?style=flat-square&labelColor=050713" alt="No API keys, public sources" />
  <img src="https://img.shields.io/badge/Python-3.10+-8547e8?style=flat-square&logo=python&logoColor=white&labelColor=050713" alt="Python 3.10 or newer" />
  <img src="https://img.shields.io/badge/license-MIT-ac8cff?style=flat-square&labelColor=050713" alt="MIT license" />
</p>
<p align="center">
  <a href="https://github.com/xzchick/envy-recon/releases/latest"><img src="https://img.shields.io/github/v/release/xzchick/envy-recon?style=flat-square&amp;label=release&amp;labelColor=050713&amp;color=ff3db4" alt="Latest release" /></a>
  <a href="#verifying-a-release"><img src="https://img.shields.io/badge/releases-Sigstore_signed-35e8ff?style=flat-square&amp;labelColor=050713" alt="Releases signed with Sigstore" /></a>
  <a href="https://github.com/xzchick/envy-recon/releases/latest"><img src="https://img.shields.io/badge/SBOM-CycloneDX-ac8cff?style=flat-square&amp;labelColor=050713" alt="CycloneDX SBOM attached to each release" /></a>
  <a href="#install-on-linux"><img src="https://img.shields.io/badge/Linux-one--line_install-ff3db4?style=flat-square&amp;logo=linux&amp;logoColor=white&amp;labelColor=050713" alt="One-line Linux install" /></a>
  <a href="https://xzchick.github.io/homebrew-envy/"><img src="https://img.shields.io/badge/suite-ENVY_BLACK_VEIL-35e8ff?style=flat-square&amp;labelColor=050713" alt="Part of the ENVY BLACK VEIL suite" /></a>
</p>

ENVY Recon is a standalone terminal for open-source intelligence on **infrastructure** and
**files**. Point it at a domain, an IP address, a URL or a file and it pulls together what
public sources say, with every network request shown as it happens. It's a self-contained
bundle for macOS, Windows and Linux; no Python install, no API keys, no account.

```text
recon ▸ domain example.com
  ↳ DNS example.com (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA)
  ↳ GET https://rdap.org/domain/example.com
  ↳ TLS example.com:443
  ...
```

## What it looks up

| Command | What you get | Source |
|---|---|---|
| `domain <example.com>` | Everything below for a domain, in one report | all of the below |
| `dns <example.com>` | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA records and SPF | your DNS resolver |
| `whois <domain or IP>` | Registrar, registration/expiry dates, nameservers, DNSSEC, network owner | RDAP (rdap.org) |
| `ip <address>` | Reverse DNS, ASN and AS name, prefix, country, RDAP network | DNS, Team Cymru, RDAP |
| `certs <example.com>` | Hostnames and issuers from certificate-transparency logs | crt.sh |
| `wayback <domain or URL>` | First and last archived snapshot, months archived per year | Wayback Machine |
| `headers <URL>` | Redirect chain, server, page title, generator, security headers, cookie flags | the target |
| `tls <host[:port]>` | Certificate subject, issuer, validity, days left, alt names, protocol, cipher | the target |
| `meta <file>` | **Offline.** Hashes, file type, EXIF incl. GPS, PDF info, Word/Excel/PowerPoint properties | the file itself |

## Using it

```sh
envy-recon                          # interactive terminal
envy-recon domain example.com       # one-shot, formatted
envy-recon whois 1.1.1.1 --json     # one-shot, raw JSON (pipe into jq, scripts, etc.)
envy-recon meta photo.jpg --offline # metadata with all network access blocked
```

Inside the terminal: `help`, `offline on|off`, `requests` (every network request this
session), `history`, `json` (last result as JSON), `save report.md` / `save report.json`
(export the session; never overwrites; prints the report's SHA-256), `exit`.

**Works with the rest of the suite:** attach a saved report to a case in
[ENVY Casebook](https://github.com/xzchick/envy-casebook), and log its SHA-256 in
[ENVY Evidence Vault](https://github.com/xzchick/envy-evidence-vault) to fix it in time.

## Install

**macOS (Homebrew, Apple Silicon)**

```sh
brew tap xzchick/envy https://github.com/xzchick/homebrew-envy
brew install --cask envy-recon
```

**Windows**: download `envy-recon-vX.Y.Z-windows-x86_64.zip` from the
[latest release](https://github.com/xzchick/envy-recon/releases/latest), unzip, and run
`envy-recon.exe` from Windows Terminal or PowerShell.

## Install on Linux

One command (downloads the latest release bundle, verifies it against the signed
`SHA256SUMS`, and installs under `~/.local` with a desktop entry, no root needed):

```sh
curl -fsSL https://raw.githubusercontent.com/xzchick/envy-recon/main/install.sh | sh
```

Prefer to inspect first? Download `install.sh`, read it, then run `sh install.sh`.

**From source** (any OS, Python 3.10+): `pip install .` then `envy-recon`.

## Run with Docker

The same terminal as a container image, for Linux, macOS or Windows with Docker
(`linux/amd64` and `linux/arm64`):

```sh
docker run --rm -it ghcr.io/xzchick/envy-recon                          # interactive terminal
docker run --rm ghcr.io/xzchick/envy-recon domain example.com           # one lookup
docker run --rm -v "$PWD:/work" ghcr.io/xzchick/envy-recon meta photo.jpg --offline
```

Mount a folder at `/work` to read or save files. The image runs as a non-root user, and
every published image is signed with Sigstore (keyless) and carries build provenance and
an SBOM:

```sh
cosign verify ghcr.io/xzchick/envy-recon:latest \
  --certificate-identity-regexp 'https://github.com/xzchick/envy-recon/.github/workflows/container.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Verifying a release

Every release's `SHA256SUMS.txt` is signed with Sigstore (keyless) and ships with a CycloneDX SBOM:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/xzchick/envy-recon/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
```

## Privacy and limits

- **What it contacts:** only the public services in the table above and the target you name.
  No telemetry, no update checks. `requests` lists every request; `--offline` /
  `offline on` blocks all of them.
- **The target can see you.** `headers` and `tls` connect to the target directly, and
  lookups go out from your own IP address. Use a VPN or other network you control if that
  matters for your work.
- **Public data can be wrong or stale.** Treat every result as a lead to verify, not a fact.
- **Scope:** infrastructure and file metadata. It deliberately doesn't look people up.
- Use it only on targets you're entitled to research, and follow the terms of the services it queries.

## Roadmap

New in the suite; ideas and bug reports are welcome in [Issues](https://github.com/xzchick/envy-recon/issues).

MIT licensed. Part of [ENVY BLACK VEIL](https://xzchick.github.io/homebrew-envy/).
