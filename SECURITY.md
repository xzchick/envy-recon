# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/xzchick/envy-recon/security/advisories/new)
rather than a public issue. You'll get an acknowledgement, and a fix or an explanation, as
soon as practical.

## Design notes

- All network access goes through one place (`envy_recon/net.py`), is printed as it
  happens, and can be blocked completely with `--offline`.
- Only `http`/`https` URLs are fetched; redirects to any other scheme are not followed.
- Responses are size-capped. Cookie values are never stored or printed; only cookie
  flags are.
- `meta` only reads files. Office XML that declares a DTD or entities is refused, and
  very large images are rejected as possible decompression bombs.
- Saved reports never overwrite an existing file.
