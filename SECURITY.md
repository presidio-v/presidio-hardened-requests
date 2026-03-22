# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

If you discover a security vulnerability in `presidio-hardened-requests`,
please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email **security@presidio.dev** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
3. You will receive an acknowledgment within **48 hours**.
4. We aim to release a fix within **7 days** of confirmation.

## Security Features

This package provides the following hardening over plain `requests`:

- **TLS 1.2+ enforcement** — TLS 1.0 and 1.1 are rejected. Strong cipher
  suites are enforced. Certificate verification is always enabled.
- **HTTP → HTTPS upgrade** — Insecure HTTP URLs are automatically upgraded.
- **Certificate pinning** — Optional SHA-256 fingerprint verification per host.
- **Secret redaction** — API keys, tokens, passwords, and authorization
  headers are scrubbed from all log output.
- **Per-host rate limiting** — Prevents accidental DoS with exponential
  backoff on repeated failures.
- **CVE quick-check** — On import, the installed `requests` version is
  checked against a list of known CVEs.

## Dependency Management

- Dependabot is configured to keep all dependencies up to date.
- CodeQL analysis runs on every push and pull request.
- All changes require passing CI (pytest + ruff) before merge.

## Responsible Disclosure

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
We appreciate security researchers who report issues responsibly and will
credit them in our release notes (with permission).
