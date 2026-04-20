# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 5 business days. We aim to release a patch
within 30 days of a confirmed vulnerability.

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

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
