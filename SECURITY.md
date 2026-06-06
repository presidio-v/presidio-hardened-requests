# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Yes (current) |
| 0.1.x   | ✅ Yes (legacy) |

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

This package provides the following hardening over plain `requests` (accurate as of v0.2.0):

- **TLS 1.2+ enforcement** — TLS 1.0 and 1.1 are rejected. Strong cipher
  suites are enforced. Certificate verification is always enabled. (1.3 max where supported.)
- **HTTP → HTTPS upgrade** — Insecure HTTP URLs are automatically upgraded.
- **Certificate pinning** — Optional SHA-256 fingerprint verification per host (best-effort pre-connect; see code/docs for limitations).
- **Secret redaction** — API keys, tokens, passwords, and authorization
  headers (plus params/data/json in request logs) are scrubbed. Sink-level `RedactingFilter` on the `presidio_requests` logger enforces redaction for all records (v0.2 addition).
- **Per-host rate limiting** — Prevents accidental DoS with exponential
  backoff on repeated failures.
- **CVE quick-check + pip-audit** — On import static list awareness; full `pip-audit` integrated in dev extras and CI for current vulnerability coverage.

## Dependency Management

- Dependabot is configured to keep all dependencies up to date.
- CodeQL analysis runs on every push and pull request.
- `pip-audit` runs in CI and is available via `[dev]` extras (added v0.2.0).
- Runtime floors raised for key transitive deps (e.g. requests).
- All changes require passing CI (pytest + ruff + pip-audit) before merge.

## Responsible Disclosure

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
We appreciate security researchers who report issues responsibly and will
credit them in our release notes (with permission).

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
