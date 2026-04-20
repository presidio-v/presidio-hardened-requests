# Presidio-Hardened Requests — Requirements

## Overview

`presidio-hardened-requests` is a 100% drop-in replacement for the Python
[`requests`](https://docs.python-requests.org/) library that applies
production-grade security defaults through a single import swap
(`import presidio_requests as requests`). Developed on customer
specification; not linked to any PRES-EDU experiment.

## Mandatory Presidio Security Extensions

- Strict TLS 1.2+ enforcement — TLS 1.0/1.1 rejected, strong cipher suites
  only, `verify=True` always
- HTTP → HTTPS silent auto-upgrade — insecure `http://` URLs are rewritten
  to `https://` before the request is issued
- Optional per-host certificate pinning — SHA-256 fingerprint verification,
  opt-in per `HardenedSession`
- Secret redaction — API keys, tokens, passwords, and `Authorization`
  headers are scrubbed from all log output
- Per-host rate limiting with exponential backoff on errors
- On-import CVE quick-check for the installed `requests` version
- Structured security event logging (`presidio_requests` logger)
- Full GitHub security files: `SECURITY.md`, `.github/dependabot.yml`,
  `.github/workflows/codeql.yml`, `.github/workflows/ci.yml`

## Technical Requirements

- Python 3.9+
- `requests` (upstream dependency — not wrapped; `presidio_requests`
  re-exports the public surface with hardening applied)
- `src/presidio_requests/` layout
- pytest with line coverage enforced in CI
- ruff lint + format enforced in CI
- MIT License, version 0.1.0

## Out of scope

- HTTP/2 and HTTP/3 — follow upstream `requests` support
- Vulnerabilities in upstream `requests` / `urllib3` / `certifi` (reported
  directly to those projects)

## Version Deliberation Log

### v0.1.0 — Initial release

**Scope decision:** Import-swap pattern (`import presidio_requests as
requests`) rather than a `HardenedSession`-only API. The customer's brief
required that the hardening baseline be applied across an inventory of
scripts and services with *zero code changes* beyond the import line; a
session-only API would have required every call site to be rewritten.

**Scope decision:** HTTP → HTTPS silent auto-upgrade rather than
hard-reject. The customer's existing codebase contains legacy `http://`
URLs in config files that are unsafe to rewrite in bulk; silently upgrading
preserves runtime behaviour where the upstream supports HTTPS and is
logged as a security event so that the legacy URLs can be fixed at source
over time. Hard-reject would have broken existing integrations the moment
the library was installed.

**Scope decision:** Certificate pinning is opt-in per host rather than a
global default. The customer's integration set includes SaaS endpoints
whose CAs rotate outside the customer's control; a global pinning default
would have caused outages on CA rotation. Opt-in per-host pinning lets the
customer pin the small set of endpoints whose CAs they do control.

**Scope decision:** Python 3.9+ floor. The customer's deployment targets
include Ubuntu 20.04 LTS hosts (Python 3.8 EOL, 3.9 available via
`deadsnakes`); raising above 3.9 would have excluded existing production
hosts.

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
