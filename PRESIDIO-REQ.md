# Presidio-Hardened Requests – Top-Level Requirements

## Overview
Build a production-ready Python package `presidio-hardened-requests` that is a 100% drop-in replacement for the popular `requests` library.
Users write: `import presidio_requests as requests` and all their existing code continues to work unchanged.

## Mandatory Presidio Security Extensions
- Automatic strict TLS 1.3 enforcement + certificate pinning (use `truststore`)
- Built-in secret redaction: scan and redact API keys/tokens/passwords in headers, URLs, bodies, and logs
- Intelligent per-host rate limiting with exponential backoff
- On-import CVE quick-check (integrate `safety` or a static list of known vulnerable requests versions)
- Security event logging ("Presidio hardening applied")
- Full GitHub security files: SECURITY.md, .github/dependabot.yml, .github/workflows/codeql.yml + pytest workflow

## Technical Requirements
- Python 3.9+
- Modern pyproject.toml + hatchling
- src/presidio_requests/__init__.py layout (wrapper only – do not copy requests source)
- 100% test coverage with pytest
- Black + ruff formatting enforced
- README.md with usage examples showing security wins vs plain requests
- LICENSE = MIT
- Version = 0.1.0

Deliver the complete working project ready for GitHub publish.