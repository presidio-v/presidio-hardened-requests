# presidio-hardened-requests

[![CI](https://github.com/presidio-security/presidio-hardened-requests/actions/workflows/ci.yml/badge.svg)](https://github.com/presidio-security/presidio-hardened-requests/actions/workflows/ci.yml)
[![CodeQL](https://github.com/presidio-security/presidio-hardened-requests/actions/workflows/codeql.yml/badge.svg)](https://github.com/presidio-security/presidio-hardened-requests/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

A **100% drop-in replacement** for the Python
[`requests`](https://docs.python-requests.org/) library with automatic
Presidio security hardening.

```python
# Before (plain requests — no security hardening)
import requests

# After (Presidio hardening — zero code changes needed)
import presidio_requests as requests
```

Every call you already make — `requests.get()`, `requests.post()`,
`Session()`, etc. — keeps working exactly the same, with security
hardening applied transparently underneath.

---

## Security Features

| Feature | What it does |
|---|---|
| **Strict TLS 1.2+ enforcement** | Rejects TLS 1.0/1.1; enforces strong cipher suites; `verify=True` always |
| **HTTP → HTTPS auto-upgrade** | Insecure `http://` URLs are silently upgraded to `https://` |
| **Certificate pinning** | Optional per-host SHA-256 cert fingerprint verification |
| **Secret redaction** | API keys, tokens, passwords, and auth headers are scrubbed from all logs |
| **Per-host rate limiting** | Intelligent rate limiting with exponential backoff on errors |
| **CVE quick-check** | On import, warns if the installed `requests` version has known CVEs |
| **Security event logging** | Structured logs for every hardening action (`presidio_requests` logger) |

---

## Installation

```bash
pip install presidio-hardened-requests
```

For development:

```bash
git clone https://github.com/presidio-security/presidio-hardened-requests.git
cd presidio-hardened-requests
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Usage

### Basic — Zero Code Changes

```python
import presidio_requests as requests

# All your existing code works unchanged
resp = requests.get("https://httpbin.org/get")
print(resp.json())
```

### Secret Redaction in Action

```python
import logging
import presidio_requests as requests

logging.basicConfig(level=logging.DEBUG)

# The Bearer token is automatically redacted in all logs
resp = requests.get(
    "https://httpbin.org/get",
    headers={"Authorization": "Bearer sk-proj-SUPER_SECRET_KEY"},
)
# Log output shows: Authorization: Bearer ***REDACTED***
```

### Compared to Plain `requests`

```python
# --- Plain requests (INSECURE) ---
import requests

# ✗ No TLS enforcement — silently allows http://
requests.get("http://api.example.com/data")

# ✗ Secrets visible in logs
requests.get("https://api.example.com?api_key=sk_live_abc123")

# ✗ No rate limiting — can overwhelm servers
for i in range(10000):
    requests.get("https://api.example.com/data")

# --- presidio-hardened-requests (SECURE) ---
import presidio_requests as requests

# ✓ Auto-upgrades to https://
requests.get("http://api.example.com/data")

# ✓ api_key redacted in all logs
requests.get("https://api.example.com?api_key=sk_live_abc123")

# ✓ Per-host rate limiting with backoff
for i in range(10000):
    requests.get("https://api.example.com/data")
```

### Advanced — HardenedSession

```python
from presidio_requests import HardenedSession, SecretRedactor, RateLimiter

session = HardenedSession(
    redactor=SecretRedactor(placeholder="[SCRUBBED]"),
    rate_limiter=RateLimiter(max_requests_per_second=5.0),
    pinned_certs={"api.example.com": "abcdef1234567890..."},
    enforce_tls=True,
)

resp = session.get("https://api.example.com/v1/users")
```

### CVE Quick-Check

```python
from presidio_requests import check_cve

warnings = check_cve()
if warnings:
    for w in warnings:
        print(f"⚠ {w}")
else:
    print("✓ Installed requests version is clean")
```

---

## Running Tests

```bash
pytest -v --cov=presidio_requests --cov-report=term-missing
```

---

## Project Structure

```
presidio-hardened-requests/
├── src/presidio_requests/
│   └── __init__.py          # Security wrapper (the only source file)
├── tests/
│   ├── test_cve.py          # CVE quick-check tests
│   ├── test_drop_in.py      # Drop-in API compatibility tests
│   ├── test_rate_limiter.py  # Rate limiter tests
│   ├── test_redaction.py    # Secret redaction tests
│   ├── test_session.py      # HardenedSession tests
│   └── test_tls.py          # TLS hardening tests
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── ci.yml           # pytest + ruff on every push/PR
│       └── codeql.yml       # GitHub CodeQL security scanning
├── pyproject.toml
├── LICENSE                  # MIT
├── README.md
└── SECURITY.md
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Security

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.
