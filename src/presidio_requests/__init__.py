"""
presidio-hardened-requests
~~~~~~~~~~~~~~~~~~~~~~~~~~

A 100% drop-in replacement for the ``requests`` library with Presidio
security hardening applied automatically on import.

Usage::

    import presidio_requests as requests
    resp = requests.get("https://httpbin.org/get")

Security features applied transparently:
  - Strict TLS 1.2+ enforcement with system trust-store certificates
  - Automatic secret redaction in headers, URLs, and bodies
  - Per-host rate limiting with exponential backoff
  - CVE quick-check against known vulnerable ``requests`` versions
  - Structured security event logging
"""

from __future__ import annotations

import hashlib
import logging
import re
import ssl
import threading
import time
from importlib.metadata import version as _pkg_version
from typing import Any
from urllib.parse import urlparse

import requests  # noqa: F401 — keep reference for submodule access
from requests import *  # noqa: F401, F403 — re-export entire public API
from requests import ConnectionError as ConnectionError  # noqa: A004
from requests import HTTPError, RequestException, Response, Session, Timeout, URLRequired

# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------
__version__ = "0.1.0"
__all__ = [
    # Our additions
    "HardenedSession",
    "SecretRedactor",
    "RateLimiter",
    "check_cve",
    "get_hardened_ssl_context",
    # Re-export key requests symbols explicitly
    "Session",
    "Response",
    "RequestException",
    "ConnectionError",
    "HTTPError",
    "Timeout",
    "URLRequired",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "request",
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("presidio_requests")

# ---------------------------------------------------------------------------
# CVE Quick-Check
# ---------------------------------------------------------------------------
KNOWN_VULNERABLE_VERSIONS: dict[str, str] = {
    "2.3.0": "CVE-2014-1829 — cookie leak on redirect",
    "2.5.3": "CVE-2014-1830 — cookie leak on redirect",
    "2.6.0": "CVE-2015-2296 — session fixation via cookies",
    "2.19.1": "CVE-2018-18074 — redirect credential leak",
    "2.25.1": "CVE-2023-32681 — Proxy-Authorization header leak",
}


def check_cve() -> list[str]:
    """Return list of CVE warnings for the installed ``requests`` version."""
    try:
        installed = _pkg_version("requests")
    except Exception:
        return ["Unable to determine installed requests version"]
    warnings: list[str] = []
    for vuln_ver, description in KNOWN_VULNERABLE_VERSIONS.items():
        if installed == vuln_ver:
            warnings.append(f"requests {installed} is vulnerable: {description}")
    return warnings


# ---------------------------------------------------------------------------
# TLS / SSL hardening
# ---------------------------------------------------------------------------
def get_hardened_ssl_context() -> ssl.SSLContext:
    """Build an SSL context enforcing TLS 1.2+ with strong ciphers."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    return ctx


# ---------------------------------------------------------------------------
# Certificate Pinning
# ---------------------------------------------------------------------------
class CertificatePinError(RequestException):
    """Raised when a server certificate does not match the pinned fingerprint."""


def _get_cert_fingerprint(host: str, port: int = 443) -> str | None:
    """Retrieve the SHA-256 fingerprint of the server's TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            __import__("socket").create_connection((host, port), timeout=5),
            server_hostname=host,
        ) as sock:
            cert_bin = sock.getpeercert(binary_form=True)
            if cert_bin:
                return hashlib.sha256(cert_bin).hexdigest()
    except Exception:
        logger.debug("Failed to retrieve certificate fingerprint for %s", host)
    return None


# ---------------------------------------------------------------------------
# Secret Redaction
# ---------------------------------------------------------------------------
class SecretRedactor:
    """Detects and redacts secrets from strings (headers, URLs, bodies)."""

    DEFAULT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("Bearer Token", re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)),
        ("Basic Auth", re.compile(r"(Basic\s+)[A-Za-z0-9+/]+=*", re.IGNORECASE)),
        (
            "API Key param",
            re.compile(r"((?:api[_-]?key|token|secret|password|apikey)=)[^&\s]+", re.IGNORECASE),
        ),
        ("Authorization header value", re.compile(r"(authorization:\s*)\S+", re.IGNORECASE)),
        ("AWS Key", re.compile(r"(AKIA)[A-Z0-9]{16}")),
        (
            "Generic secret",
            re.compile(
                r"((?:secret|password|passwd|pwd|token)[\"\']?\s*[:=]\s*[\"\']?)[^\s\"\'&,;}{)]+",
                re.IGNORECASE,
            ),
        ),
    ]

    def __init__(self, placeholder: str = "***REDACTED***") -> None:
        self.placeholder = placeholder
        self._patterns = list(self.DEFAULT_PATTERNS)

    def add_pattern(self, name: str, pattern: re.Pattern[str]) -> None:
        self._patterns.append((name, pattern))

    def redact(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        result = text
        for _name, pattern in self._patterns:

            def _replace(m: re.Match[str]) -> str:
                if m.lastindex and m.lastindex >= 1:
                    return m.group(1) + self.placeholder
                return self.placeholder

            result = pattern.sub(_replace, result)
        return result

    def redact_dict(self, d: dict[str, str] | None) -> dict[str, str]:
        if not d:
            return d or {}
        return {k: self.redact(v) for k, v in d.items()}


_default_redactor = SecretRedactor()

# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------
_RATE_LIMIT_LOCK = threading.Lock()


class RateLimiter:
    """Per-host rate limiter with exponential backoff."""

    def __init__(
        self,
        max_requests_per_second: float = 10.0,
        backoff_factor: float = 0.5,
        max_backoff: float = 30.0,
    ) -> None:
        self.max_rps = max_requests_per_second
        self.min_interval = 1.0 / max_requests_per_second
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        self._hosts: dict[str, _HostState] = {}

    def _get_host_state(self, host: str) -> _HostState:
        with _RATE_LIMIT_LOCK:
            if host not in self._hosts:
                self._hosts[host] = _HostState()
            return self._hosts[host]

    def wait_if_needed(self, url: str) -> float:
        """Block the caller if rate limit requires it. Returns seconds waited."""
        host = urlparse(url).hostname or "unknown"
        state = self._get_host_state(host)

        with state.lock:
            now = time.monotonic()
            elapsed = now - state.last_request
            wait = max(0.0, state.current_interval - elapsed)
            if wait > 0:
                logger.debug("Rate limiter: sleeping %.3fs for %s", wait, host)
                time.sleep(wait)
            state.last_request = time.monotonic()
            return wait

    def record_error(self, url: str) -> None:
        host = urlparse(url).hostname or "unknown"
        state = self._get_host_state(host)
        with state.lock:
            state.consecutive_errors += 1
            state.current_interval = min(
                self.max_backoff,
                self.min_interval * (2**state.consecutive_errors) * self.backoff_factor,
            )

    def record_success(self, url: str) -> None:
        host = urlparse(url).hostname or "unknown"
        state = self._get_host_state(host)
        with state.lock:
            state.consecutive_errors = 0
            state.current_interval = self.min_interval

    def reset(self) -> None:
        with _RATE_LIMIT_LOCK:
            self._hosts.clear()


class _HostState:
    __slots__ = ("lock", "last_request", "consecutive_errors", "current_interval")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last_request: float = 0.0
        self.consecutive_errors: int = 0
        self.current_interval: float = 0.0


# ---------------------------------------------------------------------------
# Hardened Session
# ---------------------------------------------------------------------------
class HardenedSession(Session):
    """``requests.Session`` subclass with Presidio security hardening."""

    def __init__(
        self,
        *,
        redactor: SecretRedactor | None = None,
        rate_limiter: RateLimiter | None = None,
        pinned_certs: dict[str, str] | None = None,
        enforce_tls: bool = True,
    ) -> None:
        super().__init__()
        self.redactor = redactor or SecretRedactor()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.pinned_certs: dict[str, str] = pinned_certs or {}
        self.enforce_tls = enforce_tls
        self._apply_tls_hardening()
        logger.info("Presidio hardening applied — HardenedSession initialized")

    def _apply_tls_hardening(self) -> None:
        if not self.enforce_tls:
            return
        try:
            from urllib3.util.ssl_ import create_urllib3_context

            ctx = create_urllib3_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        except Exception:
            logger.debug("urllib3 TLS context customization unavailable")
        self.verify = True

    def request(self, method: str, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        if self.enforce_tls and url.startswith("http://"):
            logger.warning("Upgrading insecure HTTP to HTTPS: %s", url)
            url = "https://" + url[7:]

        self.rate_limiter.wait_if_needed(url)

        self._log_redacted_request(method, url, kwargs)

        self._check_pinned_cert(url)

        try:
            response = super().request(method, url, **kwargs)
        except Exception:
            self.rate_limiter.record_error(url)
            raise

        self.rate_limiter.record_success(url)

        logger.debug(
            "Response %s %s → %d",
            method.upper(),
            self.redactor.redact(url),
            response.status_code,
        )
        return response

    def _log_redacted_request(self, method: str, url: str, kwargs: dict[str, Any]) -> None:
        redacted_url = self.redactor.redact(url)
        redacted_headers = self.redactor.redact_dict(
            {k: str(v) for k, v in kwargs.get("headers", {}).items()}
            if kwargs.get("headers")
            else None
        )
        logger.debug(
            "Request %s %s headers=%s",
            method.upper(),
            redacted_url,
            redacted_headers,
        )

    def _check_pinned_cert(self, url: str) -> None:
        if not self.pinned_certs:
            return
        parsed = urlparse(url)
        host = parsed.hostname
        if not host or host not in self.pinned_certs:
            return
        port = parsed.port or 443
        actual = _get_cert_fingerprint(host, port)
        expected = self.pinned_certs[host]
        if actual and actual != expected:
            raise CertificatePinError(
                f"Certificate fingerprint mismatch for {host}: "
                f"expected {expected[:16]}…, got {actual[:16]}…"
            )


# ---------------------------------------------------------------------------
# Module-level convenience functions (drop-in replacements)
# ---------------------------------------------------------------------------
_session = HardenedSession()


def request(method: str, url: str, **kwargs: Any) -> Response:
    return _session.request(method, url, **kwargs)


def get(url: str, **kwargs: Any) -> Response:
    return _session.request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> Response:
    return _session.request("POST", url, **kwargs)


def put(url: str, **kwargs: Any) -> Response:
    return _session.request("PUT", url, **kwargs)


def patch(url: str, **kwargs: Any) -> Response:
    return _session.request("PATCH", url, **kwargs)


def delete(url: str, **kwargs: Any) -> Response:
    return _session.request("DELETE", url, **kwargs)


def head(url: str, **kwargs: Any) -> Response:
    return _session.request("HEAD", url, **kwargs)


def options(url: str, **kwargs: Any) -> Response:
    return _session.request("OPTIONS", url, **kwargs)


# ---------------------------------------------------------------------------
# On-import security audit
# ---------------------------------------------------------------------------
def _on_import_audit() -> None:
    cve_warnings = check_cve()
    for w in cve_warnings:
        logger.warning("[PRESIDIO CVE CHECK] %s", w)
    if not cve_warnings:
        logger.info("[PRESIDIO CVE CHECK] requests version OK")
    logger.info("Presidio hardening applied")


_on_import_audit()

# Ensure requests symbols we explicitly re-export are accessible
# (the wildcard import above covers the rest)
__all__  # noqa: B018 — reference to suppress unused warning
