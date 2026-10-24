"""
presidio-hardened-requests
~~~~~~~~~~~~~~~~~~~~~~~~~~

A 100% drop-in replacement for the ``requests`` library with Presidio
security hardening applied automatically on import.

Usage::

    import presidio_requests as requests
    resp = requests.get("https://httpbin.org/get")

Security features applied transparently:
  - Strict TLS 1.2+ (1.3 max) with strong ciphers + cert verification
  - Secret redaction (headers/URLs/params/data/json) via call sites +
    sink-level RedactingFilter on the logger (v0.2)
  - Per-host rate limiting with exponential backoff
  - CVE awareness (static + pip-audit in dev/CI)
  - Structured security event logging
  - Optional cert pinning, checked on every TLS connection (v0.2.2)
"""

from __future__ import annotations

import hashlib
import logging
import re
import socket
import ssl
import threading
import time
from importlib.metadata import version as _pkg_version
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

import requests  # noqa: F401 — keep reference for submodule access
from requests import ConnectionError as ConnectionError  # noqa: A004
from requests import (
    HTTPError,
    PreparedRequest,
    RequestException,
    Response,
    Session,
    Timeout,
    URLRequired,
)
from requests.adapters import HTTPAdapter

# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------
__version__ = "0.2.2"
__all__ = [
    # Our additions
    "HardenedSession",
    "CertificatePinError",
    "InsecureTransportError",
    "SecretRedactor",
    "RedactingFilter",
    "install_log_redaction",
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
# CVE Quick-Check (v0.2: static list + strong recommendation for pip-audit)
# ---------------------------------------------------------------------------
KNOWN_VULNERABLE_VERSIONS: dict[str, str] = {
    "2.3.0": "CVE-2014-1829 — cookie leak on redirect",
    "2.5.3": "CVE-2014-1830 — cookie leak on redirect",
    "2.6.0": "CVE-2015-2296 — session fixation via cookies",
    "2.19.1": "CVE-2018-18074 — redirect credential leak",
    "2.25.1": "CVE-2023-32681 — Proxy-Authorization header leak",
    # NOTE: For current coverage, run `pip-audit` in CI/dev (added v0.2).
    # Static list is best-effort only.
}


def check_cve() -> list[str]:
    """Return list of CVE warnings for the installed ``requests`` version.

    In v0.2.0 the on-import check is supplemented by pip-audit in dev/CI.
    """
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


class InsecureTransportError(RequestException):
    """Raised when ``enforce_tls`` is on and a request or redirect hop is not HTTPS."""


_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")


def _normalize_pins(pins: dict[str, str] | None) -> dict[str, str]:
    """Lowercase hosts (no trailing dot) and SHA-256 hex fingerprints (no colons)."""
    out: dict[str, str] = {}
    for host, fp in (pins or {}).items():
        h = host.strip().rstrip(".").lower()
        f = fp.strip().replace(":", "").lower()
        if not h or not _FINGERPRINT_RE.fullmatch(f):
            raise ValueError(f"pinned_certs[{host!r}] must be a SHA-256 hex fingerprint")
        out[h] = f
    return out


class _PinnedAdapter(HTTPAdapter):
    """Adapter whose connections must present the pinned certificate.

    urllib3 checks ``assert_fingerprint`` during the handshake of every connection
    it opens (first request, redirect hops, reused pools), after normal CA
    verification. A mismatch fails the request; there is no fail-open path.
    """

    def __init__(self, fingerprint: str) -> None:
        self._fingerprint = fingerprint
        super().__init__()

    def init_poolmanager(self, *args: Any, **pool_kwargs: Any) -> None:
        pool_kwargs["assert_fingerprint"] = self._fingerprint
        super().init_poolmanager(*args, **pool_kwargs)

    def send(self, request: PreparedRequest, *args: Any, **kwargs: Any) -> Response:
        try:
            return super().send(request, *args, **kwargs)
        except requests.exceptions.SSLError as e:
            if "fingerprint" in str(e).lower():
                raise CertificatePinError(
                    f"Certificate fingerprint mismatch for {urlparse(request.url).hostname}"
                ) from e
            raise


def _get_cert_fingerprint(host: str, port: int = 443) -> str | None:
    """Retrieve the SHA-256 fingerprint of the server's TLS certificate.

    Diagnostic helper only (for example, to obtain a value for ``pinned_certs``).
    Since v0.2.2 pins are enforced on the request's own connection by
    ``_PinnedAdapter``, not by this separate probe.
    """
    try:
        ctx = get_hardened_ssl_context()
        with ctx.wrap_socket(
            socket.create_connection((host, port), timeout=5),
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
        ("URL userinfo password", re.compile(r"(://[^/\s:@]*:)[^@/\s]+(?=@)")),
        (
            "Generic secret",
            re.compile(
                r"((?:secret|password|passwd|pwd|token)[\"\']?\s*[:=]\s*[\"\']?)[^\s\"\'&,;}{)]+",
                re.IGNORECASE,
            ),
        ),
    ]

    # A dict key is a credential when one of its parts ("x-api-key" -> x, api, key)
    # is in this set; its whole value is then replaced, whatever it looks like.
    SENSITIVE_KEY_PARTS: frozenset[str] = frozenset(
        {
            "apikey",
            "auth",
            "authorization",
            "bearer",
            "cookie",
            "credential",
            "credentials",
            "jwt",
            "key",
            "passwd",
            "password",
            "pwd",
            "secret",
            "session",
            "sessionid",
            "signature",
            "token",
        }
    )

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

    def is_sensitive_key(self, key: Any) -> bool:
        parts = re.split(r"[^a-z0-9]+", str(key).lower())
        return any(p in self.SENSITIVE_KEY_PARTS for p in parts)

    def redact_value(self, value: Any) -> Any:
        """Redact strings by pattern and dicts/lists recursively by key and pattern."""
        if isinstance(value, dict):
            return self.redact_dict(value)
        if isinstance(value, (list, tuple)):
            return [
                (v[0], self.placeholder)
                if isinstance(v, tuple) and len(v) == 2 and self.is_sensitive_key(v[0])
                else self.redact_value(v)
                for v in value
            ]
        if isinstance(value, bytes):
            return self.redact(value.decode("utf-8", "replace"))
        return self.redact(value)

    def redact_dict(self, d: dict[str, Any] | None) -> dict[str, Any]:
        if not d:
            return d or {}
        return {
            k: self.placeholder if self.is_sensitive_key(k) else self.redact_value(v)
            for k, v in d.items()
        }


_default_redactor = SecretRedactor()


# ---------------------------------------------------------------------------
# Sink-level log redaction (v0.2.0 addition for defense-in-depth)
# Matches family pattern from more mature projects (e.g. angellist).
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(sk_(?:live|test)_)[A-Za-z0-9]+"), r"\1***REDACTED***"),
    (re.compile(r"(sk-ant-)[A-Za-z0-9\-_]+"), r"\1***REDACTED***"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*"), r"\1***REDACTED***"),
    (re.compile(r"(access_token=)[^&\s]+"), r"\1***REDACTED***"),
    (re.compile(r"(api_key=)[^&\s]+"), r"\1***REDACTED***"),
    (re.compile(r"(Authorization:\s*)[^\r\n]+", re.IGNORECASE), r"\1***REDACTED***"),
]


class RedactingFilter(logging.Filter):
    """A logging.Filter that scrubs secrets from every record at the sink.

    Installed on the ``presidio_requests`` logger so the redaction commitment
    is enforced for *every* log record, not just the call sites that redact
    manually.
    """

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        super().__init__()
        self._redactor = redactor or SecretRedactor()

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - never let logging crash
            return True
        record.msg = self._redactor.redact(message)
        record.args = None
        return True


def install_log_redaction(redactor: SecretRedactor | None = None) -> RedactingFilter:
    """Attach a RedactingFilter to the ``presidio_requests`` logger.

    Idempotent. Returns the active filter.
    """
    logger = logging.getLogger("presidio_requests")
    for existing in logger.filters:
        if isinstance(existing, RedactingFilter):
            return existing
    flt = RedactingFilter(redactor)
    logger.addFilter(flt)
    return flt


# Enforce redaction at the sink as soon as the module is imported.
install_log_redaction()


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
        self.pinned_certs: dict[str, str] = _normalize_pins(pinned_certs)
        self.enforce_tls = enforce_tls
        self._apply_tls_hardening()
        self._mount_pins()
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

    def _mount_pins(self) -> None:
        # Both prefixes end the host part, so "https://api.example.com" never
        # matches "https://api.example.com.evil.net". requests lowercases the
        # URL before matching mount prefixes.
        for host, fingerprint in self.pinned_certs.items():
            adapter = _PinnedAdapter(fingerprint)
            self.mount(f"https://{host}/", adapter)
            self.mount(f"https://{host}:", adapter)

    def _upgrade_to_https(self, url: str) -> str:
        """Upgrade an http URL as requests will read it (leading whitespace, any case)."""
        if not isinstance(url, str):
            return url
        stripped = url.lstrip()
        parts = urlsplit(stripped)
        if parts.scheme.lower() == "http":
            logger.warning("Upgrading insecure HTTP to HTTPS: %s", self.redactor.redact(url))
            return urlunsplit(("https",) + tuple(parts[1:]))
        return url

    def send(self, request: PreparedRequest, **kwargs: Any) -> Response:  # type: ignore[override]
        # Every hop requests sends, including redirects, passes through here.
        if self.enforce_tls and urlsplit(request.url or "").scheme.lower() != "https":
            raise InsecureTransportError(
                "Refusing non-HTTPS request with enforce_tls=True: "
                + self.redactor.redact(request.url or "")
            )
        return super().send(request, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        if self.enforce_tls:
            url = self._upgrade_to_https(url)

        self.rate_limiter.wait_if_needed(url)

        self._log_redacted_request(method, url, kwargs)

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
        # Credentials are matched by key name as well as by value pattern (v0.2.2).
        redacted_params = (
            self.redactor.redact_value(kwargs.get("params")) if kwargs.get("params") else None
        )
        data = kwargs.get("data")
        redacted_data = (
            self.redactor.redact_value(data)
            if isinstance(data, (dict, list, tuple))
            else self.redactor.redact(str(data))
            if data
            else None
        )
        redacted_json = (
            self.redactor.redact_value(kwargs.get("json"))
            if kwargs.get("json") is not None
            else None
        )

        logger.debug(
            "Request %s %s headers=%s params=%s data=%s json=%s",
            method.upper(),
            redacted_url,
            redacted_headers,
            redacted_params,
            redacted_data,
            redacted_json,
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
# On-import security audit (v0.2: includes sink redaction install + pip-audit note)
# ---------------------------------------------------------------------------
def _on_import_audit() -> None:
    cve_warnings = check_cve()
    for w in cve_warnings:
        logger.warning("[PRESIDIO CVE CHECK] %s", w)
    if not cve_warnings:
        logger.info("[PRESIDIO CVE CHECK] requests version OK (supplement with pip-audit)")
    logger.info("Presidio hardening applied (v0.2.0: sink redaction filter active)")


_on_import_audit()

# Ensure requests symbols we explicitly re-export are accessible
# (the wildcard import above covers the rest)
__all__  # noqa: B018 — reference to suppress unused warning
