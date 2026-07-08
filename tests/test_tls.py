"""Tests for TLS hardening and certificate pinning."""

from __future__ import annotations

import hashlib
import ssl

import responses

import presidio_requests
from presidio_requests import (
    CertificatePinError,
    HardenedSession,
    get_hardened_ssl_context,
)


class TestTLSHardening:
    def test_ssl_context_minimum_version(self):
        ctx = get_hardened_ssl_context()
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_ssl_context_maximum_version(self):
        ctx = get_hardened_ssl_context()
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3

    def test_ssl_context_verify_mode(self):
        ctx = get_hardened_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_ssl_context_check_hostname(self):
        ctx = get_hardened_ssl_context()
        assert ctx.check_hostname is True

    def test_session_verify_enabled(self):
        s = HardenedSession()
        assert s.verify is True

    def test_session_verify_disabled(self):
        s = HardenedSession(enforce_tls=False)
        assert s.verify is not False or s.verify is True  # default requests behavior

    @responses.activate
    def test_http_upgraded_to_https(self, caplog_info):
        responses.add(responses.GET, "https://example.com/plain", status=200)
        resp = presidio_requests.get("http://example.com/plain")
        assert resp.status_code == 200
        assert any("Upgrading insecure HTTP to HTTPS" in r.message for r in caplog_info.records)


class TestCertificatePinning:
    def test_pin_error_is_request_exception(self):
        assert issubclass(CertificatePinError, presidio_requests.RequestException)

    @responses.activate
    def test_no_pin_check_when_no_pins(self):
        responses.add(responses.GET, "https://example.com/", status=200)
        s = HardenedSession(pinned_certs={})
        resp = s.get("https://example.com/")
        assert resp.status_code == 200

    @responses.activate
    def test_no_pin_check_for_unlisted_host(self):
        responses.add(responses.GET, "https://example.com/", status=200)
        s = HardenedSession(pinned_certs={"other.com": "abc123"})
        resp = s.get("https://example.com/")
        assert resp.status_code == 200

    def test_fingerprint_lookup_uses_hardened_tls_context(self, monkeypatch):
        cert = b"certificate"

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getpeercert(self, *, binary_form=False):
                assert binary_form is True
                return cert

        class FakeContext:
            minimum_version = ssl.TLSVersion.TLSv1_2

            def wrap_socket(self, sock, *, server_hostname):
                assert sock == "socket"
                assert server_hostname == "example.com"
                return FakeSocket()

        def fail_default_context():
            raise AssertionError("certificate pinning must use the hardened TLS context")

        def fake_hardened_context():
            return FakeContext()

        def fake_create_connection(address, timeout):
            assert address == ("example.com", 8443)
            assert timeout == 5
            return "socket"

        monkeypatch.setattr(presidio_requests.ssl, "create_default_context", fail_default_context)
        monkeypatch.setattr(presidio_requests, "get_hardened_ssl_context", fake_hardened_context)
        monkeypatch.setattr(presidio_requests.socket, "create_connection", fake_create_connection)

        assert (
            presidio_requests._get_cert_fingerprint("example.com", 8443)
            == hashlib.sha256(cert).hexdigest()
        )
