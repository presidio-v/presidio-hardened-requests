"""Tests for HardenedSession."""

from __future__ import annotations

import pytest
import responses

from presidio_requests import HardenedSession, RateLimiter, SecretRedactor


class TestHardenedSession:
    @responses.activate
    def test_basic_get(self):
        responses.add(responses.GET, "https://example.com/", json={"ok": True}, status=200)
        s = HardenedSession()
        resp = s.get("https://example.com/")
        assert resp.status_code == 200

    @responses.activate
    def test_http_upgrade(self, caplog_info):
        responses.add(responses.GET, "https://insecure.com/page", status=200)
        s = HardenedSession()
        resp = s.get("http://insecure.com/page")
        assert resp.status_code == 200
        assert any("Upgrading insecure HTTP" in r.message for r in caplog_info.records)

    @responses.activate
    def test_no_upgrade_when_disabled(self):
        responses.add(responses.GET, "http://insecure.com/page", status=200)
        s = HardenedSession(enforce_tls=False)
        resp = s.get("http://insecure.com/page")
        assert resp.status_code == 200

    @responses.activate
    def test_custom_redactor(self):
        responses.add(responses.GET, "https://example.com/", status=200)
        redactor = SecretRedactor(placeholder="[GONE]")
        s = HardenedSession(redactor=redactor)
        s.get("https://example.com/")
        assert s.redactor.placeholder == "[GONE]"

    @responses.activate
    def test_custom_rate_limiter(self):
        responses.add(responses.GET, "https://example.com/", status=200)
        rl = RateLimiter(max_requests_per_second=100.0)
        s = HardenedSession(rate_limiter=rl)
        s.get("https://example.com/")
        assert s.rate_limiter.max_rps == 100.0

    @responses.activate
    def test_rate_limiter_error_recorded(self):
        responses.add(
            responses.GET,
            "https://example.com/fail",
            body=ConnectionError("fail"),
        )
        s = HardenedSession()
        with pytest.raises(ConnectionError):
            s.get("https://example.com/fail")
        state = s.rate_limiter._get_host_state("example.com")
        assert state.consecutive_errors >= 1

    @responses.activate
    def test_rate_limiter_success_recorded(self):
        responses.add(responses.GET, "https://example.com/ok", status=200)
        s = HardenedSession()
        s.get("https://example.com/ok")
        state = s.rate_limiter._get_host_state("example.com")
        assert state.consecutive_errors == 0

    @responses.activate
    def test_request_with_headers_logged(self, caplog_info):
        responses.add(responses.GET, "https://example.com/", status=200)
        s = HardenedSession()
        s.get("https://example.com/", headers={"Authorization": "Bearer secret123"})
        logged = " ".join(r.message for r in caplog_info.records)
        assert "secret123" not in logged

    @responses.activate
    def test_request_without_headers(self, caplog_info):
        responses.add(responses.GET, "https://example.com/", status=200)
        s = HardenedSession()
        s.get("https://example.com/")
        assert any("Request GET" in r.message for r in caplog_info.records)

    @responses.activate
    def test_response_logged(self, caplog_info):
        responses.add(responses.GET, "https://example.com/", status=200)
        s = HardenedSession()
        s.get("https://example.com/")
        assert any("Response GET" in r.message for r in caplog_info.records)

    def test_init_logs_hardening(self, caplog_info):
        HardenedSession()
        assert any("HardenedSession initialized" in r.message for r in caplog_info.records)

    def test_pinned_certs_default_empty(self):
        s = HardenedSession()
        assert s.pinned_certs == {}
