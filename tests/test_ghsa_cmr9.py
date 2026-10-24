"""Regressions for GHSA-cmr9-799c-jmhv (fail-open TLS upgrade, pinning, redaction)."""

from __future__ import annotations

import logging
import re

import pytest
import requests
import responses

import presidio_requests
from presidio_requests import (
    CertificatePinError,
    HardenedSession,
    InsecureTransportError,
    SecretRedactor,
)

FP = "AB:" * 31 + "AB"


class TestSchemeUpgrade:
    @pytest.mark.parametrize(
        "url",
        [
            "HTTP://example.com/x",
            "Http://example.com/x",
            " http://example.com/x",
            "\thttp://example.com/x",
        ],
    )
    @responses.activate
    def test_any_case_or_leading_space_is_upgraded(self, url):
        responses.add(responses.GET, "https://example.com/x", status=200)
        assert HardenedSession().get(url).url == "https://example.com/x"

    @responses.activate
    def test_module_function_upgrades_uppercase(self):
        responses.add(responses.GET, "https://example.com/m", status=200)
        assert presidio_requests.get("HTTP://example.com/m").status_code == 200

    @responses.activate
    def test_disabled_leaves_http_alone(self):
        responses.add(responses.GET, "http://example.com/x", status=200)
        assert HardenedSession(enforce_tls=False).get("HTTP://example.com/x").status_code == 200


class TestRedirectHops:
    @pytest.mark.parametrize("status,method", [(302, "GET"), (307, "POST"), (308, "POST")])
    @responses.activate
    def test_downgrade_redirect_is_refused(self, status, method):
        responses.add(
            method,
            "https://example.com/a",
            status=status,
            headers={"Location": "http://example.com/sink"},
        )
        sink = responses.add(method, "http://example.com/sink", status=200)
        with pytest.raises(InsecureTransportError):
            HardenedSession().request(method, "https://example.com/a", headers={"X-API-Key": "k"})
        assert sink.call_count == 0

    @responses.activate
    def test_redirect_still_inspectable_without_following(self):
        responses.add(
            responses.GET,
            "https://example.com/a",
            status=302,
            headers={"Location": "http://example.com/s"},
        )
        r = HardenedSession().get("https://example.com/a", allow_redirects=False)
        assert r.status_code == 302

    @responses.activate
    def test_https_redirect_is_followed(self):
        responses.add(
            responses.GET,
            "https://example.com/a",
            status=302,
            headers={"Location": "https://example.com/b"},
        )
        responses.add(responses.GET, "https://example.com/b", status=200)
        assert HardenedSession().get("https://example.com/a").status_code == 200

    def test_prepared_http_request_is_refused(self):
        s = HardenedSession()
        prep = s.prepare_request(requests.Request("GET", "http://example.com/"))
        with pytest.raises(InsecureTransportError):
            s.send(prep)


class TestPinning:
    def test_pins_are_normalized(self):
        s = HardenedSession(pinned_certs={"Pinned.EXAMPLE.": FP})
        assert s.pinned_certs == {"pinned.example": "ab" * 32}

    def test_invalid_pin_rejected(self):
        with pytest.raises(ValueError):
            HardenedSession(pinned_certs={"pinned.example": "abc123"})

    def test_pinned_host_uses_fingerprint_adapter_for_every_hop(self):
        s = HardenedSession(pinned_certs={"pinned.example": FP})
        for url in ("https://pinned.example/a", "https://PINNED.example:8443/b"):
            adapter = s.get_adapter(url)
            assert isinstance(adapter, presidio_requests._PinnedAdapter)
            assert adapter.poolmanager.connection_pool_kw["assert_fingerprint"] == "ab" * 32
        # a look-alike host is not covered by the pin's mount prefix
        assert not isinstance(
            s.get_adapter("https://pinned.example.evil.net/"), presidio_requests._PinnedAdapter
        )

    def test_no_probe_connection_is_made(self, monkeypatch):
        def boom(*a, **k):
            raise AssertionError("pinning must not use a separate probe socket")

        monkeypatch.setattr(presidio_requests, "_get_cert_fingerprint", boom)
        s = HardenedSession(pinned_certs={"pinned.example": FP})
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, "https://pinned.example/", status=200)
            assert s.get("https://pinned.example/").status_code == 200

    def test_fingerprint_mismatch_maps_to_pin_error(self, monkeypatch):
        def fake_send(self, request, *a, **k):
            raise requests.exceptions.SSLError("Fingerprints did not match. Expected ...")

        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", fake_send)
        s = HardenedSession(pinned_certs={"pinned.example": FP})
        with pytest.raises(CertificatePinError):
            s.get("https://pinned.example/")


class TestRedactionByKey:
    @responses.activate
    def test_credentials_never_reach_the_log(self, caplog):
        responses.add(responses.POST, re.compile(r"https://.*example\.com/.*"), status=200)
        with caplog.at_level(logging.DEBUG, logger="presidio_requests"):
            HardenedSession().post(
                "https://user:LEAK1pass@example.com/",
                headers={
                    "X-API-Key": "LEAK2",
                    "Cookie": "sid=LEAK3",
                    "Authorization": "Token LEAK4",
                },
                params={"api_key": "LEAK5", "q": "ok"},
                data={"client_secret": "LEAK6"},
                json={"nested": {"access_token": "LEAK7"}, "items": [{"password": "LEAK8"}]},
            )
        logged = " ".join(r.getMessage() for r in caplog.records)
        assert "Request POST" in logged and "'q': 'ok'" in logged
        for n in range(1, 9):
            assert f"LEAK{n}" not in logged

    def test_non_secret_keys_are_kept(self):
        r = SecretRedactor()
        assert r.redact_dict({"author": "ada", "monkey": "x"}) == {"author": "ada", "monkey": "x"}
        assert r.redact_dict({"x-api-key": "v"}) == {"x-api-key": r.placeholder}

    def test_key_value_pairs_redacted_by_key(self):
        r = SecretRedactor()
        assert r.redact_value([("api_key", "LEAK"), ("q", "ok")]) == [
            ("api_key", r.placeholder),
            ["q", "ok"],
        ]
