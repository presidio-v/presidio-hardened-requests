"""Verify that presidio_requests is a true drop-in replacement for requests."""

from __future__ import annotations

import responses

import presidio_requests


class TestDropInAPI:
    """Every public requests symbol should be accessible."""

    def test_has_get(self):
        assert callable(presidio_requests.get)

    def test_has_post(self):
        assert callable(presidio_requests.post)

    def test_has_put(self):
        assert callable(presidio_requests.put)

    def test_has_patch(self):
        assert callable(presidio_requests.patch)

    def test_has_delete(self):
        assert callable(presidio_requests.delete)

    def test_has_head(self):
        assert callable(presidio_requests.head)

    def test_has_options(self):
        assert callable(presidio_requests.options)

    def test_has_request(self):
        assert callable(presidio_requests.request)

    def test_has_session_class(self):
        assert presidio_requests.Session is not None

    def test_has_response_class(self):
        assert presidio_requests.Response is not None

    def test_has_exceptions(self):
        assert presidio_requests.RequestException is not None
        assert presidio_requests.ConnectionError is not None
        assert presidio_requests.HTTPError is not None
        assert presidio_requests.Timeout is not None
        assert presidio_requests.URLRequired is not None

    def test_version(self):
        assert presidio_requests.__version__ == "0.1.0"


class TestDropInBehavior:
    """HTTP methods should work identically to plain requests."""

    @responses.activate
    def test_get_returns_response(self):
        responses.add(responses.GET, "https://example.com/api", json={"ok": True}, status=200)
        resp = presidio_requests.get("https://example.com/api")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    @responses.activate
    def test_post_with_json(self):
        responses.add(responses.POST, "https://example.com/api", json={"id": 1}, status=201)
        resp = presidio_requests.post("https://example.com/api", json={"name": "test"})
        assert resp.status_code == 201

    @responses.activate
    def test_put_request(self):
        responses.add(responses.PUT, "https://example.com/api/1", status=200)
        resp = presidio_requests.put("https://example.com/api/1", json={"name": "updated"})
        assert resp.status_code == 200

    @responses.activate
    def test_patch_request(self):
        responses.add(responses.PATCH, "https://example.com/api/1", status=200)
        resp = presidio_requests.patch("https://example.com/api/1", json={"name": "patched"})
        assert resp.status_code == 200

    @responses.activate
    def test_delete_request(self):
        responses.add(responses.DELETE, "https://example.com/api/1", status=204)
        resp = presidio_requests.delete("https://example.com/api/1")
        assert resp.status_code == 204

    @responses.activate
    def test_head_request(self):
        responses.add(responses.HEAD, "https://example.com/", status=200)
        resp = presidio_requests.head("https://example.com/")
        assert resp.status_code == 200

    @responses.activate
    def test_options_request(self):
        responses.add(responses.OPTIONS, "https://example.com/", status=200)
        resp = presidio_requests.options("https://example.com/")
        assert resp.status_code == 200

    @responses.activate
    def test_request_method(self):
        responses.add(responses.GET, "https://example.com/", status=200)
        resp = presidio_requests.request("GET", "https://example.com/")
        assert resp.status_code == 200
