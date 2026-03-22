"""Tests for the SecretRedactor."""

from __future__ import annotations

from presidio_requests import SecretRedactor


class TestSecretRedactor:
    def setup_method(self):
        self.r = SecretRedactor()

    def test_bearer_token_redacted(self):
        text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        result = self.r.redact(text)
        assert "eyJhbGci" not in result
        assert "***REDACTED***" in result
        assert result.startswith("Bearer ")

    def test_basic_auth_redacted(self):
        text = "Basic dXNlcjpwYXNz"
        result = self.r.redact(text)
        assert "dXNlcjpwYXNz" not in result
        assert "***REDACTED***" in result

    def test_api_key_in_url_redacted(self):
        url = "https://api.example.com/v1?api_key=sk_live_abc123&format=json"
        result = self.r.redact(url)
        assert "sk_live_abc123" not in result
        assert "format=json" in result

    def test_token_param_redacted(self):
        url = "https://api.example.com/v1?token=my-secret-token"
        result = self.r.redact(url)
        assert "my-secret-token" not in result

    def test_password_param_redacted(self):
        url = "https://api.example.com/v1?password=hunter2"
        result = self.r.redact(url)
        assert "hunter2" not in result

    def test_authorization_header_redacted(self):
        text = "authorization: sk-proj-123456"
        result = self.r.redact(text)
        assert "sk-proj-123456" not in result

    def test_aws_key_redacted(self):
        text = "key=AKIAIOSFODNN7EXAMPLE"
        result = self.r.redact(text)
        assert "IOSFODNN7EXAMPLE" not in result

    def test_generic_secret_redacted(self):
        text = 'password="super_secret_pw"'
        result = self.r.redact(text)
        assert "super_secret_pw" not in result

    def test_generic_token_value_redacted(self):
        text = "token=abcdef123456"
        result = self.r.redact(text)
        assert "abcdef123456" not in result

    def test_plain_text_unchanged(self):
        text = "Hello, this is a normal string with no secrets."
        assert self.r.redact(text) == text

    def test_non_string_passthrough(self):
        assert self.r.redact(42) == 42  # type: ignore[arg-type]

    def test_custom_placeholder(self):
        r = SecretRedactor(placeholder="[HIDDEN]")
        result = r.redact("Bearer abc123")
        assert "[HIDDEN]" in result

    def test_add_custom_pattern(self):
        import re

        self.r.add_pattern("custom", re.compile(r"(CUSTOM-)[A-Z0-9]+"))
        result = self.r.redact("CUSTOM-ABC123")
        assert "ABC123" not in result

    def test_redact_dict(self):
        headers = {
            "Authorization": "Bearer secret-token-xyz",
            "Content-Type": "application/json",
        }
        result = self.r.redact_dict(headers)
        assert "secret-token-xyz" not in result["Authorization"]
        assert result["Content-Type"] == "application/json"

    def test_redact_dict_none(self):
        assert self.r.redact_dict(None) == {}

    def test_redact_dict_empty(self):
        assert self.r.redact_dict({}) == {}

    def test_secret_in_json_body(self):
        body = '{"password": "my-secret-pass", "username": "admin"}'
        result = self.r.redact(body)
        assert "my-secret-pass" not in result
        assert "admin" in result
