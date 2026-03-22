"""Tests for CVE quick-check."""

from __future__ import annotations

from unittest.mock import patch

import presidio_requests
from presidio_requests import KNOWN_VULNERABLE_VERSIONS, check_cve


class TestCVECheck:
    def test_safe_version_returns_empty(self):
        with patch("presidio_requests._pkg_version", return_value="2.32.5"):
            warnings = check_cve()
            assert warnings == []

    def test_vulnerable_version_returns_warning(self):
        with patch("presidio_requests._pkg_version", return_value="2.25.1"):
            warnings = check_cve()
            assert len(warnings) == 1
            assert "CVE-2023-32681" in warnings[0]

    def test_all_vulnerable_versions_detected(self):
        for ver, _desc in KNOWN_VULNERABLE_VERSIONS.items():
            with patch("presidio_requests._pkg_version", return_value=ver):
                warnings = check_cve()
                assert len(warnings) >= 1
                assert any(ver in w for w in warnings)

    def test_import_error_handled(self):
        with patch("presidio_requests._pkg_version", side_effect=Exception("no package")):
            warnings = check_cve()
            assert len(warnings) == 1
            assert "Unable to determine" in warnings[0]

    def test_known_vulnerable_versions_not_empty(self):
        assert len(KNOWN_VULNERABLE_VERSIONS) >= 5


class TestOnImportAudit:
    def test_audit_runs_on_import(self, caplog_info):
        presidio_requests._on_import_audit()
        assert any("PRESIDIO CVE CHECK" in r.message for r in caplog_info.records)

    def test_audit_logs_hardening_applied(self, caplog_info):
        presidio_requests._on_import_audit()
        assert any("Presidio hardening applied" in r.message for r in caplog_info.records)
