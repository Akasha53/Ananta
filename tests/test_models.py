"""
Tests for Pydantic validation models.
"""

import pytest
from pydantic import ValidationError

from models import (
    ScanRequest,
    TargetRequest,
    DomainRequest,
    APIKeyCreate,
    ExportRequest,
    LogFilter,
    CompareRequest,
    validate_target,
    validate_query,
)


class TestValidateTarget:
    """Tests for validate_target function."""

    def test_valid_domain(self):
        assert validate_target("google.com") == "google.com"
        assert validate_target("sub.example.co.uk") == "sub.example.co.uk"
        assert validate_target("EXAMPLE.COM") == "example.com"  # Should lowercase

    def test_valid_ip(self):
        assert validate_target("8.8.8.8") == "8.8.8.8"
        assert validate_target("192.168.1.1") == "192.168.1.1"
        assert validate_target("255.255.255.255") == "255.255.255.255"

    def test_invalid_domain(self):
        with pytest.raises(ValueError, match="n'est pas un domaine ou une IP valide"):
            validate_target("not_a_domain")

    def test_invalid_ip(self):
        with pytest.raises(ValueError, match="n'est pas un domaine ou une IP valide"):
            validate_target("999.999.999.999")

    def test_empty_target(self):
        with pytest.raises(ValueError, match="ne peut pas être vide"):
            validate_target("")

    def test_injection_attempt(self):
        with pytest.raises(ValueError, match="caractères non autorisés"):
            validate_target("google.com; rm -rf /")

        with pytest.raises(ValueError, match="caractères non autorisés"):
            validate_target("$(whoami).attacker.com")

    def test_too_long(self):
        long_domain = "a" * 254 + ".com"
        with pytest.raises(ValueError, match="trop longue"):
            validate_target(long_domain)


class TestValidateQuery:
    """Tests for validate_query function."""

    def test_valid_query(self):
        assert validate_query("analyze google.com") == "analyze google.com"
        assert validate_query("  trimmed  ") == "trimmed"

    def test_empty_query(self):
        with pytest.raises(ValueError, match="ne peut pas être vide"):
            validate_query("")

    def test_too_long(self):
        long_query = "a" * 1001
        with pytest.raises(ValueError, match="trop longue"):
            validate_query(long_query)

    def test_dangerous_chars(self):
        with pytest.raises(ValueError, match="caractères non autorisés"):
            validate_query("analyze; rm -rf /")


class TestScanRequest:
    """Tests for ScanRequest model."""

    def test_valid_request(self):
        req = ScanRequest(query="analyze google.com")
        assert req.query == "analyze google.com"
        assert req.scan_mode == "full"  # default

    def test_all_scan_modes(self):
        for mode in ["fast", "standard", "full", "critical", "priority", "parallel"]:
            req = ScanRequest(query="test", scan_mode=mode)
            assert req.scan_mode == mode

    def test_invalid_scan_mode(self):
        with pytest.raises(ValidationError):
            ScanRequest(query="test", scan_mode="invalid_mode")

    def test_approved_tools(self):
        req = ScanRequest(
            query="test",
            scan_mode="critical",
            approved_tools=["port_scan", "vuln_scan"]
        )
        assert req.approved_tools == ["port_scan", "vuln_scan"]

    def test_invalid_approved_tool(self):
        with pytest.raises(ValidationError, match="non reconnu"):
            ScanRequest(query="test", approved_tools=["invalid_tool"])


class TestTargetRequest:
    """Tests for TargetRequest model."""

    def test_valid_domain(self):
        req = TargetRequest(target="example.com")
        assert req.target == "example.com"

    def test_valid_ip(self):
        req = TargetRequest(target="8.8.8.8")
        assert req.target == "8.8.8.8"

    def test_invalid_target(self):
        with pytest.raises(ValidationError):
            TargetRequest(target="not_valid")


class TestDomainRequest:
    """Tests for DomainRequest model."""

    def test_valid_domain(self):
        req = DomainRequest(domain="google.com")
        assert req.domain == "google.com"

    def test_ip_not_allowed(self):
        # DomainRequest should only accept domains, not IPs
        with pytest.raises(ValidationError):
            DomainRequest(domain="8.8.8.8")


class TestAPIKeyCreate:
    """Tests for APIKeyCreate model."""

    def test_valid_name(self):
        req = APIKeyCreate(name="My App")
        assert req.name == "My App"

    def test_name_with_special_chars(self):
        req = APIKeyCreate(name="my-app_v2")
        assert req.name == "my-app_v2"

    def test_empty_name(self):
        with pytest.raises(ValidationError):
            APIKeyCreate(name="")

    def test_invalid_chars_in_name(self):
        with pytest.raises(ValidationError, match="caractères non autorisés"):
            APIKeyCreate(name="app<script>")


class TestExportRequest:
    """Tests for ExportRequest model."""

    def test_valid_export(self):
        req = ExportRequest(query="example.com", format="pdf")
        assert req.query == "example.com"
        assert req.format == "pdf"

    def test_all_formats(self):
        for fmt in ["pdf", "json", "csv", "xml", "markdown"]:
            req = ExportRequest(query="example.com", format=fmt)
            assert req.format == fmt

    def test_invalid_format(self):
        with pytest.raises(ValidationError):
            ExportRequest(query="example.com", format="docx")


class TestLogFilter:
    """Tests for LogFilter model."""

    def test_default_values(self):
        filter = LogFilter()
        assert filter.page == 1
        assert filter.limit == 50

    def test_pagination_limits(self):
        filter = LogFilter(page=5, limit=100)
        assert filter.page == 5
        assert filter.limit == 100

    def test_invalid_pagination(self):
        with pytest.raises(ValidationError):
            LogFilter(page=0)  # page must be >= 1

        with pytest.raises(ValidationError):
            LogFilter(limit=1000)  # limit must be <= 500


class TestCompareRequest:
    """Tests for CompareRequest model."""

    def test_valid_compare(self):
        req = CompareRequest(target="example.com", report_id_1=1, report_id_2=2)
        assert req.report_id_1 == 1
        assert req.report_id_2 == 2

    def test_same_report_ids(self):
        with pytest.raises(ValidationError, match="différents"):
            CompareRequest(target="example.com", report_id_1=1, report_id_2=1)
