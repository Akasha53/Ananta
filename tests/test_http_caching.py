"""
Tests for HTTP caching functionality (ETag, Last-Modified, 304 responses).

Tests cover:
- ETag generation and If-None-Match handling
- Last-Modified headers and If-Modified-Since handling
- Cache-Control headers
- 304 Not Modified responses
- All cacheable endpoints: /osint/report, /osint/history, /osint/export/*, /monitoring/stats
"""

import pytest
import json
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from database import EntityReport, ToolExecutionLog


class TestCacheUtilities:
    """Tests for the cache utility functions."""

    def test_generate_etag_string(self):
        """Test ETag generation from string."""
        from web_routes import generate_etag
        
        etag = generate_etag("test content")
        assert etag.startswith('"')
        assert etag.endswith('"')
        assert len(etag) == 34  # MD5 hex (32) + 2 quotes

    def test_generate_etag_dict(self):
        """Test ETag generation from dict."""
        from web_routes import generate_etag
        
        data = {"key": "value", "number": 42}
        etag = generate_etag(data)
        assert etag.startswith('"')
        assert etag.endswith('"')

    def test_generate_etag_consistency(self):
        """Test that same content generates same ETag."""
        from web_routes import generate_etag
        
        data = {"test": "data", "list": [1, 2, 3]}
        etag1 = generate_etag(data)
        etag2 = generate_etag(data)
        assert etag1 == etag2

    def test_generate_etag_different_for_different_content(self):
        """Test that different content generates different ETags."""
        from web_routes import generate_etag
        
        etag1 = generate_etag({"key": "value1"})
        etag2 = generate_etag({"key": "value2"})
        assert etag1 != etag2

    def test_format_http_date(self):
        """Test HTTP date formatting."""
        from web_routes import format_http_date
        
        dt = datetime(2026, 1, 21, 10, 30, 0, tzinfo=timezone.utc)
        http_date = format_http_date(dt)
        assert "Tue" in http_date
        assert "21 Jan 2026" in http_date
        assert "GMT" in http_date

    def test_format_http_date_naive_datetime(self):
        """Test HTTP date formatting with naive datetime."""
        from web_routes import format_http_date
        
        dt = datetime(2026, 1, 21, 10, 30, 0)  # No timezone
        http_date = format_http_date(dt)
        assert "GMT" in http_date

    def test_check_not_modified_with_matching_etag(self):
        """Test 304 detection with matching ETag."""
        from web_routes import check_not_modified
        from starlette.requests import Request
        from starlette.testclient import TestClient
        
        # Create a mock request with If-None-Match header
        class MockRequest:
            headers = {"if-none-match": '"abc123"'}
        
        result = check_not_modified(MockRequest(), etag='"abc123"')
        assert result is True

    def test_check_not_modified_with_non_matching_etag(self):
        """Test 304 detection with non-matching ETag."""
        from web_routes import check_not_modified
        
        class MockRequest:
            headers = {"if-none-match": '"old_etag"'}
        
        result = check_not_modified(MockRequest(), etag='"new_etag"')
        assert result is False

    def test_check_not_modified_with_wildcard_etag(self):
        """Test 304 detection with wildcard If-None-Match."""
        from web_routes import check_not_modified
        
        class MockRequest:
            headers = {"if-none-match": "*"}
        
        result = check_not_modified(MockRequest(), etag='"any_etag"')
        assert result is True

    def test_check_not_modified_with_multiple_etags(self):
        """Test 304 detection with multiple ETags in header."""
        from web_routes import check_not_modified
        
        class MockRequest:
            headers = {"if-none-match": '"etag1", "etag2", "etag3"'}
        
        result = check_not_modified(MockRequest(), etag='"etag2"')
        assert result is True

    def test_check_not_modified_with_if_modified_since(self):
        """Test 304 detection with If-Modified-Since."""
        from web_routes import check_not_modified
        from email.utils import formatdate
        
        # Last modified is older than client's cached version
        last_modified = datetime(2026, 1, 20, 10, 0, 0, tzinfo=timezone.utc)
        client_date = formatdate((datetime(2026, 1, 21, 10, 0, 0, tzinfo=timezone.utc)).timestamp(), usegmt=True)
        
        class MockRequest:
            headers = {"if-modified-since": client_date}
        
        result = check_not_modified(MockRequest(), last_modified=last_modified)
        assert result is True

    def test_check_not_modified_with_newer_content(self):
        """Test that newer content doesn't trigger 304."""
        from web_routes import check_not_modified
        from email.utils import formatdate
        
        # Last modified is newer than client's cached version
        last_modified = datetime(2026, 1, 22, 10, 0, 0, tzinfo=timezone.utc)
        client_date = formatdate((datetime(2026, 1, 21, 10, 0, 0, tzinfo=timezone.utc)).timestamp(), usegmt=True)
        
        class MockRequest:
            headers = {"if-modified-since": client_date}
        
        result = check_not_modified(MockRequest(), last_modified=last_modified)
        assert result is False


class TestHistoryEndpointCaching:
    """Tests for /osint/history/ caching."""

    def test_history_returns_etag(self, fresh_client: TestClient, db_session: Session):
        """Test that /osint/history returns ETag header."""
        response = fresh_client.get("/osint/history/")
        assert response.status_code == 200
        assert "ETag" in response.headers
        assert response.headers["ETag"].startswith('"')

    def test_history_returns_cache_control(self, fresh_client: TestClient, db_session: Session):
        """Test that /osint/history returns Cache-Control header."""
        response = fresh_client.get("/osint/history/")
        assert response.status_code == 200
        assert "Cache-Control" in response.headers
        assert "max-age=" in response.headers["Cache-Control"]

    def test_history_304_with_matching_etag(self, fresh_client: TestClient, db_session: Session):
        """Test 304 response when ETag matches."""
        # First request to get ETag
        response1 = fresh_client.get("/osint/history/")
        assert response1.status_code == 200
        etag = response1.headers["ETag"]
        
        # Second request with If-None-Match
        response2 = fresh_client.get(
            "/osint/history/",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304
        assert response2.headers["ETag"] == etag

    def test_history_200_with_different_etag(self, fresh_client: TestClient, db_session: Session):
        """Test 200 response when ETag doesn't match."""
        response = fresh_client.get(
            "/osint/history/",
            headers={"If-None-Match": '"old_invalid_etag"'}
        )
        assert response.status_code == 200


class TestReportEndpointCaching:
    """Tests for /osint/report/ caching."""

    @pytest.fixture
    def sample_report(self, db_session: Session):
        """Create a sample report for testing."""
        report = EntityReport(
            target="example.com",
            target_type="DOMAIN",
            final_report="# Test Report\n\nThis is a test report.",
            raw_data=json.dumps({
                "scanned_at": "2026-01-21 10:00:00",
                "tools": {"whois": {"status": "ok", "data": {"registrar": "Test Registrar"}}}
            })
        )
        db_session.add(report)
        db_session.commit()
        db_session.refresh(report)
        return report

    def test_report_returns_etag(self, fresh_client: TestClient, db_session: Session, sample_report):
        """Test that /osint/report returns ETag header."""
        response = fresh_client.get("/osint/report/?target=example.com")
        assert response.status_code == 200
        assert "ETag" in response.headers

    def test_report_returns_last_modified(self, fresh_client: TestClient, db_session: Session, sample_report):
        """Test that /osint/report returns Last-Modified header."""
        response = fresh_client.get("/osint/report/?target=example.com")
        assert response.status_code == 200
        assert "Last-Modified" in response.headers

    def test_report_304_with_matching_etag(self, fresh_client: TestClient, db_session: Session, sample_report):
        """Test 304 response with matching ETag."""
        response1 = fresh_client.get("/osint/report/?target=example.com")
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/osint/report/?target=example.com",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304

    def test_report_404_for_missing_target(self, fresh_client: TestClient, db_session: Session):
        """Test 404 for non-existent report."""
        response = fresh_client.get("/osint/report/?target=nonexistent.com")
        assert response.status_code == 404


class TestMonitoringStatsCaching:
    """Tests for /monitoring/stats caching."""

    def test_stats_returns_etag(self, fresh_client: TestClient, db_session: Session):
        """Test that /monitoring/stats returns ETag header."""
        response = fresh_client.get("/monitoring/stats")
        assert response.status_code == 200
        assert "ETag" in response.headers

    def test_stats_returns_cache_control(self, fresh_client: TestClient, db_session: Session):
        """Test that /monitoring/stats returns Cache-Control with short max-age."""
        response = fresh_client.get("/monitoring/stats")
        assert response.status_code == 200
        assert "Cache-Control" in response.headers
        # Stats should have short cache (30s)
        assert "max-age=30" in response.headers["Cache-Control"]

    def test_stats_304_with_matching_etag(self, fresh_client: TestClient, db_session: Session):
        """Test 304 response when ETag matches."""
        response1 = fresh_client.get("/monitoring/stats")
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/monitoring/stats",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304


class TestExportEndpointsCaching:
    """Tests for /osint/export/* endpoints caching."""

    @pytest.fixture
    def sample_report_for_export(self, db_session: Session):
        """Create a sample report for export testing."""
        report = EntityReport(
            target="exporttest.com",
            target_type="DOMAIN",
            final_report="# Export Test Report\n\nTest content for export.",
            raw_data=json.dumps({
                "scanned_at": "2026-01-21 12:00:00",
                "risk_analysis": {"score": 25, "level": "LOW", "indicators": {"positive": ["HTTPS"], "negative": []}},
                "tools": {
                    "whois": {"status": "ok", "duration": 1.5, "data": {"registrar": "Test"}},
                    "dns_resolution": {"status": "ok", "duration": 0.5, "data": "93.184.216.34"}
                }
            })
        )
        db_session.add(report)
        db_session.commit()
        db_session.refresh(report)
        return report

    def test_export_json_returns_etag(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test that JSON export returns ETag."""
        response = fresh_client.get("/osint/export/json?query=exporttest.com")
        assert response.status_code == 200
        assert "ETag" in response.headers

    def test_export_json_304(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test 304 for JSON export."""
        response1 = fresh_client.get("/osint/export/json?query=exporttest.com")
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/osint/export/json?query=exporttest.com",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304

    def test_export_csv_returns_etag(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test that CSV export returns ETag."""
        response = fresh_client.get("/osint/export/csv?query=exporttest.com")
        assert response.status_code == 200
        assert "ETag" in response.headers

    def test_export_csv_304(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test 304 for CSV export."""
        response1 = fresh_client.get("/osint/export/csv?query=exporttest.com")
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/osint/export/csv?query=exporttest.com",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304

    def test_export_xml_returns_etag(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test that XML export returns ETag."""
        response = fresh_client.get("/osint/export/xml?query=exporttest.com")
        assert response.status_code == 200
        assert "ETag" in response.headers

    def test_export_xml_304(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test 304 for XML export."""
        response1 = fresh_client.get("/osint/export/xml?query=exporttest.com")
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/osint/export/xml?query=exporttest.com",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304

    def test_export_markdown_returns_etag(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test that Markdown export returns ETag."""
        response = fresh_client.get("/osint/export/markdown?query=exporttest.com")
        assert response.status_code == 200
        assert "ETag" in response.headers

    def test_export_markdown_304(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test 304 for Markdown export."""
        response1 = fresh_client.get("/osint/export/markdown?query=exporttest.com")
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/osint/export/markdown?query=exporttest.com",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304

    def test_export_cache_control_1_hour(self, fresh_client: TestClient, db_session: Session, sample_report_for_export):
        """Test that exports have 1-hour cache."""
        response = fresh_client.get("/osint/export/json?query=exporttest.com")
        assert "max-age=3600" in response.headers["Cache-Control"]


class TestXlsxExportCaching:
    """Tests for /osint/export/xlsx caching (separate due to openpyxl dependency)."""

    @pytest.fixture
    def sample_report_xlsx(self, db_session: Session):
        """Create a sample report for XLSX export testing."""
        report = EntityReport(
            target="xlsxtest.com",
            target_type="DOMAIN",
            final_report="# XLSX Test Report\n\nTest content for XLSX export.",
            raw_data=json.dumps({
                "scanned_at": "2026-01-21 14:00:00",
                "risk_analysis": {"score": 50, "level": "MEDIUM", "indicators": {"positive": [], "negative": ["No HSTS"]}},
                "tools": {"whois": {"status": "ok", "duration": 1.0, "data": {"registrar": "XLSX Test"}}}
            })
        )
        db_session.add(report)
        db_session.commit()
        db_session.refresh(report)
        return report

    def test_export_xlsx_returns_etag(self, fresh_client: TestClient, db_session: Session, sample_report_xlsx):
        """Test that XLSX export returns ETag."""
        try:
            import openpyxl
        except ImportError:
            pytest.skip("openpyxl not installed")
        
        response = fresh_client.get("/osint/export/xlsx?query=xlsxtest.com")
        assert response.status_code == 200
        assert "ETag" in response.headers

    def test_export_xlsx_304(self, fresh_client: TestClient, db_session: Session, sample_report_xlsx):
        """Test 304 for XLSX export."""
        try:
            import openpyxl
        except ImportError:
            pytest.skip("openpyxl not installed")
        
        response1 = fresh_client.get("/osint/export/xlsx?query=xlsxtest.com")
        if response1.status_code == 501:
            pytest.skip("openpyxl not available")
        
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/osint/export/xlsx?query=xlsxtest.com",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304


class TestCacheInvalidation:
    """Tests for cache invalidation scenarios."""

    def test_etag_changes_when_data_changes(self, fresh_client: TestClient, db_session: Session):
        """Test that ETag changes when underlying data changes."""
        # Create initial report
        report = EntityReport(
            target="cachetest.com",
            target_type="DOMAIN",
            final_report="Initial report content",
            raw_data=json.dumps({"tools": {}})
        )
        db_session.add(report)
        db_session.commit()
        
        # Get initial ETag
        response1 = fresh_client.get("/osint/report/?target=cachetest.com")
        etag1 = response1.headers["ETag"]
        
        # Update the report
        report.final_report = "Updated report content"
        db_session.commit()
        
        # Get new ETag (should be different)
        response2 = fresh_client.get("/osint/report/?target=cachetest.com")
        etag2 = response2.headers["ETag"]
        
        assert etag1 != etag2

    def test_old_etag_returns_200_after_update(self, fresh_client: TestClient, db_session: Session):
        """Test that old ETag returns 200 (fresh data) after update."""
        # Create initial report
        report = EntityReport(
            target="cachetest2.com",
            target_type="DOMAIN",
            final_report="Version 1",
            raw_data=json.dumps({"tools": {}})
        )
        db_session.add(report)
        db_session.commit()
        
        # Get initial ETag
        response1 = fresh_client.get("/osint/report/?target=cachetest2.com")
        old_etag = response1.headers["ETag"]
        
        # Update the report
        report.final_report = "Version 2"
        db_session.commit()
        
        # Try to use old ETag - should get 200, not 304
        response2 = fresh_client.get(
            "/osint/report/?target=cachetest2.com",
            headers={"If-None-Match": old_etag}
        )
        assert response2.status_code == 200


class TestCacheHeadersFormat:
    """Tests for correct cache header formatting."""

    @pytest.fixture
    def sample_report_headers(self, db_session: Session):
        """Create a sample report for header testing."""
        report = EntityReport(
            target="headertest.com",
            target_type="DOMAIN",
            final_report="Header test report",
            raw_data=json.dumps({"tools": {}})
        )
        db_session.add(report)
        db_session.commit()
        return report

    def test_etag_is_quoted(self, fresh_client: TestClient, db_session: Session, sample_report_headers):
        """Test that ETag values are properly quoted."""
        response = fresh_client.get("/osint/report/?target=headertest.com")
        etag = response.headers["ETag"]
        assert etag.startswith('"')
        assert etag.endswith('"')

    def test_last_modified_format(self, fresh_client: TestClient, db_session: Session, sample_report_headers):
        """Test that Last-Modified is in RFC 7231 format."""
        response = fresh_client.get("/osint/report/?target=headertest.com")
        last_modified = response.headers.get("Last-Modified")
        
        if last_modified:
            # Should contain day name, date, and GMT
            assert "GMT" in last_modified
            # Should be parseable
            from email.utils import parsedate_to_datetime
            parsed = parsedate_to_datetime(last_modified)
            assert parsed is not None

    def test_cache_control_public(self, fresh_client: TestClient, db_session: Session, sample_report_headers):
        """Test that Cache-Control includes 'public' for cacheable responses."""
        response = fresh_client.get("/osint/report/?target=headertest.com")
        cache_control = response.headers["Cache-Control"]
        assert "public" in cache_control

    def test_304_response_has_no_body(self, fresh_client: TestClient, db_session: Session, sample_report_headers):
        """Test that 304 responses have no body."""
        response1 = fresh_client.get("/osint/report/?target=headertest.com")
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/osint/report/?target=headertest.com",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304
        assert len(response2.content) == 0

    def test_304_preserves_cache_headers(self, fresh_client: TestClient, db_session: Session, sample_report_headers):
        """Test that 304 response includes cache headers."""
        response1 = fresh_client.get("/osint/report/?target=headertest.com")
        etag = response1.headers["ETag"]
        
        response2 = fresh_client.get(
            "/osint/report/?target=headertest.com",
            headers={"If-None-Match": etag}
        )
        assert response2.status_code == 304
        assert "ETag" in response2.headers
        assert "Cache-Control" in response2.headers
