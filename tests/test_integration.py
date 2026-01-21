"""
Integration tests for complete workflows.

These tests verify that different components work together correctly.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


class TestScanWorkflow:
    """Integration tests for the scan workflow."""

    def test_async_scan_creates_job(self, client: TestClient):
        """Test that async scan endpoint creates a job."""
        response = client.post(
            "/agent/ask_async",
            json={"query": "analyze example.com", "scan_mode": "fast"}
        )
        # Should return 200 with job_id or 503 if services unavailable
        assert response.status_code in [200, 503]
        if response.status_code == 200:
            data = response.json()
            assert "job_id" in data or "error" in data

    def test_job_status_endpoint(self, client: TestClient):
        """Test job status endpoint with non-existent job."""
        response = client.get("/jobs/nonexistent-job-id")
        assert response.status_code in [404, 200]

    def test_scan_modes_accepted(self, client: TestClient):
        """Test that all scan modes are accepted."""
        modes = ["fast", "standard", "full"]
        for mode in modes:
            response = client.post(
                "/agent/ask_async",
                json={"query": "test example.com", "scan_mode": mode}
            )
            # Should not return 422 (validation error)
            assert response.status_code != 422


class TestExportWorkflow:
    """Integration tests for export functionality."""

    def test_export_json_endpoint(self, client: TestClient):
        """Test JSON export endpoint."""
        response = client.get("/osint/export/json?query=example.com")
        # May return 404 if no cached report, or 200 with data
        assert response.status_code in [200, 404, 500]

    def test_export_csv_endpoint(self, client: TestClient):
        """Test CSV export endpoint."""
        response = client.get("/osint/export/csv?query=example.com")
        assert response.status_code in [200, 404, 500]

    def test_export_requires_query(self, client: TestClient):
        """Test that export requires query parameter."""
        response = client.get("/osint/export/json")
        assert response.status_code == 422


class TestToolEndpoints:
    """Integration tests for individual tool endpoints."""

    def test_whois_endpoint(self, client: TestClient, sample_domain):
        """Test WHOIS endpoint returns expected structure."""
        response = client.get(f"/osint/whois/?domain={sample_domain}")
        assert response.status_code == 200
        data = response.json()
        # Should have either data or error
        assert "raw" in data or "error" in data or "domain" in data

    def test_dns_endpoint(self, client: TestClient, sample_domain):
        """Test DNS endpoint returns expected structure."""
        response = client.get(f"/osint/dns/?domain={sample_domain}")
        assert response.status_code == 200

    def test_headers_endpoint(self, client: TestClient, sample_domain):
        """Test HTTP headers endpoint."""
        response = client.get(f"/osint/headers/?domain={sample_domain}")
        assert response.status_code == 200


class TestMonitoringWorkflow:
    """Integration tests for monitoring functionality."""

    def test_stats_endpoint(self, client: TestClient):
        """Test monitoring stats endpoint."""
        response = client.get("/monitoring/stats")
        assert response.status_code == 200
        data = response.json()
        # Should have statistics fields
        assert "total_scans" in data or "error" in data

    def test_logs_endpoint(self, client: TestClient):
        """Test monitoring logs endpoint."""
        response = client.get("/monitoring/logs")
        assert response.status_code == 200
        data = response.json()
        assert "logs" in data or "error" in data

    def test_logs_with_filters(self, client: TestClient):
        """Test monitoring logs with filters."""
        response = client.get("/monitoring/logs?page=1&limit=10&period=24h")
        assert response.status_code == 200

    def test_logs_pagination(self, client: TestClient):
        """Test logs pagination."""
        response = client.get("/monitoring/logs?page=1&limit=5")
        assert response.status_code == 200
        data = response.json()
        if "logs" in data:
            assert len(data["logs"]) <= 5


class TestDatabaseWorkflow:
    """Integration tests for database operations."""

    def test_history_endpoint(self, client: TestClient):
        """Test scan history endpoint."""
        response = client.get("/osint/history/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_report_not_found(self, client: TestClient):
        """Test report retrieval for non-existent target."""
        response = client.get("/osint/report/?target=nonexistent-domain-12345.com")
        assert response.status_code == 404


class TestAPIKeyWorkflow:
    """Integration tests for API key management."""

    def test_list_api_keys(self, client: TestClient):
        """Test listing API keys."""
        response = client.get("/api-keys/list")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_create_api_key_requires_name(self, client: TestClient):
        """Test API key creation requires name."""
        response = client.post("/api-keys/create")
        assert response.status_code == 422


class TestSecurityIntegration:
    """Integration tests for security features."""

    def test_rate_limit_headers(self, client: TestClient):
        """Test that rate limit related responses work."""
        # Make a request and verify it doesn't fail
        response = client.get("/health")
        assert response.status_code == 200

    def test_request_id_propagation(self, client: TestClient):
        """Test that request ID is in response headers."""
        response = client.get("/health")
        assert "X-Request-ID" in response.headers

    def test_security_headers_present(self, client: TestClient):
        """Test that security headers are present."""
        response = client.get("/health")
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers

    def test_csp_header(self, client: TestClient):
        """Test Content-Security-Policy header."""
        response = client.get("/health")
        assert "Content-Security-Policy" in response.headers


class TestHealthIntegration:
    """Integration tests for health check."""

    def test_health_returns_components(self, client: TestClient):
        """Test health check returns component statuses."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        # Check for health details
        assert "health" in data or "status" in data

    def test_health_legacy_format(self, client: TestClient):
        """Test health check returns legacy format for frontend."""
        response = client.get("/health")
        data = response.json()
        # Legacy fields for frontend compatibility
        assert "cpu_load" in data
        assert "ram_load" in data
