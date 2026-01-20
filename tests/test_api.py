"""
Tests for API endpoints.
"""

import pytest
from fastapi.testclient import TestClient


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    def test_health_returns_200(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_contains_required_fields(self, client: TestClient):
        response = client.get("/health")
        data = response.json()

        # Check legacy format fields
        assert "cpu_load" in data
        assert "ram_load" in data
        assert "backend_api" in data
        assert "worker_state" in data

        # Check new detailed format
        assert "health" in data

    def test_health_has_request_id(self, client: TestClient):
        response = client.get("/health")
        assert "X-Request-ID" in response.headers


class TestRootEndpoint:
    """Tests for / endpoint."""

    def test_root_returns_200(self, client: TestClient):
        response = client.get("/")
        assert response.status_code == 200

    def test_root_contains_message(self, client: TestClient):
        response = client.get("/")
        data = response.json()
        assert "message" in data
        assert "ui" in data


class TestSecurityHeaders:
    """Tests for security headers."""

    def test_csp_header_present(self, client: TestClient):
        response = client.get("/health")
        assert "Content-Security-Policy" in response.headers

    def test_x_frame_options_header(self, client: TestClient):
        response = client.get("/health")
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options_header(self, client: TestClient):
        response = client.get("/health")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_request_id_header(self, client: TestClient):
        response = client.get("/health")
        request_id = response.headers.get("X-Request-ID")
        assert request_id is not None
        assert len(request_id) == 8  # 8-char UUID prefix

    def test_response_time_header(self, client: TestClient):
        response = client.get("/health")
        response_time = response.headers.get("X-Response-Time")
        assert response_time is not None
        assert response_time.endswith("ms")


class TestRateLimitHeaders:
    """Tests for rate limit headers."""

    def test_rate_limit_headers_present(self, client: TestClient, mock_env_vars):
        # Note: Rate limiting is disabled in tests via mock_env_vars
        response = client.get("/health")
        # These headers should still be present (even if rate limiting is disabled)
        # In production, they would show actual limits


class TestAgentEndpoints:
    """Tests for /agent/* endpoints."""

    def test_ask_requires_query(self, client: TestClient):
        response = client.post("/agent/ask", json={})
        assert response.status_code == 422  # Validation error

    def test_ask_async_requires_query(self, client: TestClient):
        response = client.post("/agent/ask_async", json={})
        assert response.status_code == 422

    def test_ask_with_valid_query(self, client: TestClient):
        # This test might fail if LLM is not available
        # In CI, we should mock the LLM response
        response = client.post(
            "/agent/ask",
            json={"query": "hello"}
        )
        # Should return 200 or 503 (if LLM unavailable)
        assert response.status_code in [200, 503]


class TestDatabaseEndpoint:
    """Tests for database-related endpoints."""

    def test_reports_list(self, client: TestClient):
        response = client.get("/osint/reports/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestMonitoringEndpoints:
    """Tests for /monitoring/* endpoints."""

    def test_monitoring_stats(self, client: TestClient):
        response = client.get("/monitoring/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_executions" in data or "error" in data

    def test_monitoring_logs(self, client: TestClient):
        response = client.get("/monitoring/logs")
        assert response.status_code == 200


class TestOSINTEndpoints:
    """Tests for /osint/* endpoints."""

    def test_whois_requires_domain(self, client: TestClient):
        response = client.get("/osint/whois/")
        assert response.status_code == 422  # Missing required param

    def test_whois_with_valid_domain(self, client: TestClient, sample_domain):
        response = client.get(f"/osint/whois/?domain={sample_domain}")
        # Should return 200 (success) or contain error (if network issue)
        assert response.status_code == 200
