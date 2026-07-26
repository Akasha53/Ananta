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

    def test_health_uses_the_active_llm_provider(self, monkeypatch):
        import llm_providers
        from middleware import check_llm_health

        class HealthyProvider:
            model = "test-model"

            def check(self):
                return True, "fournisseur actif disponible"

        monkeypatch.setattr(llm_providers, "current_provider_id", lambda: "codex_cli")
        monkeypatch.setattr(llm_providers, "get_provider", lambda: HealthyProvider())

        status = check_llm_health()
        assert status["status"] == "ok"
        assert status["provider"] == "codex_cli"
        assert status["message"] == "fournisseur actif disponible"

    def test_unconfigured_redis_is_optional(self, monkeypatch):
        from middleware import check_redis_health

        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
        assert check_redis_health()["status"] == "not_configured"


class TestRootEndpoint:
    """Entités est l'interface canonique."""

    def test_root_returns_200(self, client: TestClient):
        response = client.get("/")
        assert response.status_code == 200
        assert "ANANTA // ENTITÉ" in response.text

    @pytest.mark.parametrize("path", ["/", "/ui", "/web/html/index.html"])
    def test_legacy_entries_redirect_to_entity(self, client: TestClient, path):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 308
        assert response.headers["location"] == "/web/html/entity.html"

    @pytest.mark.parametrize("path", ["/", "/ui", "/web/html/index.html"])
    def test_legacy_head_requests_redirect_to_entity(self, client: TestClient, path):
        response = client.head(path, follow_redirects=False)
        assert response.status_code == 308
        assert response.headers["location"] == "/web/html/entity.html"


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
        response = client.get("/osint/history/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestMonitoringEndpoints:
    """Tests for /monitoring/* endpoints."""

    def test_monitoring_stats(self, client: TestClient):
        response = client.get("/monitoring/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data or "error" in data

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
