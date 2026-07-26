"""Production authentication, roles and privacy-cache guarantees."""

from pathlib import Path


def test_production_auth_bootstrap_and_roles(fresh_client, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("ANANTA_BOOTSTRAP_TOKEN", "bootstrap-test-secret")

    status = fresh_client.get("/auth/status")
    assert status.status_code == 200
    assert status.json()["required"] is True
    assert status.json()["initialized"] is False

    assert fresh_client.get("/entity/runs").status_code == 401
    assert fresh_client.post("/api-keys/create?name=Root").status_code == 401

    bootstrap = fresh_client.post(
        "/api-keys/create?name=Root",
        headers={"X-Bootstrap-Token": "bootstrap-test-secret"},
    )
    assert bootstrap.status_code == 200
    admin_key = bootstrap.json()["api_key"]
    admin_owner = bootstrap.json()["owner_id"]
    assert bootstrap.json()["role"] == "admin"
    assert bootstrap.headers["cache-control"] == "no-store, private"

    admin_headers = {"X-API-Key": admin_key}
    assert fresh_client.get("/api-keys/list", headers=admin_headers).status_code == 200

    viewer = fresh_client.post(
        "/api-keys/create?name=Audit&role=viewer",
        headers=admin_headers,
    )
    assert viewer.status_code == 200
    viewer_key = viewer.json()["api_key"]
    viewer_owner = viewer.json()["owner_id"]
    assert viewer_owner != admin_owner

    viewer_headers = {"X-API-Key": viewer_key}
    assert fresh_client.get("/entity/runs", headers=viewer_headers).status_code == 200
    assert fresh_client.post(
        "/entity/preview",
        json={"query": "example.com"},
        headers=viewer_headers,
    ).status_code == 403
    assert fresh_client.get("/api-keys/list", headers=viewer_headers).status_code == 403

    from database import EntityResearchRun
    from tests.conftest import TestingSessionLocal

    db = TestingSessionLocal()
    try:
        db.add_all(
            [
                EntityResearchRun(
                    run_id="admin-private-run",
                    query="admin",
                    created_by=admin_owner,
                    status="COMPLETED",
                ),
                EntityResearchRun(
                    run_id="viewer-private-run",
                    query="viewer",
                    created_by=viewer_owner,
                    status="COMPLETED",
                ),
            ]
        )
        db.commit()
    finally:
        db.close()

    viewer_runs = fresh_client.get("/entity/runs", headers=viewer_headers).json()["items"]
    assert [run["run_id"] for run in viewer_runs] == ["viewer-private-run"]
    admin_runs = fresh_client.get("/entity/runs", headers=admin_headers).json()["items"]
    assert {run["run_id"] for run in admin_runs} == {
        "admin-private-run",
        "viewer-private-run",
    }


def test_invalid_key_is_rejected_in_production(fresh_client, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    response = fresh_client.get(
        "/entity/runs",
        headers={"X-API-Key": "ananta_invalid"},
    )
    assert response.status_code == 401


def test_service_worker_never_caches_private_api_responses():
    source = Path("web/javascript/service-worker.js").read_text(encoding="utf-8")

    assert "'/entity/'" in source
    assert "'/monitoring/'" in source
    assert "event.respondWith(networkOnly(request))" in source
    assert "'Cache-Control': 'no-store'" in source
