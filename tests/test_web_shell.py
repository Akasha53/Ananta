"""Contrats minimaux de l'interface partagée et de la confidentialité PWA."""

from pathlib import Path


ONLINE_PAGES = {
    "database.html",
    "entity.html",
    "monitoring.html",
    "scheduled.html",
    "timeline.html",
    "comparison.html",
    "workers.html",
}


def test_online_pages_load_shared_access_shell():
    html_dir = Path("web/html")
    for name in ONLINE_PAGES:
        source = (html_dir / name).read_text(encoding="utf-8")
        assert "../css/app-shell.css" in source, name
        assert "../javascript/api-client.js" in source, name
        assert "../javascript/app-shell.js" in source, name


def test_service_worker_private_prefixes_cover_sensitive_features():
    source = Path("web/javascript/service-worker.js").read_text(encoding="utf-8")
    for prefix in ("/entity/", "/api-keys/", "/monitoring/", "/workers/", "/jobs/"):
        assert repr(prefix) in source


def test_entity_ui_keeps_run_permalink_and_exposes_system_prompt():
    javascript = Path("web/javascript/entity.js").read_text(encoding="utf-8")
    html = Path("web/html/entity.html").read_text(encoding="utf-8")

    assert "function syncRunUrl(runId)" in javascript
    assert "window.history.replaceState" in javascript
    assert 'api("/llm/system-prompt"' in javascript
    assert 'id="input-llm-system-prompt"' in html
    assert 'id="btn-llm-prompt-save"' in html
    assert 'value="authorized_investigation"' in html
    assert 'id="opt-authorized-investigation"' in html
    assert 'body.purpose === "authorized_investigation"' in javascript
    assert 'id="select-match-policy"' in html
    assert 'data-tab="resolution"' in html
    assert 'match_policy: $("select-match-policy").value' in javascript
    assert "function renderResolutionTab(dossier)" in javascript
    assert "function saveResolutionReview(button)" in javascript
    assert "/observations" in javascript
    assert "Corrélations automatiques" in javascript
    assert "Faux positif" in javascript


def test_entity_is_the_only_primary_workspace():
    shell = Path("web/javascript/app-shell.js").read_text(encoding="utf-8")
    legacy = Path("web/html/index.html").read_text(encoding="utf-8")
    service_worker = Path("web/javascript/service-worker.js").read_text(
        encoding="utf-8"
    )

    assert "/web/html/index.html" not in shell
    assert "<strong>Console</strong>" not in shell
    assert 'content="0; url=entity.html"' in legacy
    assert "/web/javascript/app.js" not in service_worker
    assert "'/web/html/index.html'" not in service_worker


def test_unified_launcher_is_present():
    launcher = Path("ananta")
    source = launcher.read_text(encoding="utf-8")

    assert launcher.exists()
    assert "native_start()" in source
    assert "docker_start()" in source
    assert "start_native_redis()" in source
    assert "LLM_PROVIDER" in source
