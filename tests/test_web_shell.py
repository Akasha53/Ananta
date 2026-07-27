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
    assert "ananta-v1.5.4" in source
    assert "/web/javascript/entity.js?v=1.5.4" in source
    assert "/web/javascript/entity-graph.js?v=1.5.4" in source


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
    assert 'id="opt-async"' in html
    assert 'id="opt-async" class="mt-1 accent-cyan-500" checked' in html
    assert "function syncBackgroundExecution()" in javascript
    assert 'api("/entity/research_async"' in javascript
    assert "function resumeActiveRun()" in javascript
    assert "function addLiveInstruction()" in javascript
    assert 'id="active-run-panel"' in html
    assert "une seule à la fois" in html
    assert "Standard · 2 niveaux" in html
    assert "Approfondi · 2 niveaux" in html
    assert '$("select-mode").addEventListener("change", syncBackgroundExecution)' in javascript
    assert "state.pollFailures >= 3" in javascript
    assert "Connexion momentanément indisponible" in javascript
    assert 'id="run-summary"' in html
    assert "function renderRunSummary(run)" in javascript
    assert 'id="btn-run-panel-toggle"' in html
    assert "function toggleRunPanel()" in javascript
    assert "Appels" in html
    assert "Sans donnée" in html
    assert "préparation automatique de la passe 2" in javascript
    assert "run.next_run" in javascript
    assert "À vérifier" in javascript


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


def test_entity_file_opening_redirects_to_the_running_http_app():
    html = Path("web/html/entity.html").read_text(encoding="utf-8")

    assert 'window.location.protocol === "file:"' in html
    assert "http://127.0.0.1:8010/web/html/entity.html" in html
    assert "window.location.replace" in html


def test_unified_launcher_is_present():
    launcher = Path("ananta")
    source = launcher.read_text(encoding="utf-8")

    assert launcher.exists()
    assert "native_start()" in source
    assert "docker_start()" in source
    assert "start_native_redis()" in source
    assert "LLM_PROVIDER" in source
    assert "  mcp)" in source
    assert "tools/ananta_mcp.py" in source
