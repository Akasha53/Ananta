"""Contrats minimaux de l'interface partagée et de la confidentialité PWA."""

from pathlib import Path


ONLINE_PAGES = {
    "index.html",
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
