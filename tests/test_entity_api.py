"""
Tests des endpoints /entity/* .

Ces tests montent l'application FastAPI complète. Le moteur de recherche est
remplacé par un double : on vérifie ici le câblage HTTP (validation, codes de
statut, persistance, exports), pas la collecte elle-même — celle-ci est
couverte par `test_entity_engine.py`.
"""

from __future__ import annotations

import pytest

from entity_research.identifiers import EntityKind, SelectorType, make_selector
from entity_research.schema import Dossier, EntityNode, make_attribute, make_relationship


def build_fake_dossier(run_id: str = "test_run_1") -> Dossier:
    """Un dossier minimal mais réaliste, sans aucun appel réseau."""
    root = EntityNode(
        kind=EntityKind.ORGANIZATION,
        label="ACME INDUSTRIES",
        selectors=[make_selector(SelectorType.SIREN, "552100554")],
        confidence=0.95,
        is_root=True,
    )
    root.attributes = [
        make_attribute("legal_name", "ACME INDUSTRIES", "sirene", category="identity", confidence=0.97),
        make_attribute("siren", "552100554", "sirene", category="legal", confidence=0.99),
        make_attribute("status", "Active", "sirene", category="legal", confidence=0.97),
    ]

    officer = EntityNode(kind=EntityKind.PERSON, label="Jean Dupont", confidence=0.85)
    officer.attributes = [
        make_attribute("full_name", "Jean Dupont", "sirene", category="identity", confidence=0.9)
    ]

    dossier = Dossier(
        run_id=run_id,
        query="552 100 554",
        kind=EntityKind.ORGANIZATION,
        label="ACME INDUSTRIES",
        root_key=root.key,
        entities=[root, officer],
        relationships=[
            make_relationship(officer.key, root.key, "officer_of", "sirene", role="Président")
        ],
        report_markdown="# Dossier d'entité — ACME INDUSTRIES\n\nRapport de test.",
    )
    dossier.compliance = {"policy": {"mode": "standard"}, "statements": ["Sources publiques."]}
    dossier.risk_flags = [
        {
            "code": "no_dmarc",
            "severity": "medium",
            "title": "Absence de politique DMARC",
            "detail": "Le domaine ne publie pas de DMARC.",
            "sources": ["dns_intel"],
            "recommendation": "Publier un enregistrement DMARC.",
        }
    ]
    dossier.timeline = [
        {"date": "2011-04-12", "label": "Immatriculation", "detail": "2011-04-12", "source": "sirene", "url": None, "confidence": 0.97}
    ]
    dossier.stats = {"sources_ok": 2, "source_calls": 3}
    dossier.finished_at = "2026-07-26T10:00:00+00:00"
    return dossier


@pytest.fixture
def patched_engine(monkeypatch):
    """Remplace `research_entity` par un double déterministe."""
    import entity_research

    def fake_research_entity(query, **kwargs):
        dossier = build_fake_dossier()
        dossier.query = query
        dossier.stats["mode"] = kwargs.get("mode", "standard")
        return dossier

    monkeypatch.setattr(entity_research, "research_entity", fake_research_entity)
    return fake_research_entity


class TestEntityPreview:
    def test_preview_returns_selectors(self, client):
        response = client.post(
            "/entity/preview", json={"query": "Jean Dupont contact@acme.fr"}
        )
        assert response.status_code == 200

        payload = response.json()
        types = {s["type"] for s in payload["selectors"]}
        assert "email" in types
        assert payload["entity_kind"] in {"person", "organization"}
        assert payload["personal_data_involved"] is True

    def test_preview_rejects_injection(self, client):
        response = client.post("/entity/preview", json={"query": "acme.fr; rm -rf /"})
        assert response.status_code == 422

    def test_preview_rejects_empty(self, client):
        assert client.post("/entity/preview", json={"query": ""}).status_code == 422


class TestEntitySources:
    def test_sources_catalogue(self, client):
        response = client.get("/entity/sources")
        assert response.status_code == 200

        payload = response.json()
        assert payload["total"] >= 20
        assert payload["by_layer"]["1"] > 0

        by_id = {s["id"]: s for s in payload["sources"]}
        assert by_id["sirene"]["requires_api_key"] is False
        assert by_id["hibp"]["requires_api_key"] is True
        assert "siren" in by_id["sirene"]["accepts"]

    def test_sources_are_cacheable(self, client):
        first = client.get("/entity/sources")
        etag = first.headers.get("ETag")
        assert etag

        second = client.get("/entity/sources", headers={"If-None-Match": etag})
        assert second.status_code == 304


class TestEntityResearch:
    def test_research_returns_and_persists_dossier(self, client, patched_engine):
        response = client.post(
            "/entity/research", json={"query": "552 100 554", "mode": "passive", "use_llm": False}
        )
        assert response.status_code == 200

        payload = response.json()
        assert payload["type"] == "dossier"
        assert payload["label"] == "ACME INDUSTRIES"
        assert len(payload["entities"]) == 2
        assert payload["graph"]["nodes"]

        # Le dossier doit être consultable ensuite
        detail = client.get(f"/entity/run/{payload['run_id']}")
        assert detail.status_code == 200
        assert detail.json()["label"] == "ACME INDUSTRIES"

    def test_invalid_mode_rejected(self, client):
        response = client.post("/entity/research", json={"query": "acme.fr", "mode": "ultra"})
        assert response.status_code == 422

    def test_invalid_source_id_rejected(self, client):
        response = client.post(
            "/entity/research", json={"query": "acme.fr", "only_sources": ["../etc/passwd"]}
        )
        assert response.status_code == 422

    def test_briefing_is_forwarded_to_engine(self, client, monkeypatch):
        import entity_research

        captured = {}

        def fake_research_entity(query, **kwargs):
            captured.update(kwargs)
            return build_fake_dossier("briefing_api")

        monkeypatch.setattr(entity_research, "research_entity", fake_research_entity)

        response = client.post(
            "/entity/research",
            json={
                "query": "ACME",
                "briefing_text": "Email : contact@acme.fr",
                "briefing_origin": "external_ai",
                "briefing_facts": [
                    {
                        "label": "SIREN",
                        "value": "552100554",
                        "confidence": 0.6,
                    }
                ],
                "use_llm": False,
            },
        )

        assert response.status_code == 200
        assert captured["briefing_text"] == "Email : contact@acme.fr"
        assert captured["briefing_origin"] == "external_ai"
        assert captured["briefing_facts"][0]["value"] == "552100554"

    def test_unknown_run_returns_404(self, client):
        assert client.get("/entity/run/does-not-exist").status_code == 404


class TestEntityRunViews:
    @pytest.fixture
    def existing_run(self, client, patched_engine):
        response = client.post("/entity/research", json={"query": "552 100 554"})
        assert response.status_code == 200
        return response.json()["run_id"]

    def test_graph_endpoint(self, client, existing_run):
        response = client.get(f"/entity/run/{existing_run}/graph")
        assert response.status_code == 200

        graph = response.json()
        node_ids = {n["id"] for n in graph["nodes"]}
        assert graph["edges"]
        for edge in graph["edges"]:
            assert edge["source"] in node_ids
            assert edge["target"] in node_ids

    def test_report_endpoint(self, client, existing_run):
        response = client.get(f"/entity/run/{existing_run}/report")
        assert response.status_code == 200
        assert "ACME INDUSTRIES" in response.json()["report"]

    def test_export_json(self, client, existing_run):
        response = client.get(f"/entity/run/{existing_run}/export/json")
        assert response.status_code == 200
        assert "attachment" in response.headers["content-disposition"]
        assert response.json()["label"] == "ACME INDUSTRIES"

    def test_export_csv_has_one_row_per_fact(self, client, existing_run):
        response = client.get(f"/entity/run/{existing_run}/export/csv")
        assert response.status_code == 200

        lines = [line for line in response.text.splitlines() if line.strip()]
        assert lines[0].startswith("entity,kind,attribute,value")
        assert len(lines) >= 4  # en-tête + 3 faits
        assert any("552100554" in line for line in lines)

    def test_export_markdown(self, client, existing_run):
        response = client.get(f"/entity/run/{existing_run}/export/markdown")
        assert response.status_code == 200
        assert response.text.startswith("# Dossier")

    def test_unsupported_export_format(self, client, existing_run):
        assert client.get(f"/entity/run/{existing_run}/export/pdf").status_code == 400

    def test_runs_listing_and_filters(self, client, existing_run):
        response = client.get("/entity/runs?limit=10")
        assert response.status_code == 200

        payload = response.json()
        assert payload["total"] >= 1
        assert any(item["run_id"] == existing_run for item in payload["items"])

        filtered = client.get("/entity/runs?entity_kind=person")
        assert filtered.status_code == 200
        assert all(i["entity_kind"] == "person" for i in filtered.json()["items"])

        searched = client.get("/entity/runs?search=ACME")
        assert searched.json()["total"] >= 1

    def test_related_runs_lookup(self, client, existing_run):
        detail = client.get(f"/entity/run/{existing_run}").json()
        officer = next(e for e in detail["dossier"]["entities"] if e["kind"] == "person")

        response = client.get(f"/entity/entity/{officer['key']}/runs")
        assert response.status_code == 200
        assert any(r["run_id"] == existing_run for r in response.json()["runs"])

    def test_delete_removes_dossier(self, client, existing_run):
        assert client.delete(f"/entity/run/{existing_run}").status_code == 200
        assert client.get(f"/entity/run/{existing_run}").status_code == 404
        assert client.delete(f"/entity/run/{existing_run}").status_code == 404
