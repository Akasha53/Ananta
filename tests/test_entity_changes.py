"""Tests du delta de dossiers, sans réseau ni base de données."""

from entity_research.changes import compare_dossiers


def _dossier(run_id, *, status="active", officer=True, risk=False):
    relationships = []
    entities = [
        {
            "key": "organization:acme",
            "kind": "organization",
            "label": "ACME",
            "confidence": 0.95,
            "attributes": [
                {
                    "name": "status",
                    "label": "Statut",
                    "value": status,
                    "confidence": 0.9,
                }
            ],
        }
    ]
    if officer:
        entities.append(
            {
                "key": "person:jean",
                "kind": "person",
                "label": "Jean",
                "confidence": 0.8,
                "attributes": [],
            }
        )
        relationships.append(
            {
                "source": "person:jean",
                "target": "organization:acme",
                "type": "officer_of",
                "role": "Président",
                "confidence": 0.8,
            }
        )
    return {
        "run_id": run_id,
        "root_key": "organization:acme",
        "entities": entities,
        "relationships": relationships,
        "risk_flags": (
            [
                {
                    "code": "sanction",
                    "title": "Sanction",
                    "severity": "high",
                    "detail": "Correspondance détectée",
                }
            ]
            if risk
            else []
        ),
    }


def test_compare_dossiers_reports_material_changes():
    changes = compare_dossiers(
        _dossier("new", status="closed", officer=False, risk=True),
        _dossier("old"),
    )

    assert changes["has_changes"] is True
    assert changes["change_score"] > 0
    assert changes["counts"]["attributes_changed"] == 1
    assert changes["counts"]["entities_removed"] == 1
    assert changes["counts"]["relationships_removed"] == 1
    assert changes["counts"]["risks_added"] == 1
    assert changes["attributes"]["changed"][0]["before"] == "active"
    assert changes["attributes"]["changed"][0]["after"] == "closed"


def test_compare_identical_dossiers_is_stable():
    dossier = _dossier("same")
    changes = compare_dossiers(dossier, dossier)

    assert changes["has_changes"] is False
    assert changes["change_score"] == 0
    assert sum(changes["counts"].values()) == 0
