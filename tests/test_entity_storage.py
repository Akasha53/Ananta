"""Tests de persistance et d'agrégation temporelle des entités."""

from __future__ import annotations

from datetime import datetime

from database import ResearchEntity
from entity_research.storage import entity_observation_history, persist_dossier
from tests.test_entity_api import build_fake_dossier


def test_observation_history_preserves_global_bounds_when_truncated(db_session):
    first = build_fake_dossier("history_first")
    second = build_fake_dossier("history_second")
    persist_dossier(db_session, first, created_by="analyst")
    persist_dossier(db_session, second, created_by="analyst")

    officer_key = first.entities[1].key
    db_session.query(ResearchEntity).filter_by(run_id=first.run_id).update(
        {"created_at": datetime(2024, 1, 1, 10, 0, 0)}
    )
    db_session.query(ResearchEntity).filter_by(run_id=second.run_id).update(
        {"created_at": datetime(2025, 2, 2, 11, 0, 0)}
    )
    db_session.commit()

    truncated = entity_observation_history(
        db_session,
        officer_key,
        limit=1,
        created_by="analyst",
    )
    assert truncated["sightings"] == 2
    assert truncated["truncated"] is True
    assert len(truncated["runs"]) == 1
    assert truncated["first_seen"].startswith("2024-01-01")
    assert truncated["last_seen"].startswith("2025-02-02")

    complete = entity_observation_history(
        db_session,
        officer_key,
        limit=10,
        created_by="analyst",
    )
    relation = complete["relationships"][0]
    assert relation["rel_type"] == "officer_of"
    assert relation["observations"] == 2
    assert relation["first_seen"].startswith("2024-01-01")
    assert relation["last_seen"].startswith("2025-02-02")


def test_observation_history_is_scoped_to_owner(db_session):
    dossier = build_fake_dossier("history_private")
    persist_dossier(db_session, dossier, created_by="alice")
    officer_key = dossier.entities[1].key

    assert entity_observation_history(
        db_session,
        officer_key,
        created_by="bob",
    )["sightings"] == 0
    assert entity_observation_history(
        db_session,
        officer_key,
        created_by="alice",
    )["sightings"] == 1
