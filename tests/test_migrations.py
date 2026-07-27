"""Régressions du démarrage sur une base locale créée avant Alembic."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def test_upgrade_accepts_precreated_development_schema(tmp_path: Path):
    database_path = tmp_path / "legacy-ananta.db"
    environment = {
        **os.environ,
        "DATABASE_URL": f"sqlite:///{database_path}",
    }

    subprocess.run(
        [
            sys.executable,
            "-c",
            "from database import Base, engine; Base.metadata.create_all(engine)",
        ],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )
    # Simule la variante réellement rencontrée chez les premiers utilisateurs :
    # la table de revue existait avant l'ajout de la traçabilité updated_by.
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "ALTER TABLE entity_resolution_reviews DROP COLUMN updated_by"
        )

    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )

    with sqlite3.connect(database_path) as connection:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(api_keys)")
        }
        review_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(entity_resolution_reviews)"
            )
        }

    assert revision == ("c0d1e2f3a445",)
    assert {"role", "scopes", "owner_id"} <= columns
    assert "updated_by" in review_columns
