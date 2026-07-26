"""add entity research tables

Revision ID: d4e91b7c2a08
Revises: 7b8c2c1d9a90
Create Date: 2026-07-26 00:00:00.000000

Tables du moteur de recherche d'entité (`entity_research`) :
- `entity_research_runs`  : un dossier par requête (statut, rapport, dossier JSON)
- `research_entities`     : entités normalisées, pour le recoupement inter-dossiers
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e91b7c2a08"
down_revision: Union[str, None] = "7b8c2c1d9a90"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    existing_tables = set(sa.inspect(bind).get_table_names())

    if "entity_research_runs" not in existing_tables:
        op.create_table(
        "entity_research_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=True),
        sa.Column("query", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("entity_kind", sa.String(), nullable=True),
        sa.Column("root_key", sa.String(), nullable=True),
        sa.Column("mode", sa.String(), nullable=True),
        sa.Column("purpose", sa.String(), nullable=True),
        sa.Column("language", sa.String(), nullable=True),
        sa.Column("report_template", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("entities_count", sa.Integer(), nullable=True),
        sa.Column("relationships_count", sa.Integer(), nullable=True),
        sa.Column("sources_ok", sa.Integer(), nullable=True),
        sa.Column("partial", sa.Boolean(), nullable=True),
        sa.Column("dossier", sa.Text(), nullable=True),
        sa.Column("report_markdown", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        )

    run_indexes = {
        index["name"]
        for index in sa.inspect(bind).get_indexes("entity_research_runs")
    }
    for name, columns, unique in (
        ("ix_entity_research_runs_id", ["id"], False),
        ("ix_entity_research_runs_run_id", ["run_id"], True),
        ("ix_entity_research_runs_job_id", ["job_id"], False),
        ("ix_entity_runs_status", ["status"], False),
        ("ix_entity_runs_kind", ["entity_kind"], False),
        ("ix_entity_runs_created_at", ["created_at"], False),
        ("ix_entity_runs_label", ["label"], False),
        ("ix_entity_runs_kind_created", ["entity_kind", "created_at"], False),
    ):
        if name not in run_indexes:
            op.create_index(name, "entity_research_runs", columns, unique=unique)

    if "research_entities" not in existing_tables:
        op.create_table(
        "research_entities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("entity_key", sa.String(), nullable=False),
        sa.Column("entity_kind", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("is_root", sa.Boolean(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("siren", sa.String(), nullable=True),
        sa.Column("lei", sa.String(), nullable=True),
        sa.Column("vat_number", sa.String(), nullable=True),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("email", sa.String(), nullable=True),
        sa.Column("country", sa.String(), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=True),
        sa.Column("relations", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        )

    entity_indexes = {
        index["name"]
        for index in sa.inspect(bind).get_indexes("research_entities")
    }
    for name, columns in (
        ("ix_research_entities_id", ["id"]),
        ("ix_research_entities_run", ["run_id"]),
        ("ix_research_entities_key", ["entity_key"]),
        ("ix_research_entities_kind", ["entity_kind"]),
        ("ix_research_entities_label", ["label"]),
        ("ix_research_entities_siren", ["siren"]),
        ("ix_research_entities_lei", ["lei"]),
        ("ix_research_entities_vat_number", ["vat_number"]),
        ("ix_research_entities_domain", ["domain"]),
        ("ix_research_entities_email", ["email"]),
    ):
        if name not in entity_indexes:
            op.create_index(name, "research_entities", columns)


def downgrade() -> None:
    op.drop_table("research_entities")
    op.drop_table("entity_research_runs")
