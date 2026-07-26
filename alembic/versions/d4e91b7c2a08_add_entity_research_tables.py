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
    op.create_index("ix_entity_research_runs_id", "entity_research_runs", ["id"])
    op.create_index("ix_entity_research_runs_run_id", "entity_research_runs", ["run_id"], unique=True)
    op.create_index("ix_entity_research_runs_job_id", "entity_research_runs", ["job_id"])
    op.create_index("ix_entity_runs_status", "entity_research_runs", ["status"])
    op.create_index("ix_entity_runs_kind", "entity_research_runs", ["entity_kind"])
    op.create_index("ix_entity_runs_created_at", "entity_research_runs", ["created_at"])
    op.create_index("ix_entity_runs_label", "entity_research_runs", ["label"])
    op.create_index("ix_entity_runs_kind_created", "entity_research_runs", ["entity_kind", "created_at"])

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
    op.create_index("ix_research_entities_id", "research_entities", ["id"])
    op.create_index("ix_research_entities_run", "research_entities", ["run_id"])
    op.create_index("ix_research_entities_key", "research_entities", ["entity_key"])
    op.create_index("ix_research_entities_kind", "research_entities", ["entity_kind"])
    op.create_index("ix_research_entities_label", "research_entities", ["label"])
    op.create_index("ix_research_entities_siren", "research_entities", ["siren"])
    op.create_index("ix_research_entities_lei", "research_entities", ["lei"])
    op.create_index("ix_research_entities_vat_number", "research_entities", ["vat_number"])
    op.create_index("ix_research_entities_domain", "research_entities", ["domain"])
    op.create_index("ix_research_entities_email", "research_entities", ["email"])


def downgrade() -> None:
    op.drop_table("research_entities")
    op.drop_table("entity_research_runs")
