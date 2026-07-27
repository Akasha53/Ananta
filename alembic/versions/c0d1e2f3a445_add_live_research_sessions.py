"""Add one-active-run lock, linked passes and live instructions.

Revision ID: c0d1e2f3a445
Revises: b9c0d1e2f334
Create Date: 2026-07-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c0d1e2f3a445"
down_revision: Union[str, None] = "b9c0d1e2f334"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("entity_research_runs")}

    if "active_owner" not in columns:
        op.add_column("entity_research_runs", sa.Column("active_owner", sa.String(), nullable=True))
    if "parent_run_id" not in columns:
        op.add_column("entity_research_runs", sa.Column("parent_run_id", sa.String(), nullable=True))
    if "pass_number" not in columns:
        op.add_column(
            "entity_research_runs",
            sa.Column("pass_number", sa.Integer(), nullable=False, server_default="1"),
        )

    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("entity_research_runs")}
    if "ix_entity_research_runs_active_owner" not in indexes:
        op.create_index(
            "ix_entity_research_runs_active_owner",
            "entity_research_runs",
            ["active_owner"],
            unique=True,
        )
    if "ix_entity_research_runs_parent_run_id" not in indexes:
        op.create_index(
            "ix_entity_research_runs_parent_run_id",
            "entity_research_runs",
            ["parent_run_id"],
            unique=False,
        )

    if not inspector.has_table("entity_research_instructions"):
        op.create_table(
            "entity_research_instructions",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("run_id", sa.String(), nullable=False),
            sa.Column("text", sa.Text(), nullable=False),
            sa.Column("origin", sa.String(), nullable=False, server_default="analyst"),
            sa.Column("status", sa.String(), nullable=False, server_default="PENDING"),
            sa.Column("created_by", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(
                ["run_id"], ["entity_research_runs.run_id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_entity_research_instructions_id",
            "entity_research_instructions",
            ["id"],
            unique=False,
        )
        op.create_index(
            "ix_entity_instructions_run_status",
            "entity_research_instructions",
            ["run_id", "status"],
            unique=False,
        )
        op.create_index(
            "ix_entity_instructions_created_at",
            "entity_research_instructions",
            ["created_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("entity_research_instructions"):
        op.drop_table("entity_research_instructions")

    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("entity_research_runs")}
    if "ix_entity_research_runs_parent_run_id" in indexes:
        op.drop_index("ix_entity_research_runs_parent_run_id", table_name="entity_research_runs")
    if "ix_entity_research_runs_active_owner" in indexes:
        op.drop_index("ix_entity_research_runs_active_owner", table_name="entity_research_runs")

    columns = {column["name"] for column in sa.inspect(bind).get_columns("entity_research_runs")}
    for column in ("pass_number", "parent_run_id", "active_owner"):
        if column in columns:
            op.drop_column("entity_research_runs", column)
