"""Add persistent analyst reviews for identity resolution.

Revision ID: a8d9e0f1b223
Revises: f7c8d9e0a112
Create Date: 2026-07-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a8d9e0f1b223"
down_revision: Union[str, None] = "f7c8d9e0a112"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "entity_resolution_reviews",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("decision_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["entity_research_runs.run_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id",
            "decision_id",
            name="uq_entity_resolution_reviews_run_decision",
        ),
    )
    op.create_index(
        "ix_entity_resolution_reviews_id",
        "entity_resolution_reviews",
        ["id"],
    )
    op.create_index(
        "ix_entity_resolution_reviews_run",
        "entity_resolution_reviews",
        ["run_id"],
    )
    op.create_index(
        "ix_entity_resolution_reviews_status",
        "entity_resolution_reviews",
        ["status"],
    )
    op.create_index(
        "ix_entity_resolution_reviews_owner",
        "entity_resolution_reviews",
        ["created_by"],
    )


def downgrade() -> None:
    op.drop_table("entity_resolution_reviews")
