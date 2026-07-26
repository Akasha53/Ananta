"""Add analyst entity watchlist.

Revision ID: f7c8d9e0a112
Revises: e6b7c8d9f001
Create Date: 2026-07-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f7c8d9e0a112"
down_revision: Union[str, None] = "e6b7c8d9f001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("entity_watches"):
        op.create_table(
        "entity_watches",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("query", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("entity_kind", sa.String(), nullable=True),
        sa.Column("root_key", sa.String(), nullable=True),
        sa.Column("mode", sa.String(), nullable=True),
        sa.Column("purpose", sa.String(), nullable=True),
        sa.Column("language", sa.String(), nullable=True),
        sa.Column("report_template", sa.String(), nullable=True),
        sa.Column("baseline_run_id", sa.String(), nullable=True),
        sa.Column("last_run_id", sa.String(), nullable=True),
        sa.Column("last_change_score", sa.Integer(), nullable=True),
        sa.Column("last_change_summary", sa.JSON(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(), nullable=True),
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
        sa.PrimaryKeyConstraint("id"),
        )

    indexes = {
        index["name"] for index in sa.inspect(bind).get_indexes("entity_watches")
    }
    for name, columns in (
        ("ix_entity_watches_id", ["id"]),
        ("ix_entity_watches_root_key", ["root_key"]),
        ("ix_entity_watches_created_by", ["created_by"]),
        ("ix_entity_watches_owner_active", ["created_by", "is_active"]),
        ("ix_entity_watches_root_owner", ["root_key", "created_by"]),
    ):
        if name not in indexes:
            op.create_index(name, "entity_watches", columns)


def downgrade() -> None:
    op.drop_table("entity_watches")
