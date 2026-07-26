"""Repair review tables created by the pre-Alembic development bootstrap.

Revision ID: b9c0d1e2f334
Revises: a8d9e0f1b223
Create Date: 2026-07-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b9c0d1e2f334"
down_revision: Union[str, None] = "a8d9e0f1b223"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("entity_resolution_reviews"):
        return

    columns = {
        column["name"]
        for column in inspector.get_columns("entity_resolution_reviews")
    }
    if "updated_by" not in columns:
        op.add_column(
            "entity_resolution_reviews",
            sa.Column("updated_by", sa.String(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("entity_resolution_reviews"):
        return

    columns = {
        column["name"]
        for column in inspector.get_columns("entity_resolution_reviews")
    }
    if "updated_by" in columns:
        op.drop_column("entity_resolution_reviews", "updated_by")
