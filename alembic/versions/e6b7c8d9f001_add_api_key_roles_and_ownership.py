"""Add API key roles and logical ownership.

Revision ID: e6b7c8d9f001
Revises: d4e91b7c2a08
Create Date: 2026-07-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e6b7c8d9f001"
down_revision: Union[str, None] = "d4e91b7c2a08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {
        column["name"] for column in sa.inspect(bind).get_columns("api_keys")
    }
    if "role" not in columns:
        op.add_column(
            "api_keys",
            sa.Column("role", sa.String(), nullable=False, server_default="admin"),
        )
    if "scopes" not in columns:
        op.add_column("api_keys", sa.Column("scopes", sa.JSON(), nullable=True))
    if "owner_id" not in columns:
        op.add_column("api_keys", sa.Column("owner_id", sa.String(), nullable=True))

    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("api_keys")}
    if "ix_api_keys_owner_id" not in indexes:
        op.create_index("ix_api_keys_owner_id", "api_keys", ["owner_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_api_keys_owner_id", table_name="api_keys")
    op.drop_column("api_keys", "owner_id")
    op.drop_column("api_keys", "scopes")
    op.drop_column("api_keys", "role")
