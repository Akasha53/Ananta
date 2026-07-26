"""add api_keys table

Revision ID: c3f8d9e12a45
Revises: 89fdab921d04
Create Date: 2026-01-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3f8d9e12a45'
down_revision: Union[str, None] = '89fdab921d04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Local development historically called ``Base.metadata.create_all`` before
    # Alembic.  Keep the migration compatible with those databases instead of
    # failing on an already existing (and valid) table.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("api_keys"):
        op.create_table(
            'api_keys',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('key_hash', sa.String(), nullable=False),
            sa.Column('name', sa.String(), nullable=False),
            sa.Column('prefix', sa.String(), nullable=False),
            sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
            sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('created_by', sa.String(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )

    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("api_keys")}
    if "ix_api_keys_id" not in indexes:
        op.create_index(op.f('ix_api_keys_id'), 'api_keys', ['id'], unique=False)
    if "ix_api_keys_key_hash" not in indexes:
        op.create_index(op.f('ix_api_keys_key_hash'), 'api_keys', ['key_hash'], unique=True)


def downgrade() -> None:
    # Drop api_keys table
    op.drop_index(op.f('ix_api_keys_key_hash'), table_name='api_keys')
    op.drop_index(op.f('ix_api_keys_id'), table_name='api_keys')
    op.drop_table('api_keys')
