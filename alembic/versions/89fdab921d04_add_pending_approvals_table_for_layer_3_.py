"""Add pending_approvals table for Layer 3 user consent

Revision ID: 89fdab921d04
Revises: b5ae6063be0a
Create Date: 2026-01-13 16:10:36.691778

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '89fdab921d04'
down_revision: Union[str, Sequence[str], None] = 'b5ae6063be0a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the Layer 3 approval queue."""
    from database import Base

    Base.metadata.tables["pending_approvals"].create(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    """Drop the Layer 3 approval queue."""
    from database import Base

    Base.metadata.tables["pending_approvals"].drop(bind=op.get_bind(), checkfirst=True)
