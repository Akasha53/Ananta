"""add llm_hard_limit to scheduled_scans

Revision ID: 2f7a1c9d4e11
Revises: c3f8d9e12a45
Create Date: 2026-01-22 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "2f7a1c9d4e11"
down_revision: Union[str, None] = "c3f8d9e12a45"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scheduled_scans",
        sa.Column("llm_hard_limit", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scheduled_scans", "llm_hard_limit")
