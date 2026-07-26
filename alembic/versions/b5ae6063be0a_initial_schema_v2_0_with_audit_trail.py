"""Initial schema v2.0 with audit trail

Revision ID: b5ae6063be0a
Revises: 
Create Date: 2026-01-13 09:26:51.328346

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b5ae6063be0a'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the original core schema on a clean database."""
    from database import Base

    bind = op.get_bind()
    table_order = (
        "entity_reports",
        "scan_jobs",
        "tool_execution_logs",
        "entities",
        "findings",
        "sources",
        "scan_sessions",
        "scheduled_scans",
    )
    for table_name in table_order:
        Base.metadata.tables[table_name].create(bind=bind, checkfirst=True)


def downgrade() -> None:
    """Drop the original core schema in dependency-safe order."""
    from database import Base

    bind = op.get_bind()
    for table_name in (
        "scheduled_scans",
        "scan_sessions",
        "sources",
        "findings",
        "entities",
        "tool_execution_logs",
        "scan_jobs",
        "entity_reports",
    ):
        Base.metadata.tables[table_name].drop(bind=bind, checkfirst=True)
