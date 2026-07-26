"""add scan_jobs_archive table

Revision ID: 7b8c2c1d9a90
Revises: 2f7a1c9d4e11
Create Date: 2026-01-29

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7b8c2c1d9a90"
down_revision: Union[str, None] = "2f7a1c9d4e11"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("scan_jobs_archive"):
        op.create_table(
            "scan_jobs_archive",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("original_scan_job_id", sa.Integer(), nullable=False),
            sa.Column("job_id", sa.String(), nullable=False),
            sa.Column("query", sa.String(), nullable=False),
            sa.Column("report_type", sa.String(), nullable=True, server_default="osint"),
            sa.Column("status", sa.String(), nullable=False),
            sa.Column("progress", sa.Integer(), nullable=True, server_default="0"),
            sa.Column("result", sa.Text(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("archived_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    indexes = {
        index["name"]
        for index in sa.inspect(bind).get_indexes("scan_jobs_archive")
    }
    for name, columns in (
        ("ix_scan_jobs_archive_status", ["status"]),
        ("ix_scan_jobs_archive_archived_at", ["archived_at"]),
        ("ix_scan_jobs_archive_created_at", ["created_at"]),
        ("ix_scan_jobs_archive_original_id", ["original_scan_job_id"]),
        ("ix_scan_jobs_archive_job_id", ["job_id"]),
    ):
        if name not in indexes:
            op.create_index(name, "scan_jobs_archive", columns, unique=False)


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_archive_job_id", table_name="scan_jobs_archive")
    op.drop_index("ix_scan_jobs_archive_original_id", table_name="scan_jobs_archive")
    op.drop_index("ix_scan_jobs_archive_created_at", table_name="scan_jobs_archive")
    op.drop_index("ix_scan_jobs_archive_archived_at", table_name="scan_jobs_archive")
    op.drop_index("ix_scan_jobs_archive_status", table_name="scan_jobs_archive")
    op.drop_table("scan_jobs_archive")
