"""
Alembic migration: 0007 — add status column to scan_results table.

Revision ID: 0007
Create Date: 2026-04-12
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision: str = "0007"
down_revision: str = "0006"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "scan_results",
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'completed'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_results", "status")
