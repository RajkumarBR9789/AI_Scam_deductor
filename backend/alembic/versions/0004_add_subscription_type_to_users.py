"""
Alembic migration: 0004 — add subscription_type column to users table.

Revision ID: 0004
Create Date: 2026-04-12
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision: str = "0004"
down_revision: str = "0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "subscription_type",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'free'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "subscription_type")
