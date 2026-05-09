"""
Alembic migration: 0003 — create scan_results table.

Revision ID: 0003
Create Date: 2026-04-12
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Create the scan_results table for storing scam-detection outputs."""
    op.create_table(
        "scan_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("input_text", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_label", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("red_flags", sa.Text(), nullable=True),
        sa.Column("ai_analysis", sa.Text(), nullable=True),
        sa.Column("citations", sa.Text(), nullable=True),
        sa.Column("recommendations", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_risk_score_range"),
    )
    op.create_index("ix_scan_results_user_id", "scan_results", ["user_id"])
    op.create_index("ix_scan_results_created_at", "scan_results", ["created_at"])


def downgrade() -> None:
    """Drop the scan_results table."""
    op.drop_index("ix_scan_results_created_at", table_name="scan_results")
    op.drop_index("ix_scan_results_user_id", table_name="scan_results")
    op.drop_table("scan_results")
