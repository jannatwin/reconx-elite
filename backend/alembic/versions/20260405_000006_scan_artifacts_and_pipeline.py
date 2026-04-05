"""scan_artifacts table for modular pipeline outputs

Revision ID: 20260405_000006
Revises: 20260403_000005
Create Date: 2026-04-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20260405_000006"
down_revision: Union[str, None] = "20260403_000005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_artifacts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("module", sa.String(length=64), nullable=False),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("summary_json", sa.JSON(), nullable=True),
        sa.Column("text_preview", sa.Text(), nullable=True),
        sa.Column("blob_path", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_artifacts_id"), "scan_artifacts", ["id"], unique=False)
    op.create_index(op.f("ix_scan_artifacts_scan_id"), "scan_artifacts", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_artifacts_scan_id"), table_name="scan_artifacts")
    op.drop_index(op.f("ix_scan_artifacts_id"), table_name="scan_artifacts")
    op.drop_table("scan_artifacts")
