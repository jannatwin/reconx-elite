"""manual_test_logs for manual testing history

Revision ID: 20260405_000007
Revises: 20260405_000006
Create Date: 2026-04-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20260405_000007"
down_revision: Union[str, None] = "20260405_000006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "manual_test_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("vulnerability_id", sa.Integer(), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("summary_json", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["vulnerabilities.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_manual_test_logs_id"), "manual_test_logs", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_manual_test_logs_user_id"),
        "manual_test_logs",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_manual_test_logs_user_id"), table_name="manual_test_logs")
    op.drop_index(op.f("ix_manual_test_logs_id"), table_name="manual_test_logs")
    op.drop_table("manual_test_logs")
