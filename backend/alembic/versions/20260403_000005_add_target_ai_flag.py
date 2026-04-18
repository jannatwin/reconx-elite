"""Add enable_ai_processing to targets.

Revision ID: 20260403_000005
Revises: 20260403_000004
Create Date: 2026-04-03 21:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260403_000005"
down_revision: Union[str, None] = "20260403_000004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column(
            "enable_ai_processing",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )
    op.alter_column("targets", "enable_ai_processing", server_default=None)


def downgrade() -> None:
    op.drop_column("targets", "enable_ai_processing")
