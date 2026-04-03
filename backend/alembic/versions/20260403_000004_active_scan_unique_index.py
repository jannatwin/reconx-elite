"""Add partial unique index for active scans.

Revision ID: 20260403_000004
Revises: 20260403_000003
Create Date: 2026-04-03 20:20:00
"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "20260403_000004"
down_revision: Union[str, None] = "20260403_000003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_target_active
        ON scans (target_id)
        WHERE status IN ('pending', 'running')
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_scans_target_active")
