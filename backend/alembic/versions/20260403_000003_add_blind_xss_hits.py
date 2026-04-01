"""Add blind xss hits table.

Revision ID: 20260403_000003
Revises: 20260402_000002
Create Date: 2026-04-03 00:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260403_000003"
down_revision: Union[str, None] = "20260402_000002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "blind_xss_hits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token", sa.String(length=64), unique=True, nullable=False),
        sa.Column("payload_opportunity_id", sa.Integer(), sa.ForeignKey("payload_opportunities.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("headers_json", sa.JSON(), nullable=True),
        sa.Column("cookies_json", sa.JSON(), nullable=True),
        sa.Column("raw_request", sa.Text(), nullable=True),
        sa.Column("referrer", sa.String(length=2048), nullable=True),
        sa.Column("url_path", sa.String(length=2048), nullable=True),
        sa.Column("method", sa.String(length=8), nullable=False, server_default="GET"),
        sa.Column("triggered_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_blind_xss_hits_user_id", "blind_xss_hits", ["user_id"])
    op.create_index("ix_blind_xss_hits_token", "blind_xss_hits", ["token"])
    op.create_index("ix_blind_xss_hits_payload_opportunity_id", "blind_xss_hits", ["payload_opportunity_id"])
    op.create_index("ix_blind_xss_hits_ip_address", "blind_xss_hits", ["ip_address"])
    op.create_index("ix_blind_xss_hits_triggered_at", "blind_xss_hits", ["triggered_at"])


def downgrade() -> None:
    op.drop_index("ix_blind_xss_hits_triggered_at", table_name="blind_xss_hits")
    op.drop_index("ix_blind_xss_hits_ip_address", table_name="blind_xss_hits")
    op.drop_index("ix_blind_xss_hits_payload_opportunity_id", table_name="blind_xss_hits")
    op.drop_index("ix_blind_xss_hits_token", table_name="blind_xss_hits")
    op.drop_index("ix_blind_xss_hits_user_id", table_name="blind_xss_hits")
    op.drop_table("blind_xss_hits")