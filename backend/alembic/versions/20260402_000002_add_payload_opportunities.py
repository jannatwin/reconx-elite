"""Add payload opportunities table.

Revision ID: 20260402_000002
Revises: 20260401_000001
Create Date: 2026-04-02 00:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260402_000002"
down_revision: Union[str, None] = "20260401_000001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "payload_opportunities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "endpoint_id",
            sa.Integer(),
            sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("parameter_name", sa.String(length=255), nullable=False),
        sa.Column(
            "parameter_location",
            sa.String(length=32),
            nullable=False,
            server_default="query",
        ),
        sa.Column("vulnerability_type", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("payloads_json", sa.JSON(), nullable=True),
        sa.Column("tested_json", sa.JSON(), nullable=True),
        sa.Column("highest_match", sa.String(length=50), nullable=True),
        sa.Column("match_confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("notes", sa.String(length=1024), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_payload_opportunities_endpoint_id", "payload_opportunities", ["endpoint_id"]
    )
    op.create_index(
        "ix_payload_opportunities_scan_id", "payload_opportunities", ["scan_id"]
    )
    op.create_index(
        "ix_payload_opportunities_vulnerability_type",
        "payload_opportunities",
        ["vulnerability_type"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_payload_opportunities_vulnerability_type",
        table_name="payload_opportunities",
    )
    op.drop_index(
        "ix_payload_opportunities_scan_id", table_name="payload_opportunities"
    )
    op.drop_index(
        "ix_payload_opportunities_endpoint_id", table_name="payload_opportunities"
    )
    op.drop_table("payload_opportunities")
