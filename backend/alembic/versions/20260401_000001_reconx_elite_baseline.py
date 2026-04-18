"""ReconX Elite baseline schema.

Revision ID: 20260401_000001
Revises:
Create Date: 2026-04-01 00:00:01
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260401_000001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role", "users", ["role"])

    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.UniqueConstraint("owner_id", "domain", name="uq_owner_domain"),
    )
    op.create_index("ix_targets_owner_id", "targets", ["owner_id"])
    op.create_index("ix_targets_domain", "targets", ["domain"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_jti", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index(
        "ix_refresh_tokens_token_jti", "refresh_tokens", ["token_jti"], unique=True
    )
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"])
    op.create_index("ix_refresh_tokens_is_revoked", "refresh_tokens", ["is_revoked"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "status", sa.String(length=50), nullable=False, server_default="pending"
        ),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("scan_config_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
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
    op.create_index("ix_scans_target_id", "scans", ["target_id"])
    op.create_index("ix_scans_status", "scans", ["status"])

    op.create_table(
        "subdomains",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column(
            "is_live", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "environment",
            sa.String(length=32),
            nullable=False,
            server_default="unknown",
        ),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column(
            "takeover_candidate",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("cname", sa.String(length=512), nullable=True),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("tech_stack", sa.JSON(), nullable=True),
        sa.Column("cdn", sa.String(length=255), nullable=True),
        sa.Column("waf", sa.String(length=255), nullable=True),
        sa.Column("cdn_waf", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("scan_id", "hostname", name="uq_scan_subdomain"),
    )
    op.create_index("ix_subdomains_scan_id", "subdomains", ["scan_id"])
    op.create_index("ix_subdomains_hostname", "subdomains", ["hostname"])
    op.create_index("ix_subdomains_environment", "subdomains", ["environment"])
    op.create_index(
        "ix_subdomains_takeover_candidate", "subdomains", ["takeover_candidate"]
    )

    op.create_table(
        "endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("normalized_url", sa.String(length=2048), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=True),
        sa.Column("query_params", sa.JSON(), nullable=True),
        sa.Column("priority_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("focus_reasons", sa.JSON(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False, server_default="gau"),
        sa.Column("js_source", sa.String(length=2048), nullable=True),
        sa.Column("category", sa.String(length=50), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column(
            "is_interesting",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.UniqueConstraint(
            "scan_id", "normalized_url", name="uq_scan_endpoint_normalized"
        ),
    )
    op.create_index("ix_endpoints_scan_id", "endpoints", ["scan_id"])
    op.create_index("ix_endpoints_url", "endpoints", ["url"])
    op.create_index("ix_endpoints_hostname", "endpoints", ["hostname"])
    op.create_index("ix_endpoints_normalized_url", "endpoints", ["normalized_url"])
    op.create_index("ix_endpoints_priority_score", "endpoints", ["priority_score"])
    op.create_index("ix_endpoints_source", "endpoints", ["source"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("template_id", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column(
            "source", sa.String(length=16), nullable=False, server_default="nuclei"
        ),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.8"),
        sa.Column("matcher_name", sa.String(length=255), nullable=True),
        sa.Column("matched_url", sa.String(length=2048), nullable=True),
        sa.Column("host", sa.String(length=1024), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
    )
    op.create_index("ix_vulnerabilities_scan_id", "vulnerabilities", ["scan_id"])
    op.create_index(
        "ix_vulnerabilities_template_id", "vulnerabilities", ["template_id"]
    )
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vulnerabilities_source", "vulnerabilities", ["source"])
    op.create_index(
        "ix_vulnerabilities_matched_url", "vulnerabilities", ["matched_url"]
    )

    op.create_table(
        "javascript_assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("normalized_url", sa.String(length=2048), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("source_endpoint_url", sa.String(length=2048), nullable=True),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="queued"
        ),
        sa.Column("extracted_endpoints", sa.JSON(), nullable=True),
        sa.Column("secrets_json", sa.JSON(), nullable=True),
        sa.Column("warnings_json", sa.JSON(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("content_sha256", sa.String(length=64), nullable=True),
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
        sa.UniqueConstraint("scan_id", "normalized_url", name="uq_scan_js_asset"),
    )
    op.create_index("ix_javascript_assets_scan_id", "javascript_assets", ["scan_id"])
    op.create_index(
        "ix_javascript_assets_normalized_url", "javascript_assets", ["normalized_url"]
    )
    op.create_index("ix_javascript_assets_hostname", "javascript_assets", ["hostname"])
    op.create_index("ix_javascript_assets_status", "javascript_assets", ["status"])

    op.create_table(
        "attack_paths",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column(
            "severity", sa.String(length=32), nullable=False, server_default="medium"
        ),
        sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
        sa.Column("steps_json", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index("ix_attack_paths_scan_id", "attack_paths", ["scan_id"])
    op.create_index("ix_attack_paths_severity", "attack_paths", ["severity"])
    op.create_index("ix_attack_paths_score", "attack_paths", ["score"])

    op.create_table(
        "scan_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("step", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("stdout", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index("ix_scan_logs_scan_id", "scan_logs", ["scan_id"])
    op.create_index("ix_scan_logs_step", "scan_logs", ["step"])
    op.create_index("ix_scan_logs_status", "scan_logs", ["status"])

    op.create_table(
        "scan_diffs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "previous_scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True
        ),
        sa.Column("new_subdomains", sa.JSON(), nullable=True),
        sa.Column("new_endpoints", sa.JSON(), nullable=True),
        sa.Column("new_vulnerabilities", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index("ix_scan_diffs_scan_id", "scan_diffs", ["scan_id"])
    op.create_index(
        "ix_scan_diffs_previous_scan_id", "scan_diffs", ["previous_scan_id"]
    )

    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("frequency", sa.String(length=20), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("next_run", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_config_json", sa.JSON(), nullable=True),
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
    op.create_index("ix_scheduled_scans_target_id", "scheduled_scans", ["target_id"])
    op.create_index("ix_scheduled_scans_user_id", "scheduled_scans", ["user_id"])

    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.String(length=50), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column(
            "read", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index("ix_notifications_user_id", "notifications", ["user_id"])

    op.create_table(
        "bookmarks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "endpoint_id",
            sa.Integer(),
            sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("note", sa.String(length=1024), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.UniqueConstraint("user_id", "endpoint_id", name="uq_user_endpoint_bookmark"),
    )
    op.create_index("ix_bookmarks_user_id", "bookmarks", ["user_id"])
    op.create_index("ix_bookmarks_endpoint_id", "bookmarks", ["endpoint_id"])


def downgrade() -> None:
    op.drop_index("ix_bookmarks_endpoint_id", table_name="bookmarks")
    op.drop_index("ix_bookmarks_user_id", table_name="bookmarks")
    op.drop_table("bookmarks")

    op.drop_index("ix_notifications_user_id", table_name="notifications")
    op.drop_table("notifications")

    op.drop_index("ix_scheduled_scans_user_id", table_name="scheduled_scans")
    op.drop_index("ix_scheduled_scans_target_id", table_name="scheduled_scans")
    op.drop_table("scheduled_scans")

    op.drop_index("ix_scan_diffs_previous_scan_id", table_name="scan_diffs")
    op.drop_index("ix_scan_diffs_scan_id", table_name="scan_diffs")
    op.drop_table("scan_diffs")

    op.drop_index("ix_scan_logs_status", table_name="scan_logs")
    op.drop_index("ix_scan_logs_step", table_name="scan_logs")
    op.drop_index("ix_scan_logs_scan_id", table_name="scan_logs")
    op.drop_table("scan_logs")

    op.drop_index("ix_attack_paths_score", table_name="attack_paths")
    op.drop_index("ix_attack_paths_severity", table_name="attack_paths")
    op.drop_index("ix_attack_paths_scan_id", table_name="attack_paths")
    op.drop_table("attack_paths")

    op.drop_index("ix_javascript_assets_status", table_name="javascript_assets")
    op.drop_index("ix_javascript_assets_hostname", table_name="javascript_assets")
    op.drop_index("ix_javascript_assets_normalized_url", table_name="javascript_assets")
    op.drop_index("ix_javascript_assets_scan_id", table_name="javascript_assets")
    op.drop_table("javascript_assets")

    op.drop_index("ix_vulnerabilities_matched_url", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_source", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_severity", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_template_id", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_scan_id", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")

    op.drop_index("ix_endpoints_source", table_name="endpoints")
    op.drop_index("ix_endpoints_priority_score", table_name="endpoints")
    op.drop_index("ix_endpoints_normalized_url", table_name="endpoints")
    op.drop_index("ix_endpoints_hostname", table_name="endpoints")
    op.drop_index("ix_endpoints_url", table_name="endpoints")
    op.drop_index("ix_endpoints_scan_id", table_name="endpoints")
    op.drop_table("endpoints")

    op.drop_index("ix_subdomains_takeover_candidate", table_name="subdomains")
    op.drop_index("ix_subdomains_environment", table_name="subdomains")
    op.drop_index("ix_subdomains_hostname", table_name="subdomains")
    op.drop_index("ix_subdomains_scan_id", table_name="subdomains")
    op.drop_table("subdomains")

    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_target_id", table_name="scans")
    op.drop_table("scans")

    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_refresh_tokens_is_revoked", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_token_jti", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

    op.drop_index("ix_targets_domain", table_name="targets")
    op.drop_index("ix_targets_owner_id", table_name="targets")
    op.drop_table("targets")

    op.drop_index("ix_users_role", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
