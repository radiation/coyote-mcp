"""Remove persisted OIDC provider coupling from greenfield auth storage."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    """Rebuild transient sessions and provider-coupled group mappings without provider IDs."""
    op.drop_table("oidc_login_transactions")
    op.drop_table("browser_sessions")
    op.drop_table("group_role_mappings")
    op.drop_table("external_groups")

    op.create_table(
        "browser_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "principal_id",
            sa.Uuid(),
            sa.ForeignKey("principals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "active_organization_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
        ),
        sa.Column("token_id", sa.String(64), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("csrf_token_hash", sa.String(128)),
        sa.Column("verified_group_ids", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "last_activity_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("token_id", name="uq_browser_sessions_token_id"),
    )
    op.create_index("ix_browser_sessions_principal_id", "browser_sessions", ["principal_id"])
    op.create_index(
        "ix_browser_sessions_active_organization_id", "browser_sessions", ["active_organization_id"]
    )
    op.create_index("ix_browser_sessions_token_id", "browser_sessions", ["token_id"])
    op.create_index("ix_browser_sessions_expires_at", "browser_sessions", ["expires_at"])
    op.create_index("ix_browser_sessions_revoked_at", "browser_sessions", ["revoked_at"])
    op.create_table(
        "external_groups",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_id", sa.String(512), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "organization_id", "external_id", name="uq_external_groups_org_external_id"
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_external_groups_id_organization_id"),
    )
    op.create_index("ix_external_groups_organization_id", "external_groups", ["organization_id"])
    op.create_table(
        "group_role_mappings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_group_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("collection_id", sa.Uuid()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["external_group_id", "organization_id"],
            ["external_groups.id", "external_groups.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["collection_id", "organization_id"],
            ["collections.id", "collections.organization_id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "role IN ('owner', 'administrator', 'maintainer', 'consumer', 'viewer')",
            name="ck_group_role_mappings_role",
        ),
        sa.UniqueConstraint(
            "external_group_id", "role", "collection_id", name="uq_group_role_mapping_scope"
        ),
    )
    op.create_index(
        "ix_group_role_mappings_organization_id", "group_role_mappings", ["organization_id"]
    )
    op.create_index(
        "ix_group_role_mappings_external_group_id", "group_role_mappings", ["external_group_id"]
    )
    op.create_index(
        "ix_group_role_mappings_collection_id", "group_role_mappings", ["collection_id"]
    )
    op.create_table(
        "oidc_login_transactions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("state_hash", sa.String(128), nullable=False),
        sa.Column("browser_binding_hash", sa.String(128), nullable=False),
        sa.Column("nonce", sa.String(255), nullable=False),
        sa.Column("pkce_verifier", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("state_hash", name="uq_oidc_login_transactions_state_hash"),
    )
    op.create_index(
        "ix_oidc_login_transactions_expires_at", "oidc_login_transactions", ["expires_at"]
    )
    op.create_index(
        "ix_oidc_login_transactions_consumed_at", "oidc_login_transactions", ["consumed_at"]
    )


def downgrade() -> None:
    raise RuntimeError("0014 is a greenfield corrective migration and cannot be downgraded.")
