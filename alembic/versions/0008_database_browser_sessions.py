"""Persist browser sessions and OIDC login transactions in PostgreSQL."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    uuid = sa.Uuid()
    op.create_unique_constraint(
        "uq_identity_providers_id_organization_id",
        "identity_providers",
        ["id", "organization_id"],
    )
    op.create_table(
        "browser_sessions",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "organization_id",
            uuid,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("principal_id", uuid, nullable=False),
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
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["principal_id", "organization_id"],
            ["principals.id", "principals.organization_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("token_id", name="uq_browser_sessions_token_id"),
    )
    op.create_index("ix_browser_sessions_organization_id", "browser_sessions", ["organization_id"])
    op.create_index("ix_browser_sessions_principal_id", "browser_sessions", ["principal_id"])
    op.create_index("ix_browser_sessions_expires_at", "browser_sessions", ["expires_at"])
    op.create_index("ix_browser_sessions_revoked_at", "browser_sessions", ["revoked_at"])
    op.create_table(
        "oidc_login_transactions",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "organization_id",
            uuid,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider_id", uuid, nullable=False),
        sa.Column("state_hash", sa.String(128), nullable=False),
        sa.Column("nonce", sa.String(255), nullable=False),
        sa.Column("pkce_verifier", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["provider_id", "organization_id"],
            ["identity_providers.id", "identity_providers.organization_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("state_hash", name="uq_oidc_login_transactions_state_hash"),
    )
    op.create_index(
        "ix_oidc_login_transactions_organization_id", "oidc_login_transactions", ["organization_id"]
    )
    op.create_index(
        "ix_oidc_login_transactions_provider_id", "oidc_login_transactions", ["provider_id"]
    )
    op.create_index(
        "ix_oidc_login_transactions_expires_at", "oidc_login_transactions", ["expires_at"]
    )
    op.create_index(
        "ix_oidc_login_transactions_consumed_at", "oidc_login_transactions", ["consumed_at"]
    )


def downgrade() -> None:
    op.drop_table("oidc_login_transactions")
    op.drop_table("browser_sessions")
    op.drop_constraint(
        "uq_identity_providers_id_organization_id", "identity_providers", type_="unique"
    )
