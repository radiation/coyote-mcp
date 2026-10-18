"""Add downstream authentication policies and encrypted credential storage.

Servers gain an explicit authentication policy (default ``none`` preserves the
existing unauthenticated behaviour). Encrypted shared credentials, per-user OAuth
integration settings, per-user connections, and short-lived OAuth transactions
are stored with a key-version column so that encryption keys can be rotated.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column(
            "auth_policy",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'none'"),
        ),
    )
    op.create_check_constraint(
        "ck_servers_auth_policy",
        "servers",
        "auth_policy IN ('none', 'shared_bearer', 'per_user_oauth')",
    )

    op.create_table(
        "downstream_shared_credentials",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("server_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("key_version", sa.String(64), nullable=False),
        sa.Column("sealed_value", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("server_id", name="uq_downstream_shared_credentials_server_id"),
        sa.ForeignKeyConstraint(
            ["server_id", "organization_id"],
            ["servers.id", "servers.organization_id"],
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_downstream_shared_credentials_organization_id",
        "downstream_shared_credentials",
        ["organization_id"],
    )

    op.create_table(
        "downstream_oauth_integrations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("server_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("authorization_endpoint", sa.String(2048), nullable=False),
        sa.Column("token_endpoint", sa.String(2048), nullable=False),
        sa.Column("revocation_endpoint", sa.String(2048), nullable=True),
        sa.Column("account_endpoint", sa.String(2048), nullable=True),
        sa.Column("client_id", sa.String(255), nullable=False),
        sa.Column("client_secret_key_version", sa.String(64), nullable=True),
        sa.Column("client_secret_sealed", sa.LargeBinary(), nullable=True),
        sa.Column("scopes", JSON_TYPE, nullable=True),
        sa.Column("icon_key", sa.String(64), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("configuration_error", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("server_id", name="uq_downstream_oauth_integrations_server_id"),
        sa.ForeignKeyConstraint(
            ["server_id", "organization_id"],
            ["servers.id", "servers.organization_id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'generic')",
            name="ck_downstream_oauth_integrations_provider",
        ),
    )
    op.create_index(
        "ix_downstream_oauth_integrations_organization_id",
        "downstream_oauth_integrations",
        ["organization_id"],
    )

    op.create_table(
        "downstream_connections",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("server_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "principal_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("principals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'connected'")),
        sa.Column("key_version", sa.String(64), nullable=False),
        sa.Column("sealed_tokens", sa.LargeBinary(), nullable=False),
        sa.Column("scopes", JSON_TYPE, nullable=True),
        sa.Column("account_identifier", sa.String(255), nullable=True),
        sa.Column("access_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_refreshed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "organization_id",
            "server_id",
            "principal_id",
            name="uq_downstream_connections_org_server_principal",
        ),
        sa.ForeignKeyConstraint(
            ["server_id", "organization_id"],
            ["servers.id", "servers.organization_id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "status IN ('connected', 'reauthorization_required')",
            name="ck_downstream_connections_status",
        ),
    )
    op.create_index("ix_downstream_connections_server_id", "downstream_connections", ["server_id"])
    op.create_index(
        "ix_downstream_connections_principal_id", "downstream_connections", ["principal_id"]
    )

    op.create_table(
        "downstream_oauth_transactions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("state_hash", sa.String(128), nullable=False),
        sa.Column(
            "browser_session_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("browser_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "principal_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("principals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("server_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("key_version", sa.String(64), nullable=False),
        sa.Column("sealed_verifier", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("state_hash", name="uq_downstream_oauth_transactions_state_hash"),
        sa.ForeignKeyConstraint(
            ["server_id", "organization_id"],
            ["servers.id", "servers.organization_id"],
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_downstream_oauth_transactions_browser_session_id",
        "downstream_oauth_transactions",
        ["browser_session_id"],
    )
    op.create_index(
        "ix_downstream_oauth_transactions_expires_at",
        "downstream_oauth_transactions",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_table("downstream_oauth_transactions")
    op.drop_table("downstream_connections")
    op.drop_table("downstream_oauth_integrations")
    op.drop_table("downstream_shared_credentials")
    op.drop_constraint("ck_servers_auth_policy", "servers", type_="check")
    op.drop_column("servers", "auth_policy")
