"""Bind OIDC transactions to browsers and provider-scope external groups."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    uuid = sa.Uuid()
    op.add_column(
        "oidc_login_transactions",
        sa.Column("browser_binding_hash", sa.String(128), nullable=True),
    )
    op.execute(
        "UPDATE oidc_login_transactions SET browser_binding_hash = state_hash "
        "WHERE browser_binding_hash IS NULL"
    )
    op.alter_column("oidc_login_transactions", "browser_binding_hash", nullable=False)
    op.add_column("browser_sessions", sa.Column("identity_provider_id", uuid, nullable=True))
    op.add_column("external_groups", sa.Column("identity_provider_id", uuid, nullable=True))
    op.drop_constraint("uq_external_groups_org_external_id", "external_groups", type_="unique")
    op.create_unique_constraint(
        "uq_external_groups_org_provider_external_id",
        "external_groups",
        ["organization_id", "identity_provider_id", "external_id"],
    )
    op.create_unique_constraint(
        "uq_external_groups_id_org_provider",
        "external_groups",
        ["id", "organization_id", "identity_provider_id"],
    )
    op.create_foreign_key(
        "fk_external_groups_provider_organization",
        "external_groups",
        "identity_providers",
        ["identity_provider_id", "organization_id"],
        ["id", "organization_id"],
        ondelete="CASCADE",
    )
    op.execute(
        """
        UPDATE external_groups AS groups
        SET identity_provider_id = providers.id
        FROM identity_providers AS providers
        WHERE providers.organization_id = groups.organization_id
          AND (SELECT count(*) FROM identity_providers candidates
               WHERE candidates.organization_id = groups.organization_id) = 1
        """
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_external_groups_provider_organization", "external_groups", type_="foreignkey"
    )
    op.drop_constraint("uq_external_groups_id_org_provider", "external_groups", type_="unique")
    op.drop_constraint(
        "uq_external_groups_org_provider_external_id", "external_groups", type_="unique"
    )
    op.create_unique_constraint(
        "uq_external_groups_org_external_id", "external_groups", ["organization_id", "external_id"]
    )
    op.drop_column("external_groups", "identity_provider_id")
    op.drop_column("browser_sessions", "identity_provider_id")
    op.drop_column("oidc_login_transactions", "browser_binding_hash")
