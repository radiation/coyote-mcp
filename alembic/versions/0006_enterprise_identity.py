"""Add enterprise OIDC identities and external group role mappings."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    uuid = sa.Uuid()
    op.create_table(
        "identity_providers",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "organization_id",
            uuid,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("client_id", sa.String(512), nullable=False),
        sa.Column("client_secret_reference", sa.String(255), nullable=False),
        sa.Column("allowed_organization", sa.String(255)),
        sa.Column("group_claim", sa.String(128)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "jit_provisioning_enabled", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("organization_id", "name", name="uq_identity_providers_org_name"),
        sa.UniqueConstraint("organization_id", "issuer", name="uq_identity_providers_org_issuer"),
    )
    op.create_index(
        "ix_identity_providers_organization_id", "identity_providers", ["organization_id"]
    )
    op.create_index(
        "uq_identity_providers_one_active_org",
        "identity_providers",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("enabled"),
    )
    op.create_table(
        "external_identities",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "organization_id",
            uuid,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("principal_id", uuid, nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("subject", sa.String(1024), nullable=False),
        sa.Column("email", sa.String(320)),
        sa.Column("display_name", sa.String(255)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["principal_id", "organization_id"],
            ["principals.id", "principals.organization_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "organization_id", "issuer", "subject", name="uq_external_identities_org_issuer_subject"
        ),
    )
    op.create_index(
        "ix_external_identities_organization_id", "external_identities", ["organization_id"]
    )
    op.create_index("ix_external_identities_principal_id", "external_identities", ["principal_id"])
    op.create_table(
        "external_groups",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "organization_id",
            uuid,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_id", sa.String(512), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "organization_id", "external_id", name="uq_external_groups_org_external_id"
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_external_groups_id_organization_id"),
    )
    op.create_index("ix_external_groups_organization_id", "external_groups", ["organization_id"])
    op.create_table(
        "group_role_mappings",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "organization_id",
            uuid,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_group_id", uuid, nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("collection_id", uuid),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
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


def downgrade() -> None:
    op.drop_table("group_role_mappings")
    op.drop_table("external_groups")
    op.drop_table("external_identities")
    op.drop_table("identity_providers")
