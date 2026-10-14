"""Add organization-scoped identities, credentials, and roles."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    organization_id = sa.Uuid()
    op.create_table(
        "organizations",
        sa.Column("id", organization_id, primary_key=True),
        sa.Column("slug", sa.String(160), nullable=False, unique=True),
        sa.Column("display_name", sa.String(160), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    connection = op.get_bind()
    default_id = "00000000-0000-0000-0000-000000000001"
    connection.execute(
        sa.text(
            "INSERT INTO organizations (id, slug, display_name) "
            "VALUES (:id, 'default', 'Default Organization')"
        ),
        {"id": default_id},
    )
    for table in ("servers", "collections"):
        op.add_column(table, sa.Column("organization_id", organization_id, nullable=True))
        connection.execute(sa.text(f"UPDATE {table} SET organization_id = :id"), {"id": default_id})
        op.alter_column(table, "organization_id", nullable=False)
        op.create_foreign_key(
            f"fk_{table}_organization", table, "organizations", ["organization_id"], ["id"]
        )
    op.drop_constraint("servers_name_key", "servers", type_="unique")
    op.drop_constraint("collections_slug_key", "collections", type_="unique")
    op.create_unique_constraint(
        "uq_servers_organization_id_name", "servers", ["organization_id", "name"]
    )
    op.create_unique_constraint(
        "uq_collections_organization_id_slug", "collections", ["organization_id", "slug"]
    )
    op.create_unique_constraint(
        "uq_servers_id_organization_id", "servers", ["id", "organization_id"]
    )
    op.create_unique_constraint(
        "uq_collections_id_organization_id", "collections", ["id", "organization_id"]
    )
    op.add_column(
        "collection_servers", sa.Column("organization_id", organization_id, nullable=True)
    )
    connection.execute(
        sa.text(
            "UPDATE collection_servers cs SET organization_id = c.organization_id "
            "FROM collections c WHERE cs.collection_id = c.id"
        )
    )
    op.alter_column("collection_servers", "organization_id", nullable=False)
    op.create_foreign_key(
        "fk_collection_servers_organization",
        "collection_servers",
        "organizations",
        ["organization_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_collection_servers_collection_org",
        "collection_servers",
        "collections",
        ["collection_id", "organization_id"],
        ["id", "organization_id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_collection_servers_server_org",
        "collection_servers",
        "servers",
        ["server_id", "organization_id"],
        ["id", "organization_id"],
        ondelete="CASCADE",
    )
    op.create_table(
        "principals",
        sa.Column("id", organization_id, primary_key=True),
        sa.Column(
            "organization_id",
            organization_id,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("identifier", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("identity_type", sa.String(32), nullable=False, server_default="human"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("organization_id", "identifier", name="uq_principals_org_identifier"),
        sa.UniqueConstraint("id", "organization_id", name="uq_principals_id_organization_id"),
    )
    op.create_table(
        "role_assignments",
        sa.Column("id", organization_id, primary_key=True),
        sa.Column(
            "organization_id",
            organization_id,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("principal_id", organization_id, nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("collection_id", organization_id, nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["principal_id", "organization_id"],
            ["principals.id", "principals.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["collection_id", "organization_id"],
            ["collections.id", "collections.organization_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "principal_id",
            "role",
            "collection_id",
            name="uq_role_assignments_principal_role_collection",
        ),
    )
    op.create_table(
        "personal_access_tokens",
        sa.Column("id", organization_id, primary_key=True),
        sa.Column(
            "organization_id",
            organization_id,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("principal_id", organization_id, nullable=False),
        sa.Column("token_id", sa.String(64), nullable=False, unique=True),
        sa.Column("secret_hash", sa.String(128), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["principal_id", "organization_id"],
            ["principals.id", "principals.organization_id"],
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_personal_access_tokens_token_id", "personal_access_tokens", ["token_id"])


def downgrade() -> None:
    op.drop_table("personal_access_tokens")
    op.drop_table("role_assignments")
    op.drop_table("principals")
    op.drop_constraint("fk_collection_servers_server_org", "collection_servers", type_="foreignkey")
    op.drop_constraint(
        "fk_collection_servers_collection_org", "collection_servers", type_="foreignkey"
    )
    op.drop_column("collection_servers", "organization_id")
    op.drop_constraint("uq_collections_organization_id_slug", "collections", type_="unique")
    op.drop_constraint("uq_servers_organization_id_name", "servers", type_="unique")
    op.drop_column("collections", "organization_id")
    op.drop_column("servers", "organization_id")
    op.drop_table("organizations")
