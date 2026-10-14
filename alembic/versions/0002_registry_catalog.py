"""Add dynamic server registry and collection catalog fields."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column(
            "display_name", sa.String(length=160), server_default=sa.text("''"), nullable=False
        ),
    )
    op.execute("UPDATE servers SET display_name = name WHERE display_name = ''")
    op.add_column(
        "servers",
        sa.Column(
            "transport",
            sa.String(length=32),
            server_default=sa.text("'streamable_http'"),
            nullable=False,
        ),
    )
    op.add_column("servers", sa.Column("last_synced_at", sa.DateTime(timezone=True)))
    op.add_column("servers", sa.Column("last_sync_error", sa.String(length=2048)))
    op.add_column(
        "servers",
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    op.add_column(
        "tools",
        sa.Column(
            "input_schema",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
    )
    op.execute(
        """
        WITH duplicates AS (
            SELECT id, name,
                row_number() OVER (PARTITION BY server_id, name ORDER BY id) AS row_number
            FROM tools
        )
        UPDATE tools
        SET name = left(tools.name, 167) || '-legacy-' || left(tools.id::text, 8)
        FROM duplicates
        WHERE tools.id = duplicates.id AND duplicates.row_number > 1
        """
    )
    op.add_column("tools", sa.Column("output_schema", postgresql.JSONB(astext_type=sa.Text())))
    op.add_column(
        "tools",
        sa.Column(
            "annotations",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
    )
    op.add_column(
        "tools",
        sa.Column(
            "fingerprint", sa.String(length=64), server_default=sa.text("''"), nullable=False
        ),
    )
    op.add_column(
        "tools", sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False)
    )
    op.add_column(
        "tools",
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_unique_constraint("uq_tools_server_id_name", "tools", ["server_id", "name"])
    op.create_index("ix_tools_server_id_active_name", "tools", ["server_id", "active", "name"])

    op.add_column(
        "collections",
        sa.Column(
            "display_name", sa.String(length=160), server_default=sa.text("''"), nullable=False
        ),
    )
    op.execute("UPDATE collections SET display_name = slug WHERE display_name = ''")
    op.add_column(
        "collections", sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False)
    )
    op.add_column(
        "collections",
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.add_column(
        "collections",
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.add_column(
        "collection_servers",
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.create_index(
        "ix_collection_servers_server_id_enabled", "collection_servers", ["server_id", "enabled"]
    )


def downgrade() -> None:
    op.drop_index("ix_collection_servers_server_id_enabled", table_name="collection_servers")
    op.drop_column("collection_servers", "enabled")
    op.drop_column("collections", "updated_at")
    op.drop_column("collections", "created_at")
    op.drop_column("collections", "enabled")
    op.drop_column("collections", "display_name")
    op.drop_index("ix_tools_server_id_active_name", table_name="tools")
    op.drop_constraint("uq_tools_server_id_name", "tools", type_="unique")
    op.drop_column("tools", "last_seen_at")
    op.drop_column("tools", "active")
    op.drop_column("tools", "fingerprint")
    op.drop_column("tools", "annotations")
    op.drop_column("tools", "output_schema")
    op.drop_column("tools", "input_schema")
    op.drop_column("servers", "updated_at")
    op.drop_column("servers", "last_synced_at")
    op.drop_column("servers", "last_sync_error")
    op.drop_column("servers", "transport")
    op.drop_column("servers", "display_name")
