"""Add collection-scoped native tool publications."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint("uq_tools_id_server_id", "tools", ["id", "server_id"])
    op.create_table(
        "collection_tool_publications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("collection_id", sa.Uuid(), nullable=False),
        sa.Column("server_id", sa.Uuid(), nullable=False),
        sa.Column("tool_id", sa.Uuid(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("published_name", sa.String(length=200), nullable=False),
        sa.Column("description_override", sa.String(length=4096)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["collection_id", "server_id"],
            ["collection_servers.collection_id", "collection_servers.server_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tool_id", "server_id"], ["tools.id", "tools.server_id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "collection_id", "tool_id", name="uq_collection_tool_publications_tool"
        ),
        sa.UniqueConstraint(
            "collection_id", "published_name", name="uq_collection_tool_publications_name"
        ),
    )
    op.create_index(
        "ix_collection_tool_publications_collection_enabled",
        "collection_tool_publications",
        ["collection_id", "enabled"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_collection_tool_publications_collection_enabled",
        table_name="collection_tool_publications",
    )
    op.drop_table("collection_tool_publications")
    op.drop_constraint("uq_tools_id_server_id", "tools", type_="unique")
