"""Initial server, tool, and collection catalog."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "servers",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(160), unique=True, nullable=False),
        sa.Column("endpoint", sa.String(2048), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_table(
        "collections",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("slug", sa.String(160), unique=True, nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
    )
    op.create_table(
        "tools",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("server_id", sa.Uuid(), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(4096), nullable=False),
    )
    op.create_table(
        "collection_servers",
        sa.Column("collection_id", sa.Uuid(), sa.ForeignKey("collections.id"), primary_key=True),
        sa.Column("server_id", sa.Uuid(), sa.ForeignKey("servers.id"), primary_key=True),
    )
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")


def downgrade() -> None:
    op.drop_table("collection_servers")
    op.drop_table("tools")
    op.drop_table("collections")
    op.drop_table("servers")
    # Retain vector extension: may be shared with other database objects.
