"""Add a server-level enabled flag.

Disabling a server hides its tools from MCP discovery and execution without
removing registration, memberships, publications, or discovered tools.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_servers_enabled", "servers", ["enabled"])


def downgrade() -> None:
    op.drop_index("ix_servers_enabled", "servers")
    op.drop_column("servers", "enabled")
