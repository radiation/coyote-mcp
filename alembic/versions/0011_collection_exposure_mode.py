"""Add collection MCP exposure mode."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "collections",
        sa.Column(
            "exposure_mode",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'discovery'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("collections", "exposure_mode")
