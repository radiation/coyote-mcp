"""Replace the stored browser-session CSRF hash with a rotation epoch.

CSRF tokens are now derived from the session's stored secret hash and this
non-secret epoch, so every page render can reuse the same token without
invalidating forms that were already opened.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "browser_sessions",
        sa.Column("csrf_epoch", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.drop_column("browser_sessions", "csrf_token_hash")


def downgrade() -> None:
    op.add_column(
        "browser_sessions",
        sa.Column("csrf_token_hash", sa.String(128), nullable=True),
    )
    op.drop_column("browser_sessions", "csrf_epoch")
