"""Bind downstream credentials and OAuth transactions to integration revisions."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "downstream_oauth_integrations",
        sa.Column("revision", sa.Integer(), nullable=False, server_default=sa.text("1")),
    )
    op.add_column(
        "downstream_connections",
        sa.Column(
            "integration_revision", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
    )
    op.add_column(
        "downstream_connections",
        sa.Column("credential_revision", sa.Integer(), nullable=False, server_default=sa.text("1")),
    )
    op.add_column(
        "downstream_oauth_transactions",
        sa.Column(
            "integration_revision", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
    )


def downgrade() -> None:
    op.drop_column("downstream_oauth_transactions", "integration_revision")
    op.drop_column("downstream_connections", "credential_revision")
    op.drop_column("downstream_connections", "integration_revision")
    op.drop_column("downstream_oauth_integrations", "revision")
