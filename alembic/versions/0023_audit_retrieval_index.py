"""Add keyset pagination index for audit retrieval."""

from collections.abc import Sequence

from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_audit_events_organization_occurred_at_id",
        "audit_events",
        ["organization_id", "occurred_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_organization_occurred_at_id", table_name="audit_events")
