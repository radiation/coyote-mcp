"""Scope organization-level role uniqueness to an organization.

Global principals may hold the same organization-level role in multiple
organizations. Collection-level role uniqueness is unchanged.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("uq_role_assignments_organization_scope", "role_assignments")
    op.create_index(
        "uq_role_assignments_organization_scope",
        "role_assignments",
        ["principal_id", "organization_id", "role"],
        unique=True,
        postgresql_where=sa.text("collection_id IS NULL"),
        sqlite_where=sa.text("collection_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_role_assignments_organization_scope", "role_assignments")
    op.create_index(
        "uq_role_assignments_organization_scope",
        "role_assignments",
        ["principal_id", "role"],
        unique=True,
        postgresql_where=sa.text("collection_id IS NULL"),
        sqlite_where=sa.text("collection_id IS NULL"),
    )
