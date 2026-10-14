"""Harden role-assignment uniqueness and allowed role values."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_role_assignments_role",
        "role_assignments",
        "role IN ('owner', 'administrator', 'maintainer', 'consumer', 'viewer')",
    )
    op.create_index(
        "uq_role_assignments_organization_scope",
        "role_assignments",
        ["principal_id", "role"],
        unique=True,
        postgresql_where=sa.text("collection_id IS NULL"),
    )
    op.create_index(
        "ix_role_assignments_principal_organization_collection",
        "role_assignments",
        ["principal_id", "organization_id", "collection_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_role_assignments_principal_organization_collection", "role_assignments")
    op.drop_index("uq_role_assignments_organization_scope", "role_assignments")
    op.drop_constraint("ck_role_assignments_role", "role_assignments", type_="check")
