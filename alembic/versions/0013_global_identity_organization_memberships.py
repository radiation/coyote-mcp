"""Replace organization-owned identities with global principals and memberships.

This corrective migration intentionally removes existing session, credential,
principal, role, and legacy identity-provider data. It preserves organizations
and catalog data. Operators configure the instance OIDC provider through
environment variables, bootstrap an instance administrator, and recreate
organization memberships and role assignments.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from coyote_mcp.models import Base

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_AUTH_TABLES = (
    "oidc_login_transactions",
    "browser_sessions",
    "group_role_mappings",
    "external_groups",
    "external_identities",
    "identity_providers",
    "personal_access_tokens",
    "role_assignments",
    "principals",
)
_NEW_AUTH_TABLES = (
    "principals",
    "organization_memberships",
    "instance_administrators",
    "role_assignments",
    "personal_access_tokens",
    "browser_sessions",
    "external_identities",
    "external_groups",
    "group_role_mappings",
    "oidc_login_transactions",
)


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    for table_name in _AUTH_TABLES:
        op.drop_table(table_name)
    bind = op.get_bind()
    for table_name in _NEW_AUTH_TABLES:
        Base.metadata.tables[table_name].create(bind, checkfirst=False)


def downgrade() -> None:
    raise RuntimeError("0013 is a destructive corrective migration and cannot be downgraded.")
