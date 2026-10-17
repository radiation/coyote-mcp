"""Remove the untouched legacy default organization seed.

Revision 0004 seeded ``default`` while introducing tenant ownership. New
deployments now start without departments, but existing deployments retain that
organization whenever any catalog or authorization record depends on it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            DELETE FROM organizations
            WHERE slug = 'default'
              AND display_name = 'Default Organization'
              AND NOT EXISTS (
                  SELECT 1 FROM servers WHERE servers.organization_id = organizations.id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM collections WHERE collections.organization_id = organizations.id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM organization_memberships
                  WHERE organization_memberships.organization_id = organizations.id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM role_assignments
                  WHERE role_assignments.organization_id = organizations.id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM personal_access_tokens
                  WHERE personal_access_tokens.organization_id = organizations.id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM external_groups
                  WHERE external_groups.organization_id = organizations.id
              )
            """
        )
    )


def downgrade() -> None:
    pass
