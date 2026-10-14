"""Replace arbitrary OIDC secret references with provider-bound references."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE identity_providers
            SET client_secret_reference =
                'env:COYOTE_OIDC_CLIENT_SECRET_' ||
                upper(replace(organization_id::text, '-', '')) || '_' ||
                upper(replace(id::text, '-', ''))
            """
        )
    )


def downgrade() -> None:
    pass
