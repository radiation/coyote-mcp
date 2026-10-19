"""Extend audit actions for administrative identity mutations."""

from collections.abc import Sequence

from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_PREVIOUS_ACTIONS = (
    "'organization.created', "
    "'server.created', 'server.updated', 'server.enabled', 'server.disabled', "
    "'server.deleted', 'server.sync', "
    "'collection.created', 'collection.updated', 'collection.enabled', "
    "'collection.disabled', 'collection.membership_added', "
    "'collection.membership_removed', "
    "'publication.created', 'publication.updated', 'publication.deleted', "
    "'credential.created', 'credential.revoked', "
    "'connection.started', 'connection.connected', 'connection.disconnected', "
    "'policy.updated', 'authentication.failed', 'authorization.denied', "
    "'mcp.execution'"
)
_NEW_ACTIONS = (
    "'principal.created', 'principal.disabled', 'group.created', 'role_mapping.created', "
    + _PREVIOUS_ACTIONS
)


def _set_action_constraint(actions: str) -> None:
    op.drop_constraint("ck_audit_events_action", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_action", "audit_events", f"action IN ({actions})")


def upgrade() -> None:
    _set_action_constraint(_NEW_ACTIONS)


def downgrade() -> None:
    _set_action_constraint(_PREVIOUS_ACTIONS)
