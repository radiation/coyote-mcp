"""Add immutable organization-scoped security audit events."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=True),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('human', 'service', 'system')",
            name="ck_audit_events_actor_type",
        ),
        sa.CheckConstraint(
            "(actor_type = 'system' AND actor_id IS NULL) OR "
            "(actor_type IN ('human', 'service') AND actor_id IS NOT NULL)",
            name="ck_audit_events_actor",
        ),
        sa.CheckConstraint(
            "action IN ("
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
            ")",
            name="ck_audit_events_action",
        ),
        sa.CheckConstraint(
            "target_type IN ("
            "'organization', 'principal', 'server', 'collection', 'publication', "
            "'credential', 'connection', 'policy', 'authentication', 'authorization', 'mcp_tool'"
            ")",
            name="ck_audit_events_target_type",
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'failure')",
            name="ck_audit_events_outcome",
        ),
    )
    op.create_index("ix_audit_events_organization_id", "audit_events", ["organization_id"])
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_target_id", "audit_events", ["target_id"])
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])
    op.create_index(
        "ix_audit_events_organization_occurred_at",
        "audit_events",
        ["organization_id", "occurred_at"],
    )
    op.create_index(
        "ix_audit_events_organization_target",
        "audit_events",
        ["organization_id", "target_type", "target_id"],
    )
    op.execute(
        """
        CREATE FUNCTION prevent_audit_event_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events are append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_no_update
        BEFORE UPDATE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_no_delete
        BEFORE DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation();
        """
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.execute("DROP FUNCTION prevent_audit_event_mutation()")
