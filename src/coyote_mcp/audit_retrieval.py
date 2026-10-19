"""Read-only, organization-scoped retrieval of approved audit evidence."""

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.audit import AuditAction, AuditOutcome, AuditTargetType
from coyote_mcp.auth import AuthenticatedPrincipal, authorize
from coyote_mcp.models import AuditEvent

_MAX_PAGE_SIZE = 100


class AuditRetrievalAuthorizationError(PermissionError):
    """Raised when the authenticated caller cannot read the organization ledger."""


class AuditQueryValidationError(ValueError):
    """Raised when an audit filter or cursor is malformed."""


@dataclass(frozen=True)
class AuditEventFilters:
    occurred_after: datetime | None = None
    occurred_before: datetime | None = None
    action: AuditAction | None = None
    outcome: AuditOutcome | None = None
    actor_id: UUID | None = None
    target_type: AuditTargetType | None = None
    target_id: UUID | None = None

    def validate(self) -> None:
        for value in (self.occurred_after, self.occurred_before):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise AuditQueryValidationError("Audit time filters must include a timezone.")
        if (
            self.occurred_after is not None
            and self.occurred_before is not None
            and self.occurred_after > self.occurred_before
        ):
            raise AuditQueryValidationError("The audit time range is invalid.")


@dataclass(frozen=True)
class AuditEventPage:
    events: list[AuditEvent]
    next_cursor: str | None


def _encode_cursor(occurred_at: datetime, event_id: UUID) -> str:
    payload = json.dumps(
        {"occurred_at": occurred_at.astimezone(UTC).isoformat(), "id": str(event_id)},
        separators=(",", ":"),
    ).encode("ascii")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if cursor is None:
        return None
    if not cursor or len(cursor) > 256:
        raise AuditQueryValidationError("The audit cursor is invalid.")
    try:
        payload = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        decoded = json.loads(payload)
        if set(decoded) != {"occurred_at", "id"}:
            raise ValueError
        occurred_at = datetime.fromisoformat(decoded["occurred_at"])
        event_id = UUID(decoded["id"])
    except (ValueError, TypeError, binascii.Error, json.JSONDecodeError) as error:
        raise AuditQueryValidationError("The audit cursor is invalid.") from error
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise AuditQueryValidationError("The audit cursor is invalid.")
    return occurred_at.astimezone(UTC), event_id


async def _authorize_audit_read(session: AsyncSession, current: AuthenticatedPrincipal) -> UUID:
    if "audit:read" not in current.scopes or current.organization_id is None:
        raise AuditRetrievalAuthorizationError("Audit access is not permitted.")
    decision = await authorize(
        session,
        current.principal,
        "audit:read",
        context={"organization_id": current.organization_id},
        verified_group_ids=current.verified_group_ids,
        credential_context=current.credential_context,
    )
    if not decision.allowed:
        raise AuditRetrievalAuthorizationError("Audit access is not permitted.")
    return current.organization_id


async def list_audit_events(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    *,
    limit: int = 50,
    cursor: str | None = None,
    filters: AuditEventFilters | None = None,
) -> AuditEventPage:
    """Return one stable, bounded page from the caller's organization ledger."""
    if not 1 <= limit <= _MAX_PAGE_SIZE:
        raise AuditQueryValidationError("The audit page size is invalid.")
    filters = filters or AuditEventFilters()
    filters.validate()
    cursor_position = _decode_cursor(cursor)
    organization_id = await _authorize_audit_read(session, current)

    query = select(AuditEvent).where(AuditEvent.organization_id == organization_id)
    if filters.occurred_after is not None:
        query = query.where(AuditEvent.occurred_at >= filters.occurred_after)
    if filters.occurred_before is not None:
        query = query.where(AuditEvent.occurred_at <= filters.occurred_before)
    if filters.action is not None:
        query = query.where(AuditEvent.action == filters.action.value)
    if filters.outcome is not None:
        query = query.where(AuditEvent.outcome == filters.outcome.value)
    if filters.actor_id is not None:
        query = query.where(AuditEvent.actor_id == filters.actor_id)
    if filters.target_type is not None:
        query = query.where(AuditEvent.target_type == filters.target_type.value)
    if filters.target_id is not None:
        query = query.where(AuditEvent.target_id == filters.target_id)
    if cursor_position is not None:
        occurred_at, event_id = cursor_position
        query = query.where(
            or_(
                AuditEvent.occurred_at < occurred_at,
                and_(AuditEvent.occurred_at == occurred_at, AuditEvent.id < event_id),
            )
        )

    events = list(
        (
            await session.scalars(
                query.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(limit + 1)
            )
        ).all()
    )
    next_cursor = None
    if len(events) > limit:
        events.pop()
        final_event = events[-1]
        next_cursor = _encode_cursor(final_event.occurred_at, final_event.id)
    return AuditEventPage(events=events, next_cursor=next_cursor)


async def get_audit_event(
    session: AsyncSession, current: AuthenticatedPrincipal, event_id: UUID
) -> AuditEvent | None:
    """Return an approved event only when it belongs to the authorized organization."""
    organization_id = await _authorize_audit_read(session, current)
    return await session.scalar(
        select(AuditEvent).where(
            AuditEvent.id == event_id,
            AuditEvent.organization_id == organization_id,
        )
    )
