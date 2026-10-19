from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.audit import (
    AuditAction,
    AuditActorType,
    AuditMetadataValidationError,
    AuditOutcome,
    AuditPersistenceError,
    AuditTargetType,
    record_audit_event,
)
from coyote_mcp.models import AuditEvent, Organization, Principal


async def _principal(session: AsyncSession) -> Principal:
    principal = Principal(identifier="audit-user", display_name="Audit User")
    session.add(principal)
    await session.flush()
    return principal


@pytest.mark.asyncio
async def test_records_human_event_in_caller_transaction(
    session: AsyncSession, organization: Organization
) -> None:
    principal = await _principal(session)

    event = await record_audit_event(
        session,
        organization_id=organization.id,
        actor_type=AuditActorType.HUMAN,
        actor_id=principal.id,
        action=AuditAction.SERVER_CREATED,
        target_type=AuditTargetType.SERVER,
        target_id=uuid4(),
        outcome=AuditOutcome.SUCCESS,
        metadata={"server_name": "example", "transport": "streamable_http"},
        request_id_value="request-123",
    )
    await session.commit()

    stored = await session.scalar(select(AuditEvent).where(AuditEvent.id == event.id))
    assert stored is not None
    assert stored.organization_id == organization.id
    assert stored.actor_id == principal.id
    assert stored.request_id == "request-123"
    assert stored.metadata_ == {"server_name": "example", "transport": "streamable_http"}


@pytest.mark.asyncio
async def test_rollback_removes_uncommitted_event(
    session: AsyncSession, organization: Organization
) -> None:
    await record_audit_event(
        session,
        organization_id=organization.id,
        actor_type=AuditActorType.SYSTEM,
        actor_id=None,
        action=AuditAction.SERVER_SYNC,
        target_type=AuditTargetType.SERVER,
        target_id=uuid4(),
        outcome=AuditOutcome.FAILURE,
        metadata={"result_code": "timeout"},
    )
    await session.rollback()

    assert await session.scalar(select(AuditEvent)) is None


@pytest.mark.asyncio
async def test_audit_write_failure_prevents_associated_mutation(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    organization = Organization(slug="audit-rollback", display_name="Audit Rollback")
    session.add(organization)

    async def failing_flush() -> None:
        raise IntegrityError("INSERT INTO audit_events", {}, RuntimeError("database unavailable"))

    monkeypatch.setattr(session, "flush", failing_flush)
    with pytest.raises(AuditPersistenceError):
        await record_audit_event(
            session,
            organization_id=organization.id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=None,
            action=AuditAction.ORGANIZATION_CREATED,
            target_type=AuditTargetType.ORGANIZATION,
            target_id=organization.id,
            outcome=AuditOutcome.SUCCESS,
            metadata={"organization_slug": "audit-rollback"},
        )
    await session.rollback()

    assert (
        await session.scalar(select(Organization).where(Organization.slug == "audit-rollback"))
        is None
    )


@pytest.mark.asyncio
async def test_system_actor_has_no_principal_and_audit_event_survives_actor_removal(
    session: AsyncSession, organization: Organization
) -> None:
    principal = await _principal(session)
    event = await record_audit_event(
        session,
        organization_id=organization.id,
        actor_type=AuditActorType.HUMAN,
        actor_id=principal.id,
        action=AuditAction.COLLECTION_CREATED,
        target_type=AuditTargetType.COLLECTION,
        target_id=uuid4(),
        outcome=AuditOutcome.SUCCESS,
        metadata={"collection_slug": "audit"},
    )
    await session.commit()

    await session.delete(principal)
    await session.commit()

    stored = await session.scalar(select(AuditEvent).where(AuditEvent.id == event.id))
    assert stored is not None
    assert stored.actor_id == principal.id


@pytest.mark.asyncio
async def test_events_are_scoped_by_organization(
    session: AsyncSession, organization: Organization
) -> None:
    other_organization = Organization(slug="other-audit", display_name="Other Audit")
    session.add(other_organization)
    await session.flush()
    await record_audit_event(
        session,
        organization_id=organization.id,
        actor_type=AuditActorType.SYSTEM,
        actor_id=None,
        action=AuditAction.SERVER_DISABLED,
        target_type=AuditTargetType.SERVER,
        target_id=uuid4(),
        outcome=AuditOutcome.SUCCESS,
    )
    await record_audit_event(
        session,
        organization_id=other_organization.id,
        actor_type=AuditActorType.SYSTEM,
        actor_id=None,
        action=AuditAction.SERVER_DISABLED,
        target_type=AuditTargetType.SERVER,
        target_id=uuid4(),
        outcome=AuditOutcome.SUCCESS,
    )
    await session.commit()

    events = list(
        (
            await session.scalars(
                select(AuditEvent).where(AuditEvent.organization_id == organization.id)
            )
        ).all()
    )
    assert len(events) == 1
    assert events[0].organization_id == organization.id


@pytest.mark.asyncio
async def test_metadata_rejects_sensitive_and_unbounded_values(
    session: AsyncSession, organization: Organization
) -> None:
    for metadata in (
        {"authorization": "Bearer secret"},
        {"server_name": "Bearer secret"},
        {"server_name": "x" * 257},
        {"server_name": {"untrusted": "value"}},
    ):
        with pytest.raises(AuditMetadataValidationError):
            await record_audit_event(
                session,
                organization_id=organization.id,
                actor_type=AuditActorType.SYSTEM,
                actor_id=None,
                action=AuditAction.SERVER_CREATED,
                target_type=AuditTargetType.SERVER,
                target_id=uuid4(),
                outcome=AuditOutcome.SUCCESS,
                metadata=metadata,
            )


@pytest.mark.asyncio
async def test_orm_rejects_audit_event_mutation_and_deletion(
    session: AsyncSession, organization: Organization
) -> None:
    event = await record_audit_event(
        session,
        organization_id=organization.id,
        actor_type=AuditActorType.SYSTEM,
        actor_id=None,
        action=AuditAction.SERVER_DISABLED,
        target_type=AuditTargetType.SERVER,
        target_id=uuid4(),
        outcome=AuditOutcome.SUCCESS,
    )
    await session.commit()

    event.outcome = AuditOutcome.FAILURE.value
    with pytest.raises(TypeError, match="append-only"):
        await session.flush()
    await session.rollback()

    await session.delete(event)
    with pytest.raises(TypeError, match="append-only"):
        await session.flush()
