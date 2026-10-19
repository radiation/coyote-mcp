from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.app import app
from coyote_mcp.audit import AuditAction, AuditActorType, AuditOutcome, AuditTargetType
from coyote_mcp.audit_retrieval import (
    AuditEventFilters,
    AuditQueryValidationError,
    AuditRetrievalAuthorizationError,
    get_audit_event,
    list_audit_events,
)
from coyote_mcp.auth import AuthenticatedPrincipal, issue_pat
from coyote_mcp.db import get_session
from coyote_mcp.models import (
    AuditEvent,
    Organization,
    OrganizationMembership,
    Principal,
    RoleAssignment,
)
from coyote_mcp.settings import Settings


async def add_principal(
    session: AsyncSession,
    organization: Organization,
    *,
    identifier: str,
    role: str,
    identity_type: str = "human",
) -> Principal:
    principal = Principal(
        identifier=identifier,
        display_name=identifier.title(),
        identity_type=identity_type,
    )
    session.add(principal)
    await session.flush()
    session.add_all(
        [
            OrganizationMembership(organization_id=organization.id, principal_id=principal.id),
            RoleAssignment(
                organization_id=organization.id,
                principal_id=principal.id,
                role=role,
            ),
        ]
    )
    return principal


def add_event(
    session: AsyncSession,
    organization: Organization,
    *,
    event_id: UUID,
    occurred_at: datetime,
    actor: Principal | None = None,
    action: AuditAction = AuditAction.SERVER_CREATED,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    target_type: AuditTargetType = AuditTargetType.SERVER,
    target_id: UUID | None = None,
    metadata: dict[str, str | int | bool] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        id=event_id,
        occurred_at=occurred_at,
        organization_id=organization.id,
        actor_id=actor.id if actor is not None else None,
        actor_type=AuditActorType.HUMAN.value if actor is not None else AuditActorType.SYSTEM.value,
        action=action.value,
        target_type=target_type.value,
        target_id=target_id,
        outcome=outcome.value,
        metadata_=metadata or {},
    )
    session.add(event)
    return event


def current(principal: Principal, organization: Organization) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(principal, frozenset({"audit:read"}), None, organization.id)


@pytest.mark.asyncio
async def test_retrieval_is_organization_scoped_and_authorized(
    session: AsyncSession, organization: Organization
) -> None:
    other = Organization(slug="audit-other", display_name="Audit Other")
    session.add(other)
    owner = await add_principal(session, organization, identifier="audit-owner", role="owner")
    other_owner = await add_principal(session, other, identifier="other-owner", role="owner")
    event = add_event(
        session,
        organization,
        event_id=UUID(int=1),
        occurred_at=datetime(2026, 10, 19, tzinfo=UTC),
        actor=owner,
    )
    other_event = add_event(
        session,
        other,
        event_id=UUID(int=2),
        occurred_at=datetime(2026, 10, 19, tzinfo=UTC),
        actor=other_owner,
    )
    await session.commit()

    page = await list_audit_events(session, current(owner, organization))
    assert [item.id for item in page.events] == [event.id]
    assert await get_audit_event(session, current(owner, organization), other_event.id) is None
    other_page = await list_audit_events(session, current(other_owner, other))
    assert other_page.events[0].id == other_event.id


@pytest.mark.asyncio
async def test_retrieval_requires_owner_or_administrator_and_rejects_service_principals(
    session: AsyncSession, organization: Organization
) -> None:
    viewer = await add_principal(session, organization, identifier="audit-viewer", role="viewer")
    service = await add_principal(
        session,
        organization,
        identifier="audit-service",
        role="owner",
        identity_type="service",
    )
    await session.commit()

    with pytest.raises(AuditRetrievalAuthorizationError):
        await list_audit_events(session, current(viewer, organization))
    with pytest.raises(AuditRetrievalAuthorizationError):
        await list_audit_events(session, current(service, organization))


@pytest.mark.asyncio
async def test_retrieval_filters_on_historical_actor_uuid(
    session: AsyncSession, organization: Organization
) -> None:
    owner = await add_principal(session, organization, identifier="filter-owner", role="owner")
    target_id = UUID(int=12)
    matching = add_event(
        session,
        organization,
        event_id=UUID(int=1),
        occurred_at=datetime(2026, 10, 19, 10, tzinfo=UTC),
        actor=owner,
        action=AuditAction.SERVER_CREATED,
        target_id=target_id,
        metadata={"server_name": "safe"},
    )
    add_event(
        session,
        organization,
        event_id=UUID(int=2),
        occurred_at=datetime(2026, 10, 19, 11, tzinfo=UTC),
        actor=owner,
        action=AuditAction.MCP_EXECUTION,
        outcome=AuditOutcome.FAILURE,
    )
    await session.commit()

    page = await list_audit_events(
        session,
        current(owner, organization),
        filters=AuditEventFilters(
            occurred_after=datetime(2026, 10, 19, 9, tzinfo=UTC),
            occurred_before=datetime(2026, 10, 19, 10, 30, tzinfo=UTC),
            action=AuditAction.SERVER_CREATED,
            outcome=AuditOutcome.SUCCESS,
            actor_id=owner.id,
            target_type=AuditTargetType.SERVER,
            target_id=target_id,
        ),
    )
    assert [item.id for item in page.events] == [matching.id]

    historical_actor = await add_principal(
        session, organization, identifier="deleted-actor", role="viewer"
    )
    historical_event = add_event(
        session,
        organization,
        event_id=UUID(int=3),
        occurred_at=datetime(2026, 10, 19, 12, tzinfo=UTC),
        actor=historical_actor,
    )
    historical_actor_id = historical_actor.id
    await session.commit()
    await session.delete(historical_actor)
    await session.commit()

    historical_page = await list_audit_events(
        session,
        current(owner, organization),
        filters=AuditEventFilters(actor_id=historical_actor_id),
    )
    assert [item.id for item in historical_page.events] == [historical_event.id]


@pytest.mark.asyncio
async def test_keyset_pagination_is_stable_and_tenant_scoped(
    session: AsyncSession, organization: Organization
) -> None:
    other = Organization(slug="cursor-other", display_name="Cursor Other")
    session.add(other)
    owner = await add_principal(session, organization, identifier="cursor-owner", role="owner")
    other_owner = await add_principal(session, other, identifier="cursor-other-owner", role="owner")
    occurred_at = datetime(2026, 10, 19, 10, tzinfo=UTC)
    oldest = add_event(
        session,
        organization,
        event_id=UUID(int=1),
        occurred_at=occurred_at - timedelta(seconds=1),
    )
    second = add_event(session, organization, event_id=UUID(int=2), occurred_at=occurred_at)
    newest = add_event(
        session,
        organization,
        event_id=UUID(int=3),
        occurred_at=occurred_at + timedelta(seconds=1),
    )
    await session.commit()

    first_page = await list_audit_events(session, current(owner, organization), limit=2)
    assert [item.id for item in first_page.events] == [newest.id, second.id]
    assert first_page.next_cursor is not None
    add_event(
        session,
        organization,
        event_id=UUID(int=4),
        occurred_at=occurred_at + timedelta(seconds=2),
    )
    await session.commit()

    second_page = await list_audit_events(
        session, current(owner, organization), cursor=first_page.next_cursor
    )
    assert [item.id for item in second_page.events] == [oldest.id]
    assert (
        await list_audit_events(session, current(other_owner, other), cursor=first_page.next_cursor)
    ).events == []
    with pytest.raises(AuditQueryValidationError):
        await list_audit_events(session, current(owner, organization), cursor="not-a-cursor")
    with pytest.raises(AuditQueryValidationError):
        await list_audit_events(session, current(owner, organization), limit=101)


@pytest.mark.asyncio
async def test_audit_api_is_read_only_and_uses_safe_response_schema(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    async with session_factory() as session:
        organization = Organization(slug="audit-api", display_name="Audit API")
        other = Organization(slug="audit-api-other", display_name="Audit API Other")
        session.add_all([organization, other])
        await session.flush()
        owner = await add_principal(session, organization, identifier="api-owner", role="owner")
        viewer = await add_principal(session, organization, identifier="api-viewer", role="viewer")
        other_owner = await add_principal(
            session, other, identifier="api-other-owner", role="owner"
        )
        event = add_event(
            session,
            organization,
            event_id=UUID(int=20),
            occurred_at=datetime(2026, 10, 19, tzinfo=UTC),
            actor=owner,
            metadata={"server_name": "safe"},
        )
        other_event = add_event(
            session,
            other,
            event_id=UUID(int=21),
            occurred_at=datetime(2026, 10, 19, tzinfo=UTC),
            actor=other_owner,
        )
        await session.commit()
        _, owner_token = await issue_pat(
            session,
            owner,
            organization.id,
            "audit-owner",
            {"audit:read"},
            timedelta(days=1),
            Settings(),
        )
        _, viewer_token = await issue_pat(
            session,
            viewer,
            organization.id,
            "audit-viewer",
            {"server:read"},
            timedelta(days=1),
            Settings(),
        )

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            headers = {"Authorization": f"Bearer {owner_token}"}
            listing = await client.get(
                f"/api/v1/audit-events?limit=1&actor_id={owner.id}", headers=headers
            )
            detail = await client.get(f"/api/v1/audit-events/{event.id}", headers=headers)
            cross_tenant = await client.get(
                f"/api/v1/audit-events/{other_event.id}", headers=headers
            )
            invalid_cursor = await client.get(
                "/api/v1/audit-events?cursor=invalid", headers=headers
            )
            invalid_limit = await client.get("/api/v1/audit-events?limit=101", headers=headers)
            denied = await client.get(
                "/api/v1/audit-events",
                headers={"Authorization": f"Bearer {viewer_token}"},
            )
    finally:
        app.dependency_overrides.clear()

    assert listing.status_code == 200
    assert listing.json()["events"][0]["id"] == str(event.id)
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body == {
        "id": str(event.id),
        "occurred_at": detail_body["occurred_at"],
        "actor_id": str(owner.id),
        "actor_type": "human",
        "action": "server.created",
        "target_type": "server",
        "target_id": None,
        "outcome": "success",
        "request_id": None,
        "metadata": {"server_name": "safe"},
    }
    assert detail_body["occurred_at"].startswith("2026-10-19T00:00:00")
    assert cross_tenant.status_code == 404
    assert invalid_cursor.status_code == 422
    assert invalid_limit.status_code == 422
    assert denied.status_code == 403
