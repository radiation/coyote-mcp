import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp import api, audit
from coyote_mcp.app import app
from coyote_mcp.auth import (
    ALL_ACTIONS,
    AuthenticatedPrincipal,
    authenticate_token,
    issue_browser_session,
    issue_pat,
)
from coyote_mcp.db import get_session
from coyote_mcp.models import (
    AuditEvent,
    InstanceAdministrator,
    Organization,
    OrganizationMembership,
    PersonalAccessToken,
    Principal,
    RoleAssignment,
    Tool,
)
from coyote_mcp.settings import Settings


async def credentials(session_factory: async_sessionmaker[AsyncSession]) -> dict[str, str]:
    async with session_factory() as session:
        suffix = uuid4().hex
        organization = Organization(slug=f"api-{suffix}", display_name="API")
        session.add(organization)
        await session.flush()
        principal = Principal(identifier=f"tester-{suffix}", display_name="Tester")
        session.add(principal)
        await session.flush()
        session.add(
            OrganizationMembership(organization_id=organization.id, principal_id=principal.id)
        )
        session.add(
            RoleAssignment(organization_id=organization.id, principal_id=principal.id, role="owner")
        )
        await session.commit()
        _, token = await issue_pat(
            session,
            principal,
            organization.id,
            "test",
            set(ALL_ACTIONS),
            timedelta(days=1),
            Settings(),
        )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_register_server_and_duplicate_response(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        headers = await credentials(session_factory)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            payload = {
                "name": "example",
                "display_name": "Example",
                "endpoint": "https://example.com/mcp",
            }
            response = await client.post("/api/v1/servers", json=payload, headers=headers)
            duplicate = await client.post("/api/v1/servers", json=payload, headers=headers)
            listing = await client.get("/api/v1/servers", headers=headers)
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    assert response.json()["name"] == "example"
    assert duplicate.status_code == 409
    assert [server["name"] for server in listing.json()] == ["example"]


@pytest.mark.asyncio
async def test_instance_administrator_read_only_pat_cannot_register_server(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    async with session_factory() as session:
        organization = Organization(slug="narrow-admin", display_name="Narrow Admin")
        principal = Principal(identifier="narrow-admin", display_name="Narrow Admin")
        session.add_all([organization, principal])
        await session.flush()
        session.add_all(
            [
                OrganizationMembership(organization_id=organization.id, principal_id=principal.id),
                RoleAssignment(
                    organization_id=organization.id, principal_id=principal.id, role="viewer"
                ),
                InstanceAdministrator(principal_id=principal.id),
            ]
        )
        await session.commit()
        _, token = await issue_pat(
            session,
            principal,
            organization.id,
            "read-only",
            {"server:read"},
            timedelta(days=1),
            Settings(),
        )

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/servers",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "name": "denied",
                    "display_name": "Denied",
                    "endpoint": "https://example.com/mcp",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_require_rejects_organization_action_without_active_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        principal = Principal(identifier="no-organization", display_name="No Organization")
        session.add(principal)
        await session.commit()
        current = AuthenticatedPrincipal(principal, frozenset({"server:read"}), None, None)

        with pytest.raises(HTTPException, match="active organization") as error:
            await api.require(session, current, "server:read")

    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_require_independently_audits_denied_authenticated_principal(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        organization = Organization(slug="denial-audit", display_name="Denial Audit")
        principal = Principal(identifier="denial-audit", display_name="Denial Audit")
        session.add_all([organization, principal])
        await session.flush()
        session.add(
            OrganizationMembership(organization_id=organization.id, principal_id=principal.id)
        )
        await session.commit()
        current = AuthenticatedPrincipal(principal, frozenset(), None, organization.id)

        with pytest.raises(HTTPException):
            await api.require(session, current, "server:read")

        event = await session.scalar(
            select(AuditEvent).where(AuditEvent.action == "authorization.denied")
        )
        assert event is not None
        assert event.organization_id == organization.id
        assert event.actor_id == principal.id
        assert event.metadata_ == {"action": "server:read", "reason_code": "scope_not_granted"}


@pytest.mark.asyncio
async def test_require_preserves_denial_when_independent_audit_times_out(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def stalled_record(*_: object, **__: object) -> AuditEvent:
        await asyncio.sleep(1)
        raise AssertionError("The independent audit deadline did not cancel the write.")

    monkeypatch.setenv("COYOTE_INDEPENDENT_AUDIT_TIMEOUT_SECONDS", "0.001")
    monkeypatch.setattr(audit, "record_audit_event", stalled_record)
    async with session_factory() as session:
        organization = Organization(slug="denial-timeout", display_name="Denial Timeout")
        principal = Principal(identifier="denial-timeout", display_name="Denial Timeout")
        session.add_all([organization, principal])
        await session.flush()
        session.add(
            OrganizationMembership(organization_id=organization.id, principal_id=principal.id)
        )
        await session.commit()
        current = AuthenticatedPrincipal(principal, frozenset(), None, organization.id)

        with pytest.raises(HTTPException) as error:
            await api.require(session, current, "server:read")

    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_api_rejects_browser_session_without_active_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    async with session_factory() as session:
        principal = Principal(identifier="unaffiliated-browser", display_name="Unaffiliated")
        session.add(principal)
        await session.commit()
        _, cookie = await issue_browser_session(session, principal, [], Settings())

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            api_response = await client.get(f"/api/v1/servers/{uuid4()}")
            console_response = await client.get("/console")
    finally:
        app.dependency_overrides.clear()

    assert api_response.status_code == 403
    assert api_response.json() == {"detail": "An active organization is required."}
    assert console_response.status_code == 200
    assert "Select organization" in console_response.text


@pytest.mark.asyncio
async def test_pat_self_service_is_scoped_to_active_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    async with session_factory() as session:
        suffix = uuid4().hex
        first = Organization(slug=f"first-{suffix}", display_name="First")
        second = Organization(slug=f"second-{suffix}", display_name="Second")
        principal = Principal(identifier=f"multi-{suffix}", display_name="Multi Organization")
        session.add_all([first, second, principal])
        await session.flush()
        session.add_all(
            [
                OrganizationMembership(organization_id=first.id, principal_id=principal.id),
                OrganizationMembership(organization_id=second.id, principal_id=principal.id),
                RoleAssignment(organization_id=first.id, principal_id=principal.id, role="owner"),
                RoleAssignment(organization_id=second.id, principal_id=principal.id, role="viewer"),
            ]
        )
        await session.commit()
        first_pat, first_token = await issue_pat(
            session,
            principal,
            first.id,
            "first-token",
            {"credential:create", "credential:revoke"},
            timedelta(days=1),
            Settings(),
        )
        second_pat, _ = await issue_pat(
            session,
            principal,
            second.id,
            "second-token",
            {"server:read"},
            timedelta(days=1),
            Settings(),
        )

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            listed = await client.get(
                "/api/v1/me/pats", headers={"Authorization": f"Bearer {first_token}"}
            )
            cross_organization_revoke = await client.delete(
                f"/api/v1/me/pats/{second_pat.id}",
                headers={"Authorization": f"Bearer {first_token}"},
            )
    finally:
        app.dependency_overrides.clear()

    assert [item["id"] for item in listed.json()] == [str(first_pat.id)]
    assert cross_organization_revoke.status_code == 404
    async with session_factory() as session:
        persisted = await session.get(PersonalAccessToken, second_pat.id)
    assert persisted is not None
    assert persisted.revoked_at is None


@pytest.mark.asyncio
async def test_collection_and_server_catalog_endpoints(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        headers = await credentials(session_factory)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            server = await client.post(
                "/api/v1/servers",
                headers=headers,
                json={
                    "name": "catalog",
                    "display_name": "Catalog",
                    "endpoint": "https://example.com/mcp",
                },
            )
            server_id = server.json()["id"]
            server_detail = await client.get(f"/api/v1/servers/{server_id}", headers=headers)
            server_tools = await client.get(f"/api/v1/servers/{server_id}/tools", headers=headers)
            collection = await client.post(
                "/api/v1/collections",
                headers=headers,
                json={
                    "slug": "engineering",
                    "display_name": "Engineering",
                    "exposure_mode": "native",
                },
            )
            collection_id = collection.json()["id"]
            collection_list = await client.get("/api/v1/collections", headers=headers)
            collection_update = await client.patch(
                f"/api/v1/collections/{collection_id}",
                headers=headers,
                json={"exposure_mode": "discovery"},
            )
            membership = await client.post(
                f"/api/v1/collections/{collection_id}/servers",
                headers=headers,
                json={"server_id": server_id},
            )
            collection_detail = await client.get(
                f"/api/v1/collections/{collection_id}", headers=headers
            )
            collection_tools = await client.get(
                f"/api/v1/collections/{collection_id}/tools", headers=headers
            )
            deleted = await client.delete(
                f"/api/v1/collections/{collection_id}/servers/{server_id}", headers=headers
            )
            collection_without_membership = await client.get(
                f"/api/v1/collections/{collection_id}", headers=headers
            )
    finally:
        app.dependency_overrides.clear()

    assert server.status_code == 201
    assert server_detail.json()["id"] == server_id
    assert server_tools.json() == []
    assert collection.status_code == 201
    assert collection.json()["exposure_mode"] == "native"
    assert [item["slug"] for item in collection_list.json()] == ["engineering"]
    assert collection_update.json()["exposure_mode"] == "discovery"
    assert membership.status_code == 201
    assert [item["server_id"] for item in collection_detail.json()["memberships"]] == [server_id]
    assert collection_tools.json() == []
    assert deleted.status_code == 204
    assert collection_without_membership.json()["memberships"] == []


@pytest.mark.asyncio
async def test_collection_publication_management_endpoints(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        headers = await credentials(session_factory)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            server = await client.post(
                "/api/v1/servers",
                headers=headers,
                json={
                    "name": "published",
                    "display_name": "Published",
                    "endpoint": "https://example.com/mcp",
                },
            )
            collection = await client.post(
                "/api/v1/collections",
                headers=headers,
                json={"slug": "published", "display_name": "Published", "exposure_mode": "native"},
            )
            collection_id = collection.json()["id"]
            await client.post(
                f"/api/v1/collections/{collection_id}/servers",
                headers=headers,
                json={"server_id": server.json()["id"]},
            )
            async with session_factory() as session:
                tools = [
                    Tool(
                        server_id=UUID(server.json()["id"]),
                        name=name,
                        description=name,
                        input_schema={"type": "object"},
                        annotations={},
                        fingerprint=name.ljust(64, "0"),
                        active=True,
                        last_seen_at=datetime.now(UTC),
                    )
                    for name in ("first", "second")
                ]
                session.add_all(tools)
                await session.commit()
                first_tool_id, second_tool_id = (str(tool.id) for tool in tools)

            available = await client.get(
                f"/api/v1/collections/{collection_id}/tools", headers=headers
            )
            published = await client.post(
                f"/api/v1/collections/{collection_id}/publications",
                headers=headers,
                json={"tool_id": first_tool_id, "published_name": "curated_first"},
            )
            collision = await client.post(
                f"/api/v1/collections/{collection_id}/publications",
                headers=headers,
                json={"tool_id": second_tool_id, "published_name": "curated_first"},
            )
            publication_id = published.json()["id"]
            updated = await client.patch(
                f"/api/v1/collections/{collection_id}/publications/{publication_id}",
                headers=headers,
                json={"description_override": "Curated first tool", "enabled": False},
            )
            null_enabled = await client.patch(
                f"/api/v1/collections/{collection_id}/publications/{publication_id}",
                headers=headers,
                json={"enabled": None},
            )
            null_name = await client.patch(
                f"/api/v1/collections/{collection_id}/publications/{publication_id}",
                headers=headers,
                json={"published_name": None},
            )
            cleared_override = await client.patch(
                f"/api/v1/collections/{collection_id}/publications/{publication_id}",
                headers=headers,
                json={"description_override": None},
            )
            listed = await client.get(
                f"/api/v1/collections/{collection_id}/publications", headers=headers
            )
            deleted = await client.delete(
                f"/api/v1/collections/{collection_id}/publications/{publication_id}",
                headers=headers,
            )
    finally:
        app.dependency_overrides.clear()

    assert [item["name"] for item in available.json()] == ["first", "second"]
    assert published.status_code == 201
    assert collision.status_code == 409
    assert updated.json()["enabled"] is False
    assert updated.json()["description_override"] == "Curated first tool"
    assert null_enabled.status_code == 422
    assert null_name.status_code == 422
    assert cleared_override.json()["description_override"] is None
    assert [item["published_name"] for item in listed.json()] == ["curated_first"]
    assert deleted.status_code == 204


@pytest.mark.asyncio
async def test_service_principal_credentials_are_admin_managed(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        headers = await credentials(session_factory)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            created = await client.post(
                "/api/v1/service-principals",
                headers=headers,
                json={
                    "identifier": "automation",
                    "display_name": "Automation",
                    "roles": ["viewer"],
                },
            )
            duplicate = await client.post(
                "/api/v1/service-principals",
                headers=headers,
                json={
                    "identifier": "automation",
                    "display_name": "Automation",
                    "roles": ["viewer"],
                },
            )
            principal_id = created.json()["id"]
            listed = await client.get("/api/v1/service-principals", headers=headers)
            issued = await client.post(
                f"/api/v1/service-principals/{principal_id}/pats",
                headers=headers,
                json={
                    "name": "worker",
                    "scopes": ["server:read"],
                    "lifetime_seconds": 3600,
                },
            )
            group = await client.post(
                "/api/v1/external-groups",
                headers=headers,
                json={
                    "external_id": "group-id",
                    "display_name": "Engineering",
                },
            )
            mapping = await client.post(
                f"/api/v1/external-groups/{group.json()['id']}/role-mappings",
                headers=headers,
                json={"role": "viewer"},
            )
            disabled = await client.post(
                f"/api/v1/service-principals/{principal_id}/disable", headers=headers
            )
    finally:
        app.dependency_overrides.clear()

    assert created.status_code == 201
    assert duplicate.status_code == 409
    assert [principal["identifier"] for principal in listed.json()] == ["automation"]
    assert issued.status_code == 201
    assert mapping.status_code == 201
    assert disabled.status_code == 204
    async with session_factory() as session:
        assert await authenticate_token(session, issued.json()["token"]) is None


@pytest.mark.asyncio
async def test_scoped_owner_pat_cannot_delegate_unscoped_permissions(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        suffix = uuid4().hex
        organization = Organization(slug=f"scoped-{suffix}", display_name="Scoped")
        session.add(organization)
        await session.flush()
        owner = Principal(identifier=f"owner-{suffix}", display_name="Owner", enabled=True)
        service = Principal(
            identifier=f"service-{suffix}",
            display_name="Service",
            identity_type="service",
            enabled=True,
        )
        session.add_all([owner, service])
        await session.flush()
        session.add_all(
            [
                OrganizationMembership(organization_id=organization.id, principal_id=owner.id),
                OrganizationMembership(organization_id=organization.id, principal_id=service.id),
                RoleAssignment(
                    organization_id=organization.id, principal_id=owner.id, role="owner"
                ),
                RoleAssignment(
                    organization_id=organization.id, principal_id=service.id, role="viewer"
                ),
            ]
        )
        await session.commit()
        _, token = await issue_pat(
            session,
            owner,
            organization.id,
            "policy-only",
            {"policy:manage"},
            timedelta(days=1),
            Settings(),
        )

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            headers = {"Authorization": f"Bearer {token}"}
            delegated_owner = await client.post(
                "/api/v1/service-principals",
                headers=headers,
                json={
                    "identifier": f"escalated-{suffix}",
                    "display_name": "Escalated",
                    "roles": ["owner"],
                },
            )
            broader_pat = await client.post(
                f"/api/v1/service-principals/{service.id}/pats",
                headers=headers,
                json={
                    "name": "broader",
                    "scopes": ["server:read"],
                    "lifetime_seconds": 3600,
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert delegated_owner.status_code == 403
    assert broader_pat.status_code == 403
