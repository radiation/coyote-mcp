from collections.abc import AsyncIterator
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.app import app
from coyote_mcp.auth import ALL_ACTIONS, authenticate_token, issue_pat
from coyote_mcp.db import get_session
from coyote_mcp.models import Organization, Principal, RoleAssignment
from coyote_mcp.settings import Settings


async def credentials(session_factory: async_sessionmaker[AsyncSession]) -> dict[str, str]:
    async with session_factory() as session:
        suffix = uuid4().hex
        organization = Organization(slug=f"api-{suffix}", display_name="API")
        session.add(organization)
        await session.flush()
        principal = Principal(
            organization_id=organization.id, identifier=f"tester-{suffix}", display_name="Tester"
        )
        session.add(principal)
        await session.flush()
        session.add(
            RoleAssignment(organization_id=organization.id, principal_id=principal.id, role="owner")
        )
        await session.commit()
        _, token = await issue_pat(
            session, principal, "test", set(ALL_ACTIONS), timedelta(days=1), Settings()
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
            identity_provider = await client.post(
                "/api/v1/identity-providers",
                headers=headers,
                json={
                    "name": "Corporate",
                    "issuer": "https://issuer.example",
                    "client_id": "client",
                    "client_secret_reference": "env:auto",
                    "group_claim": "groups",
                    "jit_provisioning_enabled": True,
                },
            )
            group = await client.post(
                "/api/v1/external-groups",
                headers=headers,
                json={
                    "identity_provider_id": identity_provider.json()["id"],
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
    assert identity_provider.status_code == 201
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
        owner = Principal(
            organization_id=organization.id,
            identifier=f"owner-{suffix}",
            display_name="Owner",
            enabled=True,
        )
        service = Principal(
            organization_id=organization.id,
            identifier=f"service-{suffix}",
            display_name="Service",
            identity_type="service",
            enabled=True,
        )
        session.add_all([owner, service])
        await session.flush()
        session.add_all(
            [
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
            session, owner, "policy-only", {"policy:manage"}, timedelta(days=1), Settings()
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
