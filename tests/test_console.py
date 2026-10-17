from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.app import app
from coyote_mcp.auth import issue_browser_session
from coyote_mcp.db import get_session
from coyote_mcp.models import (
    Collection,
    CollectionMembership,
    CollectionToolPublication,
    MCPServer,
    Organization,
    Principal,
    RoleAssignment,
    Tool,
)
from coyote_mcp.settings import Settings


async def _browser_session(
    session_factory: async_sessionmaker[AsyncSession], role: str | None = "owner"
) -> tuple[str, Organization, Principal]:
    async with session_factory() as session:
        organization = Organization(
            slug=f"console-{uuid4().hex}", display_name="Console Organization"
        )
        session.add(organization)
        await session.flush()
        principal = Principal(
            organization_id=organization.id,
            identifier=f"console-user-{uuid4().hex}",
            display_name="Console User",
        )
        session.add(principal)
        await session.flush()
        if role is not None:
            session.add(
                RoleAssignment(
                    organization_id=organization.id,
                    principal_id=principal.id,
                    role=role,
                )
            )
        await session.commit()
        _, cookie = await issue_browser_session(session, principal, [], uuid4(), Settings())
        return cookie, organization, principal


@pytest.mark.asyncio
async def test_console_requires_browser_session_and_enters_existing_oidc_flow(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            console = await client.get("/console")
            login = await client.get("/console/login?organization=example")
            api = await client.get("/api/v1/servers")
            mcp = await client.get("/mcp")
    finally:
        app.dependency_overrides.clear()

    assert console.status_code == 303
    assert console.headers["location"] == "/console/login"
    assert login.status_code == 303
    assert login.headers["location"] == "/auth/oidc/example/login"
    assert api.status_code == 401
    assert mcp.status_code == 401


@pytest.mark.asyncio
async def test_console_dashboard_is_organization_scoped(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    cookie, organization, _ = await _browser_session(session_factory)
    async with session_factory() as session:
        server = MCPServer(
            organization_id=organization.id,
            name="ready-server",
            display_name="Ready server",
            endpoint="https://example.test/mcp",
            status="ready",
            last_synced_at=datetime.now(UTC),
        )
        unavailable = MCPServer(
            organization_id=organization.id,
            name="pending-server",
            display_name="Pending server",
            endpoint="https://pending.example.test/mcp",
            status="pending",
        )
        other_organization = Organization(slug=f"other-{uuid4().hex}", display_name="Other")
        session.add_all([server, unavailable, other_organization])
        await session.flush()
        tool = Tool(
            server_id=server.id,
            name="visible_tool",
            description="Visible",
            input_schema={"type": "object"},
            annotations={},
            fingerprint="a" * 64,
            active=True,
            last_seen_at=datetime.now(UTC),
        )
        collection = Collection(
            organization_id=organization.id,
            slug="console-tools",
            display_name="Console tools",
        )
        session.add_all([tool, collection])
        await session.flush()
        session.add_all(
            [
                CollectionMembership(
                    collection_id=collection.id,
                    server_id=server.id,
                    organization_id=organization.id,
                ),
                CollectionToolPublication(
                    collection_id=collection.id,
                    server_id=server.id,
                    tool_id=tool.id,
                    published_name="visible_tool",
                    enabled=True,
                ),
                MCPServer(
                    organization_id=other_organization.id,
                    name="other-server",
                    display_name="Other server",
                    endpoint="https://other.example.test/mcp",
                    status="ready",
                ),
            ]
        )
        await session.commit()

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            response = await client.get("/console")
            fragment = await client.get("/console", headers={"HX-Request": "true"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Console Organization" in response.text
    assert "Registered MCP servers</span><strong>2" in response.text
    assert "1 ready · 1 unavailable" in response.text
    assert "Cataloged active tools</span><strong>1" in response.text
    assert "Enabled publications</span><strong>1" in response.text
    assert "Other server" not in response.text
    assert fragment.status_code == 200
    assert "<!doctype html>" not in fragment.text.lower()
    assert "Organization-scoped registry status" in fragment.text


@pytest.mark.asyncio
async def test_console_enforces_rbac_and_renders_empty_dashboard(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    unauthorized_cookie, _, _ = await _browser_session(session_factory, role=None)
    authorized_cookie, _, _ = await _browser_session(session_factory)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, unauthorized_cookie)
            forbidden = await client.get("/console")
            client.cookies.set(Settings().browser_session_cookie_name, authorized_cookie)
            empty = await client.get("/console")
            csrf_protected = await client.post("/api/v1/servers", json={})
    finally:
        app.dependency_overrides.clear()

    assert forbidden.status_code == 403
    assert "Access denied" in forbidden.text
    assert empty.status_code == 200
    assert "No registered servers" in empty.text
    assert csrf_protected.status_code == 403
