import base64
import html
import re
import secrets
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp import connected_apps
from coyote_mcp import console as console_module
from coyote_mcp.app import app
from coyote_mcp.auth import (
    authenticate_browser_session,
    csrf_token_for,
    issue_browser_session,
)
from coyote_mcp.console import _see_other
from coyote_mcp.db import get_session
from coyote_mcp.discovery import DiscoveredTool, DiscoveryService
from coyote_mcp.models import (
    BrowserSession,
    Collection,
    CollectionMembership,
    CollectionToolPublication,
    InstanceAdministrator,
    MCPServer,
    Organization,
    OrganizationMembership,
    Principal,
    RoleAssignment,
    Tool,
)
from coyote_mcp.settings import Settings


async def _browser_session(
    session_factory: async_sessionmaker[AsyncSession],
    role: str | None = "owner",
    *,
    instance_administrator: bool = False,
    organization: Organization | None = None,
) -> tuple[str, Organization, Principal]:
    async with session_factory() as session:
        if organization is None:
            organization = Organization(
                slug=f"console-{uuid4().hex}", display_name="Console Organization"
            )
            session.add(organization)
            await session.flush()
        principal = Principal(
            identifier=f"console-user-{uuid4().hex}",
            display_name="Console User",
        )
        session.add(principal)
        await session.flush()
        session.add(
            OrganizationMembership(organization_id=organization.id, principal_id=principal.id)
        )
        if role is not None:
            session.add(
                RoleAssignment(
                    organization_id=organization.id,
                    principal_id=principal.id,
                    role=role,
                )
            )
        if instance_administrator:
            session.add(InstanceAdministrator(principal_id=principal.id))
        await session.commit()
        browser_session, cookie = await issue_browser_session(session, principal, [], Settings())
        browser_session.active_organization_id = organization.id
        await session.commit()
        return cookie, organization, principal


async def _unaffiliated_browser_session(
    session_factory: async_sessionmaker[AsyncSession], *, instance_administrator: bool
) -> tuple[str, Principal]:
    async with session_factory() as session:
        principal = Principal(identifier=f"console-user-{uuid4().hex}", display_name="Console User")
        session.add(principal)
        await session.flush()
        if instance_administrator:
            session.add(InstanceAdministrator(principal_id=principal.id))
        await session.commit()
        _, cookie = await issue_browser_session(session, principal, [], Settings())
        return cookie, principal


def _csrf_token(response: httpx.Response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


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
            login = await client.get("/console/login?start=1")
            api = await client.get("/api/v1/servers")
            mcp = await client.get("/mcp")
    finally:
        app.dependency_overrides.clear()

    assert console.status_code == 303
    assert console.headers["location"] == "/console/login"
    assert login.status_code == 303
    assert login.headers["location"] == "/auth/oidc/login"
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


@pytest.mark.asyncio
async def test_instance_administrator_can_create_first_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    cookie, principal = await _unaffiliated_browser_session(
        session_factory, instance_administrator=True
    )
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            select_page = await client.get("/console")
            created = await client.post(
                "/console/organizations",
                data={
                    "csrf_token": _csrf_token(select_page),
                    "slug": "first-organization",
                    "display_name": "First Organization",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert select_page.status_code == 200
    assert "Create organization" in select_page.text
    assert created.status_code == 303
    assert created.headers["location"] == "/console"
    async with session_factory() as session:
        organization = await session.scalar(
            select(Organization).where(Organization.slug == "first-organization")
        )
        assert organization is not None
        membership = await session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id,
                OrganizationMembership.principal_id == principal.id,
            )
        )
        role = await session.scalar(
            select(RoleAssignment).where(
                RoleAssignment.organization_id == organization.id,
                RoleAssignment.principal_id == principal.id,
                RoleAssignment.role == "owner",
            )
        )
        browser_session = await session.scalar(
            select(BrowserSession).where(BrowserSession.principal_id == principal.id)
        )
    assert membership is not None and membership.enabled
    assert role is not None
    assert browser_session is not None
    assert browser_session.active_organization_id == organization.id


@pytest.mark.asyncio
async def test_active_instance_administrator_can_reopen_chooser_and_create_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    cookie, first, principal = await _browser_session(session_factory, instance_administrator=True)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            dashboard = await client.get("/console")
            chooser = await client.get("/console/organizations")
            created = await client.post(
                "/console/organizations",
                data={
                    "csrf_token": _csrf_token(chooser),
                    "slug": "second-organization",
                    "display_name": "Second Organization",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert dashboard.status_code == 200
    assert "Switch organization" in dashboard.text
    assert 'hx-boost="false"' in dashboard.text
    assert chooser.status_code == 200
    assert first.display_name in chooser.text
    assert "Create organization" in chooser.text
    assert created.status_code == 303
    async with session_factory() as session:
        second = await session.scalar(
            select(Organization).where(Organization.slug == "second-organization")
        )
        browser_session = await session.scalar(
            select(BrowserSession).where(BrowserSession.principal_id == principal.id)
        )
    assert second is not None
    assert browser_session is not None
    assert browser_session.active_organization_id == second.id


@pytest.mark.asyncio
async def test_active_member_can_reopen_chooser_and_switch_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    cookie, first, principal = await _browser_session(session_factory)
    async with session_factory() as session:
        second = Organization(slug="switch-target", display_name="Switch Target")
        session.add(second)
        await session.flush()
        session.add(OrganizationMembership(organization_id=second.id, principal_id=principal.id))
        await session.commit()

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            chooser = await client.get("/console/organizations")
            switched = await client.post(
                "/console/organization",
                data={"csrf_token": _csrf_token(chooser), "organization_id": str(second.id)},
            )
    finally:
        app.dependency_overrides.clear()

    assert chooser.status_code == 200
    assert first.display_name in chooser.text
    assert second.display_name in chooser.text
    assert switched.status_code == 303
    async with session_factory() as session:
        browser_session = await session.scalar(
            select(BrowserSession).where(BrowserSession.principal_id == principal.id)
        )
    assert browser_session is not None
    assert browser_session.active_organization_id == second.id


@pytest.mark.asyncio
async def test_non_administrator_cannot_create_first_organization_directly(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    cookie, _ = await _unaffiliated_browser_session(session_factory, instance_administrator=False)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            select_page = await client.get("/console")
            denied = await client.post(
                "/console/organizations",
                data={
                    "csrf_token": (await client.get("/auth/oidc/csrf")).json()["csrf_token"],
                    "slug": "denied-organization",
                    "display_name": "Denied Organization",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert select_page.status_code == 200
    assert "Create organization" not in select_page.text
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_duplicate_organization_slug_rolls_back_first_run_bootstrap(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    async with session_factory() as session:
        session.add_all(
            [
                Organization(slug="taken-organization", display_name="Taken Organization"),
                Organization(slug="another-organization", display_name="Another Organization"),
            ]
        )
        await session.commit()
    cookie, principal = await _unaffiliated_browser_session(
        session_factory, instance_administrator=True
    )
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            select_page = await client.get("/console")
            duplicate = await client.post(
                "/console/organizations",
                data={
                    "csrf_token": _csrf_token(select_page),
                    "slug": "taken-organization",
                    "display_name": "Taken Organization",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert duplicate.status_code == 409
    assert "already exists" in duplicate.text
    async with session_factory() as session:
        assert (
            await session.scalar(
                select(OrganizationMembership).where(
                    OrganizationMembership.principal_id == principal.id
                )
            )
            is None
        )
        assert (
            await session.scalar(
                select(RoleAssignment).where(RoleAssignment.principal_id == principal.id)
            )
            is None
        )
        browser_session = await session.scalar(
            select(BrowserSession).where(BrowserSession.principal_id == principal.id)
        )
    assert browser_session is not None
    assert browser_session.active_organization_id is None


@pytest.mark.asyncio
async def test_first_run_creation_does_not_grant_access_to_another_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    async with session_factory() as session:
        other_organization = Organization(
            slug="other-organization", display_name="Other Organization"
        )
        other_principal = Principal(identifier="other-user", display_name="Other User")
        session.add_all([other_organization, other_principal])
        await session.flush()
        session.add(
            OrganizationMembership(
                organization_id=other_organization.id, principal_id=other_principal.id
            )
        )
        session.add(Organization(slug="second-organization", display_name="Second Organization"))
        await session.commit()
    cookie, principal = await _unaffiliated_browser_session(
        session_factory, instance_administrator=True
    )
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            select_page = await client.get("/console")
            created = await client.post(
                "/console/organizations",
                data={
                    "csrf_token": _csrf_token(select_page),
                    "slug": "isolated-organization",
                    "display_name": "Isolated Organization",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert created.status_code == 303
    async with session_factory() as session:
        memberships = list(
            (
                await session.scalars(
                    select(OrganizationMembership).where(
                        OrganizationMembership.principal_id == principal.id
                    )
                )
            ).all()
        )
    assert len(memberships) == 1
    assert memberships[0].organization_id != other_organization.id


@pytest.mark.asyncio
async def test_instance_administrator_can_select_and_administer_ownerless_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    async with session_factory() as session:
        ownerless = Organization(slug="ownerless", display_name="Ownerless Department")
        session.add_all(
            [ownerless, Organization(slug="second-ownerless", display_name="Second Ownerless")]
        )
        await session.commit()
    cookie, administrator = await _unaffiliated_browser_session(
        session_factory, instance_administrator=True
    )
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            select_page = await client.get("/console")
            selected = await client.post(
                "/console/organization",
                data={"csrf_token": _csrf_token(select_page), "organization_id": str(ownerless.id)},
            )
            csrf_token = (await client.get("/auth/oidc/csrf")).json()["csrf_token"]
            created = await client.post(
                "/api/v1/servers",
                headers={"x-csrf-token": csrf_token},
                json={
                    "name": "ownerless-server",
                    "display_name": "Ownerless Server",
                    "endpoint": "https://example.com/mcp",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert select_page.status_code == 200
    assert "Ownerless Department" in select_page.text
    assert "Create organization" in select_page.text
    assert selected.status_code == 303
    assert created.status_code == 201
    async with session_factory() as session:
        assert (
            await session.scalar(
                select(OrganizationMembership).where(
                    OrganizationMembership.principal_id == administrator.id
                )
            )
            is None
        )


@pytest.mark.asyncio
async def test_ordinary_user_cannot_select_unrelated_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    cookie, organization, principal = await _browser_session(session_factory)
    async with session_factory() as session:
        unrelated = Organization(slug="unrelated", display_name="Unrelated Department")
        additional_membership = Organization(
            slug="additional", display_name="Additional Department"
        )
        session.add_all([unrelated, additional_membership])
        await session.flush()
        session.add(
            OrganizationMembership(
                organization_id=additional_membership.id, principal_id=principal.id
            )
        )
        browser_session = await session.scalar(
            select(BrowserSession).where(BrowserSession.principal_id == principal.id)
        )
        assert browser_session is not None
        browser_session.active_organization_id = None
        await session.commit()
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            select_page = await client.get("/console")
            denied = await client.post(
                "/console/organization",
                data={"csrf_token": _csrf_token(select_page), "organization_id": str(unrelated.id)},
            )
    finally:
        app.dependency_overrides.clear()

    assert "Unrelated Department" not in select_page.text
    assert organization.display_name in select_page.text
    assert "Additional Department" in select_page.text
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_console_rejects_invalid_organization_forms_and_unknown_pages(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    cookie, _ = await _unaffiliated_browser_session(session_factory, instance_administrator=True)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            select_page = await client.get("/console")
            invalid_create = await client.post(
                "/console/organizations",
                data={
                    "csrf_token": _csrf_token(select_page),
                    "slug": "Invalid Slug",
                    "display_name": "Invalid",
                },
            )
            csrf_token = (await client.get("/auth/oidc/csrf")).json()["csrf_token"]
            invalid_selection = await client.post(
                "/console/organization",
                data={"csrf_token": csrf_token, "organization_id": "not-a-uuid"},
            )
            unknown = await client.get("/console/unknown")
    finally:
        app.dependency_overrides.clear()

    assert invalid_create.status_code == 422
    assert "Enter a valid organization slug" in invalid_create.text
    assert invalid_selection.status_code == 403
    assert unknown.status_code == 404


@pytest.mark.asyncio
async def test_console_placeholder_pages_select_organization_and_enforce_page_rbac(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    owner_cookie, _, owner = await _browser_session(session_factory)
    viewer_cookie, _, _ = await _browser_session(session_factory, role="viewer")
    async with session_factory() as session:
        browser_session = await session.scalar(
            select(BrowserSession).where(BrowserSession.principal_id == owner.id)
        )
        assert browser_session is not None
        browser_session.active_organization_id = None
        await session.commit()

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            unauthenticated = await client.get("/console/servers")
            client.cookies.set(Settings().browser_session_cookie_name, owner_cookie)
            selected = await client.get("/console/servers")
            servers = await client.get("/console/servers")
            principals = await client.get("/console/principals")
            client.cookies.set(Settings().browser_session_cookie_name, viewer_cookie)
            forbidden = await client.get("/console/principals")
    finally:
        app.dependency_overrides.clear()

    assert unauthenticated.status_code == 303
    assert selected.status_code == 303
    assert selected.headers["location"] == "/console"
    assert servers.status_code == 200
    assert "MCP Servers" in servers.text
    assert principals.status_code == 200
    assert forbidden.status_code == 403


SERVER_LINK = r"/console/servers/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"


class _FailingDiscoveryClient:
    async def list_tools(
        self, endpoint: str, headers: Mapping[str, str] | None = None
    ) -> list[DiscoveredTool]:
        raise TimeoutError(endpoint)


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(host: str, *args: object, **kwargs: object) -> list[tuple[object, ...]]:
        address = "10.0.0.5" if host.startswith("internal.") else "93.184.216.34"
        return [(None, None, None, None, (address, 0))]

    monkeypatch.setattr("coyote_mcp.security.socket.getaddrinfo", resolve)


@asynccontextmanager
async def _console_client(
    session_factory: async_sessionmaker[AsyncSession], cookie: str
) -> AsyncIterator[httpx.AsyncClient]:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            client.cookies.set(Settings().browser_session_cookie_name, cookie)
            yield client
    finally:
        app.dependency_overrides.clear()


async def _csrf_for_cookie(session_factory: async_sessionmaker[AsyncSession], cookie: str) -> str:
    async with session_factory() as session:
        current = await authenticate_browser_session(session, cookie)
        assert current is not None and current.browser_session is not None
        return csrf_token_for(current.browser_session, Settings())


async def _create_server(
    session_factory: async_sessionmaker[AsyncSession],
    organization_id: UUID,
    name: str,
    *,
    endpoint: str = "https://downstream.example.test/mcp",
    status: str = "ready",
    last_sync_error: str | None = None,
) -> UUID:
    async with session_factory() as session:
        server = MCPServer(
            organization_id=organization_id,
            name=name,
            display_name=name.title(),
            endpoint=endpoint,
            status=status,
            last_sync_error=last_sync_error,
            last_synced_at=datetime.now(UTC),
        )
        session.add(server)
        await session.commit()
        return server.id


async def _load_server(
    session_factory: async_sessionmaker[AsyncSession], name: str
) -> MCPServer | None:
    async with session_factory() as session:
        return await session.scalar(select(MCPServer).where(MCPServer.name == name))


@pytest.mark.asyncio
async def test_server_registry_is_organization_scoped_and_redacts_endpoints(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="viewer")
    _, other_organization, _ = await _browser_session(session_factory, role="owner")
    own_id = await _create_server(
        session_factory,
        organization.id,
        "own-server",
        endpoint="https://downstream.example.test/private/mcp?token=supersecret",
    )
    other_id = await _create_server(session_factory, other_organization.id, "other-org-server")

    async with _console_client(session_factory, cookie) as client:
        listing = await client.get("/console/servers")
        detail = await client.get(f"/console/servers/{own_id}")
        foreign = await client.get(f"/console/servers/{other_id}")

    assert listing.status_code == 200
    assert "own-server" in listing.text
    assert "other-org-server" not in listing.text
    assert detail.status_code == 200
    assert "https://downstream.example.test/private/mcp" in detail.text
    assert "supersecret" not in detail.text
    assert foreign.status_code == 404
    assert "other-org-server" not in foreign.text


@pytest.mark.asyncio
async def test_instance_admin_session_reads_servers_without_membership_role(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    admin_cookie, organization, _ = await _browser_session(
        session_factory, role=None, instance_administrator=True
    )
    member_cookie, _, _ = await _browser_session(
        session_factory, role=None, organization=organization
    )
    await _create_server(session_factory, organization.id, "admin-visible")

    async with _console_client(session_factory, admin_cookie) as client:
        admin_listing = await client.get("/console/servers")
    async with _console_client(session_factory, member_cookie) as client:
        member_listing = await client.get("/console/servers")

    assert admin_listing.status_code == 200
    assert "admin-visible" in admin_listing.text
    assert member_listing.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_write_servers_even_with_valid_csrf_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="viewer")
    server_id = await _create_server(session_factory, organization.id, "viewer-target")
    token = await _csrf_for_cookie(session_factory, cookie)

    async with _console_client(session_factory, cookie) as client:
        register = await client.post(
            "/console/servers",
            data={
                "csrf_token": token,
                "name": "viewer-created",
                "display_name": "Viewer created",
                "endpoint": "https://downstream.example.test/mcp",
            },
        )
        disable = await client.post(
            f"/console/servers/{server_id}/enabled", data={"csrf_token": token, "enabled": "false"}
        )
        delete = await client.post(
            f"/console/servers/{server_id}/delete", data={"csrf_token": token}
        )

    assert register.status_code == 403
    assert disable.status_code == 403
    assert delete.status_code == 403
    assert await _load_server(session_factory, "viewer-created") is None
    target = await _load_server(session_factory, "viewer-target")
    assert target is not None
    assert target.enabled is True


@pytest.mark.asyncio
async def test_server_writes_require_csrf_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="maintainer")
    server_id = await _create_server(session_factory, organization.id, "csrf-target")

    async with _console_client(session_factory, cookie) as client:
        missing_token = await client.post(
            f"/console/servers/{server_id}/enabled", data={"enabled": "false"}
        )
        forged_token = await client.post(
            f"/console/servers/{server_id}/delete", data={"csrf_token": "forged"}
        )
        non_ascii_token = await client.post(
            f"/console/servers/{server_id}/delete", data={"csrf_token": "tokén-é"}
        )
        missing_create = await client.post(
            "/console/servers",
            data={
                "name": "csrf-created",
                "display_name": "CSRF created",
                "endpoint": "https://downstream.example.test/mcp",
            },
        )

    assert missing_token.status_code == 403
    assert forged_token.status_code == 403
    assert non_ascii_token.status_code == 403
    assert missing_create.status_code == 403
    target = await _load_server(session_factory, "csrf-target")
    assert target is not None
    assert target.enabled is True
    assert await _load_server(session_factory, "csrf-created") is None


@pytest.mark.asyncio
async def test_maintainer_registers_server_with_validated_endpoint(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="maintainer")

    async with _console_client(session_factory, cookie) as client:
        form = await client.get("/console/servers/new")
        response = await client.post(
            "/console/servers",
            data={
                "csrf_token": _csrf_token(form),
                "name": "registered-server",
                "display_name": "Registered server",
                "endpoint": "https://downstream.example.test/mcp",
            },
        )

    server = await _load_server(session_factory, "registered-server")
    assert server is not None
    assert server.organization_id == organization.id
    assert server.endpoint == "https://downstream.example.test/mcp"
    assert response.status_code == 303
    assert response.headers["location"] == f"/console/servers/{server.id}"


@pytest.mark.asyncio
async def test_registration_rejects_unsafe_endpoints_and_duplicate_names(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="maintainer")
    await _create_server(session_factory, organization.id, "taken-server")

    async with _console_client(session_factory, cookie) as client:
        form = await client.get("/console/servers/new")
        unsafe = await client.post(
            "/console/servers",
            data={
                "csrf_token": _csrf_token(form),
                "name": "unsafe-server",
                "display_name": "Unsafe server",
                "endpoint": "https://internal.example.test/mcp",
            },
        )
        duplicate = await client.post(
            "/console/servers",
            data={
                "csrf_token": _csrf_token(unsafe),
                "name": "taken-server",
                "display_name": "Taken server",
                "endpoint": "https://downstream.example.test/mcp",
            },
        )

    assert unsafe.status_code == 422
    assert await _load_server(session_factory, "unsafe-server") is None
    assert duplicate.status_code == 409
    assert "already" in duplicate.text.lower()


@pytest.mark.asyncio
async def test_discovery_failure_is_reported_on_server_detail(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="maintainer")
    server_id = await _create_server(session_factory, organization.id, "flaky-server")
    monkeypatch.setattr(
        "coyote_mcp.catalog.get_discovery_service",
        lambda settings: DiscoveryService(_FailingDiscoveryClient(), settings),
    )

    async with _console_client(session_factory, cookie) as client:
        token = _csrf_token(await client.get(f"/console/servers/{server_id}"))
        sync = await client.post(f"/console/servers/{server_id}/sync", data={"csrf_token": token})
        detail = await client.get(f"/console/servers/{server_id}")

    assert sync.status_code == 303
    assert detail.status_code == 200
    assert "badge-error" in detail.text
    assert "Discovery failed." in detail.text
    assert "downstream.example.test" in detail.text
    assert "TimeoutError" not in detail.text


@pytest.mark.asyncio
async def test_owner_can_disable_and_enable_server(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "toggled-server")

    async with _console_client(session_factory, cookie) as client:
        token = _csrf_token(await client.get(f"/console/servers/{server_id}"))
        disabled = await client.post(
            f"/console/servers/{server_id}/enabled", data={"csrf_token": token, "enabled": "false"}
        )
        detail = await client.get(f"/console/servers/{server_id}")
        token = _csrf_token(detail)
        invalid = await client.post(
            f"/console/servers/{server_id}/enabled", data={"csrf_token": token, "enabled": "maybe"}
        )
        enabled = await client.post(
            f"/console/servers/{server_id}/enabled", data={"csrf_token": token, "enabled": "true"}
        )

    assert disabled.status_code == 303
    assert "Disabled" in detail.text
    assert invalid.status_code == 422
    assert enabled.status_code == 303
    server = await _load_server(session_factory, "toggled-server")
    assert server is not None
    assert server.enabled is True


@pytest.mark.asyncio
async def test_edit_server_validates_endpoint_and_resets_discovery_state(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="maintainer")
    server_id = await _create_server(
        session_factory,
        organization.id,
        "edited-server",
        status="error",
        last_sync_error="Discovery failed.",
    )

    async with _console_client(session_factory, cookie) as client:
        form = await client.get(f"/console/servers/{server_id}/edit")
        unsafe = await client.post(
            f"/console/servers/{server_id}/edit",
            data={
                "csrf_token": _csrf_token(form),
                "display_name": "Renamed server",
                "endpoint": "https://internal.example.test/mcp",
            },
        )
        valid = await client.post(
            f"/console/servers/{server_id}/edit",
            data={
                "csrf_token": _csrf_token(unsafe),
                "display_name": "Renamed server",
                "endpoint": "https://replacement.example.test/mcp",
            },
        )

    assert unsafe.status_code == 422
    assert valid.status_code == 303
    server = await _load_server(session_factory, "edited-server")
    assert server is not None
    assert server.endpoint == "https://replacement.example.test/mcp"
    assert server.display_name == "Renamed server"
    assert server.status == "pending"
    assert server.last_sync_error is None


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", None])
async def test_server_edit_checks_authorization_before_validation_errors(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None, role: str | None
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role=role)
    server_id = await _create_server(
        session_factory,
        organization.id,
        "guarded-server",
        endpoint="https://downstream.example.test/private/mcp?token=supersecret",
    )
    csrf_token = await _csrf_for_cookie(session_factory, cookie)

    async with _console_client(session_factory, cookie) as client:
        response = await client.post(
            f"/console/servers/{server_id}/edit",
            data={
                "csrf_token": csrf_token,
                "display_name": "Renamed server",
                "endpoint": "https://internal.example.test/mcp",
            },
        )

    assert response.status_code == 403
    assert "Guarded-Server" not in response.text
    assert "downstream.example.test" not in response.text
    server = await _load_server(session_factory, "guarded-server")
    assert server is not None
    assert server.display_name == "Guarded-Server"
    assert server.endpoint == "https://downstream.example.test/private/mcp?token=supersecret"


@pytest.mark.asyncio
async def test_server_delete_is_refused_while_collections_reference_it(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "referenced-server")
    async with session_factory() as session:
        collection = Collection(
            organization_id=organization.id,
            slug="referenced-collection",
            display_name="Referenced collection",
        )
        session.add(collection)
        await session.flush()
        collection_id = collection.id
        session.add(
            CollectionMembership(
                collection_id=collection_id, server_id=server_id, organization_id=organization.id
            )
        )
        await session.commit()

    async with _console_client(session_factory, cookie) as client:
        token = _csrf_token(await client.get(f"/console/servers/{server_id}"))
        refused = await client.post(
            f"/console/servers/{server_id}/delete", data={"csrf_token": token}
        )
        assert await _load_server(session_factory, "referenced-server") is not None

        async with session_factory() as session:
            membership = await session.get(CollectionMembership, (collection_id, server_id))
            assert membership is not None
            await session.delete(membership)
            await session.commit()

        token = _csrf_token(await client.get(f"/console/servers/{server_id}"))
        deleted = await client.post(
            f"/console/servers/{server_id}/delete", data={"csrf_token": token}
        )

    assert refused.status_code == 409
    assert "Remove this server from all collections" in refused.text
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/console/servers"
    assert await _load_server(session_factory, "referenced-server") is None


@pytest.mark.asyncio
async def test_server_registry_pages_results(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="viewer")
    for index in range(26):
        await _create_server(session_factory, organization.id, f"paged-{index:02d}")

    async with _console_client(session_factory, cookie) as client:
        first = await client.get("/console/servers")
        second = await client.get("/console/servers?page=2")

    first_links = set(re.findall(SERVER_LINK, first.text))
    second_links = set(re.findall(SERVER_LINK, second.text))
    assert len(first_links) == 25
    assert len(second_links) == 1
    assert first_links.isdisjoint(second_links)


COLLECTION_LINK = (
    r"/console/collections/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)


async def _create_collection(
    session_factory: async_sessionmaker[AsyncSession],
    organization_id: UUID,
    slug: str,
    *,
    enabled: bool = True,
) -> UUID:
    async with session_factory() as session:
        collection = Collection(
            organization_id=organization_id,
            slug=slug,
            display_name=slug.title(),
            enabled=enabled,
        )
        session.add(collection)
        await session.commit()
        return collection.id


async def _create_tool(
    session_factory: async_sessionmaker[AsyncSession],
    server_id: UUID,
    name: str,
    *,
    description: str | None = None,
) -> UUID:
    async with session_factory() as session:
        tool = Tool(
            server_id=server_id,
            name=name,
            description=description or f"{name} description",
            input_schema={},
            fingerprint=uuid4().hex,
            active=True,
            last_seen_at=datetime.now(UTC),
        )
        session.add(tool)
        await session.commit()
        return tool.id


async def _membership_exists(
    session_factory: async_sessionmaker[AsyncSession], collection_id: UUID, server_id: UUID
) -> bool:
    async with session_factory() as session:
        return await session.get(CollectionMembership, (collection_id, server_id)) is not None


async def _load_collection(
    session_factory: async_sessionmaker[AsyncSession], slug: str
) -> Collection | None:
    async with session_factory() as session:
        return await session.scalar(select(Collection).where(Collection.slug == slug))


@pytest.mark.asyncio
async def test_collections_are_organization_scoped_and_show_endpoint(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="viewer")
    _, other_organization, _ = await _browser_session(session_factory, role="owner")
    own_id = await _create_collection(session_factory, organization.id, "own-collection")
    other_id = await _create_collection(session_factory, other_organization.id, "other-collection")

    async with _console_client(session_factory, cookie) as client:
        listing = await client.get("/console/collections")
        detail = await client.get(f"/console/collections/{own_id}")
        foreign = await client.get(f"/console/collections/{other_id}")

    assert listing.status_code == 200
    assert "own-collection" in listing.text
    assert "other-collection" not in listing.text
    assert "Create collection" not in listing.text
    assert detail.status_code == 200
    assert "/mcp/collections/own-collection" in detail.text
    assert foreign.status_code == 404
    assert "other-collection" not in foreign.text


@pytest.mark.asyncio
async def test_collection_endpoint_uses_configured_public_origin(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COYOTE_PUBLIC_BASE_URL", "https://gateway.example.test")
    cookie, organization, _ = await _browser_session(session_factory, role="viewer")
    collection_id = await _create_collection(session_factory, organization.id, "public-collection")

    async with _console_client(session_factory, cookie) as client:
        detail = await client.get(f"/console/collections/{collection_id}")

    assert detail.status_code == 200
    assert "https://gateway.example.test/mcp/collections/public-collection" in detail.text
    assert "http://test/mcp/collections/public-collection" not in detail.text


@pytest.mark.asyncio
async def test_instance_admin_reads_collections_without_membership_role(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    admin_cookie, organization, _ = await _browser_session(
        session_factory, role=None, instance_administrator=True
    )
    member_cookie, _, _ = await _browser_session(
        session_factory, role=None, organization=organization
    )
    await _create_collection(session_factory, organization.id, "admin-visible-collection")

    async with _console_client(session_factory, admin_cookie) as client:
        admin_listing = await client.get("/console/collections")
    async with _console_client(session_factory, member_cookie) as client:
        member_listing = await client.get("/console/collections")

    assert admin_listing.status_code == 200
    assert "admin-visible-collection" in admin_listing.text
    assert member_listing.status_code == 403


async def _grant_collection_role(
    session_factory: async_sessionmaker[AsyncSession],
    organization_id: UUID,
    principal_id: UUID,
    collection_id: UUID,
    role: str,
) -> None:
    async with session_factory() as session:
        session.add(
            RoleAssignment(
                organization_id=organization_id,
                principal_id=principal_id,
                collection_id=collection_id,
                role=role,
            )
        )
        await session.commit()


@pytest.mark.asyncio
async def test_collection_maintainer_manages_only_assigned_collection(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, principal = await _browser_session(session_factory, role="viewer")
    managed = await _create_collection(session_factory, organization.id, "managed-collection")
    other = await _create_collection(session_factory, organization.id, "other-collection")
    await _grant_collection_role(
        session_factory, organization.id, principal.id, managed, "maintainer"
    )

    async with _console_client(session_factory, cookie) as client:
        managed_edit = await client.get(f"/console/collections/{managed}/edit")
        managed_publications = await client.get(f"/console/collections/{managed}/publications")
        other_edit = await client.get(f"/console/collections/{other}/edit")
        other_publications = await client.get(f"/console/collections/{other}/publications")

    assert managed_edit.status_code == 200
    assert managed_publications.status_code == 200
    assert other_edit.status_code == 403
    assert other_publications.status_code == 403


@pytest.mark.asyncio
async def test_collection_scoped_member_lists_and_opens_only_assigned_collections(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, principal = await _browser_session(session_factory, role=None)
    shared = await _create_collection(session_factory, organization.id, "shared-collection")
    private = await _create_collection(session_factory, organization.id, "private-collection")
    await _grant_collection_role(session_factory, organization.id, principal.id, shared, "consumer")

    async with _console_client(session_factory, cookie) as client:
        listing = await client.get("/console/collections")
        shared_detail = await client.get(f"/console/collections/{shared}")
        private_detail = await client.get(f"/console/collections/{private}")

    assert listing.status_code == 200
    assert "shared-collection" in listing.text
    assert "private-collection" not in listing.text
    assert shared_detail.status_code == 200
    assert private_detail.status_code == 403


@pytest.mark.asyncio
async def test_collection_pages_reject_other_organization_collections(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, _, _ = await _browser_session(session_factory, role="owner")
    _, foreign_organization, _ = await _browser_session(session_factory, role="owner")
    foreign = await _create_collection(session_factory, foreign_organization.id, "foreign-one")

    async with _console_client(session_factory, cookie) as client:
        detail = await client.get(f"/console/collections/{foreign}")
        edit = await client.get(f"/console/collections/{foreign}/edit")
        publications = await client.get(f"/console/collections/{foreign}/publications")

    assert detail.status_code == 404
    assert edit.status_code == 404
    assert publications.status_code == 404


@pytest.mark.asyncio
async def test_collection_scoped_role_cannot_write_other_collection(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, principal = await _browser_session(session_factory, role="viewer")
    managed = await _create_collection(session_factory, organization.id, "writable-collection")
    other = await _create_collection(session_factory, organization.id, "locked-collection")
    await _grant_collection_role(
        session_factory, organization.id, principal.id, managed, "maintainer"
    )
    token = await _csrf_for_cookie(session_factory, cookie)

    async with _console_client(session_factory, cookie) as client:
        rejected = await client.post(
            f"/console/collections/{other}/edit",
            data={"csrf_token": token, "display_name": "Hijacked", "description": ""},
        )

    assert rejected.status_code == 403
    unchanged = await _load_collection(session_factory, "locked-collection")
    assert unchanged is not None
    assert unchanged.display_name == "Locked-Collection"


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "consumer"])
async def test_read_only_roles_cannot_write_collections(
    session_factory: async_sessionmaker[AsyncSession], role: str
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role=role)
    server_id = await _create_server(session_factory, organization.id, f"{role}-server")
    collection_id = await _create_collection(session_factory, organization.id, f"{role}-target")
    token = await _csrf_for_cookie(session_factory, cookie)

    async with _console_client(session_factory, cookie) as client:
        create = await client.post(
            "/console/collections",
            data={
                "csrf_token": token,
                "slug": f"{role}-created",
                "display_name": "Created",
                "exposure_mode": "discovery",
            },
        )
        edit = await client.post(
            f"/console/collections/{collection_id}/edit",
            data={"csrf_token": token, "display_name": "Renamed", "description": ""},
        )
        disable = await client.post(
            f"/console/collections/{collection_id}/enabled",
            data={"csrf_token": token, "enabled": "false"},
        )
        add = await client.post(
            f"/console/collections/{collection_id}/servers",
            data={"csrf_token": token, "server_id": str(server_id)},
        )

    assert create.status_code == 403
    assert edit.status_code == 403
    assert disable.status_code == 403
    assert add.status_code == 403
    assert await _load_collection(session_factory, f"{role}-created") is None
    target = await _load_collection(session_factory, f"{role}-target")
    assert target is not None
    assert target.enabled is True
    assert target.display_name == f"{role}-target".title()
    assert not await _membership_exists(session_factory, collection_id, server_id)


@pytest.mark.asyncio
async def test_collection_writes_require_csrf_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="maintainer")
    collection_id = await _create_collection(session_factory, organization.id, "csrf-collection")

    async with _console_client(session_factory, cookie) as client:
        missing_create = await client.post(
            "/console/collections",
            data={"slug": "no-token", "display_name": "No token", "exposure_mode": "discovery"},
        )
        forged_disable = await client.post(
            f"/console/collections/{collection_id}/enabled",
            data={"csrf_token": "forged", "enabled": "false"},
        )

    assert missing_create.status_code == 403
    assert forged_disable.status_code == 403
    assert await _load_collection(session_factory, "no-token") is None
    target = await _load_collection(session_factory, "csrf-collection")
    assert target is not None
    assert target.enabled is True


@pytest.mark.asyncio
async def test_collection_create_and_edit_validate_input_and_conflicts(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="maintainer")
    await _create_collection(session_factory, organization.id, "taken-slug")

    async with _console_client(session_factory, cookie) as client:
        form = await client.get("/console/collections/new")
        created = await client.post(
            "/console/collections",
            data={
                "csrf_token": _csrf_token(form),
                "slug": "fresh-slug",
                "display_name": "Fresh",
                "description": "Downstream tools for finance",
                "exposure_mode": "native",
            },
        )
        invalid_slug = await client.post(
            "/console/collections",
            data={
                "csrf_token": _csrf_token(await client.get("/console/collections/new")),
                "slug": "Not A Slug",
                "display_name": "Invalid",
                "exposure_mode": "discovery",
            },
        )
        duplicate = await client.post(
            "/console/collections",
            data={
                "csrf_token": _csrf_token(await client.get("/console/collections/new")),
                "slug": "taken-slug",
                "display_name": "Duplicate",
                "exposure_mode": "discovery",
            },
        )

        fresh = await _load_collection(session_factory, "fresh-slug")
        assert fresh is not None
        edit_form = await client.get(f"/console/collections/{fresh.id}/edit")
        edited = await client.post(
            f"/console/collections/{fresh.id}/edit",
            data={
                "csrf_token": _csrf_token(edit_form),
                "display_name": "Renamed",
                "description": "Updated",
                "exposure_mode": "discovery",
            },
        )
        bad_mode = await client.post(
            f"/console/collections/{fresh.id}/edit",
            data={
                "csrf_token": _csrf_token(
                    await client.get(f"/console/collections/{fresh.id}/edit")
                ),
                "display_name": "Renamed",
                "description": "",
                "exposure_mode": "bogus",
            },
        )

    assert created.status_code == 303
    assert invalid_slug.status_code == 422
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.text.lower()
    assert edited.status_code == 303
    assert bad_mode.status_code == 422
    reloaded = await _load_collection(session_factory, "fresh-slug")
    assert reloaded is not None
    assert reloaded.display_name == "Renamed"
    assert reloaded.description == "Updated"
    assert reloaded.exposure_mode == "discovery"
    assert await _load_collection(session_factory, "not a slug") is None


@pytest.mark.asyncio
async def test_collection_membership_updates_are_validated_and_isolated(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="maintainer")
    _, other_organization, _ = await _browser_session(session_factory, role="owner")
    collection_id = await _create_collection(session_factory, organization.id, "members")
    server_id = await _create_server(session_factory, organization.id, "member-server")
    foreign_server_id = await _create_server(
        session_factory, other_organization.id, "foreign-member-server"
    )

    detail_path = f"/console/collections/{collection_id}"
    members_path = f"{detail_path}/servers"
    async with _console_client(session_factory, cookie) as client:
        added = await client.post(
            members_path,
            data={
                "csrf_token": _csrf_token(await client.get(detail_path)),
                "server_id": str(server_id),
            },
        )
        assert added.status_code == 303
        assert await _membership_exists(session_factory, collection_id, server_id)

        duplicate = await client.post(
            members_path,
            data={
                "csrf_token": _csrf_token(await client.get(detail_path)),
                "server_id": str(server_id),
            },
        )
        malformed = await client.post(
            members_path,
            data={
                "csrf_token": _csrf_token(await client.get(detail_path)),
                "server_id": "not-a-uuid",
            },
        )
        foreign = await client.post(
            members_path,
            data={
                "csrf_token": _csrf_token(await client.get(detail_path)),
                "server_id": str(foreign_server_id),
            },
        )
        assert not await _membership_exists(session_factory, collection_id, foreign_server_id)

        detail = await client.get(detail_path)
        assert "member-server" in detail.text
        assert "foreign-member-server" not in detail.text

        removed = await client.post(
            f"{members_path}/{server_id}/remove",
            data={"csrf_token": _csrf_token(detail)},
        )

    assert duplicate.status_code == 409
    assert malformed.status_code == 422
    assert foreign.status_code == 422
    assert "Choose a server from this organization." in foreign.text
    assert removed.status_code == 303
    assert not await _membership_exists(session_factory, collection_id, server_id)


@pytest.mark.asyncio
async def test_disabled_collection_hides_available_tools_until_enabled(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "tool-server")
    await _create_tool(session_factory, server_id, "alpha-tool")
    collection_id = await _create_collection(session_factory, organization.id, "toggle")
    async with session_factory() as session:
        session.add(
            CollectionMembership(
                collection_id=collection_id, server_id=server_id, organization_id=organization.id
            )
        )
        await session.commit()

    async with _console_client(session_factory, cookie) as client:
        before = await client.get(f"/console/collections/{collection_id}")
        disabled = await client.post(
            f"/console/collections/{collection_id}/enabled",
            data={"csrf_token": _csrf_token(before), "enabled": "false"},
        )
        during = await client.get(f"/console/collections/{collection_id}")
        enabled = await client.post(
            f"/console/collections/{collection_id}/enabled",
            data={"csrf_token": _csrf_token(during), "enabled": "true"},
        )
        after = await client.get(f"/console/collections/{collection_id}")

    assert "alpha-tool" in before.text
    assert disabled.status_code == 303
    assert "alpha-tool" not in during.text
    assert "no tools are listed" in during.text
    assert enabled.status_code == 303
    assert "alpha-tool" in after.text


@pytest.mark.asyncio
async def test_published_tools_are_limited_to_collection_editors_and_escaped(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    owner_cookie, organization, _ = await _browser_session(session_factory, role="owner")
    viewer_cookie, _, _ = await _browser_session(
        session_factory, role="viewer", organization=organization
    )
    server_id = await _create_server(session_factory, organization.id, "publish-server")
    tool_id = await _create_tool(
        session_factory,
        server_id,
        "risky-tool",
        description="<script>alert('downstream')</script>",
    )
    collection_id = await _create_collection(session_factory, organization.id, "published")
    async with session_factory() as session:
        session.add(
            CollectionMembership(
                collection_id=collection_id, server_id=server_id, organization_id=organization.id
            )
        )
        session.add(
            CollectionToolPublication(
                collection_id=collection_id,
                server_id=server_id,
                tool_id=tool_id,
                enabled=True,
                published_name="risky-alias",
            )
        )
        await session.commit()

    async with _console_client(session_factory, owner_cookie) as client:
        owner_detail = await client.get(f"/console/collections/{collection_id}")
    async with _console_client(session_factory, viewer_cookie) as client:
        viewer_detail = await client.get(f"/console/collections/{collection_id}")

    assert owner_detail.status_code == 200
    assert "risky-alias" in owner_detail.text
    assert "<script>alert" not in owner_detail.text
    assert "&lt;script&gt;" in owner_detail.text
    assert viewer_detail.status_code == 200
    assert "risky-tool" in viewer_detail.text
    assert "risky-alias" not in viewer_detail.text
    assert "Published tools" not in viewer_detail.text


@pytest.mark.asyncio
async def test_collection_list_pages_results(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="viewer")
    for index in range(26):
        await _create_collection(session_factory, organization.id, f"paged-collection-{index:02d}")

    async with _console_client(session_factory, cookie) as client:
        first = await client.get("/console/collections")
        second = await client.get("/console/collections?page=2")

    first_links = set(re.findall(COLLECTION_LINK, first.text))
    second_links = set(re.findall(COLLECTION_LINK, second.text))
    assert len(first_links) == 25
    assert len(second_links) == 1
    assert first_links.isdisjoint(second_links)


async def _join_collection(
    session_factory: async_sessionmaker[AsyncSession],
    collection_id: UUID,
    server_id: UUID,
    organization_id: UUID,
) -> None:
    async with session_factory() as session:
        session.add(
            CollectionMembership(
                collection_id=collection_id, server_id=server_id, organization_id=organization_id
            )
        )
        await session.commit()


async def _publish_directly(
    session_factory: async_sessionmaker[AsyncSession],
    collection_id: UUID,
    server_id: UUID,
    tool_id: UUID,
    published_name: str,
    *,
    description_override: str | None = None,
) -> UUID:
    async with session_factory() as session:
        publication = CollectionToolPublication(
            collection_id=collection_id,
            server_id=server_id,
            tool_id=tool_id,
            enabled=True,
            published_name=published_name,
            description_override=description_override,
        )
        session.add(publication)
        await session.commit()
        return publication.id


async def _load_publications(
    session_factory: async_sessionmaker[AsyncSession], collection_id: UUID
) -> list[CollectionToolPublication]:
    async with session_factory() as session:
        result = await session.scalars(
            select(CollectionToolPublication)
            .where(CollectionToolPublication.collection_id == collection_id)
            .order_by(CollectionToolPublication.published_name)
        )
        return list(result)


async def _fresh_token(client: httpx.AsyncClient, path: str) -> str:
    return _csrf_token(await client.get(path))


@pytest.mark.asyncio
async def test_publication_lifecycle_publishes_edits_and_unpublishes(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "lifecycle-server")
    tool_id = await _create_tool(session_factory, server_id, "lookup-tool")
    collection_id = await _create_collection(session_factory, organization.id, "lifecycle")
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    listing_path = f"/console/collections/{collection_id}/publications"

    async with _console_client(session_factory, cookie) as client:
        before = await client.get(listing_path)
        published = await client.post(
            listing_path,
            data={
                "csrf_token": _csrf_token(before),
                "tool_id": str(tool_id),
                "published_name": "lookup-alias",
            },
        )

    assert before.status_code == 200
    assert "lookup-tool" in before.text
    assert published.status_code == 303
    assert published.headers["location"] == listing_path
    [publication] = await _load_publications(session_factory, collection_id)
    assert publication.tool_id == tool_id
    assert publication.published_name == "lookup-alias"
    assert publication.enabled is True
    edit_path = f"{listing_path}/{publication.id}/edit"

    async with _console_client(session_factory, cookie) as client:
        form = await client.get(edit_path)
        updated = await client.post(
            edit_path,
            data={
                "csrf_token": _csrf_token(form),
                "published_name": "renamed-alias",
                "description_override": "Looks up issues.",
                "enabled": "false",
            },
        )

    assert form.status_code == 200
    assert 'value="lookup-alias"' in form.text
    assert updated.status_code == 303
    [publication] = await _load_publications(session_factory, collection_id)
    assert publication.published_name == "renamed-alias"
    assert publication.description_override == "Looks up issues."
    assert publication.enabled is False

    async with _console_client(session_factory, cookie) as client:
        listing = await client.get(listing_path)
        removed = await client.post(
            f"{listing_path}/{publication.id}/remove",
            data={"csrf_token": _csrf_token(listing)},
        )

    assert removed.status_code == 303
    assert await _load_publications(session_factory, collection_id) == []


@pytest.mark.asyncio
async def test_disabled_collection_publications_page_warns_without_hiding_publications(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "disabled-server")
    tool_id = await _create_tool(session_factory, server_id, "disabled-tool")
    collection_id = await _create_collection(
        session_factory, organization.id, "disabled-publications", enabled=False
    )
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    await _publish_directly(session_factory, collection_id, server_id, tool_id, "disabled-alias")

    async with _console_client(session_factory, cookie) as client:
        page = await client.get(f"/console/collections/{collection_id}/publications")

    assert page.status_code == 200
    assert "This collection is disabled." in page.text
    assert "disabled-alias" in page.text


@pytest.mark.asyncio
async def test_publication_alias_and_tool_conflicts_are_rejected(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "conflict-server")
    taken_tool_id = await _create_tool(session_factory, server_id, "taken-tool")
    free_tool_id = await _create_tool(session_factory, server_id, "free-tool")
    orphan_server_id = await _create_server(session_factory, organization.id, "orphan-server")
    orphan_tool_id = await _create_tool(session_factory, orphan_server_id, "orphan-tool")
    collection_id = await _create_collection(session_factory, organization.id, "conflicts")
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    await _publish_directly(session_factory, collection_id, server_id, taken_tool_id, "taken-name")
    base = f"/console/collections/{collection_id}/publications"

    async with _console_client(session_factory, cookie) as client:
        name_conflict = await client.post(
            base,
            data={
                "csrf_token": await _fresh_token(client, base),
                "tool_id": str(free_tool_id),
                "published_name": "taken-name",
            },
        )
        tool_conflict = await client.post(
            base,
            data={
                "csrf_token": await _fresh_token(client, base),
                "tool_id": str(taken_tool_id),
                "published_name": "other-name",
            },
        )
        invalid_name = await client.post(
            base,
            data={
                "csrf_token": await _fresh_token(client, base),
                "tool_id": str(free_tool_id),
                "published_name": "bad name!",
            },
        )
        invalid_tool = await client.post(
            base,
            data={
                "csrf_token": await _fresh_token(client, base),
                "tool_id": "not-a-uuid",
                "published_name": "free-name",
            },
        )
        outside_membership = await client.post(
            base,
            data={
                "csrf_token": await _fresh_token(client, base),
                "tool_id": str(orphan_tool_id),
                "published_name": "free-name",
            },
        )

    assert name_conflict.status_code == 409
    assert "That published name is already used in this collection." in name_conflict.text
    assert tool_conflict.status_code == 409
    assert "This tool is already published in this collection." in tool_conflict.text
    assert invalid_name.status_code == 422
    assert "starting with a letter or digit." in invalid_name.text
    assert invalid_tool.status_code == 422
    assert outside_membership.status_code == 422
    assert "Choose a tool that is available in this collection." in invalid_tool.text
    assert "Choose a tool that is available in this collection." in outside_membership.text
    publications = await _load_publications(session_factory, collection_id)
    assert [publication.published_name for publication in publications] == ["taken-name"]


@pytest.mark.asyncio
async def test_newly_discovered_tools_default_to_unpublished(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "default-deny-server")
    collection_id = await _create_collection(session_factory, organization.id, "default-deny")
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    for index in range(26):
        await _create_tool(session_factory, server_id, f"bulk-tool-{index:02d}")

    base = f"/console/collections/{collection_id}/publications"
    async with _console_client(session_factory, cookie) as client:
        first = await client.get(base)
        second = await client.get(f"{base}?page=2")
        catalog_page = await client.get("/console/tools")

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(re.findall(r'name="tool_id"', first.text)) == 25
    assert len(re.findall(r'name="tool_id"', second.text)) == 1
    assert "bulk-tool-00" in first.text
    assert "Unpublished" in first.text
    assert catalog_page.status_code == 200
    assert "Unpublished" in catalog_page.text
    assert await _load_publications(session_factory, collection_id) == []


@pytest.mark.asyncio
async def test_published_tools_are_paginated(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "paged-publication-server")
    collection_id = await _create_collection(session_factory, organization.id, "paged-published")
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    for index in range(26):
        tool_id = await _create_tool(session_factory, server_id, f"paged-tool-{index:02d}")
        await _publish_directly(
            session_factory, collection_id, server_id, tool_id, f"paged-alias-{index:02d}"
        )

    base = f"/console/collections/{collection_id}/publications"
    remove_form = r'/publications/[0-9a-f-]{36}/remove"'
    async with _console_client(session_factory, cookie) as client:
        first = await client.get(base)
        second = await client.get(f"{base}?published_page=2")

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(re.findall(remove_form, first.text)) == 25
    assert len(re.findall(remove_form, second.text)) == 1


@pytest.mark.asyncio
async def test_publication_writes_require_collection_update_and_csrf(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    maintainer_cookie, organization, _ = await _browser_session(session_factory, role="maintainer")
    viewer_cookie, _, _ = await _browser_session(
        session_factory, role="viewer", organization=organization
    )
    consumer_cookie, _, _ = await _browser_session(
        session_factory, role="consumer", organization=organization
    )
    server_id = await _create_server(session_factory, organization.id, "guarded-server")
    guarded_tool_id = await _create_tool(session_factory, server_id, "guarded-tool")
    second_tool_id = await _create_tool(session_factory, server_id, "second-tool")
    collection_id = await _create_collection(session_factory, organization.id, "guarded")
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    publication_id = await _publish_directly(
        session_factory, collection_id, server_id, guarded_tool_id, "guarded-alias"
    )
    base = f"/console/collections/{collection_id}/publications"
    edit_path = f"{base}/{publication_id}/edit"
    remove_path = f"{base}/{publication_id}/remove"

    async with _console_client(session_factory, viewer_cookie) as client:
        viewer_page = await client.get(base)
        viewer_publish = await client.post(
            base,
            data={
                "csrf_token": await _csrf_for_cookie(session_factory, viewer_cookie),
                "tool_id": str(second_tool_id),
                "published_name": "viewer-alias",
            },
        )
        viewer_update = await client.post(
            edit_path,
            data={
                "csrf_token": await _csrf_for_cookie(session_factory, viewer_cookie),
                "published_name": "viewer-rename",
                "enabled": "true",
            },
        )
        viewer_remove = await client.post(
            remove_path,
            data={"csrf_token": await _csrf_for_cookie(session_factory, viewer_cookie)},
        )
    async with _console_client(session_factory, consumer_cookie) as client:
        consumer_page = await client.get(base)

    assert viewer_page.status_code == 403
    assert viewer_publish.status_code == 403
    assert viewer_update.status_code == 403
    assert viewer_remove.status_code == 403
    assert consumer_page.status_code == 403

    async with _console_client(session_factory, maintainer_cookie) as client:
        forged_publish = await client.post(
            base,
            data={
                "csrf_token": "forged",
                "tool_id": str(second_tool_id),
                "published_name": "forged-alias",
            },
        )
        forged_update = await client.post(
            edit_path,
            data={"csrf_token": "forged", "published_name": "forged-rename", "enabled": "true"},
        )
        missing_remove = await client.post(remove_path, data={})
        forged_remove = await client.post(remove_path, data={"csrf_token": "forged"})
        published = await client.post(
            base,
            data={
                "csrf_token": await _csrf_for_cookie(session_factory, maintainer_cookie),
                "tool_id": str(second_tool_id),
                "published_name": "maintainer-alias",
            },
        )

    assert forged_publish.status_code == 403
    assert forged_update.status_code == 403
    assert missing_remove.status_code == 403
    assert forged_remove.status_code == 403
    assert published.status_code == 303
    publications = await _load_publications(session_factory, collection_id)
    assert [publication.published_name for publication in publications] == [
        "guarded-alias",
        "maintainer-alias",
    ]


@pytest.mark.asyncio
async def test_publication_routes_are_organization_scoped(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    _, other_organization, _ = await _browser_session(session_factory, role="owner")
    foreign_server_id = await _create_server(session_factory, other_organization.id, "foreign-srv")
    foreign_tool_id = await _create_tool(session_factory, foreign_server_id, "foreign-tool")
    foreign_collection_id = await _create_collection(
        session_factory, other_organization.id, "foreign-collection"
    )
    await _join_collection(
        session_factory, foreign_collection_id, foreign_server_id, other_organization.id
    )
    foreign_publication_id = await _publish_directly(
        session_factory,
        foreign_collection_id,
        foreign_server_id,
        foreign_tool_id,
        "foreign-alias",
    )
    own_server_id = await _create_server(session_factory, organization.id, "own-srv")
    own_tool_id = await _create_tool(session_factory, own_server_id, "own-tool")
    own_collection_id = await _create_collection(session_factory, organization.id, "own-collection")
    await _join_collection(session_factory, own_collection_id, own_server_id, organization.id)
    own_publication_id = await _publish_directly(
        session_factory, own_collection_id, own_server_id, own_tool_id, "own-alias"
    )
    foreign_base = f"/console/collections/{foreign_collection_id}/publications"
    own_base = f"/console/collections/{own_collection_id}/publications"

    async with _console_client(session_factory, cookie) as client:
        page = await client.get(foreign_base)
        edit = await client.get(f"{foreign_base}/{foreign_publication_id}/edit")
        publish = await client.post(
            foreign_base,
            data={
                "csrf_token": await _fresh_token(client, own_base),
                "tool_id": str(own_tool_id),
                "published_name": "stolen",
            },
        )
        update = await client.post(
            f"{foreign_base}/{foreign_publication_id}/edit",
            data={
                "csrf_token": await _fresh_token(client, own_base),
                "published_name": "hijacked",
                "enabled": "true",
            },
        )
        cross_update = await client.post(
            f"{foreign_base}/{own_publication_id}/edit",
            data={
                "csrf_token": await _fresh_token(client, own_base),
                "published_name": "hijacked",
                "enabled": "true",
            },
        )
        remove = await client.post(
            f"{foreign_base}/{foreign_publication_id}/remove",
            data={"csrf_token": await _fresh_token(client, own_base)},
        )
        foreign_tool = await client.post(
            own_base,
            data={
                "csrf_token": await _fresh_token(client, own_base),
                "tool_id": str(foreign_tool_id),
                "published_name": "borrowed",
            },
        )

    assert page.status_code == 404
    assert edit.status_code == 404
    assert publish.status_code == 404
    assert update.status_code == 404
    assert cross_update.status_code == 404
    assert remove.status_code == 404
    assert foreign_tool.status_code == 422
    foreign_names = [
        p.published_name for p in await _load_publications(session_factory, foreign_collection_id)
    ]
    own_names = [
        p.published_name for p in await _load_publications(session_factory, own_collection_id)
    ]
    assert foreign_names == ["foreign-alias"]
    assert own_names == ["own-alias"]


@pytest.mark.asyncio
async def test_publications_respect_instance_admin_and_member_roles(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    admin_cookie, organization, _ = await _browser_session(
        session_factory, role=None, instance_administrator=True
    )
    member_cookie, _, _ = await _browser_session(
        session_factory, role=None, organization=organization
    )
    server_id = await _create_server(session_factory, organization.id, "admin-server")
    tool_id = await _create_tool(session_factory, server_id, "admin-tool")
    collection_id = await _create_collection(session_factory, organization.id, "admin-managed")
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    base = f"/console/collections/{collection_id}/publications"

    async with _console_client(session_factory, admin_cookie) as client:
        admin_page = await client.get(base)
        admin_publish = await client.post(
            base,
            data={
                "csrf_token": await _csrf_for_cookie(session_factory, admin_cookie),
                "tool_id": str(tool_id),
                "published_name": "admin-alias",
            },
        )
    async with _console_client(session_factory, member_cookie) as client:
        member_page = await client.get(base)
        member_catalog = await client.get("/console/tools")

    assert admin_page.status_code == 200
    assert admin_publish.status_code == 303
    assert member_page.status_code == 403
    assert member_catalog.status_code == 403


@pytest.mark.asyncio
async def test_tool_catalog_shows_publication_state_only_to_collection_editors(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    owner_cookie, organization, _ = await _browser_session(session_factory, role="owner")
    viewer_cookie, _, _ = await _browser_session(
        session_factory, role="viewer", organization=organization
    )
    server_id = await _create_server(session_factory, organization.id, "catalog-server")
    published_tool_id = await _create_tool(
        session_factory,
        server_id,
        "catalog-published",
        description="<script>alert('catalog')</script>",
    )
    await _create_tool(session_factory, server_id, "catalog-unpublished")
    collection_id = await _create_collection(session_factory, organization.id, "catalog")
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    await _publish_directly(
        session_factory, collection_id, server_id, published_tool_id, "catalog-alias"
    )

    async with _console_client(session_factory, owner_cookie) as client:
        owner_catalog = await client.get("/console/tools")
    async with _console_client(session_factory, viewer_cookie) as client:
        viewer_catalog = await client.get("/console/tools")

    assert owner_catalog.status_code == 200
    assert "Published in 1 collection" in owner_catalog.text
    assert "Unpublished" in owner_catalog.text
    assert "<script>alert" not in owner_catalog.text
    assert "catalog-unpublished" in owner_catalog.text
    assert viewer_catalog.status_code == 200
    assert "catalog-unpublished" in viewer_catalog.text
    assert "Published in" not in viewer_catalog.text
    assert "badge-unpublished" not in viewer_catalog.text


@pytest.mark.asyncio
async def test_publication_conflicts_from_constraints_keep_state_and_rerender(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "constraint-server")
    keep_tool_id = await _create_tool(session_factory, server_id, "keep-tool")
    edit_tool_id = await _create_tool(session_factory, server_id, "edit-tool")
    create_tool_id = await _create_tool(session_factory, server_id, "create-tool")
    collection_id = await _create_collection(session_factory, organization.id, "constraints")
    await _join_collection(session_factory, collection_id, server_id, organization.id)
    await _publish_directly(session_factory, collection_id, server_id, keep_tool_id, "keep-name")
    edit_id = await _publish_directly(
        session_factory, collection_id, server_id, edit_tool_id, "edit-name"
    )
    base = f"/console/collections/{collection_id}/publications"
    edit_path = f"{base}/{edit_id}/edit"

    async def skip_availability_check(*args: object, **kwargs: object) -> None:
        return None

    # Bypass the pre-check so the database unique constraints are what reject the write.
    monkeypatch.setattr("coyote_mcp.catalog._ensure_publication_available", skip_availability_check)

    async with _console_client(session_factory, cookie) as client:
        update = await client.post(
            edit_path,
            data={
                "csrf_token": await _fresh_token(client, edit_path),
                "published_name": "keep-name",
                "description_override": "",
                "enabled": "true",
            },
        )
        form = await client.get(edit_path)
        create = await client.post(
            base,
            data={
                "csrf_token": await _fresh_token(client, base),
                "tool_id": str(create_tool_id),
                "published_name": "keep-name",
            },
        )
        listing = await client.get(base)

    assert update.status_code == 409
    assert "A publication already uses that published name." in update.text
    assert form.status_code == 200
    assert 'value="edit-name"' in form.text
    assert create.status_code == 409
    assert "A publication already uses that tool or published name." in create.text
    assert listing.status_code == 200
    publications = await _load_publications(session_factory, collection_id)
    assert [publication.published_name for publication in publications] == [
        "edit-name",
        "keep-name",
    ]


@pytest.mark.asyncio
async def test_removing_missing_publication_reports_not_found(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    collection_id = await _create_collection(session_factory, organization.id, "missing-remove")
    base = f"/console/collections/{collection_id}/publications"

    csrf_token = await _csrf_for_cookie(session_factory, cookie)
    async with _console_client(session_factory, cookie) as client:
        missing = await client.post(
            f"{base}/{uuid4()}/remove",
            data={"csrf_token": csrf_token},
        )

    assert missing.status_code == 404
    assert "That tool is no longer published in this collection." in missing.text


@pytest.mark.asyncio
async def test_two_open_forms_both_submit_with_stable_csrf_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    collection_id = await _create_collection(session_factory, organization.id, "open-forms")

    async with _console_client(session_factory, cookie) as client:
        detail = await client.get(f"/console/collections/{collection_id}")
        create_form = await client.get("/console/collections/new")
        assert _csrf_token(detail) == _csrf_token(create_form)
        toggled = await client.post(
            f"/console/collections/{collection_id}/enabled",
            data={"csrf_token": _csrf_token(detail), "enabled": "false"},
        )
        created = await client.post(
            "/console/collections",
            data={
                "csrf_token": _csrf_token(create_form),
                "slug": "second-open-form",
                "display_name": "Second open form",
                "exposure_mode": "discovery",
            },
        )

    assert toggled.status_code == 303
    assert created.status_code == 303
    target = await _load_collection(session_factory, "open-forms")
    assert target is not None
    assert target.enabled is False
    assert await _load_collection(session_factory, "second-open-form") is not None


@pytest.mark.asyncio
async def test_missing_invalid_and_cross_session_csrf_tokens_are_rejected(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    other_cookie, _, _ = await _browser_session(
        session_factory, role="owner", organization=organization
    )
    other_session_token = await _csrf_for_cookie(session_factory, other_cookie)
    fields = {"slug": "guarded-slug", "display_name": "Guarded", "exposure_mode": "discovery"}

    async with _console_client(session_factory, cookie) as client:
        missing = await client.post("/console/collections", data=fields)
        invalid = await client.post("/console/collections", data={**fields, "csrf_token": "forged"})
        cross_session = await client.post(
            "/console/collections", data={**fields, "csrf_token": other_session_token}
        )
        assert await _load_collection(session_factory, "guarded-slug") is None

        own_token = _csrf_token(await client.get("/console/collections/new"))
        accepted = await client.post(
            "/console/collections", data={**fields, "csrf_token": own_token}
        )

    assert missing.status_code == 403
    assert invalid.status_code == 403
    assert cross_session.status_code == 403
    assert accepted.status_code == 303
    assert await _load_collection(session_factory, "guarded-slug") is not None


@pytest.mark.asyncio
async def test_first_organization_creation_rotates_csrf_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, _ = await _unaffiliated_browser_session(session_factory, instance_administrator=True)
    before = await _csrf_for_cookie(session_factory, cookie)

    async with _console_client(session_factory, cookie) as client:
        created = await client.post(
            "/console/organizations",
            data={
                "csrf_token": before,
                "slug": "rotation-first-org",
                "display_name": "Rotation First Organization",
            },
        )
        stale = await client.post(
            "/console/organizations",
            data={
                "csrf_token": before,
                "slug": "stale-first-org",
                "display_name": "Stale First Organization",
            },
        )

    assert created.status_code == 303
    assert stale.status_code == 403
    assert await _csrf_for_cookie(session_factory, cookie) != before


@pytest.mark.asyncio
async def test_csrf_token_is_stable_per_session_and_rotates_on_organization_switch(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cookie, first, principal = await _browser_session(session_factory)
    async with session_factory() as session:
        second = Organization(slug="rotate-target", display_name="Rotate Target")
        session.add(second)
        await session.flush()
        session.add(OrganizationMembership(organization_id=second.id, principal_id=principal.id))
        await session.commit()

    async with _console_client(session_factory, cookie) as client:
        first_render = _csrf_token(await client.get("/console/organizations"))
        second_render = _csrf_token(await client.get("/console/organizations"))
        endpoint_token = (await client.get("/auth/oidc/csrf")).json()["csrf_token"]
        switched = await client.post(
            "/console/organization",
            data={"csrf_token": first_render, "organization_id": str(second.id)},
        )
        stale = await client.post(
            "/console/organization",
            data={"csrf_token": first_render, "organization_id": str(first.id)},
        )
        after_switch = _csrf_token(await client.get("/console/organizations"))

    assert first_render == second_render == endpoint_token
    assert switched.status_code == 303
    assert stale.status_code == 403
    assert after_switch != first_render


@pytest.mark.parametrize(
    "location",
    [
        "/console/servers",
        f"/console/servers/{uuid4()}",
        f"/console/collections/{uuid4()}/publications",
    ],
)
def test_see_other_allows_local_console_paths(location: str) -> None:
    response = _see_other(location)

    assert response.status_code == 303
    assert response.headers["location"] == location


@pytest.mark.parametrize(
    "location",
    [
        "//evil.example/console",
        "https://evil.example/console",
        "/console/../secrets",
        "/console\\evil",
        "/console?next=https://evil.example",
        "/console/servers/abc#frag",
        "/other/path",
    ],
)
def test_see_other_falls_back_to_console_root_for_untrusted_locations(location: str) -> None:
    response = _see_other(location)

    assert response.status_code == 303
    assert response.headers["location"] == "/console"


CLIENT_SECRET = "gh-client-secret-value-do-not-leak"
CLIENT_ID = "gh-client-id-123"


@pytest.fixture
def downstream_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Give the console a credential key and redirect base for the connected-apps routes."""
    settings = Settings(
        credential_encryption_keys={
            "v1": SecretStr(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
        },
        credential_active_key_version="v1",
        downstream_oauth_redirect_base_url="https://coyote.example.test",
    )
    monkeypatch.setattr(console_module, "Settings", lambda: settings)
    return settings


async def _csrf_for_cookie(session_factory: async_sessionmaker[AsyncSession], cookie: str) -> str:
    async with session_factory() as session:
        current = await authenticate_browser_session(session, cookie)
    assert current is not None and current.browser_session is not None
    return csrf_token_for(current.browser_session, Settings())


async def _set_auth_policy(
    session_factory: async_sessionmaker[AsyncSession], server_id: UUID, policy: str
) -> None:
    async with session_factory() as session:
        server = await session.get(MCPServer, server_id)
        assert server is not None
        server.auth_policy = policy
        await session.commit()


async def _configure_github_integration(
    client: httpx.AsyncClient, server_id: UUID, csrf: str
) -> None:
    policy = await client.post(
        f"/console/servers/{server_id}/authentication/policy",
        data={"csrf_token": csrf, "auth_policy": "per_user_oauth"},
    )
    assert policy.status_code == 303
    integration = await client.post(
        f"/console/servers/{server_id}/authentication/integration",
        data={
            "csrf_token": csrf,
            "provider": "github",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scopes": "read:user",
            "enabled": "on",
        },
    )
    assert integration.status_code == 303


async def test_profile_shows_connected_apps_to_ordinary_members_without_secrets(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    owner_cookie, organization, _ = await _browser_session(session_factory, role="owner")
    consumer_cookie, _, _ = await _browser_session(
        session_factory, role="consumer", organization=organization
    )
    server_id = await _create_server(session_factory, organization.id, "github-hosted")
    async with _console_client(session_factory, owner_cookie) as owner:
        await _configure_github_integration(
            owner,
            server_id,
            _csrf_token(await owner.get(f"/console/servers/{server_id}/authentication")),
        )

    async with _console_client(session_factory, consumer_cookie) as consumer:
        profile = await consumer.get("/console/profile")

    assert profile.status_code == 200
    assert "Connected Apps" in profile.text
    assert "github-hosted" in profile.text
    assert f"/console/connected-apps/{server_id}/connect" in profile.text
    assert CLIENT_SECRET not in profile.text
    assert CLIENT_ID not in profile.text


async def test_authentication_admin_pages_and_mutations_are_denied_to_members(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    _, organization, _ = await _browser_session(session_factory, role="owner")
    consumer_cookie, _, _ = await _browser_session(
        session_factory, role="consumer", organization=organization
    )
    server_id = await _create_server(session_factory, organization.id, "members-denied")
    csrf = await _csrf_for_cookie(session_factory, consumer_cookie)

    async with _console_client(session_factory, consumer_cookie) as consumer:
        page = await consumer.get(f"/console/servers/{server_id}/authentication")
        policy = await consumer.post(
            f"/console/servers/{server_id}/authentication/policy",
            data={"csrf_token": csrf, "auth_policy": "shared_bearer"},
        )

    assert page.status_code == 403
    assert policy.status_code == 403
    async with session_factory() as session:
        server = await session.get(MCPServer, server_id)
        assert server is not None
        assert server.auth_policy == "none"


async def test_authentication_mutations_reject_missing_csrf(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "csrf-server")

    async with _console_client(session_factory, cookie) as client:
        policy = await client.post(
            f"/console/servers/{server_id}/authentication/policy",
            data={"auth_policy": "shared_bearer"},
        )
        bad_token = await client.post(
            f"/console/servers/{server_id}/authentication/policy",
            data={"csrf_token": "not-the-token", "auth_policy": "shared_bearer"},
        )
        disconnect = await client.post(f"/console/connected-apps/{server_id}/disconnect")

    assert policy.status_code == 403
    assert bad_token.status_code == 403
    assert disconnect.status_code == 403
    async with session_factory() as session:
        server = await session.get(MCPServer, server_id)
        assert server is not None
        assert server.auth_policy == "none"


async def test_admin_configuration_never_renders_client_secret(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="owner")
    server_id = await _create_server(session_factory, organization.id, "admin-config")
    csrf = await _csrf_for_cookie(session_factory, cookie)

    async with _console_client(session_factory, cookie) as client:
        await _configure_github_integration(client, server_id, csrf)
        page = await client.get(f"/console/servers/{server_id}/authentication")

    assert page.status_code == 200
    assert CLIENT_SECRET not in page.text
    assert "github" in page.text.lower()


async def test_connect_redirects_to_github_with_pkce_and_state_without_secret(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    owner_cookie, organization, _ = await _browser_session(session_factory, role="owner")
    consumer_cookie, _, _ = await _browser_session(
        session_factory, role="consumer", organization=organization
    )
    server_id = await _create_server(session_factory, organization.id, "connect-github")
    async with _console_client(session_factory, owner_cookie) as owner:
        await _configure_github_integration(
            owner, server_id, await _csrf_for_cookie(session_factory, owner_cookie)
        )
    await _set_auth_policy(session_factory, server_id, "per_user_oauth")
    csrf = await _csrf_for_cookie(session_factory, consumer_cookie)

    async with _console_client(session_factory, consumer_cookie) as consumer:
        response = await consumer.post(
            f"/console/connected-apps/{server_id}/connect", data={"csrf_token": csrf}
        )

    assert response.status_code == 303
    location = response.headers["location"]
    assert CLIENT_SECRET not in location
    parts = urlsplit(location)
    assert (
        f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://github.com/login/oauth/authorize"
    )
    query = parse_qs(parts.query)
    assert query["client_id"] == [CLIENT_ID]
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == ["https://coyote.example.test/console/connected-apps/callback"]
    assert len(query["state"][0]) >= 32
    assert query["code_challenge"][0]


async def test_connect_requires_csrf(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="consumer")
    server_id = await _create_server(session_factory, organization.id, "connect-csrf")

    async with _console_client(session_factory, cookie) as client:
        response = await client.post(f"/console/connected-apps/{server_id}/connect")

    assert response.status_code == 403


async def test_callback_rejects_unsolicited_state(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    cookie, _, _ = await _browser_session(session_factory, role="consumer")

    async with _console_client(session_factory, cookie) as client:
        response = await client.get(
            "/console/connected-apps/callback", params={"state": "never-issued", "code": "abc"}
        )

    assert response.status_code == 422
    assert html.escape(connected_apps.INVALID_CALLBACK_MESSAGE) in response.text


async def test_callback_transaction_is_single_use(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    owner_cookie, organization, _ = await _browser_session(session_factory, role="owner")
    consumer_cookie, _, _ = await _browser_session(
        session_factory, role="consumer", organization=organization
    )
    server_id = await _create_server(session_factory, organization.id, "single-use")
    async with _console_client(session_factory, owner_cookie) as owner:
        await _configure_github_integration(
            owner, server_id, await _csrf_for_cookie(session_factory, owner_cookie)
        )
    await _set_auth_policy(session_factory, server_id, "per_user_oauth")

    async with _console_client(session_factory, consumer_cookie) as consumer:
        connect = await consumer.post(
            f"/console/connected-apps/{server_id}/connect",
            data={"csrf_token": await _csrf_for_cookie(session_factory, consumer_cookie)},
        )
        state = parse_qs(urlsplit(connect.headers["location"]).query)["state"][0]
        first = await consumer.get(
            "/console/connected-apps/callback",
            params={"state": state, "error": "access_denied"},
        )
        replay = await consumer.get(
            "/console/connected-apps/callback",
            params={"state": state, "code": "replayed-code"},
        )

    assert first.status_code == 422
    assert replay.status_code == 422
    assert html.escape(connected_apps.INVALID_CALLBACK_MESSAGE) in replay.text


async def test_disconnect_requires_csrf_then_redirects_to_profile(
    session_factory: async_sessionmaker[AsyncSession],
    downstream_settings: Settings,
) -> None:
    cookie, organization, _ = await _browser_session(session_factory, role="consumer")
    server_id = await _create_server(session_factory, organization.id, "disconnect-me")
    csrf = await _csrf_for_cookie(session_factory, cookie)

    async with _console_client(session_factory, cookie) as client:
        rejected = await client.post(f"/console/connected-apps/{server_id}/disconnect")
        accepted = await client.post(
            f"/console/connected-apps/{server_id}/disconnect", data={"csrf_token": csrf}
        )

    assert rejected.status_code == 403
    assert accepted.status_code == 303
    assert accepted.headers["location"] == "/console/profile"
