import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.app import app
from coyote_mcp.auth import issue_browser_session
from coyote_mcp.db import get_session
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
