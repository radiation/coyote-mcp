from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp import catalog
from coyote_mcp.auth import AuthenticatedPrincipal
from coyote_mcp.discovery import (
    DiscoveredTool,
    DiscoveryService,
    SyncFailedError,
    SyncSupersededError,
    reconcile_tools,
)
from coyote_mcp.models import Organization, OrganizationMembership, Principal, RoleAssignment, Tool
from coyote_mcp.schemas import (
    CollectionCreate,
    CollectionUpdate,
    MembershipCreate,
    PublicationCreate,
    PublicationUpdate,
    ServerCreate,
    ServerUpdate,
)
from coyote_mcp.settings import Settings


def server_request(name: str = "example") -> ServerCreate:
    return ServerCreate(
        name=name,
        display_name=name.title(),
        endpoint=HttpUrl("https://example.com/mcp"),
    )


def discovered_tool(name: str, description: str = "A tool") -> DiscoveredTool:
    return DiscoveredTool(
        name=name, description=description, input_schema={}, output_schema=None, annotations={}
    )


@pytest.mark.asyncio
async def test_server_duplicate_name_is_rejected(session, organization: Organization) -> None:
    await catalog.create_server(session, organization.id, server_request())
    with pytest.raises(catalog.DuplicateResourceError):
        await catalog.create_server(session, organization.id, server_request())


@pytest.mark.asyncio
async def test_collection_membership_and_active_tool_catalog(
    session, organization: Organization
) -> None:
    server = await catalog.create_server(session, organization.id, server_request())
    collection = await catalog.create_collection(
        session, organization.id, CollectionCreate(slug="engineering", display_name="Engineering")
    )
    membership = await catalog.add_membership(
        session, organization.id, collection.id, MembershipCreate(server_id=server.id)
    )
    session.add_all(
        [
            Tool(
                server_id=server.id,
                name="visible",
                description="Visible",
                input_schema={},
                annotations={},
                fingerprint="a" * 64,
                active=True,
                last_seen_at=datetime.now(UTC),
            ),
            Tool(
                server_id=server.id,
                name="hidden",
                description="Hidden",
                input_schema={},
                annotations={},
                fingerprint="b" * 64,
                active=False,
                last_seen_at=datetime.now(UTC),
            ),
        ]
    )
    await session.commit()
    tools = await catalog.list_collection_tools(session, organization.id, collection.id, 50, 0)
    assert membership.enabled is True
    assert [tool.name for tool in tools] == ["visible"]


@pytest.mark.asyncio
async def test_cross_organization_membership_is_rejected(
    session, organization: Organization
) -> None:
    other = Organization(slug="other", display_name="Other")
    session.add(other)
    await session.commit()
    server = await catalog.create_server(session, other.id, server_request())
    collection = await catalog.create_collection(
        session, organization.id, CollectionCreate(slug="engineering", display_name="Engineering")
    )
    with pytest.raises(catalog.MissingResourceError):
        await catalog.add_membership(
            session, organization.id, collection.id, MembershipCreate(server_id=server.id)
        )


@pytest.mark.asyncio
async def test_collection_update_enforces_scope_and_authorization(
    session, organization: Organization
) -> None:
    principal = Principal(
        identifier="maintainer",
        display_name="Maintainer",
    )
    session.add(principal)
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
    collection = await catalog.create_collection(
        session,
        organization.id,
        CollectionCreate(slug="engineering", display_name="Engineering"),
    )
    no_scope = AuthenticatedPrincipal(principal, frozenset(), None, organization.id)
    with pytest.raises(catalog.AuthorizationError, match="Insufficient permissions"):
        await catalog.update_collection(
            session, no_scope, collection.id, CollectionUpdate(exposure_mode="native")
        )

    scoped_but_unauthorized = AuthenticatedPrincipal(
        principal, frozenset({"collection:update"}), None, organization.id
    )
    with pytest.raises(catalog.AuthorizationError, match="Insufficient permissions"):
        await catalog.update_collection(
            session,
            scoped_but_unauthorized,
            collection.id,
            CollectionUpdate(exposure_mode="native"),
        )

    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=principal.id,
            role="maintainer",
            collection_id=collection.id,
        )
    )
    await session.commit()
    updated = await catalog.update_collection(
        session,
        scoped_but_unauthorized,
        collection.id,
        CollectionUpdate(exposure_mode="native"),
    )

    assert updated.exposure_mode == "native"


@pytest.mark.asyncio
async def test_publication_services_enforce_scope_and_authorization(
    session, organization: Organization
) -> None:
    principal = Principal(
        identifier="untrusted-publisher",
        display_name="Untrusted Publisher",
    )
    session.add(principal)
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
    collection = await catalog.create_collection(
        session,
        organization.id,
        CollectionCreate(slug="engineering", display_name="Engineering"),
    )
    no_scope = AuthenticatedPrincipal(principal, frozenset(), None, organization.id)
    scoped_but_unauthorized = AuthenticatedPrincipal(
        principal, frozenset({"collection:update"}), None, organization.id
    )
    publication_request = PublicationCreate(tool_id=uuid4(), published_name="curated_lookup")

    for current in (no_scope, scoped_but_unauthorized):
        with pytest.raises(catalog.AuthorizationError, match="Insufficient permissions"):
            await catalog.list_publications(session, current, collection.id, 10, 0)
        with pytest.raises(catalog.AuthorizationError, match="Insufficient permissions"):
            await catalog.publish_tool(session, current, collection.id, publication_request)
        with pytest.raises(catalog.AuthorizationError, match="Insufficient permissions"):
            await catalog.update_publication(
                session,
                current,
                collection.id,
                uuid4(),
                PublicationUpdate(enabled=False),
            )
        with pytest.raises(catalog.AuthorizationError, match="Insufficient permissions"):
            await catalog.remove_publication(session, current, collection.id, uuid4())


@pytest.mark.asyncio
async def test_tools_with_same_name_are_isolated_by_server(
    session, organization: Organization
) -> None:
    first = await catalog.create_server(session, organization.id, server_request("first"))
    second = await catalog.create_server(session, organization.id, server_request("second"))
    await reconcile_tools(session, first, [discovered_tool("search")])
    await reconcile_tools(session, second, [discovered_tool("search", "Other")])
    await session.commit()
    assert [
        tool.name
        for tool in await catalog.list_server_tools(session, organization.id, first.id, 50, 0)
    ] == ["search"]
    assert [
        tool.name
        for tool in await catalog.list_server_tools(session, organization.id, second.id, 50, 0)
    ] == ["search"]


class FailingDiscoveryClient:
    async def list_tools(self, endpoint: str) -> list[DiscoveredTool]:
        raise TimeoutError(endpoint)


@pytest.mark.asyncio
async def test_failed_sync_preserves_catalog(session, organization: Organization) -> None:
    server = await catalog.create_server(session, organization.id, server_request())
    await reconcile_tools(session, server, [discovered_tool("preserved")])
    await session.commit()
    with pytest.raises(SyncFailedError):
        await DiscoveryService(FailingDiscoveryClient(), Settings()).sync(session, server)
    tools = await catalog.list_server_tools(session, organization.id, server.id, 50, 0)
    assert [tool.name for tool in tools] == ["preserved"]


class FixedDiscoveryClient:
    def __init__(self, tools: list[DiscoveredTool]) -> None:
        self._tools = tools
        self.endpoints: list[str] = []

    async def list_tools(self, endpoint: str) -> list[DiscoveredTool]:
        self.endpoints.append(endpoint)
        return self._tools


class EndpointChangingDiscoveryClient:
    """Changes the server endpoint while discovery against the previous endpoint is in flight."""

    def __init__(self, session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID):
        self._session = session
        self._current = current
        self._server_id = server_id

    async def list_tools(self, endpoint: str) -> list[DiscoveredTool]:
        await catalog.update_server(
            self._session,
            self._current,
            self._server_id,
            ServerUpdate(endpoint=HttpUrl("https://example.org/mcp")),
        )
        return [discovered_tool("stale")]


@pytest.mark.asyncio
async def test_endpoint_change_rejects_in_flight_discovery(
    session, organization: Organization
) -> None:
    organization_id = organization.id
    principal = Principal(identifier="owner", display_name="Owner")
    session.add(principal)
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization_id, principal_id=principal.id))
    session.add(
        RoleAssignment(organization_id=organization_id, principal_id=principal.id, role="owner")
    )
    server = await catalog.create_server(session, organization_id, server_request())
    server_id = server.id
    current = AuthenticatedPrincipal(
        principal, frozenset({"server:update", "server:sync"}), None, organization_id
    )

    client = EndpointChangingDiscoveryClient(session, current, server_id)
    with pytest.raises(SyncSupersededError):
        await DiscoveryService(client, Settings()).sync(session, server)

    stale_view = await catalog.get_server(session, organization_id, server_id)
    assert stale_view.endpoint == "https://example.org/mcp"
    assert stale_view.status == "pending"
    assert await catalog.list_server_tools(session, organization_id, server_id, 50, 0) == []

    current_client = FixedDiscoveryClient([discovered_tool("current")])
    synced = await DiscoveryService(current_client, Settings()).sync(session, stale_view)
    assert current_client.endpoints == ["https://example.org/mcp"]
    assert synced.status == "ready"
    tools = await catalog.list_server_tools(session, organization_id, server_id, 50, 0)
    assert [tool.name for tool in tools] == ["current"]


@pytest.mark.asyncio
async def test_delete_server_refuses_in_use_server_and_deletes_unreferenced_server(
    session, organization: Organization
) -> None:
    principal = Principal(identifier="owner", display_name="Owner")
    session.add(principal)
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
    session.add(
        RoleAssignment(organization_id=organization.id, principal_id=principal.id, role="owner")
    )
    await session.commit()
    current = AuthenticatedPrincipal(principal, frozenset({"server:update"}), None, organization.id)
    in_use = await catalog.create_server(session, organization.id, server_request("in-use"))
    collection = await catalog.create_collection(
        session, organization.id, CollectionCreate(slug="engineering", display_name="Engineering")
    )
    await catalog.add_membership(
        session, organization.id, collection.id, MembershipCreate(server_id=in_use.id)
    )

    with pytest.raises(catalog.ServerInUseError):
        await catalog.delete_server(session, current, in_use.id)
    assert (await catalog.get_server(session, organization.id, in_use.id)).id == in_use.id

    unused = await catalog.create_server(session, organization.id, server_request("unused"))
    await catalog.delete_server(session, current, unused.id)
    with pytest.raises(catalog.MissingResourceError):
        await catalog.get_server(session, organization.id, unused.id)


@pytest.mark.asyncio
async def test_catalog_ordering_and_pagination(session, organization: Organization) -> None:
    for name in ("zulu", "alpha", "middle"):
        await catalog.create_server(session, organization.id, server_request(name))
    servers = await catalog.list_servers(session, organization.id, 1, 1)
    assert [server.name for server in servers] == ["middle"]
