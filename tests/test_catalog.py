from datetime import UTC, datetime

import pytest

from coyote_mcp import catalog
from coyote_mcp.discovery import DiscoveredTool, DiscoveryService, SyncFailedError, reconcile_tools
from coyote_mcp.models import Organization, Tool
from coyote_mcp.schemas import CollectionCreate, MembershipCreate, ServerCreate
from coyote_mcp.settings import Settings


def server_request(name: str = "example") -> ServerCreate:
    return ServerCreate(name=name, display_name=name.title(), endpoint="https://example.com/mcp")


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


@pytest.mark.asyncio
async def test_catalog_ordering_and_pagination(session, organization: Organization) -> None:
    for name in ("zulu", "alpha", "middle"):
        await catalog.create_server(session, organization.id, server_request(name))
    servers = await catalog.list_servers(session, organization.id, 1, 1)
    assert [server.name for server in servers] == ["middle"]
