from datetime import UTC, datetime

import pytest

from coyote_mcp import catalog
from coyote_mcp.discovery import (
    DiscoveredTool,
    DiscoveryService,
    SyncFailedError,
    reconcile_tools,
)
from coyote_mcp.models import Tool
from coyote_mcp.schemas import CollectionCreate, MembershipCreate, ServerCreate
from coyote_mcp.settings import Settings


def server_request(name: str = "example") -> ServerCreate:
    return ServerCreate(
        name=name,
        display_name=name.title(),
        endpoint="https://example.com/mcp",
    )


def discovered_tool(name: str, description: str = "A tool") -> DiscoveredTool:
    return DiscoveredTool(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": {"value": {"type": "string"}}},
        output_schema=None,
        annotations={},
    )


@pytest.mark.asyncio
async def test_server_duplicate_name_is_rejected(session) -> None:
    await catalog.create_server(session, server_request())

    with pytest.raises(catalog.DuplicateResourceError):
        await catalog.create_server(session, server_request())


@pytest.mark.asyncio
async def test_collection_membership_and_active_tool_catalog(session) -> None:
    server = await catalog.create_server(session, server_request())
    collection = await catalog.create_collection(
        session, CollectionCreate(slug="engineering", display_name="Engineering")
    )
    membership = await catalog.add_membership(
        session, collection.id, MembershipCreate(server_id=server.id)
    )
    session.add(
        Tool(
            server_id=server.id,
            name="visible",
            description="Visible",
            input_schema={},
            annotations={},
            fingerprint="a" * 64,
            active=True,
            last_seen_at=datetime.now(UTC),
        )
    )
    session.add(
        Tool(
            server_id=server.id,
            name="hidden",
            description="Hidden",
            input_schema={},
            annotations={},
            fingerprint="b" * 64,
            active=False,
            last_seen_at=datetime.now(UTC),
        )
    )
    await session.commit()

    tools = await catalog.list_collection_tools(session, collection.id, limit=50, offset=0)

    assert membership.enabled is True
    assert [tool.name for tool in tools] == ["visible"]


@pytest.mark.asyncio
async def test_tools_with_same_name_are_isolated_by_server(session) -> None:
    first = await catalog.create_server(session, server_request("first"))
    second = await catalog.create_server(session, server_request("second"))

    await reconcile_tools(session, first, [discovered_tool("search")])
    await reconcile_tools(session, second, [discovered_tool("search", "Other search")])
    await session.commit()

    assert [tool.name for tool in await catalog.list_server_tools(session, first.id, 50, 0)] == [
        "search"
    ]
    assert [tool.name for tool in await catalog.list_server_tools(session, second.id, 50, 0)] == [
        "search"
    ]


@pytest.mark.asyncio
async def test_reconciliation_updates_schema_and_deactivates_only_missing_tools(session) -> None:
    server = await catalog.create_server(session, server_request())
    await reconcile_tools(session, server, [discovered_tool("first"), discovered_tool("second")])
    await session.commit()

    changed = DiscoveredTool(
        name="first",
        description="Changed",
        input_schema={"type": "object", "properties": {"count": {"type": "integer"}}},
        output_schema={"type": "string"},
        annotations={"readOnlyHint": True},
    )
    await reconcile_tools(session, server, [changed])
    await session.commit()

    tools = await catalog.list_server_tools(session, server.id, 50, 0)
    by_name = {tool.name: tool for tool in tools}
    assert by_name["first"].fingerprint == changed.fingerprint
    assert by_name["first"].output_schema == {"type": "string"}
    assert by_name["second"].active is False


class FailingDiscoveryClient:
    async def list_tools(self, endpoint: str) -> list[DiscoveredTool]:
        raise TimeoutError(f"Timed out connecting to {endpoint}")


@pytest.mark.asyncio
async def test_failed_sync_preserves_existing_catalog(session) -> None:
    server = await catalog.create_server(session, server_request())
    await reconcile_tools(session, server, [discovered_tool("preserved")])
    await session.commit()

    service = DiscoveryService(FailingDiscoveryClient(), Settings())
    with pytest.raises(SyncFailedError):
        await service.sync(session, server)
    tools = await catalog.list_server_tools(session, server.id, 50, 0)

    await session.refresh(server)
    assert server.status == "error"
    assert server.last_sync_error == "Discovery failed."
    assert [(tool.name, tool.active) for tool in tools] == [("preserved", True)]


@pytest.mark.asyncio
async def test_catalog_ordering_and_pagination(session) -> None:
    for name in ("zulu", "alpha", "middle"):
        await catalog.create_server(session, server_request(name))

    servers = await catalog.list_servers(session, limit=1, offset=1)

    assert [server.name for server in servers] == ["middle"]
