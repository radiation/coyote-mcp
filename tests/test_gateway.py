import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import httpx2
import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from pydantic import HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp import catalog
from coyote_mcp.app import app
from coyote_mcp.auth import AuthenticatedPrincipal, authenticate_token, issue_pat
from coyote_mcp.gateway import GatewayError, GatewayService
from coyote_mcp.models import (
    AuditEvent,
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
from coyote_mcp.schemas import CollectionCreate, MembershipCreate, PublicationCreate, ServerCreate
from coyote_mcp.settings import Settings


def collection_mcp_transport(token: str, collection_slug: str) -> StreamableHttpTransport:
    def http_client_factory(
        headers: dict[str, str] | None = None,
        timeout: httpx2.Timeout | None = None,
        auth: httpx2.Auth | None = None,
        **_: object,
    ) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://test",
            headers=headers,
            timeout=timeout,
            auth=auth,
        )

    return StreamableHttpTransport(
        f"http://test/mcp/collections/{collection_slug}",
        headers={"Authorization": f"Bearer {token}"},
        httpx_client_factory=http_client_factory,
    )


@asynccontextmanager
async def downstream_server() -> AsyncIterator[tuple[str, list[bytes | None]]]:
    downstream = FastMCP("test-downstream")

    @downstream.tool
    async def issue_lookup(issue: int) -> dict[str, int]:
        return {"issue": issue}

    @downstream.tool
    async def tool_error() -> None:
        raise ToolError("Downstream rejected the request.")

    @downstream.tool
    async def delayed_lookup() -> dict[str, bool]:
        await asyncio.sleep(0.2)
        return {"finished": True}

    @downstream.tool
    async def large_lookup() -> str:
        return "x" * 2_048

    @downstream.tool
    async def nullable_lookup() -> dict[str, None]:
        return {"value": None}

    downstream_app = downstream.http_app(path="/mcp", transport="streamable-http")
    authorization_headers: list[bytes | None] = []

    async def capture_headers(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            authorization_headers.append(dict(scope["headers"]).get(b"authorization"))
        await downstream_app(scope, receive, send)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    import uvicorn

    server = uvicorn.Server(
        uvicorn.Config(capture_headers, host="127.0.0.1", port=port, log_level="critical")
    )
    server_task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.01)
    if not server.started:
        server.should_exit = True
        await server_task
        raise RuntimeError("The downstream MCP test server did not start.")
    try:
        yield f"http://127.0.0.1:{port}/mcp", authorization_headers
    finally:
        server.should_exit = True
        await server_task


async def point_tool_at_downstream(session: AsyncSession, tool: Tool, endpoint: str) -> None:
    server = await session.get(MCPServer, tool.server_id)
    assert server is not None
    server.endpoint = endpoint
    await session.commit()


async def add_catalog_tool(session: AsyncSession, source_tool: Tool, name: str) -> Tool:
    tool = Tool(
        server_id=source_tool.server_id,
        name=name,
        description=name,
        input_schema={"type": "object", "additionalProperties": False},
        annotations={},
        fingerprint=name.ljust(64, "0"),
        active=True,
        last_seen_at=datetime.now(UTC),
    )
    session.add(tool)
    await session.commit()
    await session.refresh(tool)
    return tool


def publication_current(principal: Principal, organization_id: UUID) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        principal, frozenset({"collection:update"}), None, organization_id
    )


async def _collection_consumer(
    session: AsyncSession,
) -> tuple[Principal, str, Tool, Organization]:
    suffix = uuid4().hex
    organization = Organization(slug=f"gateway-{suffix}", display_name="Gateway")
    session.add(organization)
    await session.flush()
    principal = Principal(
        identifier=f"consumer-{suffix}",
        display_name="Consumer",
    )
    session.add(principal)
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
    collection = await catalog.create_collection(
        session,
        organization.id,
        CollectionCreate(slug="engineering", display_name="Engineering"),
    )
    server = await catalog.create_server(
        session,
        organization.id,
        ServerCreate(
            name="downstream",
            display_name="Downstream",
            endpoint=HttpUrl("https://example.com/mcp"),
        ),
    )
    server.status = "ready"
    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=principal.id,
            role="administrator",
            collection_id=collection.id,
        )
    )
    await catalog.add_membership(
        session, organization.id, collection.id, MembershipCreate(server_id=server.id)
    )
    tool = Tool(
        server_id=server.id,
        name="issue_lookup",
        description="Look up an issue",
        input_schema={
            "type": "object",
            "properties": {"issue": {"type": "integer"}},
            "required": ["issue"],
            "additionalProperties": False,
        },
        annotations={},
        fingerprint="a" * 64,
        active=True,
        last_seen_at=datetime.now(UTC),
    )
    session.add(tool)
    await session.commit()
    await session.refresh(tool)
    await catalog.publish_tool(
        session,
        publication_current(principal, organization.id),
        collection.id,
        PublicationCreate(tool_id=tool.id, published_name="downstream__issue_lookup"),
    )
    _, token = await issue_pat(
        session,
        principal,
        organization.id,
        "consumer",
        {"collection:update", "tool:discover", "tool:describe", "tool:execute"},
        timedelta(days=1),
        Settings(),
    )
    return principal, token, tool, organization


@pytest.mark.asyncio
async def test_gateway_scoped_discovery_description_and_schema_validation(
    session: AsyncSession,
) -> None:
    _, token, tool, _ = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    service = GatewayService(Settings())

    tools = await service.search_tools(session, current, "lookup", "engineering", 10)
    description = await service.describe_tool(session, current, tool.id, "engineering")

    assert [(result.tool_id, result.collection_slug) for result in tools] == [
        (tool.id, "engineering")
    ]
    assert description["input_schema"] == tool.input_schema
    publication = await session.scalar(select(CollectionToolPublication))
    assert publication is not None
    publication.description_override = "Find an invoice"
    await session.commit()
    scoped_override_results = await service.search_tools(
        session, current, "invoice", "engineering", 10
    )
    global_override_results = await service.search_tools(session, current, "invoice", None, 10)
    assert [result.tool_id for result in scoped_override_results] == [tool.id]
    assert [result.tool_id for result in global_override_results] == [tool.id]
    global_description = await service.describe_tool(session, current, tool.id, None)
    assert global_description["collection_slug"] == "engineering"
    with pytest.raises(GatewayError, match="arguments"):
        await service.execute_tool(session, current, tool.id, {"issue": "invalid"}, "engineering")


@pytest.mark.asyncio
async def test_native_collection_denial_is_independently_audited(session: AsyncSession) -> None:
    principal, _, _, organization = await _collection_consumer(session)
    current = AuthenticatedPrincipal(
        principal, frozenset({"tool:discover"}), None, organization.id, credential_context="pat"
    )

    with pytest.raises(GatewayError, match="Collection endpoint"):
        await GatewayService(Settings()).native_tools(session, current, "engineering")

    event = await session.scalar(
        select(AuditEvent).where(AuditEvent.action == "authorization.denied")
    )
    assert event is not None
    assert event.organization_id == organization.id
    assert event.actor_id == principal.id
    assert event.metadata_ == {
        "action": "tool:discover",
        "reason_code": "collection_access_denied",
    }


@pytest.mark.asyncio
async def test_gateway_hides_removed_collection_membership(session: AsyncSession) -> None:
    _, token, tool, organization = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    collection = await session.scalar(select(Collection))
    assert collection is not None
    await catalog.remove_membership(session, organization.id, collection.id, tool.server_id)

    with pytest.raises(GatewayError, match="not available"):
        await GatewayService(Settings()).describe_tool(session, current, tool.id, "engineering")


@pytest.mark.asyncio
async def test_global_gateway_default_denies_unpublished_tools(session: AsyncSession) -> None:
    principal, token, tool, organization = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    publication = await session.scalar(select(CollectionToolPublication))
    assert current is not None
    assert publication is not None
    await catalog.remove_publication(
        session,
        publication_current(principal, organization.id),
        publication.collection_id,
        publication.id,
    )

    assert await GatewayService(Settings()).search_tools(session, current, "lookup", None, 10) == []
    with pytest.raises(GatewayError, match="not available"):
        await GatewayService(Settings()).describe_tool(session, current, tool.id, None)
    with pytest.raises(GatewayError, match="not available"):
        await GatewayService(Settings()).execute_tool(session, current, tool.id, {}, None)


@pytest.mark.asyncio
async def test_disabled_server_tools_are_hidden_from_discovery_and_execution(
    session: AsyncSession,
) -> None:
    _, token, tool, _ = await _collection_consumer(session)
    collection = await session.scalar(select(Collection))
    assert collection is not None
    collection.exposure_mode = "native"
    current = await authenticate_token(session, token)
    assert current is not None
    gateway = GatewayService(Settings())
    assert await gateway.native_tools(session, current, "engineering") != []

    server = await session.get(MCPServer, tool.server_id)
    assert server is not None
    server.enabled = False
    await session.commit()

    assert await gateway.search_tools(session, current, "lookup", None, 10) == []
    assert await gateway.native_tools(session, current, "engineering") == []
    with pytest.raises(GatewayError, match="not available"):
        await gateway.describe_tool(session, current, tool.id, None)
    with pytest.raises(GatewayError, match="not available"):
        await gateway.execute_tool(session, current, tool.id, {}, None)


@pytest.mark.asyncio
async def test_instance_administrator_pat_does_not_bypass_unpublished_tools(
    session: AsyncSession,
) -> None:
    organization = Organization(slug="admin-publication", display_name="Admin Publication")
    principal = Principal(identifier="admin-publication", display_name="Administrator")
    session.add_all([organization, principal])
    await session.flush()
    collection = Collection(
        organization_id=organization.id, slug="engineering", display_name="Engineering"
    )
    server = MCPServer(
        organization_id=organization.id,
        name="unpublished",
        display_name="Unpublished",
        endpoint="https://example.com/mcp",
        status="ready",
    )
    session.add_all(
        [
            collection,
            server,
            OrganizationMembership(organization_id=organization.id, principal_id=principal.id),
            RoleAssignment(
                organization_id=organization.id, principal_id=principal.id, role="owner"
            ),
            InstanceAdministrator(principal_id=principal.id),
        ]
    )
    await session.flush()
    session.add(
        CollectionMembership(
            collection_id=collection.id, server_id=server.id, organization_id=organization.id
        )
    )
    session.add(
        Tool(
            server_id=server.id,
            name="unpublished_lookup",
            description="Unpublished",
            input_schema={"type": "object"},
            annotations={},
            fingerprint="u" * 64,
            active=True,
            last_seen_at=datetime.now(UTC),
        )
    )
    await session.commit()
    _, token = await issue_pat(
        session,
        principal,
        organization.id,
        "instance-admin",
        {"tool:discover"},
        timedelta(days=1),
        Settings(),
    )
    current = await authenticate_token(session, token)

    assert current is not None
    assert await GatewayService(Settings()).search_tools(session, current, "lookup", None, 10) == []


@pytest.mark.asyncio
async def test_global_gateway_requires_context_for_multiple_publications(
    session: AsyncSession,
) -> None:
    principal, token, tool, organization = await _collection_consumer(session)
    collection = await session.scalar(select(Collection))
    assert collection is not None
    second_collection = await catalog.create_collection(
        session,
        organization.id,
        CollectionCreate(slug="operations", display_name="Operations"),
    )
    await catalog.add_membership(
        session,
        organization.id,
        second_collection.id,
        MembershipCreate(server_id=tool.server_id),
    )
    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=principal.id,
            role="consumer",
            collection_id=None,
        )
    )
    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=principal.id,
            role="administrator",
            collection_id=second_collection.id,
        )
    )
    await session.commit()
    current = await authenticate_token(session, token)
    assert current is not None
    service = GatewayService(Settings())

    with pytest.raises(GatewayError, match="not available"):
        await service.execute_tool(session, current, tool.id, {}, "operations")
    await catalog.publish_tool(
        session,
        publication_current(principal, organization.id),
        second_collection.id,
        PublicationCreate(tool_id=tool.id, published_name="operations_lookup"),
    )

    results = await service.search_tools(session, current, "lookup", None, 10)

    assert [(result.collection_slug, result.published_name) for result in results] == [
        ("engineering", "downstream__issue_lookup"),
        ("operations", "operations_lookup"),
    ]
    with pytest.raises(GatewayError, match="Collection context"):
        await service.execute_tool(session, current, tool.id, {}, None)


@pytest.mark.asyncio
async def test_mcp_endpoint_rejects_missing_invalid_and_cookie_credentials(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    original_factory = app.state.mcp_session_factory
    app.state.mcp_session_factory = session_factory
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            missing = await client.get("/mcp")
            invalid = await client.get("/mcp", headers={"Authorization": "Bearer invalid"})
            client.cookies.set("coyote_session", "coyote_session_x_y")
            cookie = await client.get("/mcp")
    finally:
        app.state.mcp_session_factory = original_factory

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert cookie.status_code == 401


@pytest.mark.asyncio
async def test_authenticated_mcp_client_negotiates_and_lists_gateway_tools(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        _, token, _, _ = await _collection_consumer(session)

    def http_client_factory(
        headers: dict[str, str] | None = None,
        timeout: httpx2.Timeout | None = None,
        auth: httpx2.Auth | None = None,
        **_: object,
    ) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://test",
            headers=headers,
            timeout=timeout,
            auth=auth,
        )

    original_factory = app.state.mcp_session_factory
    app.state.mcp_session_factory = session_factory
    transport = StreamableHttpTransport(
        "http://test/mcp",
        headers={"Authorization": f"Bearer {token}"},
        httpx_client_factory=http_client_factory,
    )
    try:
        async with app.router.lifespan_context(app):
            async with Client(transport) as client:
                tools = await client.list_tools()
                search_result = await client.call_tool(
                    "coyote_search_tools",
                    {"query": "lookup", "collection_slug": "engineering"},
                )
    finally:
        app.state.mcp_session_factory = original_factory

    assert {tool.name for tool in tools} == {
        "coyote_describe_tool",
        "coyote_execute_tool",
        "coyote_search_tools",
    }
    assert search_result.is_error is False
    assert search_result.data[0]["name"] == "issue_lookup"


@pytest.mark.asyncio
async def test_mcp_client_executes_authorized_catalog_tool_end_to_end(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with session_factory() as session:
        _, token, tool, _ = await _collection_consumer(session)

    monkeypatch.setenv("ALLOW_INSECURE_ENDPOINTS", "true")
    monkeypatch.setenv("ALLOW_PRIVATE_ENDPOINTS", "true")
    async with downstream_server() as (endpoint, authorization_headers):
        async with session_factory() as session:
            await point_tool_at_downstream(session, tool, endpoint)

        def http_client_factory(
            headers: dict[str, str] | None = None,
            timeout: httpx2.Timeout | None = None,
            auth: httpx2.Auth | None = None,
            **_: object,
        ) -> httpx2.AsyncClient:
            return httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url="http://test",
                headers=headers,
                timeout=timeout,
                auth=auth,
            )

        original_factory = app.state.mcp_session_factory
        app.state.mcp_session_factory = session_factory
        transport = StreamableHttpTransport(
            "http://test/mcp",
            headers={"Authorization": f"Bearer {token}"},
            httpx_client_factory=http_client_factory,
        )
        try:
            async with app.router.lifespan_context(app):
                async with Client(transport) as client:
                    search = await client.call_tool(
                        "coyote_search_tools",
                        {"query": "lookup", "collection_slug": "engineering"},
                    )
                    tool_id = search.data[0]["tool_id"]
                    description = await client.call_tool(
                        "coyote_describe_tool",
                        {"tool_id": tool_id, "collection_slug": "engineering"},
                    )
                    execution = await client.call_tool(
                        "coyote_execute_tool",
                        {
                            "tool_id": tool_id,
                            "arguments": {"issue": 42},
                            "collection_slug": "engineering",
                        },
                    )
        finally:
            app.state.mcp_session_factory = original_factory

    assert description.data["name"] == "issue_lookup"
    assert execution.is_error is False
    assert execution.data["structured_content"] == {"issue": 42}
    assert authorization_headers
    assert authorization_headers == [None] * len(authorization_headers)


@pytest.mark.asyncio
async def test_native_collection_endpoint_lists_and_executes_persisted_tools(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALLOW_INSECURE_ENDPOINTS", "true")
    monkeypatch.setenv("ALLOW_PRIVATE_ENDPOINTS", "true")
    async with session_factory() as session:
        _, token, tool, _ = await _collection_consumer(session)
        collection = await session.scalar(select(Collection))
        assert collection is not None
        collection.exposure_mode = "native"
        await session.commit()

    original_execute_tool = GatewayService.execute_tool

    async def assert_lookup_transaction_released(
        self: GatewayService,
        execution_session: AsyncSession,
        current: AuthenticatedPrincipal,
        tool_id: UUID,
        arguments: dict[str, Any],
        collection_slug: str | None,
    ) -> dict[str, Any]:
        assert execution_session.in_transaction() is False
        return await original_execute_tool(
            self, execution_session, current, tool_id, arguments, collection_slug
        )

    monkeypatch.setattr(GatewayService, "execute_tool", assert_lookup_transaction_released)

    async with downstream_server() as (endpoint, _):
        async with session_factory() as session:
            await point_tool_at_downstream(session, tool, endpoint)

        original_factory = app.state.mcp_session_factory
        app.state.mcp_session_factory = session_factory
        try:
            async with app.router.lifespan_context(app):
                async with Client(collection_mcp_transport(token, "engineering")) as client:
                    tools = await client.list_tools()
                    result = await client.call_tool("downstream__issue_lookup", {"issue": 42})
        finally:
            app.state.mcp_session_factory = original_factory

    assert [tool.name for tool in tools] == ["downstream__issue_lookup"]
    assert result.is_error is False
    assert result.data == {"issue": 42}


@pytest.mark.asyncio
async def test_unpublishing_removes_native_tool_from_discovery_and_execution(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALLOW_INSECURE_ENDPOINTS", "true")
    monkeypatch.setenv("ALLOW_PRIVATE_ENDPOINTS", "true")
    async with session_factory() as session:
        principal, token, tool, organization = await _collection_consumer(session)
        collection = await session.scalar(select(Collection))
        assert collection is not None
        collection.exposure_mode = "native"
        publication = await session.scalar(
            select(CollectionToolPublication).where(CollectionToolPublication.tool_id == tool.id)
        )
        assert publication is not None
        collection_id = collection.id
        publication_id = publication.id
        await session.commit()

    async with downstream_server() as (endpoint, _):
        async with session_factory() as session:
            await point_tool_at_downstream(session, tool, endpoint)

        original_factory = app.state.mcp_session_factory
        app.state.mcp_session_factory = session_factory
        try:
            async with app.router.lifespan_context(app):
                async with Client(collection_mcp_transport(token, "engineering")) as client:
                    tools_before = await client.list_tools()
                    result_before = await client.call_tool(
                        "downstream__issue_lookup", {"issue": 42}
                    )
                    async with session_factory() as session:
                        await catalog.remove_publication(
                            session,
                            publication_current(principal, organization.id),
                            collection_id,
                            publication_id,
                        )
                        await session.commit()
                    tools_after = await client.list_tools()
                    denied = await client.call_tool(
                        "downstream__issue_lookup",
                        {"issue": 42},
                        raise_on_error=False,
                    )
        finally:
            app.state.mcp_session_factory = original_factory

    assert [listed.name for listed in tools_before] == ["downstream__issue_lookup"]
    assert result_before.is_error is False
    assert tools_after == []
    assert denied.is_error is True


@pytest.mark.asyncio
async def test_collection_discovery_endpoint_binds_its_collection_context(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        _, token, tool, _ = await _collection_consumer(session)

    original_factory = app.state.mcp_session_factory
    app.state.mcp_session_factory = session_factory
    try:
        async with app.router.lifespan_context(app):
            async with Client(collection_mcp_transport(token, "engineering")) as client:
                tools = await client.list_tools()
                search = await client.call_tool("coyote_search_tools", {"query": "lookup"})
                overridden = await client.call_tool(
                    "coyote_search_tools",
                    {"query": "lookup", "collection_slug": "other"},
                    raise_on_error=False,
                )
    finally:
        app.state.mcp_session_factory = original_factory

    assert {tool.name for tool in tools} == {
        "coyote_describe_tool",
        "coyote_execute_tool",
        "coyote_search_tools",
    }
    assert [item["tool_id"] for item in search.data] == [str(tool.id)]
    assert overridden.is_error is True


@pytest.mark.asyncio
async def test_collection_endpoint_cannot_execute_an_organization_wide_tool_outside_membership(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALLOW_INSECURE_ENDPOINTS", "true")
    monkeypatch.setenv("ALLOW_PRIVATE_ENDPOINTS", "true")
    async with session_factory() as session:
        principal, token, tool, organization = await _collection_consumer(session)
        collection = await session.scalar(select(Collection))
        server = await session.get(MCPServer, tool.server_id)
        assert collection is not None
        assert server is not None
        other_collection = await catalog.create_collection(
            session,
            organization.id,
            CollectionCreate(slug="other", display_name="Other"),
        )
        await catalog.remove_membership(session, organization.id, collection.id, server.id)
        await catalog.add_membership(
            session,
            organization.id,
            other_collection.id,
            MembershipCreate(server_id=server.id),
        )
        session.add(
            RoleAssignment(
                organization_id=organization.id,
                principal_id=principal.id,
                role="consumer",
                collection_id=None,
            )
        )
        await session.commit()

    async with downstream_server() as (endpoint, authorization_headers):
        async with session_factory() as session:
            await point_tool_at_downstream(session, tool, endpoint)

        original_factory = app.state.mcp_session_factory
        app.state.mcp_session_factory = session_factory
        try:
            async with app.router.lifespan_context(app):
                async with Client(collection_mcp_transport(token, "engineering")) as client:
                    result = await client.call_tool(
                        "coyote_execute_tool",
                        {"tool_id": str(tool.id), "arguments": {"issue": 42}},
                        raise_on_error=False,
                    )
        finally:
            app.state.mcp_session_factory = original_factory

    assert result.is_error is True
    assert authorization_headers == []


@pytest.mark.asyncio
async def test_native_collection_endpoint_namespaces_duplicates_and_refreshes_catalog(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        principal, token, tool, organization = await _collection_consumer(session)
        collection = await session.scalar(select(Collection))
        assert collection is not None
        collection.exposure_mode = "native"
        duplicate_server = await catalog.create_server(
            session,
            organization.id,
            ServerCreate(
                name="secondary",
                display_name="Secondary",
                endpoint=HttpUrl("https://example.com/secondary"),
            ),
        )
        duplicate_server.status = "ready"
        await catalog.add_membership(
            session,
            organization.id,
            collection.id,
            MembershipCreate(server_id=duplicate_server.id),
        )
        duplicate = Tool(
            server_id=duplicate_server.id,
            name=tool.name,
            description="Secondary lookup",
            input_schema={"type": "object"},
            annotations={},
            fingerprint="b" * 64,
            active=True,
            last_seen_at=datetime.now(UTC),
        )
        session.add(duplicate)
        await session.commit()
        await catalog.publish_tool(
            session,
            publication_current(principal, organization.id),
            collection.id,
            PublicationCreate(tool_id=duplicate.id, published_name="secondary__issue_lookup"),
        )

    original_factory = app.state.mcp_session_factory
    app.state.mcp_session_factory = session_factory
    try:
        async with app.router.lifespan_context(app):
            async with Client(collection_mcp_transport(token, "engineering")) as client:
                initial_tools = await client.list_tools()
                async with session_factory() as session:
                    await add_catalog_tool(session, tool, "new_lookup")
                refreshed_tools = await client.list_tools()
    finally:
        app.state.mcp_session_factory = original_factory

    assert [tool.name for tool in initial_tools] == [
        "downstream__issue_lookup",
        "secondary__issue_lookup",
    ]
    assert [tool.name for tool in refreshed_tools] == [
        "downstream__issue_lookup",
        "secondary__issue_lookup",
    ]


@pytest.mark.asyncio
async def test_native_collection_aliases_are_stable_and_unique(
    session: AsyncSession,
) -> None:
    principal, token, tool, organization = await _collection_consumer(session)
    collection = await session.scalar(select(Collection))
    publication = await session.scalar(select(CollectionToolPublication))
    server = await session.get(MCPServer, tool.server_id)
    assert collection is not None
    assert publication is not None
    assert server is not None
    collection.exposure_mode = "native"
    publication.published_name = "curated_lookup"
    publication.description_override = "Curated issue lookup"
    server.name = "renamed-downstream"
    await session.commit()
    with pytest.raises(catalog.DuplicateResourceError):
        await catalog.publish_tool(
            session,
            publication_current(principal, organization.id),
            collection.id,
            PublicationCreate(tool_id=tool.id, published_name="curated_lookup"),
        )
    current = await authenticate_token(session, token)
    assert current is not None

    native_tools = await GatewayService(Settings()).native_tools(session, current, "engineering")

    assert [(item.published_name, item.description) for item in native_tools] == [
        ("curated_lookup", "Curated issue lookup")
    ]


@pytest.mark.asyncio
async def test_native_collection_rejects_unpublished_or_disabled_tool_execution(
    session: AsyncSession,
) -> None:
    _, token, tool, _ = await _collection_consumer(session)
    collection = await session.scalar(select(Collection))
    publication = await session.scalar(select(CollectionToolPublication))
    assert collection is not None
    assert publication is not None
    collection.exposure_mode = "native"
    unpublished = await add_catalog_tool(session, tool, "unpublished_lookup")
    current = await authenticate_token(session, token)
    assert current is not None

    with pytest.raises(GatewayError, match="not available"):
        await GatewayService(Settings()).execute_tool(
            session, current, unpublished.id, {}, "engineering"
        )
    publication.enabled = False
    await session.commit()
    assert await GatewayService(Settings()).native_tools(session, current, "engineering") == []
    with pytest.raises(GatewayError, match="not available"):
        await GatewayService(Settings()).execute_tool(session, current, tool.id, {}, "engineering")


@pytest.mark.asyncio
async def test_native_collection_tool_limit_rejects_partial_publication(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with session_factory() as session:
        principal, token, tool, organization = await _collection_consumer(session)
        collection = await session.scalar(select(Collection))
        assert collection is not None
        collection.exposure_mode = "native"
        second_tool = await add_catalog_tool(session, tool, "second_lookup")
        await catalog.publish_tool(
            session,
            publication_current(principal, organization.id),
            collection.id,
            PublicationCreate(tool_id=second_tool.id, published_name="downstream__second_lookup"),
        )
    monkeypatch.setenv("COYOTE_MAX_NATIVE_TOOLS_PER_COLLECTION", "1")

    original_factory = app.state.mcp_session_factory
    app.state.mcp_session_factory = session_factory
    try:
        async with app.router.lifespan_context(app):
            async with Client(collection_mcp_transport(token, "engineering")) as client:
                with pytest.raises(MCPError, match="configured limit"):
                    await client.list_tools()
    finally:
        app.state.mcp_session_factory = original_factory


@pytest.mark.asyncio
async def test_native_collection_endpoint_hides_disabled_and_non_executable_views(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        principal, token, _, _ = await _collection_consumer(session)
        collection = await session.scalar(select(Collection))
        assignment = await session.scalar(
            select(RoleAssignment).where(RoleAssignment.principal_id == principal.id)
        )
        assert collection is not None
        assert assignment is not None
        collection.exposure_mode = "native"
        collection.enabled = False
        await session.commit()

    original_factory = app.state.mcp_session_factory
    app.state.mcp_session_factory = session_factory
    try:
        async with app.router.lifespan_context(app):
            async with Client(collection_mcp_transport(token, "engineering")) as client:
                disabled_tools = await client.list_tools()
                async with session_factory() as session:
                    collection = await session.scalar(select(Collection))
                    assert collection is not None
                    membership = await session.scalar(
                        select(CollectionMembership).where(
                            CollectionMembership.collection_id == collection.id
                        )
                    )
                    assert membership is not None
                    collection.enabled = True
                    membership.enabled = False
                    await session.commit()
                disabled_membership_tools = await client.list_tools()
                async with session_factory() as session:
                    assignment = await session.scalar(
                        select(RoleAssignment).where(RoleAssignment.principal_id == principal.id)
                    )
                    membership = await session.scalar(select(CollectionMembership))
                    assert assignment is not None
                    assert membership is not None
                    membership.enabled = True
                    assignment.role = "viewer"
                    await session.commit()
                unauthorized_tools = await client.list_tools()
            async with Client(collection_mcp_transport(token, "missing")) as unknown_client:
                unknown_tools = await unknown_client.list_tools()
    finally:
        app.state.mcp_session_factory = original_factory

    assert disabled_tools == []
    assert disabled_membership_tools == []
    assert unauthorized_tools == []
    assert unknown_tools == []


@pytest.mark.asyncio
async def test_collection_endpoint_rejects_revoked_pat(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        _, token, _, _ = await _collection_consumer(session)
        current = await authenticate_token(session, token)
        assert current is not None
        assert current.token is not None
        current.token.revoked_at = datetime.now(UTC)
        await session.commit()

    original_factory = app.state.mcp_session_factory
    app.state.mcp_session_factory = session_factory
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/mcp/collections/engineering",
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        app.state.mcp_session_factory = original_factory

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_native_collection_endpoint_isolates_concurrent_tenants(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        _, first_token, first_tool, first_organization = await _collection_consumer(session)
        _, second_token, second_tool, second_organization = await _collection_consumer(session)
        first_collection = await session.scalar(
            select(Collection).where(Collection.organization_id == first_organization.id)
        )
        second_collection = await session.scalar(
            select(Collection).where(Collection.organization_id == second_organization.id)
        )
        first_server = await session.get(MCPServer, first_tool.server_id)
        second_server = await session.get(MCPServer, second_tool.server_id)
        assert first_collection is not None
        assert second_collection is not None
        assert first_server is not None
        assert second_server is not None
        first_publication = await session.scalar(
            select(CollectionToolPublication).where(
                CollectionToolPublication.collection_id == first_collection.id
            )
        )
        second_publication = await session.scalar(
            select(CollectionToolPublication).where(
                CollectionToolPublication.collection_id == second_collection.id
            )
        )
        assert first_publication is not None
        assert second_publication is not None
        first_collection.exposure_mode = "native"
        second_collection.exposure_mode = "native"
        first_server.name = "first"
        second_server.name = "second"
        first_publication.published_name = "first__issue_lookup"
        second_publication.published_name = "second__issue_lookup"
        await session.commit()

    async def listed_names(token: str) -> list[str]:
        async with Client(collection_mcp_transport(token, "engineering")) as client:
            return [tool.name for tool in await client.list_tools()]

    original_factory = app.state.mcp_session_factory
    app.state.mcp_session_factory = session_factory
    try:
        async with app.router.lifespan_context(app):
            first_names, second_names = await asyncio.gather(
                listed_names(first_token), listed_names(second_token)
            )
    finally:
        app.state.mcp_session_factory = original_factory

    assert first_names == ["first__issue_lookup"]
    assert second_names == ["second__issue_lookup"]


@pytest.mark.asyncio
async def test_gateway_preserves_tool_errors_and_enforces_execution_limits(
    session: AsyncSession,
) -> None:
    principal, token, tool, organization = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None

    async with downstream_server() as (endpoint, _):
        await point_tool_at_downstream(session, tool, endpoint)
        failing_tool = await add_catalog_tool(session, tool, "tool_error")
        delayed_tool = await add_catalog_tool(session, tool, "delayed_lookup")
        large_tool = await add_catalog_tool(session, tool, "large_lookup")
        nullable_tool = await add_catalog_tool(session, tool, "nullable_lookup")
        collection = await session.scalar(select(Collection))
        assert collection is not None
        for published_tool in (failing_tool, delayed_tool, large_tool, nullable_tool):
            await catalog.publish_tool(
                session,
                publication_current(principal, organization.id),
                collection.id,
                PublicationCreate(
                    tool_id=published_tool.id, published_name=f"downstream__{published_tool.name}"
                ),
            )
        permissive_settings = Settings(
            allow_insecure_endpoints=True,
            allow_private_endpoints=True,
            execution_timeout_seconds=1,
        )
        tool_error_result = await GatewayService(permissive_settings).execute_tool(
            session, current, failing_tool.id, {}, "engineering"
        )
        assert tool_error_result["is_error"] is True
        nullable_result = await GatewayService(permissive_settings).execute_tool(
            session, current, nullable_tool.id, {}, "engineering"
        )
        assert nullable_result["structured_content"] == {"value": None}

        with pytest.raises(GatewayError, match="timed out"):
            await GatewayService(
                Settings(
                    allow_insecure_endpoints=True,
                    allow_private_endpoints=True,
                    execution_timeout_seconds=0.01,
                )
            ).execute_tool(session, current, delayed_tool.id, {}, "engineering")
        with pytest.raises(GatewayError, match="size limit"):
            await GatewayService(
                Settings(
                    allow_insecure_endpoints=True,
                    allow_private_endpoints=True,
                    max_execution_result_bytes=100,
                )
            ).execute_tool(session, current, large_tool.id, {}, "engineering")


@pytest.mark.asyncio
async def test_gateway_execution_does_not_finalize_caller_transaction(
    session: AsyncSession,
) -> None:
    _, token, tool, _ = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None

    async with downstream_server() as (endpoint, _):
        await point_tool_at_downstream(session, tool, endpoint)
        unrelated = Organization(slug=f"pending-{uuid4().hex}", display_name="Pending")
        session.add(unrelated)
        result = await GatewayService(
            Settings(allow_insecure_endpoints=True, allow_private_endpoints=True)
        ).execute_tool(session, current, tool.id, {"issue": 42}, "engineering")

    assert result["structured_content"] == {"issue": 42}
    assert unrelated in session.new
    await session.rollback()


@pytest.mark.asyncio
async def test_gateway_rechecks_catalog_authorization_and_credentials_before_execution(
    session: AsyncSession,
) -> None:
    principal, token, tool, organization = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    service = GatewayService(Settings())
    await service.search_tools(session, current, "lookup", "engineering", 10)

    assignment = await session.scalar(
        select(RoleAssignment).where(RoleAssignment.principal_id == principal.id)
    )
    assert assignment is not None
    await session.delete(assignment)
    await session.commit()
    with pytest.raises(GatewayError, match="not available"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "engineering")

    collection = await session.scalar(select(Collection))
    assert collection is not None
    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=principal.id,
            role="consumer",
            collection_id=collection.id,
        )
    )
    await session.commit()
    assert current.token is not None
    current.token.revoked_at = datetime.now(UTC)
    await session.commit()
    with pytest.raises(GatewayError, match="Authentication is no longer valid"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "engineering")


@pytest.mark.asyncio
async def test_gateway_rejects_malformed_schemas_and_hardens_search(session: AsyncSession) -> None:
    _, token, tool, _ = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    service = GatewayService(Settings())

    no_wildcard_match = await service.search_tools(session, current, "%", "engineering", 10)
    trimmed_match = await service.search_tools(session, current, "  lookup  ", "engineering", 10)
    assert no_wildcard_match == []
    assert [result.tool_id for result in trimmed_match] == [tool.id]
    with pytest.raises(GatewayError, match="query exceeds"):
        await service.search_tools(session, current, "x" * 257, "engineering", 10)

    tool.input_schema = {"type": "not-a-real-json-schema-type"}
    await session.commit()
    with pytest.raises(GatewayError, match="Stored tool schema"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "engineering")


@pytest.mark.asyncio
async def test_gateway_bounds_untrusted_schema_validation(session: AsyncSession) -> None:
    _, token, tool, _ = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    tool.input_schema = {
        "type": "object",
        "properties": {"issue": {"type": "string", "pattern": "^(a+)+$"}},
        "required": ["issue"],
    }
    await session.commit()
    service = GatewayService(Settings(schema_validation_timeout_seconds=5))

    with pytest.raises(GatewayError, match="validation timed out"):
        await service.execute_tool(
            session,
            current,
            tool.id,
            {"issue": "a" * 50 + "!"},
            "engineering",
        )


@pytest.mark.asyncio
async def test_gateway_allows_local_schema_references_and_rejects_external_ones() -> None:
    service = GatewayService(Settings())

    await service._validate_arguments(
        {
            "type": "object",
            "$defs": {"issue": {"type": "integer"}},
            "properties": {"issue": {"$ref": "#/$defs/issue"}},
        },
        {"issue": 42},
    )

    with pytest.raises(GatewayError, match="Stored tool schema"):
        await service._validate_arguments(
            {"$ref": "http://127.0.0.1:9/untrusted-schema"},
            {},
        )


@pytest.mark.asyncio
async def test_gateway_rechecks_membership_tool_server_and_collection_context(
    session: AsyncSession,
) -> None:
    _, token, tool, organization = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    collection = await session.scalar(select(Collection))
    server = await session.get(MCPServer, tool.server_id)
    assert collection is not None
    assert server is not None
    service = GatewayService(
        Settings(
            allow_insecure_endpoints=True,
            allow_private_endpoints=True,
            execution_timeout_seconds=0.01,
        )
    )

    other_collection = await catalog.create_collection(
        session,
        organization.id,
        CollectionCreate(slug="restricted", display_name="Restricted"),
    )
    await catalog.add_membership(
        session,
        organization.id,
        other_collection.id,
        MembershipCreate(server_id=server.id),
    )
    with pytest.raises(GatewayError, match="not available"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "restricted")

    await catalog.remove_membership(session, organization.id, collection.id, server.id)
    with pytest.raises(GatewayError, match="not available"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "engineering")

    await catalog.add_membership(
        session, organization.id, collection.id, MembershipCreate(server_id=server.id)
    )
    tool.active = False
    await session.commit()
    with pytest.raises(GatewayError, match="not available"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "engineering")

    tool.active = True
    server.status = "error"
    await session.commit()
    with pytest.raises(GatewayError, match="not available"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "engineering")

    server.status = "ready"
    server.endpoint = "http://127.0.0.1:1/mcp"
    await session.commit()
    with pytest.raises(GatewayError, match="execution failed"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "engineering")
