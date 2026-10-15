import asyncio
import socket
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import httpx2
import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from pydantic import HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp import catalog
from coyote_mcp.app import app
from coyote_mcp.auth import authenticate_token, issue_pat
from coyote_mcp.gateway import GatewayError, GatewayService
from coyote_mcp.models import (
    Collection,
    MCPServer,
    Organization,
    Principal,
    RoleAssignment,
    Tool,
)
from coyote_mcp.schemas import CollectionCreate, MembershipCreate, ServerCreate
from coyote_mcp.settings import Settings


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


async def _collection_consumer(
    session: AsyncSession,
) -> tuple[Principal, str, Tool]:
    suffix = uuid4().hex
    organization = Organization(slug=f"gateway-{suffix}", display_name="Gateway")
    session.add(organization)
    await session.flush()
    principal = Principal(
        organization_id=organization.id,
        identifier=f"consumer-{suffix}",
        display_name="Consumer",
    )
    session.add(principal)
    await session.flush()
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
            role="consumer",
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
    _, token = await issue_pat(
        session,
        principal,
        "consumer",
        {"tool:discover", "tool:describe", "tool:execute"},
        timedelta(days=1),
        Settings(),
    )
    return principal, token, tool


@pytest.mark.asyncio
async def test_gateway_scoped_discovery_description_and_schema_validation(
    session: AsyncSession,
) -> None:
    _, token, tool = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    service = GatewayService(Settings())

    tools = await service.search_tools(session, current, "lookup", "engineering", 10)
    description = await service.describe_tool(session, current, tool.id, "engineering")

    assert [(result.tool_id, result.collection_slug) for result in tools] == [
        (tool.id, "engineering")
    ]
    assert description["input_schema"] == tool.input_schema
    with pytest.raises(GatewayError, match="Collection context"):
        await service.describe_tool(session, current, tool.id, None)
    with pytest.raises(GatewayError, match="arguments"):
        await service.execute_tool(session, current, tool.id, {"issue": "invalid"}, "engineering")


@pytest.mark.asyncio
async def test_gateway_hides_removed_collection_membership(session: AsyncSession) -> None:
    principal, token, tool = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    collection = await session.scalar(select(Collection))
    assert collection is not None
    await catalog.remove_membership(
        session, principal.organization_id, collection.id, tool.server_id
    )

    with pytest.raises(GatewayError, match="not available"):
        await GatewayService(Settings()).describe_tool(session, current, tool.id, "engineering")


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
        _, token, _ = await _collection_consumer(session)

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
        _, token, tool = await _collection_consumer(session)

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
async def test_gateway_preserves_tool_errors_and_enforces_execution_limits(
    session: AsyncSession,
) -> None:
    _, token, tool = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None

    async with downstream_server() as (endpoint, _):
        await point_tool_at_downstream(session, tool, endpoint)
        failing_tool = await add_catalog_tool(session, tool, "tool_error")
        delayed_tool = await add_catalog_tool(session, tool, "delayed_lookup")
        large_tool = await add_catalog_tool(session, tool, "large_lookup")
        nullable_tool = await add_catalog_tool(session, tool, "nullable_lookup")
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
    _, token, tool = await _collection_consumer(session)
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
    principal, token, tool = await _collection_consumer(session)
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
            organization_id=principal.organization_id,
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
    _, token, tool = await _collection_consumer(session)
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
    _, token, tool = await _collection_consumer(session)
    current = await authenticate_token(session, token)
    assert current is not None
    tool.input_schema = {
        "type": "object",
        "properties": {"issue": {"type": "string", "pattern": "^(a+)+$"}},
        "required": ["issue"],
    }
    await session.commit()
    service = GatewayService(Settings(schema_validation_timeout_seconds=5))

    started_at = time.monotonic()
    with pytest.raises(GatewayError, match="validation timed out"):
        await service.execute_tool(
            session,
            current,
            tool.id,
            {"issue": "a" * 50 + "!"},
            "engineering",
        )

    assert time.monotonic() - started_at < 10


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
    principal, token, tool = await _collection_consumer(session)
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
        principal.organization_id,
        CollectionCreate(slug="restricted", display_name="Restricted"),
    )
    await catalog.add_membership(
        session,
        principal.organization_id,
        other_collection.id,
        MembershipCreate(server_id=server.id),
    )
    with pytest.raises(GatewayError, match="not available"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "restricted")

    await catalog.remove_membership(session, principal.organization_id, collection.id, server.id)
    with pytest.raises(GatewayError, match="not available"):
        await service.execute_tool(session, current, tool.id, {"issue": 1}, "engineering")

    await catalog.add_membership(
        session, principal.organization_id, collection.id, MembershipCreate(server_id=server.id)
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
