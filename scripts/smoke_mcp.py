from __future__ import annotations

import asyncio
import os
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from coyote_mcp.auth import ALL_ACTIONS, issue_pat
from coyote_mcp.models import (
    Collection,
    CollectionMembership,
    MCPServer,
    Organization,
    PersonalAccessToken,
    Principal,
    RoleAssignment,
    Tool,
)
from coyote_mcp.settings import Settings

GATEWAY_URL = os.environ.get("COYOTE_SMOKE_GATEWAY_URL", "http://127.0.0.1:8000")
DOWNSTREAM_URL = os.environ.get("COYOTE_SMOKE_DOWNSTREAM_URL", "http://smoke-mcp:8001/mcp")


async def create_tenant(session: AsyncSession, settings: Settings, suffix: str) -> tuple[UUID, str]:
    organization = Organization(slug=f"smoke-{suffix}", display_name="MCP Smoke Test")
    session.add(organization)
    await session.flush()
    owner = Principal(
        organization_id=organization.id,
        identifier="smoke-owner",
        display_name="Smoke Owner",
        identity_type="service",
    )
    session.add(owner)
    await session.flush()
    session.add(
        RoleAssignment(organization_id=organization.id, principal_id=owner.id, role="owner")
    )
    await session.flush()
    _, token = await issue_pat(
        session,
        owner,
        "smoke-owner",
        set(ALL_ACTIONS),
        timedelta(minutes=10),
        settings,
        commit=False,
    )
    await session.commit()
    return organization.id, token


async def delete_tenant(session: AsyncSession, organization_id: UUID) -> None:
    server_ids = select(MCPServer.id).where(MCPServer.organization_id == organization_id)
    await session.execute(delete(Tool).where(Tool.server_id.in_(server_ids)))
    await session.execute(
        delete(CollectionMembership).where(CollectionMembership.organization_id == organization_id)
    )
    await session.execute(delete(MCPServer).where(MCPServer.organization_id == organization_id))
    await session.execute(
        delete(RoleAssignment).where(RoleAssignment.organization_id == organization_id)
    )
    await session.execute(
        delete(PersonalAccessToken).where(PersonalAccessToken.organization_id == organization_id)
    )
    await session.execute(delete(Collection).where(Collection.organization_id == organization_id))
    await session.execute(delete(Principal).where(Principal.organization_id == organization_id))
    await session.execute(delete(Organization).where(Organization.id == organization_id))
    await session.commit()


def require_status(response: httpx.Response, expected: int) -> dict[str, Any]:
    if response.status_code != expected:
        raise RuntimeError(
            f"{response.request.method} {response.url} returned {response.status_code}"
        )
    return response.json()


def mcp_transport(token: str) -> StreamableHttpTransport:
    return StreamableHttpTransport(
        f"{GATEWAY_URL}/mcp", headers={"Authorization": f"Bearer {token}"}
    )


async def run() -> None:
    settings = Settings()
    engine: AsyncEngine = create_async_engine(settings.database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex
    owner_organization_id: UUID | None = None
    isolated_organization_id: UUID | None = None
    try:
        async with sessions() as session:
            owner_organization_id, owner_token = await create_tenant(session, settings, suffix)
            isolated_organization_id, isolated_token = await create_tenant(
                session, settings, f"isolated-{suffix}"
            )

        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=15) as rest:
            health = await rest.get("/healthz")
            require_status(health, 200)
            server = require_status(
                await rest.post(
                    "/api/v1/servers",
                    headers=owner_headers,
                    json={
                        "name": f"smoke-{suffix[:12]}",
                        "display_name": "Smoke Mock",
                        "endpoint": DOWNSTREAM_URL,
                    },
                ),
                201,
            )
            synced = require_status(
                await rest.post(f"/api/v1/servers/{server['id']}/sync", headers=owner_headers),
                200,
            )
            if synced["status"] != "ready":
                raise RuntimeError("Mock server synchronization did not become ready.")
            collection = require_status(
                await rest.post(
                    "/api/v1/collections",
                    headers=owner_headers,
                    json={"slug": f"smoke-{suffix[:12]}", "display_name": "Smoke Tools"},
                ),
                201,
            )
            require_status(
                await rest.post(
                    f"/api/v1/collections/{collection['id']}/servers",
                    headers=owner_headers,
                    json={"server_id": server["id"]},
                ),
                201,
            )
            principal = require_status(
                await rest.post(
                    "/api/v1/service-principals",
                    headers=owner_headers,
                    json={
                        "identifier": f"smoke-client-{suffix[:12]}",
                        "display_name": "Smoke Client",
                        "roles": ["consumer"],
                    },
                ),
                201,
            )
            credential = require_status(
                await rest.post(
                    f"/api/v1/service-principals/{principal['id']}/pats",
                    headers=owner_headers,
                    json={
                        "name": "smoke-client",
                        "scopes": ["tool:discover", "tool:describe", "tool:execute"],
                        "lifetime_seconds": 600,
                    },
                ),
                201,
            )

            async with Client(mcp_transport(credential["token"])) as client:
                tools = await client.list_tools()
                if {tool.name for tool in tools} != {
                    "coyote_search_tools",
                    "coyote_describe_tool",
                    "coyote_execute_tool",
                }:
                    raise RuntimeError("Gateway tool list did not match the universal interface.")
                search = await client.call_tool("coyote_search_tools", {"query": "echo"})
                echo_tool_id = search.data[0]["tool_id"]
                description = await client.call_tool(
                    "coyote_describe_tool", {"tool_id": echo_tool_id}
                )
                if description.data["name"] != "echo":
                    raise RuntimeError("Describe returned the wrong downstream tool.")
                echo = await client.call_tool(
                    "coyote_execute_tool",
                    {"tool_id": echo_tool_id, "arguments": {"message": "smoke"}},
                )
                if echo.data["structured_content"] != {"message": "smoke"}:
                    raise RuntimeError("Echo execution did not preserve its structured result.")
                add_search = await client.call_tool("coyote_search_tools", {"query": "add"})
                add_result = await client.call_tool(
                    "coyote_execute_tool",
                    {
                        "tool_id": add_search.data[0]["tool_id"],
                        "arguments": {"left": 2, "right": 3},
                    },
                )
                if add_result.data["structured_content"] != {"sum": 5}:
                    raise RuntimeError("Add execution returned an unexpected result.")
                failing_search = await client.call_tool("coyote_search_tools", {"query": "fail"})
                downstream_error = await client.call_tool(
                    "coyote_execute_tool",
                    {"tool_id": failing_search.data[0]["tool_id"], "arguments": {}},
                )
                if downstream_error.data["is_error"] is not True:
                    raise RuntimeError("Downstream tool error was not preserved.")

            async with Client(mcp_transport(isolated_token)) as isolated_client:
                isolated_search = await isolated_client.call_tool(
                    "coyote_search_tools", {"query": "echo"}
                )
                if isolated_search.data != []:
                    raise RuntimeError("Tenant isolation failed: another tenant saw smoke tools.")

            revoke = await rest.delete(
                f"/api/v1/service-principals/{principal['id']}/pats/{credential['id']}",
                headers=owner_headers,
            )
            if revoke.status_code != 204:
                raise RuntimeError("Unable to revoke the smoke client credential.")
            try:
                async with Client(mcp_transport(credential["token"])) as revoked_client:
                    await revoked_client.list_tools()
            except Exception:
                pass
            else:
                raise RuntimeError("Revoked credential still negotiated an MCP session.")
        print("MCP smoke test passed.")
    finally:
        async with sessions() as session:
            if isolated_organization_id is not None:
                await delete_tenant(session, isolated_organization_id)
            if owner_organization_id is not None:
                await delete_tenant(session, owner_organization_id)
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run())
