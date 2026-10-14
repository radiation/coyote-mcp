import asyncio
import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from coyote_mcp import catalog
from coyote_mcp.discovery import (
    DiscoveredTool,
    DiscoveryService,
    SyncSupersededError,
)
from coyote_mcp.models import MCPServer, Organization, Tool
from coyote_mcp.schemas import ServerCreate
from coyote_mcp.settings import Settings

POSTGRES_INTEGRATION_URL = os.environ.get("POSTGRES_INTEGRATION_URL")
pytestmark = pytest.mark.postgres


@pytest.fixture
async def postgres_sessions() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    if POSTGRES_INTEGRATION_URL is None:
        pytest.skip("Set POSTGRES_INTEGRATION_URL to run PostgreSQL integration tests.")
    engine = create_async_engine(POSTGRES_INTEGRATION_URL)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.execute(text("TRUNCATE organizations CASCADE"))
    yield sessions
    async with engine.begin() as connection:
        await connection.execute(text("TRUNCATE organizations CASCADE"))
    await engine.dispose()


def server_request(name: str = "postgres") -> ServerCreate:
    return ServerCreate(
        name=name,
        display_name=name.title(),
        endpoint="https://example.com/mcp",
    )


def discovered_tool(name: str) -> DiscoveredTool:
    return DiscoveredTool(
        name=name,
        description=f"{name} description",
        input_schema={"type": "object", "properties": {"value": {"type": "string"}}},
        output_schema={"type": "string"},
        annotations={"readOnlyHint": True},
    )


@pytest.mark.asyncio
async def test_postgres_migration_and_jsonb_persistence(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with postgres_sessions() as session:
        revision = await session.scalar(text("SELECT version_num FROM alembic_version"))
        assert revision == "0010"
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        session.add(organization)
        await session.commit()
        server = await catalog.create_server(session, organization.id, server_request())
        tool = Tool(
            server_id=server.id,
            name="jsonb",
            description="JSONB test",
            input_schema={"type": "object"},
            output_schema={"type": "string"},
            annotations={"idempotentHint": True},
            fingerprint="a" * 64,
        )
        session.add(tool)
        await session.commit()
        persisted_type = await session.scalar(
            text("SELECT pg_typeof(input_schema)::text FROM tools WHERE id = :id"),
            {"id": tool.id},
        )

    assert persisted_type == "jsonb"


@pytest.mark.asyncio
async def test_postgres_unique_tool_constraint(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with postgres_sessions() as session:
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        session.add(organization)
        await session.commit()
        server = await catalog.create_server(session, organization.id, server_request())
        for fingerprint in ("a" * 64, "b" * 64):
            session.add(
                Tool(
                    server_id=server.id,
                    name="duplicate",
                    description="duplicate",
                    input_schema={},
                    annotations={},
                    fingerprint=fingerprint,
                )
            )
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()


class OrderedDiscoveryClient:
    def __init__(self) -> None:
        self.first_started = asyncio.Event()
        self.release_first = asyncio.Event()
        self.calls = 0

    async def list_tools(self, endpoint: str) -> list[DiscoveredTool]:
        self.calls += 1
        if self.calls == 1:
            self.first_started.set()
            await self.release_first.wait()
            return [discovered_tool("stale")]
        return [discovered_tool("current")]


@pytest.mark.asyncio
async def test_postgres_concurrent_sync_rejects_stale_result(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with postgres_sessions() as setup_session:
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        setup_session.add(organization)
        await setup_session.commit()
        server = await catalog.create_server(setup_session, organization.id, server_request())
    client = OrderedDiscoveryClient()
    service = DiscoveryService(client, Settings())

    async def sync_once() -> MCPServer:
        async with postgres_sessions() as session:
            server_for_sync = await catalog.get_server(session, organization.id, server.id)
            return await service.sync(session, server_for_sync)

    first_sync = asyncio.create_task(sync_once())
    await client.first_started.wait()
    second_result = await sync_once()
    client.release_first.set()
    with pytest.raises(SyncSupersededError):
        await first_sync

    async with postgres_sessions() as verify_session:
        tools = await catalog.list_server_tools(verify_session, organization.id, server.id, 50, 0)

    assert second_result.status == "ready"
    assert [tool.name for tool in tools] == ["current"]
