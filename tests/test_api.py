from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.app import app
from coyote_mcp.db import get_session


@pytest.mark.asyncio
async def test_register_server_and_duplicate_response(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            payload = {
                "name": "example",
                "display_name": "Example",
                "endpoint": "https://example.com/mcp",
            }
            response = await client.post("/api/v1/servers", json=payload)
            duplicate = await client.post("/api/v1/servers", json=payload)
            listing = await client.get("/api/v1/servers")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    assert response.json()["name"] == "example"
    assert duplicate.status_code == 409
    assert [server["name"] for server in listing.json()] == ["example"]
