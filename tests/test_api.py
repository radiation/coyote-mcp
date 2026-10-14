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


@pytest.mark.asyncio
async def test_collection_and_server_catalog_endpoints(
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
            server = await client.post(
                "/api/v1/servers",
                json={
                    "name": "catalog",
                    "display_name": "Catalog",
                    "endpoint": "https://example.com/mcp",
                },
            )
            server_id = server.json()["id"]
            server_detail = await client.get(f"/api/v1/servers/{server_id}")
            server_tools = await client.get(f"/api/v1/servers/{server_id}/tools")
            collection = await client.post(
                "/api/v1/collections",
                json={"slug": "engineering", "display_name": "Engineering"},
            )
            collection_id = collection.json()["id"]
            collection_list = await client.get("/api/v1/collections")
            membership = await client.post(
                f"/api/v1/collections/{collection_id}/servers",
                json={"server_id": server_id},
            )
            collection_detail = await client.get(f"/api/v1/collections/{collection_id}")
            collection_tools = await client.get(f"/api/v1/collections/{collection_id}/tools")
            deleted = await client.delete(
                f"/api/v1/collections/{collection_id}/servers/{server_id}"
            )
            collection_without_membership = await client.get(f"/api/v1/collections/{collection_id}")
    finally:
        app.dependency_overrides.clear()

    assert server.status_code == 201
    assert server_detail.json()["id"] == server_id
    assert server_tools.json() == []
    assert collection.status_code == 201
    assert [item["slug"] for item in collection_list.json()] == ["engineering"]
    assert membership.status_code == 201
    assert [item["server_id"] for item in collection_detail.json()["memberships"]] == [server_id]
    assert collection_tools.json() == []
    assert deleted.status_code == 204
    assert collection_without_membership.json()["memberships"] == []
