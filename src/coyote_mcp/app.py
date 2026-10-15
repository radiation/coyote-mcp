from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any
from uuid import UUID

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastmcp import FastMCP
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.api import router as api_router
from coyote_mcp.auth import AuthenticatedPrincipal, authenticate_token
from coyote_mcp.db import SessionLocal
from coyote_mcp.gateway import GatewayError, GatewayService
from coyote_mcp.oidc import router as oidc_router
from coyote_mcp.settings import Settings


class HealthResponse(BaseModel):
    status: str


mcp = FastMCP("coyote-mcp")
_mcp_current: ContextVar[AuthenticatedPrincipal | None] = ContextVar("mcp_current", default=None)
_mcp_session_factory: ContextVar[async_sessionmaker[AsyncSession] | None] = ContextVar(
    "mcp_session_factory", default=None
)


def _gateway_context() -> tuple[AuthenticatedPrincipal, async_sessionmaker[AsyncSession]]:
    current = _mcp_current.get()
    session_factory = _mcp_session_factory.get()
    if current is None or session_factory is None:
        raise GatewayError("Authentication is required.")
    return current, session_factory


@asynccontextmanager
async def _gateway_session() -> AsyncIterator[
    tuple[GatewayService, AsyncSession, AuthenticatedPrincipal]
]:
    current, session_factory = _gateway_context()
    async with session_factory() as session:
        yield GatewayService(Settings()), session, current


@mcp.tool(name="coyote_search_tools")
async def coyote_search_tools(
    query: str, collection_slug: str | None = None, limit: int = 10
) -> list[dict[str, str]]:
    """Search active catalog tools visible to the authenticated principal."""
    async with _gateway_session() as (service, session, current):
        tools = await service.search_tools(session, current, query, collection_slug, limit)
    return [
        {
            "tool_id": str(tool.tool_id),
            "name": tool.name,
            "description": tool.description,
            "collection_slug": tool.collection_slug,
            "server_name": tool.server_name,
        }
        for tool in tools
    ]


@mcp.tool(name="coyote_describe_tool")
async def coyote_describe_tool(tool_id: str, collection_slug: str | None = None) -> dict[str, Any]:
    """Describe one currently authorized catalog tool and its published schema."""
    async with _gateway_session() as (service, session, current):
        return await service.describe_tool(session, current, UUID(tool_id), collection_slug)


@mcp.tool(name="coyote_execute_tool")
async def coyote_execute_tool(
    tool_id: str, arguments: dict[str, Any], collection_slug: str | None = None
) -> dict[str, Any]:
    """Execute one currently authorized catalog tool through its registered server."""
    async with _gateway_session() as (service, session, current):
        return await service.execute_tool(
            session, current, UUID(tool_id), arguments, collection_slug
        )


mcp_app = mcp.http_app(path="/", transport="streamable-http")
app = FastAPI(title="coyote-mcp", lifespan=mcp_app.lifespan)
settings = Settings()
app.state.mcp_session_factory = SessionLocal


@app.middleware("http")
async def authenticate_mcp_requests(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    if not request.url.path.startswith("/mcp"):
        return await call_next(request)
    scheme, _, token_value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token_value:
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials."})
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.mcp_session_factory
    async with session_factory() as session:
        current = await authenticate_token(session, token_value)
    if current is None:
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials."})
    principal_token = _mcp_current.set(current)
    session_factory_token = _mcp_session_factory.set(session_factory)
    try:
        return await call_next(request)
    finally:
        _mcp_session_factory.reset(session_factory_token)
        _mcp_current.reset(principal_token)


app.mount("/mcp", mcp_app)
app.include_router(api_router)
app.include_router(oidc_router)


@app.get("/", include_in_schema=False)
async def landing() -> dict[str, str]:
    return {"status": "coyote-mcp"}


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")
