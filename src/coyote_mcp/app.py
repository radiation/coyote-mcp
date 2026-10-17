from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any
from uuid import UUID

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools.base import Tool, ToolResult
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, ToolAnnotations
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.api import router as api_router
from coyote_mcp.auth import AuthenticatedPrincipal, authenticate_token
from coyote_mcp.console import router as console_router
from coyote_mcp.db import SessionLocal
from coyote_mcp.gateway import GatewayError, GatewayService, NativeGatewayTool
from coyote_mcp.oidc import router as oidc_router
from coyote_mcp.settings import Settings


class HealthResponse(BaseModel):
    status: str


mcp = FastMCP("coyote-mcp")
_mcp_current: ContextVar[AuthenticatedPrincipal | None] = ContextVar("mcp_current", default=None)
_mcp_session_factory: ContextVar[async_sessionmaker[AsyncSession] | None] = ContextVar(
    "mcp_session_factory", default=None
)
_mcp_collection_slug: ContextVar[str | None] = ContextVar("mcp_collection_slug", default=None)


def _gateway_context() -> tuple[AuthenticatedPrincipal, async_sessionmaker[AsyncSession]]:
    current = _mcp_current.get()
    session_factory = _mcp_session_factory.get()
    if current is None or session_factory is None:
        raise GatewayError("Authentication is required.")
    return current, session_factory


def _bound_collection_slug() -> str | None:
    return _mcp_collection_slug.get()


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
    bound_collection = _bound_collection_slug()
    if bound_collection is not None:
        if collection_slug is not None and collection_slug != bound_collection:
            raise GatewayError("Collection endpoint is bound to its URL collection.")
        collection_slug = bound_collection
    async with _gateway_session() as (service, session, current):
        tools = await service.search_tools(session, current, query, collection_slug, limit)
    return [
        {
            "tool_id": str(tool.tool_id),
            "name": tool.name,
            "published_name": tool.published_name,
            "description": tool.description,
            "collection_slug": tool.collection_slug,
            "server_name": tool.server_name,
        }
        for tool in tools
    ]


@mcp.tool(name="coyote_describe_tool")
async def coyote_describe_tool(tool_id: str, collection_slug: str | None = None) -> dict[str, Any]:
    """Describe one currently authorized catalog tool and its published schema."""
    bound_collection = _bound_collection_slug()
    if bound_collection is not None:
        if collection_slug is not None and collection_slug != bound_collection:
            raise GatewayError("Collection endpoint is bound to its URL collection.")
        collection_slug = bound_collection
    async with _gateway_session() as (service, session, current):
        return await service.describe_tool(session, current, UUID(tool_id), collection_slug)


@mcp.tool(name="coyote_execute_tool")
async def coyote_execute_tool(
    tool_id: str, arguments: dict[str, Any], collection_slug: str | None = None
) -> dict[str, Any]:
    """Execute one currently authorized catalog tool through its registered server."""
    bound_collection = _bound_collection_slug()
    if bound_collection is not None:
        if collection_slug is not None and collection_slug != bound_collection:
            raise GatewayError("Collection endpoint is bound to its URL collection.")
        collection_slug = bound_collection
    async with _gateway_session() as (service, session, current):
        return await service.execute_tool(
            session, current, UUID(tool_id), arguments, collection_slug
        )


class CollectionMCP(FastMCP):
    async def list_tools(self, *, run_middleware: bool = True) -> list[Tool]:
        del run_middleware
        collection_slug = _bound_collection_slug()
        if collection_slug is None:
            return []
        current, session_factory = _gateway_context()
        async with session_factory() as session:
            service = GatewayService(Settings())
            try:
                exposure_mode = await service.collection_exposure_mode(
                    session, current, collection_slug
                )
            except GatewayError:
                return []
            if exposure_mode == "discovery":
                try:
                    await service.discovery_collection(session, current, collection_slug)
                except GatewayError:
                    return []
            else:
                try:
                    native_tools = await service.native_tools(session, current, collection_slug)
                except GatewayError as error:
                    if "configured limit" in str(error):
                        raise MCPError(code=INVALID_PARAMS, message=str(error)) from error
                    return []
                return [self._native_tool_metadata(tool) for tool in native_tools]
        return list(await mcp.list_tools())

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        version: object | None = None,
        run_middleware: bool = True,
    ) -> ToolResult:
        del version, run_middleware
        collection_slug = _bound_collection_slug()
        if collection_slug is None:
            raise ToolError("Collection endpoint is not available.")
        current, session_factory = _gateway_context()
        async with session_factory() as session:
            service = GatewayService(Settings())
            try:
                exposure_mode = await service.collection_exposure_mode(
                    session, current, collection_slug
                )
            except GatewayError as error:
                raise ToolError(str(error)) from error
            if exposure_mode == "discovery":
                try:
                    await service.discovery_collection(session, current, collection_slug)
                except GatewayError as error:
                    raise ToolError(str(error)) from error
            else:
                try:
                    tool = await service.native_tool(session, current, collection_slug, name)
                    await session.rollback()
                    payload = await service.execute_tool(
                        session, current, tool.tool_id, arguments or {}, collection_slug
                    )
                except GatewayError as error:
                    raise ToolError(str(error)) from error
                return ToolResult(
                    content=payload.get("content"),
                    structured_content=payload.get("structured_content"),
                    is_error=bool(payload.get("is_error", False)),
                )
        if name not in {"coyote_search_tools", "coyote_describe_tool", "coyote_execute_tool"}:
            raise ToolError("Tool is not available.")
        return await mcp.call_tool(name, arguments or {})

    @staticmethod
    def _native_tool_metadata(tool: NativeGatewayTool) -> Tool:
        try:
            annotations = ToolAnnotations.model_validate(tool.annotations)
        except TypeError, ValueError:
            annotations = None
        return Tool(
            name=tool.published_name,
            description=tool.description,
            parameters=tool.input_schema,
            output_schema=tool.output_schema,
            annotations=annotations,
        )


mcp_app = mcp.http_app(path="/", transport="streamable-http")
collection_mcp = CollectionMCP("coyote-mcp-collections")
collection_mcp_app = collection_mcp.http_app(path="/{collection_slug}", transport="streamable-http")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with mcp_app.lifespan(app), collection_mcp_app.lifespan(app):
        yield


app = FastAPI(title="coyote-mcp", lifespan=lifespan)
settings = Settings()
app.state.mcp_session_factory = SessionLocal
app.mount("/static", StaticFiles(packages=[("coyote_mcp", "static")]), name="static")


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
    request_path = request.url.path
    collection_slug = request_path.removeprefix("/mcp/collections/")
    collection_token = _mcp_collection_slug.set(
        collection_slug if request_path.startswith("/mcp/collections/") else None
    )
    try:
        return await call_next(request)
    finally:
        _mcp_collection_slug.reset(collection_token)
        _mcp_session_factory.reset(session_factory_token)
        _mcp_current.reset(principal_token)


app.mount("/mcp/collections", collection_mcp_app)
app.mount("/mcp", mcp_app)
app.include_router(api_router)
app.include_router(oidc_router)
app.include_router(console_router)


@app.get("/", include_in_schema=False)
async def landing() -> dict[str, str]:
    return {"status": "coyote-mcp"}


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")
