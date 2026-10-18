import hashlib
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx
import httpx2
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.downstream_errors import DownstreamAuthorizationError
from coyote_mcp.models import MCPServer, Tool
from coyote_mcp.security import ResolvedEndpoint, UnsafeEndpointError, resolve_endpoint
from coyote_mcp.settings import Settings


@dataclass(frozen=True)
class DiscoveredTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: dict[str, Any]

    @property
    def fingerprint(self) -> str:
        metadata = {
            "annotations": self.annotations,
            "description": self.description,
            "input_schema": self.input_schema,
            "name": self.name,
            "output_schema": self.output_schema,
        }
        canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode()).hexdigest()


class ToolDiscoveryClient(Protocol):
    async def list_tools(
        self, endpoint: str, headers: Mapping[str, str] | None = None
    ) -> Sequence[DiscoveredTool]: ...


DiscoveryHeadersProvider = Callable[[], Awaitable[Mapping[str, str]]]


class SyncFailedError(RuntimeError):
    pass


class SyncSupersededError(RuntimeError):
    pass


class PinnedDestinationTransport(httpx.AsyncHTTPTransport):
    def __init__(self, endpoint: ResolvedEndpoint) -> None:
        super().__init__(trust_env=False)
        self._endpoint = endpoint

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != self._endpoint.hostname:
            raise UnsafeEndpointError(
                "Discovery attempted to connect to an unexpected destination."
            )
        default_port = 443 if request.url.scheme == "https" else 80
        expected_port = self._endpoint.port or default_port
        request_port = request.url.port or default_port
        if request_port != expected_port:
            raise UnsafeEndpointError(
                "Discovery attempted to connect to an unexpected destination port."
            )
        headers = request.headers.copy()
        host_header = self._endpoint.hostname
        if request.url.port is not None and request.url.port != default_port:
            host_header = f"{host_header}:{request.url.port}"
        headers["host"] = host_header
        extensions = {**request.extensions, "sni_hostname": self._endpoint.hostname}
        pinned_request = httpx.Request(
            request.method,
            request.url.copy_with(host=self._endpoint.address),
            headers=headers,
            stream=request.stream,
            extensions=extensions,
        )
        return await super().handle_async_request(pinned_request)


class PinnedMCPDestinationTransport(httpx2.AsyncHTTPTransport):
    def __init__(self, endpoint: ResolvedEndpoint) -> None:
        super().__init__(trust_env=False)
        self._endpoint = endpoint

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.host != self._endpoint.hostname:
            raise UnsafeEndpointError(
                "Discovery attempted to connect to an unexpected destination."
            )
        default_port = 443 if request.url.scheme == "https" else 80
        expected_port = self._endpoint.port or default_port
        request_port = request.url.port or default_port
        if request_port != expected_port:
            raise UnsafeEndpointError(
                "Discovery attempted to connect to an unexpected destination port."
            )
        headers = request.headers.copy()
        host_header = self._endpoint.hostname
        if request.url.port is not None and request.url.port != default_port:
            host_header = f"{host_header}:{request.url.port}"
        headers["host"] = host_header
        extensions = {**request.extensions, "sni_hostname": self._endpoint.hostname}
        pinned_request = httpx2.Request(
            request.method,
            request.url.copy_with(host=self._endpoint.address),
            headers=headers,
            stream=request.stream,
            extensions=extensions,
        )
        return await super().handle_async_request(pinned_request)


class FastMCPDiscoveryClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._timeout_seconds = settings.discovery_timeout_seconds

    def _resolve_endpoint(self, endpoint: str) -> ResolvedEndpoint:
        return resolve_endpoint(endpoint, self._settings)

    @staticmethod
    def _http_client_factory(
        endpoint: ResolvedEndpoint, timeout_seconds: float
    ) -> Callable[..., httpx2.AsyncClient]:
        def factory(
            headers: dict[str, str] | None = None, auth: httpx2.Auth | None = None, **_: Any
        ) -> httpx2.AsyncClient:
            return httpx2.AsyncClient(
                auth=auth,
                follow_redirects=False,
                headers=headers,
                timeout=httpx2.Timeout(timeout_seconds),
                transport=PinnedMCPDestinationTransport(endpoint),
                trust_env=False,
            )

        return factory

    async def list_tools(
        self, endpoint: str, headers: Mapping[str, str] | None = None
    ) -> Sequence[DiscoveredTool]:
        resolved_endpoint = self._resolve_endpoint(endpoint)

        transport = StreamableHttpTransport(
            endpoint,
            headers=dict(headers) if headers else None,
            httpx_client_factory=self._http_client_factory(
                resolved_endpoint, self._timeout_seconds
            ),
        )
        async with Client(
            transport,
            timeout=self._timeout_seconds,
            init_timeout=self._timeout_seconds,
        ) as client:
            tools = await client.list_tools()
        return [
            DiscoveredTool(
                name=tool.name,
                description=tool.description or "",
                input_schema=dict(tool.input_schema),
                output_schema=dict(tool.output_schema) if tool.output_schema is not None else None,
                annotations=tool.annotations.model_dump(exclude_none=True)
                if tool.annotations is not None
                else {},
            )
            for tool in tools
        ]


async def reconcile_tools(
    session: AsyncSession, server: MCPServer, discovered_tools: Sequence[DiscoveredTool]
) -> None:
    now = datetime.now(UTC)
    existing = {
        tool.name: tool
        for tool in (
            await session.scalars(select(Tool).where(Tool.server_id == server.id).with_for_update())
        ).all()
    }
    discovered_names = {tool.name for tool in discovered_tools}

    for discovered in discovered_tools:
        tool = existing.get(discovered.name)
        if tool is None:
            session.add(
                Tool(
                    server_id=server.id,
                    name=discovered.name,
                    description=discovered.description,
                    input_schema=discovered.input_schema,
                    output_schema=discovered.output_schema,
                    annotations=discovered.annotations,
                    fingerprint=discovered.fingerprint,
                    active=True,
                    last_seen_at=now,
                )
            )
            continue
        tool.description = discovered.description
        tool.input_schema = discovered.input_schema
        tool.output_schema = discovered.output_schema
        tool.annotations = discovered.annotations
        tool.fingerprint = discovered.fingerprint
        tool.active = True
        tool.last_seen_at = now

    await session.execute(
        update(Tool)
        .where(Tool.server_id == server.id, Tool.name.not_in(discovered_names))
        .values(active=False)
    )


class DiscoveryService:
    def __init__(self, client: ToolDiscoveryClient, settings: Settings) -> None:
        self._client = client
        self._settings = settings

    async def sync(
        self,
        session: AsyncSession,
        server: MCPServer,
        headers_provider: DiscoveryHeadersProvider | None = None,
    ) -> MCPServer:
        """Refresh the catalog for ``server``.

        ``headers_provider`` supplies the downstream credential for the discovery request.
        If it fails, the sync is marked as an error and the last-known catalog is kept.
        """
        locked_server = await session.scalar(
            select(MCPServer)
            .where(MCPServer.id == server.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if locked_server is None:
            raise LookupError("Server not found.")
        locked_server.sync_generation += 1
        generation = locked_server.sync_generation
        endpoint = locked_server.endpoint
        locked_server.status = "syncing"
        await session.commit()

        try:
            headers = await headers_provider() if headers_provider is not None else None
            discovered_tools = await self._client.list_tools(endpoint, headers=headers)
        except Exception as error:
            failure_message = (
                error.message if isinstance(error, DownstreamAuthorizationError) else None
            ) or "Discovery failed."
            locked_server = await session.scalar(
                select(MCPServer)
                .where(MCPServer.id == server.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if locked_server is None:
                raise LookupError("Server not found.") from error
            if locked_server.sync_generation != generation:
                await session.rollback()
                raise SyncSupersededError("A newer synchronization is in progress.") from error
            locked_server.status = "error"
            locked_server.last_sync_error = failure_message
            await session.commit()
            raise SyncFailedError(failure_message) from error

        locked_server = await session.scalar(
            select(MCPServer)
            .where(MCPServer.id == server.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if locked_server is None:
            raise LookupError("Server not found.")
        if locked_server.sync_generation != generation:
            await session.rollback()
            raise SyncSupersededError("A newer synchronization is in progress.")
        await reconcile_tools(session, locked_server, discovered_tools)
        locked_server.status = "ready"
        locked_server.last_synced_at = datetime.now(UTC)
        locked_server.last_sync_error = None
        await session.commit()
        await session.refresh(locked_server)
        return locked_server


def get_discovery_service(settings: Settings) -> DiscoveryService:
    return DiscoveryService(FastMCPDiscoveryClient(settings), settings)
