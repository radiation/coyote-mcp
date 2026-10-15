from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import httpx
import httpx2
from fastapi.encoders import jsonable_encoder
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import FastMCPError
from jsonschema import Draft202012Validator, SchemaError
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import AuthenticatedPrincipal, authorize
from coyote_mcp.discovery import FastMCPDiscoveryClient
from coyote_mcp.models import (
    Collection,
    CollectionMembership,
    MCPServer,
    PersonalAccessToken,
    Principal,
    Tool,
)
from coyote_mcp.settings import Settings

MAX_SEARCH_RESULTS = 25
MAX_SEARCH_QUERY_LENGTH = 256
_LIKE_ESCAPE = "\\"
logger = logging.getLogger(__name__)


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayTool:
    tool_id: UUID
    name: str
    description: str
    collection_slug: str
    server_name: str


class GatewayService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def search_tools(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        query: str,
        collection_slug: str | None,
        limit: int,
    ) -> list[GatewayTool]:
        current = await self._refresh_current(session, current)
        if limit < 1 or limit > MAX_SEARCH_RESULTS:
            raise GatewayError("Result limit is outside the allowed range.")
        normalized_query = self._normalize_search_query(query)
        collections = await self._authorized_collections(
            session, current, "tool:discover", collection_slug
        )
        if not collections:
            return []
        collection_ids = [collection.id for collection in collections]
        statement = (
            self._tool_statement(collection_ids)
            .where(
                Tool.name.ilike(f"%{normalized_query}%", escape=_LIKE_ESCAPE)
                | Tool.description.ilike(f"%{normalized_query}%", escape=_LIKE_ESCAPE)
            )
            .order_by(Tool.name, MCPServer.name, Collection.slug, Tool.id)
            .limit(limit)
        )
        rows = cast(
            list[tuple[Tool, MCPServer, Collection]],
            (await session.execute(statement)).all(),
        )
        return [
            GatewayTool(
                tool_id=tool.id,
                name=tool.name,
                description=tool.description,
                collection_slug=collection.slug,
                server_name=server.name,
            )
            for tool, server, collection in rows
        ]

    async def describe_tool(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        tool_id: UUID,
        collection_slug: str | None,
    ) -> dict[str, Any]:
        current = await self._refresh_current(session, current)
        tool, server, collection = await self._authorized_tool(
            session, current, tool_id, collection_slug, "tool:describe"
        )
        return {
            "tool_id": str(tool.id),
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
            "annotations": tool.annotations,
            "collection_slug": collection.slug if collection is not None else None,
            "server_name": server.name,
        }

    async def execute_tool(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        tool_id: UUID,
        arguments: dict[str, Any],
        collection_slug: str | None,
    ) -> dict[str, Any]:
        current = await self._refresh_current(session, current)
        tool, server, _ = await self._authorized_tool(
            session, current, tool_id, collection_slug, "tool:execute"
        )
        self._validate_arguments(tool.input_schema, arguments)
        try:
            client_factory = FastMCPDiscoveryClient._http_client_factory(
                FastMCPDiscoveryClient(self._settings)._resolve_endpoint(server.endpoint),
                self._settings.execution_timeout_seconds,
            )
            transport = StreamableHttpTransport(
                server.endpoint,
                httpx_client_factory=client_factory,
            )
            async with Client(
                transport,
                timeout=self._settings.execution_timeout_seconds,
                init_timeout=self._settings.execution_timeout_seconds,
            ) as client:
                result = await client.call_tool(
                    tool.name,
                    arguments,
                    timeout=self._settings.execution_timeout_seconds,
                    raise_on_error=False,
                )
        except (TimeoutError, httpx.TimeoutException, httpx2.TimeoutException) as error:
            raise GatewayError("Downstream tool execution timed out.") from error
        except (FastMCPError, RuntimeError, httpx.HTTPError, httpx2.HTTPError) as error:
            raise GatewayError("Downstream tool execution failed.") from error
        except Exception:
            logger.exception("Unexpected downstream MCP execution failure for tool %s", tool.id)
            raise GatewayError("Downstream tool execution failed.") from None
        payload = jsonable_encoder(asdict(result), exclude_none=True)
        if len(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()) > (
            self._settings.max_execution_result_bytes
        ):
            raise GatewayError("Downstream tool result exceeded the configured size limit.")
        return cast(dict[str, Any], payload)

    async def _authorized_collections(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        action: str,
        collection_slug: str | None,
    ) -> list[Collection]:
        statement = select(Collection).where(
            Collection.organization_id == current.principal.organization_id,
            Collection.enabled.is_(True),
        )
        if collection_slug is not None:
            statement = statement.where(Collection.slug == collection_slug)
        collections = (await session.scalars(statement.order_by(Collection.slug))).all()
        return [
            collection
            for collection in collections
            if action in current.scopes
            and (
                await authorize(
                    session,
                    current.principal,
                    action,
                    collection,
                    verified_group_ids=current.verified_group_ids,
                    identity_provider_id=current.identity_provider_id,
                )
            ).allowed
        ]

    def _tool_statement(
        self, collection_ids: list[UUID]
    ) -> Select[tuple[Tool, MCPServer, Collection]]:
        statement = (
            select(Tool, MCPServer, Collection)
            .join(MCPServer, Tool.server_id == MCPServer.id)
            .join(CollectionMembership, CollectionMembership.server_id == MCPServer.id)
            .join(Collection, Collection.id == CollectionMembership.collection_id)
            .where(
                CollectionMembership.organization_id.is_not(None),
                CollectionMembership.collection_id.in_(collection_ids),
                CollectionMembership.enabled.is_(True),
                Tool.active.is_(True),
                MCPServer.status == "ready",
                MCPServer.transport == "streamable_http",
            )
        )
        return cast(Select[tuple[Tool, MCPServer, Collection]], statement)

    async def _authorized_tool(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        tool_id: UUID,
        collection_slug: str | None,
        action: str,
    ) -> tuple[Tool, MCPServer, Collection | None]:
        if action not in current.scopes:
            raise GatewayError("Tool is not available.")
        tool_row = await session.execute(
            select(Tool, MCPServer)
            .join(MCPServer, Tool.server_id == MCPServer.id)
            .where(
                Tool.id == tool_id,
                MCPServer.organization_id == current.principal.organization_id,
                Tool.active.is_(True),
                MCPServer.status == "ready",
                MCPServer.transport == "streamable_http",
            )
        )
        row = tool_row.one_or_none()
        if row is None:
            raise GatewayError("Tool is not available.")
        tool, server = row

        organization_decision = await authorize(
            session,
            current.principal,
            action,
            server,
            verified_group_ids=current.verified_group_ids,
            identity_provider_id=current.identity_provider_id,
        )
        if organization_decision.allowed:
            return tool, server, None

        if collection_slug is None:
            raise GatewayError("Collection context is required for this tool.")
        collections = await self._authorized_collections(session, current, action, collection_slug)
        if not collections:
            raise GatewayError("Tool is not available.")
        collection = collections[0]
        membership = await session.scalar(
            select(CollectionMembership).where(
                CollectionMembership.collection_id == collection.id,
                CollectionMembership.server_id == server.id,
                CollectionMembership.organization_id == current.principal.organization_id,
                CollectionMembership.enabled.is_(True),
            )
        )
        if membership is None:
            raise GatewayError("Tool is not available.")
        return tool, server, collection

    @staticmethod
    def _validate_arguments(schema: dict[str, Any], arguments: dict[str, Any]) -> None:
        try:
            Draft202012Validator.check_schema(schema)
            validator = Draft202012Validator(schema)
            errors = sorted(validator.iter_errors(arguments), key=lambda error: list(error.path))
        except SchemaError as error:
            raise GatewayError("Stored tool schema is invalid.") from error
        if errors:
            raise GatewayError("Tool arguments do not match the published schema.")

    @staticmethod
    def _normalize_search_query(query: str) -> str:
        normalized_query = query.strip()
        if len(normalized_query) > MAX_SEARCH_QUERY_LENGTH:
            raise GatewayError("Search query exceeds the allowed length.")
        return (
            normalized_query.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
            .replace("%", f"{_LIKE_ESCAPE}%")
            .replace("_", f"{_LIKE_ESCAPE}_")
        )

    @staticmethod
    async def _refresh_current(
        session: AsyncSession, current: AuthenticatedPrincipal
    ) -> AuthenticatedPrincipal:
        principal = await session.scalar(
            select(Principal).where(
                Principal.id == current.principal.id,
                Principal.organization_id == current.principal.organization_id,
                Principal.enabled.is_(True),
            )
        )
        if principal is None:
            raise GatewayError("Authentication is no longer valid.")
        if current.token is not None:
            token = await session.scalar(
                select(PersonalAccessToken).where(
                    PersonalAccessToken.id == current.token.id,
                    PersonalAccessToken.principal_id == principal.id,
                    PersonalAccessToken.organization_id == principal.organization_id,
                    PersonalAccessToken.revoked_at.is_(None),
                    PersonalAccessToken.expires_at > datetime.now(UTC),
                )
            )
            if token is None:
                raise GatewayError("Authentication is no longer valid.")
        return replace(current, principal=principal)
