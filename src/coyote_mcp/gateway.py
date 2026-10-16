from __future__ import annotations

import asyncio
import json
import logging
import multiprocessing
import resource
import signal
import sys
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from typing import Any, cast
from uuid import UUID

import httpx
import httpx2
from fastapi.encoders import jsonable_encoder
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import FastMCPError
from jsonschema import Draft202012Validator, SchemaError
from mcp.shared.exceptions import MCPError
from mcp.types import REQUEST_TIMEOUT
from referencing import Registry
from referencing.exceptions import Unresolvable
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import AuthenticatedPrincipal, authorize, authorized_collection_ids
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
_SCHEMA_VALIDATION_MEMORY_LIMIT_BYTES = 256 * 1024 * 1024
_LIKE_ESCAPE = "\\"
logger = logging.getLogger(__name__)
_LOCAL_SCHEMA_REGISTRY = Registry()


@dataclass(frozen=True)
class _SchemaValidationOutcome:
    status: str
    diagnostic: str


def _validate_schema_in_worker(
    schema: dict[str, Any], arguments: dict[str, Any], result_connection: Connection
) -> None:
    try:
        if sys.platform == "linux":
            resource.setrlimit(
                resource.RLIMIT_AS,
                (_SCHEMA_VALIDATION_MEMORY_LIMIT_BYTES, _SCHEMA_VALIDATION_MEMORY_LIMIT_BYTES),
            )
        try:
            Draft202012Validator.check_schema(schema)
            validator = Draft202012Validator(schema, registry=_LOCAL_SCHEMA_REGISTRY)
            errors = sorted(validator.iter_errors(arguments), key=lambda error: list(error.path))
        except SchemaError, Unresolvable:
            outcome = _SchemaValidationOutcome(
                "invalid_schema", "schema validation rejected schema"
            )
        except MemoryError:
            outcome = _SchemaValidationOutcome("resource_limited", "address-space limit exceeded")
        except Exception as error:
            outcome = _SchemaValidationOutcome("worker_failed", type(error).__name__)
        else:
            outcome = _SchemaValidationOutcome(
                "invalid_arguments" if errors else "valid", "validation completed"
            )
    except (OSError, ValueError) as error:
        outcome = _SchemaValidationOutcome("worker_setup_failed", type(error).__name__)
    try:
        result_connection.send(outcome)
    finally:
        result_connection.close()


def _run_schema_validation(
    schema: dict[str, Any], arguments: dict[str, Any], timeout_seconds: float
) -> str:
    context = multiprocessing.get_context("spawn")
    result_connection, worker_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=_validate_schema_in_worker,
        args=(schema, arguments, worker_connection),
    )
    try:
        try:
            process.start()
        except Exception as error:
            logger.warning("Schema validation worker failed to start: %s", type(error).__name__)
            return "worker_setup_failed"
        worker_connection.close()
        process.join(timeout_seconds)
        if process.is_alive():
            process.terminate()
            process.join()
            logger.warning("Schema validation worker exceeded its wall-clock deadline")
            return "timed_out"
        try:
            if result_connection.poll():
                outcome = cast(_SchemaValidationOutcome, result_connection.recv())
                if outcome.status not in {"valid", "invalid_arguments", "invalid_schema"}:
                    logger.warning(
                        "Schema validation worker %s: %s", outcome.status, outcome.diagnostic
                    )
                return outcome.status
        except (EOFError, OSError) as error:
            logger.warning("Schema validation worker result pipe failed: %s", type(error).__name__)
            return "worker_crashed"
        if process.exitcode == -signal.SIGXCPU:
            logger.warning("Schema validation worker exceeded its CPU limit")
            return "cpu_limited"
        if process.exitcode != 0:
            logger.warning("Schema validation worker crashed with exit code %s", process.exitcode)
            return "worker_crashed"
        logger.warning("Schema validation worker exited without returning an outcome")
        return "worker_failed"
    finally:
        worker_connection.close()
        result_connection.close()


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayTool:
    tool_id: UUID
    name: str
    description: str
    collection_slug: str
    server_name: str


@dataclass(frozen=True)
class NativeGatewayTool:
    tool_id: UUID
    published_name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: dict[str, Any]


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

    async def discovery_collection(
        self, session: AsyncSession, current: AuthenticatedPrincipal, collection_slug: str
    ) -> Collection:
        return await self._endpoint_collection(
            session, current, collection_slug, {"tool:discover"}, "discovery"
        )

    async def collection_exposure_mode(
        self, session: AsyncSession, current: AuthenticatedPrincipal, collection_slug: str
    ) -> str:
        current = await self._refresh_current(session, current)
        collection = await session.scalar(
            select(Collection).where(
                Collection.organization_id == current.principal.organization_id,
                Collection.slug == collection_slug,
                Collection.enabled.is_(True),
            )
        )
        if collection is None or collection.exposure_mode not in {"discovery", "native"}:
            raise GatewayError("Collection endpoint is not available.")
        return collection.exposure_mode

    async def native_tools(
        self, session: AsyncSession, current: AuthenticatedPrincipal, collection_slug: str
    ) -> list[NativeGatewayTool]:
        collection = await self._endpoint_collection(
            session, current, collection_slug, {"tool:discover", "tool:execute"}, "native"
        )
        rows = cast(
            list[tuple[Tool, MCPServer, Collection]],
            (
                await session.execute(
                    self._tool_statement([collection.id])
                    .order_by(MCPServer.name, Tool.name, Tool.id)
                    .limit(self._settings.max_native_tools_per_collection + 1)
                )
            ).all(),
        )
        if len(rows) > self._settings.max_native_tools_per_collection:
            raise GatewayError("Collection native tool exposure exceeds the configured limit.")
        native_tools = [
            NativeGatewayTool(
                tool_id=tool.id,
                published_name=f"{server.name}__{tool.name}",
                description=tool.description,
                input_schema=dict(tool.input_schema),
                output_schema=dict(tool.output_schema) if tool.output_schema is not None else None,
                annotations=dict(tool.annotations),
            )
            for tool, server, _ in rows
        ]
        if len({tool.published_name for tool in native_tools}) != len(native_tools):
            raise GatewayError("Collection native tool names are not unique.")
        return native_tools

    async def native_tool(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        collection_slug: str,
        published_name: str,
    ) -> NativeGatewayTool:
        for tool in await self.native_tools(session, current, collection_slug):
            if tool.published_name == published_name:
                return tool
        raise GatewayError("Tool is not available.")

    async def execute_tool(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        tool_id: UUID,
        arguments: dict[str, Any],
        collection_slug: str | None,
    ) -> dict[str, Any]:
        tool_name, endpoint, input_schema = await self._execution_snapshot(
            session,
            current,
            tool_id,
            collection_slug,
        )
        await self._validate_arguments(input_schema, arguments)
        try:
            client_factory = FastMCPDiscoveryClient._http_client_factory(
                FastMCPDiscoveryClient(self._settings)._resolve_endpoint(endpoint),
                self._settings.execution_timeout_seconds,
            )
            transport = StreamableHttpTransport(
                endpoint,
                httpx_client_factory=client_factory,
            )
            async with Client(
                transport,
                timeout=self._settings.execution_timeout_seconds,
                init_timeout=self._settings.execution_timeout_seconds,
            ) as client:
                result = await client.call_tool(
                    tool_name,
                    arguments,
                    timeout=self._settings.execution_timeout_seconds,
                    raise_on_error=False,
                )
        except (TimeoutError, httpx.TimeoutException, httpx2.TimeoutException) as error:
            raise GatewayError("Downstream tool execution timed out.") from error
        except MCPError as error:
            if error.code == REQUEST_TIMEOUT:
                raise GatewayError("Downstream tool execution timed out.") from error
            raise GatewayError("Downstream tool execution failed.") from error
        except (FastMCPError, RuntimeError, httpx.HTTPError, httpx2.HTTPError) as error:
            raise GatewayError("Downstream tool execution failed.") from error
        except Exception:
            logger.exception("Unexpected downstream MCP execution failure for tool %s", tool_id)
            raise GatewayError("Downstream tool execution failed.") from None
        payload = jsonable_encoder(asdict(result))
        if len(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()) > (
            self._settings.max_execution_result_bytes
        ):
            raise GatewayError("Downstream tool result exceeded the configured size limit.")
        return cast(dict[str, Any], payload)

    async def _execution_snapshot(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        tool_id: UUID,
        collection_slug: str | None,
    ) -> tuple[str, str, dict[str, Any]]:
        if session.bind is None:
            raise GatewayError("Gateway database session is not bound.")
        async with AsyncSession(bind=session.bind, expire_on_commit=False) as read_session:
            refreshed_current = await self._refresh_current(read_session, current)
            tool, server, _ = await self._authorized_tool(
                read_session,
                refreshed_current,
                tool_id,
                collection_slug,
                "tool:execute",
            )
            return tool.name, server.endpoint, dict(tool.input_schema)

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
        if action not in current.scopes:
            return []
        authorized_ids = await authorized_collection_ids(
            session,
            current.principal,
            action,
            collections,
            current.verified_group_ids,
            current.identity_provider_id,
        )
        return [collection for collection in collections if collection.id in authorized_ids]

    async def _endpoint_collection(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        collection_slug: str,
        required_actions: set[str],
        exposure_mode: str,
    ) -> Collection:
        current = await self._refresh_current(session, current)
        authorized_ids: set[UUID] | None = None
        collections: list[Collection] = []
        for action in required_actions:
            collections = await self._authorized_collections(
                session, current, action, collection_slug
            )
            action_ids = {collection.id for collection in collections}
            authorized_ids = action_ids if authorized_ids is None else authorized_ids & action_ids
        if not authorized_ids:
            raise GatewayError("Collection endpoint is not available.")
        collection = next(
            (
                candidate
                for candidate in collections
                if candidate.id in authorized_ids and candidate.exposure_mode == exposure_mode
            ),
            None,
        )
        if collection is None:
            raise GatewayError("Collection endpoint is not available.")
        return collection

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

        if collection_slug is not None:
            collections = await self._authorized_collections(
                session, current, action, collection_slug
            )
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
        raise GatewayError("Collection context is required for this tool.")

    async def _validate_arguments(self, schema: dict[str, Any], arguments: dict[str, Any]) -> None:
        result = await asyncio.to_thread(
            _run_schema_validation,
            schema,
            arguments,
            self._settings.schema_validation_timeout_seconds,
        )
        if result == "invalid_schema":
            raise GatewayError("Stored tool schema is invalid.")
        if result == "invalid_arguments":
            raise GatewayError("Tool arguments do not match the published schema.")
        if result in {"timed_out", "cpu_limited", "resource_limited"}:
            raise GatewayError("Tool argument validation timed out.")
        if result != "valid":
            raise GatewayError("Tool argument validation failed.")

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
