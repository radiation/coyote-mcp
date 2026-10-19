import asyncio
import base64
import json
import os
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
import uvicorn
from fastmcp import FastMCP
from pydantic import HttpUrl, SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp import catalog, connected_apps
from coyote_mcp.auth import AuthenticatedPrincipal, authenticate_token, issue_pat
from coyote_mcp.catalog import AuthorizationError
from coyote_mcp.credential_vault import seal
from coyote_mcp.credentials import (
    CONNECTION_STATUS_CONNECTED,
    CONNECTION_STATUS_REAUTHORIZATION,
    POLICY_NONE,
    POLICY_PER_USER_OAUTH,
    POLICY_SHARED_BEARER,
    REAUTHORIZE_MESSAGE,
    DownstreamAuthorization,
    seal_tokens,
    shared_credential_aad,
)
from coyote_mcp.downstream_oauth import TokenSet
from coyote_mcp.gateway import GatewayError, GatewayService, _rejection_error, _upstream_status_code
from coyote_mcp.models import (
    Collection,
    DownstreamConnection,
    DownstreamOAuthIntegration,
    DownstreamSharedCredential,
    InstanceAdministrator,
    MCPServer,
    Organization,
    OrganizationMembership,
    Principal,
    RoleAssignment,
    Tool,
)
from coyote_mcp.schemas import CollectionCreate, MembershipCreate, PublicationCreate, ServerCreate
from coyote_mcp.settings import Settings

CONSUMER_SCOPES = frozenset(
    {
        "collection:read",
        "server:read",
        "tool:discover",
        "tool:describe",
        "tool:execute",
        "connection:manage_own",
    }
)
ALICE_TOKEN = "alice-downstream-token"
BOB_TOKEN = "bob-downstream-token"


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _settings() -> Settings:
    return Settings(
        credential_encryption_keys={"v1": SecretStr(_key())},
        credential_active_key_version="v1",
        downstream_oauth_redirect_base_url="https://coyote.example.test",
        allow_insecure_endpoints=True,
        allow_private_endpoints=True,
    )


@asynccontextmanager
async def downstream_server() -> AsyncIterator[tuple[str, list[dict[bytes, bytes]]]]:
    """Run a local FastMCP server that records the headers of every inbound request."""
    downstream = FastMCP("test-downstream")

    @downstream.tool
    async def issue_lookup(issue: int) -> dict[str, int]:
        return {"issue": issue}

    downstream_app = downstream.http_app(path="/mcp", transport="streamable-http")
    received: list[dict[bytes, bytes]] = []

    async def capture_headers(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            received.append(dict(scope["headers"]))
        await downstream_app(scope, receive, send)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
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
        yield f"http://127.0.0.1:{port}/mcp", received
    finally:
        server.should_exit = True
        await server_task


@dataclass(frozen=True)
class Tenant:
    organization: Organization
    collection: Collection
    server: MCPServer
    tool: Tool
    publisher: Principal


def _publication_current(principal: Principal, organization_id: Any) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        principal, frozenset({"collection:update"}), None, organization_id
    )


async def _add_tool(session: AsyncSession, server_id: Any, name: str) -> Tool:
    tool = Tool(
        server_id=server_id,
        name=name,
        description=name,
        input_schema={
            "type": "object",
            "properties": {"issue": {"type": "integer"}},
            "required": ["issue"],
            "additionalProperties": False,
        },
        annotations={},
        fingerprint=name.ljust(64, "0"),
        active=True,
        last_seen_at=datetime.now(UTC),
    )
    session.add(tool)
    await session.commit()
    await session.refresh(tool)
    return tool


async def _member(
    session: AsyncSession,
    tenant_organization: Organization,
    collection: Collection,
    label: str,
    *,
    identity_type: str = "human",
) -> Principal:
    principal = Principal(
        identifier=f"{label}-{uuid4().hex}",
        display_name=label.title(),
        identity_type=identity_type,
    )
    session.add(principal)
    await session.flush()
    session.add(
        OrganizationMembership(organization_id=tenant_organization.id, principal_id=principal.id)
    )
    session.add(
        RoleAssignment(
            organization_id=tenant_organization.id,
            principal_id=principal.id,
            role="administrator",
            collection_id=collection.id,
        )
    )
    await session.commit()
    return principal


async def _tenant(session: AsyncSession, endpoint: str, policy: str) -> Tenant:
    organization = Organization(slug=f"gateway-{uuid4().hex}", display_name="Gateway")
    session.add(organization)
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
    server.endpoint = endpoint
    server.auth_policy = policy
    await session.commit()
    await catalog.add_membership(
        session, organization.id, collection.id, MembershipCreate(server_id=server.id)
    )
    publisher = await _member(session, organization, collection, "publisher")
    tool = await _add_tool(session, server.id, "issue_lookup")
    await catalog.publish_tool(
        session,
        _publication_current(publisher, organization.id),
        collection.id,
        PublicationCreate(tool_id=tool.id, published_name="downstream__issue_lookup"),
    )
    return Tenant(organization, collection, server, tool, publisher)


async def _pat(
    session: AsyncSession,
    tenant: Tenant,
    principal: Principal,
    scopes: frozenset[str] = CONSUMER_SCOPES,
) -> tuple[AuthenticatedPrincipal, str]:
    _, token = await issue_pat(
        session,
        principal,
        tenant.organization.id,
        "consumer",
        set(scopes),
        timedelta(days=1),
        Settings(),
    )
    current = await authenticate_token(session, token)
    assert current is not None
    return current, token


async def _github_integration(session: AsyncSession, tenant: Tenant) -> None:
    session.add(
        DownstreamOAuthIntegration(
            organization_id=tenant.organization.id,
            server_id=tenant.server.id,
            provider="github",
            authorization_endpoint="https://github.com/login/oauth/authorize",
            token_endpoint="https://github.com/login/oauth/access_token",
            client_id="client-id",
            enabled=True,
        )
    )
    await session.commit()


async def _connect(
    session: AsyncSession,
    settings: Settings,
    tenant: Tenant,
    principal: Principal,
    access_token: str,
    *,
    status: str = CONNECTION_STATUS_CONNECTED,
) -> None:
    sealed = seal_tokens(
        settings,
        TokenSet(access_token, None, None, ("repo",)),
        organization_id=tenant.organization.id,
        server_id=tenant.server.id,
        principal_id=principal.id,
    )
    session.add(
        DownstreamConnection(
            organization_id=tenant.organization.id,
            server_id=tenant.server.id,
            principal_id=principal.id,
            status=status,
            key_version=sealed.key_version,
            sealed_tokens=sealed.sealed,
            scopes=["repo"],
            access_token_expires_at=None,
        )
    )
    await session.commit()


async def _store_shared(
    session: AsyncSession, settings: Settings, tenant: Tenant, value: str
) -> None:
    sealed = seal(
        settings,
        value.encode("utf-8"),
        shared_credential_aad(tenant.organization.id, tenant.server.id),
    )
    session.add(
        DownstreamSharedCredential(
            organization_id=tenant.organization.id,
            server_id=tenant.server.id,
            key_version=sealed.key_version,
            sealed_value=sealed.sealed,
        )
    )
    await session.commit()


async def _connection_status(
    session: AsyncSession, tenant: Tenant, principal: Principal
) -> str | None:
    return await session.scalar(
        select(DownstreamConnection.status).where(
            DownstreamConnection.server_id == tenant.server.id,
            DownstreamConnection.principal_id == principal.id,
        )
    )


def _authorization_values(received: list[dict[bytes, bytes]]) -> set[bytes]:
    return {headers[b"authorization"] for headers in received if b"authorization" in headers}


def _reject_downstream_calls(monkeypatch: pytest.MonkeyPatch, status_code: int) -> list[str]:
    """Replace the MCP client so every call fails with an upstream HTTP status."""
    attempts: list[str] = []

    class RejectingClient:
        def __init__(self, transport: object, **_: object) -> None:
            return None

        async def __aenter__(self) -> RejectingClient:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def call_tool(self, name: str, arguments: dict[str, Any], **_: object) -> None:
            attempts.append(name)
            request = httpx.Request("POST", "https://downstream.example.test/mcp")
            response = httpx.Response(status_code, request=request)
            raise httpx.HTTPStatusError(
                "upstream rejected Bearer secret-upstream-body",
                request=request,
                response=response,
            )

    monkeypatch.setattr("coyote_mcp.gateway.Client", RejectingClient)
    return attempts


@pytest.mark.asyncio
async def test_none_policy_keeps_deepwiki_style_access_without_credentials(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_NONE)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        current, _ = await _pat(session, tenant, alice)

        result = await GatewayService(settings).execute_tool(
            session, current, tenant.tool.id, {"issue": 3}, "engineering"
        )

    assert isinstance(result, dict)
    assert received
    assert _authorization_values(received) == set()


@pytest.mark.asyncio
async def test_connected_user_credential_reaches_only_downstream_and_never_the_pat(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        await _connect(session, settings, tenant, alice, ALICE_TOKEN)
        current, pat = await _pat(session, tenant, alice)

        await GatewayService(settings).execute_tool(
            session, current, tenant.tool.id, {"issue": 7}, "engineering"
        )

    assert f"Bearer {ALICE_TOKEN}".encode() in _authorization_values(received)
    assert _authorization_values(received) <= {f"Bearer {ALICE_TOKEN}".encode()}
    for headers in received:
        for value in headers.values():
            assert pat.encode() not in value


@pytest.mark.asyncio
async def test_other_user_cannot_use_a_connection_owned_by_someone_else(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        bob = await _member(session, tenant.organization, tenant.collection, "bob")
        await _connect(session, settings, tenant, alice, ALICE_TOKEN)
        bob_current, _ = await _pat(session, tenant, bob)
        before = len(received)

        with pytest.raises(GatewayError, match="connection_required") as raised:
            await GatewayService(settings).execute_tool(
                session, bob_current, tenant.tool.id, {"issue": 1}, "engineering"
            )

    assert len(received) == before
    assert ALICE_TOKEN not in str(raised.value)


@pytest.mark.asyncio
async def test_sequential_principals_each_receive_only_their_own_credential(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        bob = await _member(session, tenant.organization, tenant.collection, "bob")
        await _connect(session, settings, tenant, alice, ALICE_TOKEN)
        await _connect(session, settings, tenant, bob, BOB_TOKEN)
        alice_current, _ = await _pat(session, tenant, alice)
        bob_current, _ = await _pat(session, tenant, bob)
        service = GatewayService(settings)

        for current, expected in (
            (alice_current, ALICE_TOKEN),
            (bob_current, BOB_TOKEN),
            (alice_current, ALICE_TOKEN),
        ):
            before = len(received)
            await service.execute_tool(session, current, tenant.tool.id, {"issue": 2}, None)
            values = {
                headers[b"authorization"]
                for headers in received[before:]
                if b"authorization" in headers
            }
            assert values == {f"Bearer {expected}".encode()}


@pytest.mark.asyncio
async def test_connection_for_another_organization_is_not_used(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant_a = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        tenant_b = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant_a)
        alice = await _member(session, tenant_a.organization, tenant_a.collection, "alice")
        await _connect(session, settings, tenant_b, alice, ALICE_TOKEN)
        current, _ = await _pat(session, tenant_a, alice)
        before = len(received)

        with pytest.raises(GatewayError, match="connection_required"):
            await GatewayService(settings).execute_tool(
                session, current, tenant_a.tool.id, {"issue": 4}, "engineering"
            )

    assert len(received) == before


@pytest.mark.asyncio
async def test_shared_credential_is_never_substituted_for_per_user_server(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        await _store_shared(session, settings, tenant, "shared-service-token")
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        current, _ = await _pat(session, tenant, alice)
        before = len(received)

        with pytest.raises(GatewayError, match="connection_required"):
            await GatewayService(settings).execute_tool(
                session, current, tenant.tool.id, {"issue": 5}, "engineering"
            )

    assert len(received) == before
    assert b"Bearer shared-service-token" not in _authorization_values(received)


@pytest.mark.asyncio
async def test_service_principal_fails_closed_when_user_credentials_are_required(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        service_principal = await _member(
            session,
            tenant.organization,
            tenant.collection,
            "pipeline",
            identity_type="service",
        )
        current, _ = await _pat(session, tenant, service_principal)
        before = len(received)

        with pytest.raises(GatewayError, match="service_principal_not_permitted"):
            await GatewayService(settings).execute_tool(
                session, current, tenant.tool.id, {"issue": 6}, "engineering"
            )

    assert len(received) == before


@pytest.mark.asyncio
async def test_instance_admin_browser_status_does_not_bypass_per_user_authorization(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        bob = await _member(session, tenant.organization, tenant.collection, "bob")
        session.add(InstanceAdministrator(principal_id=bob.id))
        await session.commit()
        browser_current = AuthenticatedPrincipal(
            principal=bob,
            scopes=CONSUMER_SCOPES,
            token=None,
            organization_id=tenant.organization.id,
        )
        before = len(received)

        with pytest.raises(GatewayError, match="connection_required"):
            await GatewayService(settings).execute_tool(
                session, browser_current, tenant.tool.id, {"issue": 8}, "engineering"
            )

    assert len(received) == before


@pytest.mark.asyncio
async def test_read_only_pat_cannot_execute_tools(session: AsyncSession) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_NONE)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        read_only = frozenset({"collection:read", "server:read", "tool:discover", "tool:describe"})
        current, _ = await _pat(session, tenant, alice, read_only)
        before = len(received)

        with pytest.raises(GatewayError, match="not available"):
            await GatewayService(settings).execute_tool(
                session, current, tenant.tool.id, {"issue": 9}, "engineering"
            )

    assert len(received) == before


@pytest.mark.asyncio
async def test_unpublished_tool_stays_unavailable_with_valid_downstream_credentials(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        await _connect(session, settings, tenant, alice, ALICE_TOKEN)
        unpublished = await _add_tool(session, tenant.server.id, "private_lookup")
        current, _ = await _pat(session, tenant, alice)
        before = len(received)

        with pytest.raises(GatewayError, match="not available"):
            await GatewayService(settings).execute_tool(
                session, current, unpublished.id, {"issue": 10}, "engineering"
            )

    assert len(received) == before


@pytest.mark.asyncio
async def test_disabled_server_stays_unavailable_with_valid_downstream_credentials(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        await _connect(session, settings, tenant, alice, ALICE_TOKEN)
        current, _ = await _pat(session, tenant, alice)
        tenant.server.enabled = False
        await session.commit()
        before = len(received)

        with pytest.raises(GatewayError):
            await GatewayService(settings).execute_tool(
                session, current, tenant.tool.id, {"issue": 11}, "engineering"
            )

    assert len(received) == before


@pytest.mark.asyncio
async def test_disconnect_prevents_future_calls_through_the_removed_connection(
    session: AsyncSession,
) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        await _connect(session, settings, tenant, alice, ALICE_TOKEN)
        current, _ = await _pat(session, tenant, alice)
        service = GatewayService(settings)
        await service.execute_tool(session, current, tenant.tool.id, {"issue": 12}, "engineering")
        before = len(received)

        execute_only, _ = await _pat(
            session,
            tenant,
            alice,
            frozenset(
                {"collection:read", "server:read", "tool:discover", "tool:describe", "tool:execute"}
            ),
        )
        with pytest.raises(AuthorizationError):
            await connected_apps.disconnect(session, settings, execute_only, tenant.server.id)

        browser_current = AuthenticatedPrincipal(
            principal=alice,
            scopes=CONSUMER_SCOPES,
            token=None,
            organization_id=tenant.organization.id,
        )
        result = await connected_apps.disconnect(
            session, settings, browser_current, tenant.server.id
        )
        assert result.removed is True

        with pytest.raises(GatewayError, match="connection_required"):
            await service.execute_tool(
                session, current, tenant.tool.id, {"issue": 13}, "engineering"
            )

    assert len(received) == before


@pytest.mark.asyncio
async def test_upstream_401_marks_connection_for_reauthorization_without_retry(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings()
    tenant = await _tenant(session, "http://127.0.0.1:9/mcp", POLICY_PER_USER_OAUTH)
    await _github_integration(session, tenant)
    alice = await _member(session, tenant.organization, tenant.collection, "alice")
    await _connect(session, settings, tenant, alice, ALICE_TOKEN)
    current, _ = await _pat(session, tenant, alice)
    attempts = _reject_downstream_calls(monkeypatch, 401)
    service = GatewayService(settings)

    with pytest.raises(GatewayError) as raised:
        await service.execute_tool(session, current, tenant.tool.id, {"issue": 14}, "engineering")

    assert str(raised.value) == REAUTHORIZE_MESSAGE
    assert "secret-upstream-body" not in str(raised.value)
    assert attempts == ["issue_lookup"]
    assert await _connection_status(session, tenant, alice) == CONNECTION_STATUS_REAUTHORIZATION

    with pytest.raises(GatewayError):
        await service.execute_tool(session, current, tenant.tool.id, {"issue": 15}, "engineering")
    assert attempts == ["issue_lookup"]


@pytest.mark.asyncio
async def test_upstream_403_denies_access_without_changing_the_connection(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings()
    tenant = await _tenant(session, "http://127.0.0.1:9/mcp", POLICY_PER_USER_OAUTH)
    await _github_integration(session, tenant)
    alice = await _member(session, tenant.organization, tenant.collection, "alice")
    await _connect(session, settings, tenant, alice, ALICE_TOKEN)
    current, _ = await _pat(session, tenant, alice)
    attempts = _reject_downstream_calls(monkeypatch, 403)

    with pytest.raises(GatewayError, match="denied access") as raised:
        await GatewayService(settings).execute_tool(
            session, current, tenant.tool.id, {"issue": 16}, "engineering"
        )

    assert "secret-upstream-body" not in str(raised.value)
    assert attempts == ["issue_lookup"]
    assert await _connection_status(session, tenant, alice) == CONNECTION_STATUS_CONNECTED


@pytest.mark.asyncio
async def test_upstream_401_on_shared_bearer_reports_service_credential_rejection(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings()
    tenant = await _tenant(session, "http://127.0.0.1:9/mcp", POLICY_SHARED_BEARER)
    await _store_shared(session, settings, tenant, "shared-service-token")
    alice = await _member(session, tenant.organization, tenant.collection, "alice")
    current, _ = await _pat(session, tenant, alice)
    attempts = _reject_downstream_calls(monkeypatch, 401)

    with pytest.raises(GatewayError, match="configured service credential") as raised:
        await GatewayService(settings).execute_tool(
            session, current, tenant.tool.id, {"issue": 17}, "engineering"
        )

    assert "shared-service-token" not in str(raised.value)
    assert attempts == ["issue_lookup"]


@pytest.mark.asyncio
async def test_discovery_outputs_never_contain_credentials(session: AsyncSession) -> None:
    settings = _settings()
    async with downstream_server() as (endpoint, _received):
        tenant = await _tenant(session, endpoint, POLICY_PER_USER_OAUTH)
        await _github_integration(session, tenant)
        alice = await _member(session, tenant.organization, tenant.collection, "alice")
        await _connect(session, settings, tenant, alice, ALICE_TOKEN)
        current, _ = await _pat(session, tenant, alice)
        service = GatewayService(settings)

        results = await service.search_tools(session, current, "lookup", "engineering", 10)
        description = await service.describe_tool(session, current, tenant.tool.id, None)

    rendered = json.dumps(
        {"search": [str(result) for result in results], "describe": description},
        default=str,
    )
    assert ALICE_TOKEN not in rendered
    assert "Bearer" not in rendered
    assert "authorization" not in rendered.lower()


def test_upstream_status_code_is_found_in_the_exception_chain() -> None:
    request = httpx.Request("POST", "https://downstream.example.test/mcp")
    response = httpx.Response(403, request=request)
    inner = httpx.HTTPStatusError("denied", request=request, response=response)
    outer = RuntimeError("wrapped failure")
    outer.__cause__ = inner

    assert _upstream_status_code(outer) == 403
    assert _upstream_status_code(RuntimeError("plain failure")) is None


def test_rejection_messages_are_sanitized_per_policy() -> None:
    per_user = DownstreamAuthorization(policy=POLICY_PER_USER_OAUTH, headers={}, connection_id=None)
    shared = DownstreamAuthorization(policy=POLICY_SHARED_BEARER, headers={}, connection_id=None)

    assert _rejection_error(per_user, 401) == REAUTHORIZE_MESSAGE
    assert "configured service credential" in _rejection_error(shared, 401)
    assert "denied access" in _rejection_error(shared, 403)
    assert "Bearer" not in _rejection_error(shared, 401)
