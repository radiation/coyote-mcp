import base64
import os
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.auth import (
    AuthenticatedPrincipal,
    authenticate_browser_session,
    issue_browser_session,
    self_service_action_allowed,
)
from coyote_mcp.catalog import AuthorizationError, MissingResourceError
from coyote_mcp.connected_apps import (
    ConnectedAppError,
    IntegrationInput,
    clear_shared_credential,
    complete_connection,
    disconnect,
    get_server_authentication,
    list_connected_apps,
    save_integration,
    set_auth_policy,
    set_integration_enabled,
    set_shared_credential,
    start_connection,
)
from coyote_mcp.credentials import DownstreamCredentialBroker, open_client_secret
from coyote_mcp.downstream_errors import DownstreamAuthorizationError
from coyote_mcp.downstream_oauth import OAuthProtocolError, TokenSet, code_challenge_for, hash_state
from coyote_mcp.models import (
    Collection,
    DownstreamConnection,
    DownstreamOAuthIntegration,
    DownstreamOAuthTransaction,
    ExternalGroup,
    GroupRoleMapping,
    InstanceAdministrator,
    MCPServer,
    Organization,
    OrganizationMembership,
    Principal,
    RoleAssignment,
)
from coyote_mcp.settings import Settings

CALLBACK = "https://coyote.example.test/console/connected-apps/callback"
GITHUB_SECRET = "github-client-secret-value"


def _settings() -> Settings:
    key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    return Settings(
        credential_encryption_keys={"v1": SecretStr(key)},
        credential_active_key_version="v1",
        downstream_oauth_redirect_base_url="https://coyote.example.test",
    )


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(host: str, *args: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [(None, None, None, None, ("93.184.216.34", 0))]

    monkeypatch.setattr("coyote_mcp.security.socket.getaddrinfo", resolve)


def _patch_provider(
    monkeypatch: pytest.MonkeyPatch,
    *,
    tokens: TokenSet | None = None,
    failure: Exception | None = None,
    account: str = "octocat",
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    async def exchange(settings: Settings, **kwargs: object) -> TokenSet:
        calls.append(kwargs)
        if failure is not None:
            raise failure
        return tokens or TokenSet("gho_access", None, None, ("read:user", "repo"))

    async def account_identifier(settings: Settings, **kwargs: object) -> str:
        return account

    monkeypatch.setattr("coyote_mcp.connected_apps.exchange_authorization_code", exchange)
    monkeypatch.setattr("coyote_mcp.connected_apps.fetch_account_identifier", account_identifier)
    return calls


def _github_input(
    *, enabled: bool = True, client_secret: str | None = GITHUB_SECRET
) -> IntegrationInput:
    return IntegrationInput(
        provider="github",
        client_id="github-oauth-app-client-id",
        client_secret=client_secret,
        scopes="repo read:user",
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        revocation_endpoint="",
        account_endpoint="https://api.github.com/user",
        enabled=enabled,
    )


async def _organization(session_factory: async_sessionmaker[AsyncSession]) -> Organization:
    async with session_factory() as session:
        organization = Organization(slug=f"apps-{uuid4().hex}", display_name="Apps")
        session.add(organization)
        await session.commit()
        return organization


async def _member(
    session_factory: async_sessionmaker[AsyncSession],
    organization: Organization,
    role: str | None = "consumer",
    *,
    instance_administrator: bool = False,
    identity_type: str = "human",
    membership: bool = True,
) -> Principal:
    async with session_factory() as session:
        principal = Principal(
            identifier=f"apps-user-{uuid4().hex}",
            display_name="User",
            identity_type=identity_type,
        )
        session.add(principal)
        await session.flush()
        if membership:
            session.add(
                OrganizationMembership(organization_id=organization.id, principal_id=principal.id)
            )
        if role is not None:
            session.add(
                RoleAssignment(
                    organization_id=organization.id, principal_id=principal.id, role=role
                )
            )
        if instance_administrator:
            session.add(InstanceAdministrator(principal_id=principal.id))
        await session.commit()
        return principal


async def _cookie(
    session_factory: async_sessionmaker[AsyncSession],
    principal: Principal,
    organization: Organization,
) -> str:
    async with session_factory() as session:
        browser_session, cookie = await issue_browser_session(session, principal, [], Settings())
        browser_session.active_organization_id = organization.id
        await session.commit()
        return cookie


async def _server(
    session_factory: async_sessionmaker[AsyncSession],
    organization: Organization,
    *,
    policy: str = "per_user_oauth",
) -> MCPServer:
    async with session_factory() as session:
        server = MCPServer(
            organization_id=organization.id,
            name=f"github-{uuid4().hex[:8]}",
            display_name="GitHub",
            endpoint="https://api.githubcopilot.example.test/mcp",
            status="ready",
            auth_policy=policy,
        )
        session.add(server)
        await session.commit()
        return server


async def _current(session: AsyncSession, cookie: str) -> AuthenticatedPrincipal:
    current = await authenticate_browser_session(session, cookie)
    assert current is not None
    return current


async def _configure_github(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    server: MCPServer,
    admin_cookie: str,
    *,
    enabled: bool = True,
) -> None:
    async with session_factory() as session:
        current = await _current(session, admin_cookie)
        await set_auth_policy(session, current, server.id, "per_user_oauth")
        await save_integration(
            session, settings, current, server.id, _github_input(enabled=enabled)
        )


async def _start(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    cookie: str,
    server: MCPServer,
) -> str:
    async with session_factory() as session:
        current = await _current(session, cookie)
        return await start_connection(session, settings, current, server.id)


async def _complete(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    cookie: str,
    *,
    state: str | None,
    code: str | None = "provider-code",
    error: str | None = None,
) -> str:
    async with session_factory() as session:
        current = await _current(session, cookie)
        return await complete_connection(
            session, settings, current, state=state, code=code, error=error
        )


def _state_from(url: str) -> str:
    return parse_qs(urlsplit(url).query)["state"][0]


async def _broker_error(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    cookie: str,
    server: MCPServer,
) -> str:
    async with session_factory() as session:
        current = await _current(session, cookie)
        loaded = await session.get(MCPServer, server.id)
        assert loaded is not None
        with pytest.raises(DownstreamAuthorizationError) as raised:
            await DownstreamCredentialBroker(settings).authorize(session, current, loaded)
        return raised.value.code


@pytest.mark.asyncio
async def test_start_builds_pkce_url_and_stores_only_hashed_state(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)

    url = await _start(session_factory, settings, cookie, server)

    assert url.startswith("https://github.com/login/oauth/authorize?")
    query = parse_qs(urlsplit(url).query)
    assert query["redirect_uri"] == [CALLBACK]
    assert query["code_challenge_method"] == ["S256"]
    assert query["client_id"] == ["github-oauth-app-client-id"]
    state = _state_from(url)
    async with session_factory() as session:
        rows = (await session.scalars(select(DownstreamOAuthTransaction))).all()
    assert [row.state_hash for row in rows] == [hash_state(state)]
    assert state not in {row.state_hash for row in rows}


@pytest.mark.asyncio
async def test_callback_stores_encrypted_connection_and_reports_state(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)
    calls = _patch_provider(
        monkeypatch,
        tokens=TokenSet("gho_alice_secret", "ghr_alice_refresh", None, ("read:user", "repo")),
        account="alice-gh",
    )

    url = await _start(session_factory, settings, cookie, server)
    name = await _complete(session_factory, settings, cookie, state=_state_from(url))

    assert name == server.name
    verifier = calls[0]["code_verifier"]
    assert isinstance(verifier, str)
    assert code_challenge_for(verifier) == parse_qs(urlsplit(url).query)["code_challenge"][0]
    assert calls[0]["redirect_uri"] == CALLBACK
    async with session_factory() as session:
        connection = await session.scalar(select(DownstreamConnection))
        apps = await list_connected_apps(session, await _current(session, cookie))
    assert connection is not None
    assert b"gho_alice_secret" not in connection.sealed_tokens
    assert b"ghr_alice_refresh" not in connection.sealed_tokens
    assert connection.account_identifier == "alice-gh"
    assert connection.scopes == ["read:user", "repo"]
    github = next(app for app in apps if app.server_id == server.id)
    assert github.state == "connected"
    assert github.account_identifier == "alice-gh"
    assert "gho_alice_secret" not in repr(github)


@pytest.mark.asyncio
async def test_callback_is_single_use(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)
    calls = _patch_provider(monkeypatch)

    state = _state_from(await _start(session_factory, settings, cookie, server))
    await _complete(session_factory, settings, cookie, state=state)
    with pytest.raises(ConnectedAppError) as replay:
        await _complete(session_factory, settings, cookie, state=state)

    assert replay.value.code == "invalid_callback"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_unsolicited_and_missing_callbacks_are_rejected(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)
    calls = _patch_provider(monkeypatch)

    for state in (None, "", "never-issued-state"):
        with pytest.raises(ConnectedAppError) as raised:
            await _complete(session_factory, settings, cookie, state=state)
        assert raised.value.code == "invalid_callback"
    assert calls == []


@pytest.mark.asyncio
async def test_expired_transaction_is_rejected(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)
    calls = _patch_provider(monkeypatch)

    state = _state_from(await _start(session_factory, settings, cookie, server))
    async with session_factory() as session:
        await session.execute(
            update(DownstreamOAuthTransaction).values(
                expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
        )
        await session.commit()

    with pytest.raises(ConnectedAppError) as raised:
        await _complete(session_factory, settings, cookie, state=state)
    assert raised.value.code == "invalid_callback"
    assert calls == []


@pytest.mark.asyncio
async def test_transaction_is_bound_to_browser_session_and_principal(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    bob = await _member(session_factory, organization)
    alice_cookie = await _cookie(session_factory, alice, organization)
    alice_other_browser = await _cookie(session_factory, alice, organization)
    bob_cookie = await _cookie(session_factory, bob, organization)
    calls = _patch_provider(monkeypatch)

    state = _state_from(await _start(session_factory, settings, alice_cookie, server))
    for cookie in (bob_cookie, alice_other_browser):
        with pytest.raises(ConnectedAppError) as raised:
            await _complete(session_factory, settings, cookie, state=state)
        assert raised.value.code == "invalid_callback"
    assert calls == []

    # A rejected attempt must not consume the transaction for the legitimate browser.
    await _complete(session_factory, settings, alice_cookie, state=state)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_provider_error_consumes_transaction(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)
    calls = _patch_provider(monkeypatch)

    state = _state_from(await _start(session_factory, settings, cookie, server))
    with pytest.raises(ConnectedAppError) as denied:
        await _complete(
            session_factory, settings, cookie, state=state, code=None, error="access_denied"
        )
    assert denied.value.code == "authorization_denied"
    with pytest.raises(ConnectedAppError) as replay:
        await _complete(session_factory, settings, cookie, state=state)
    assert replay.value.code == "invalid_callback"
    assert calls == []


@pytest.mark.asyncio
async def test_token_exchange_failure_stores_nothing(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)
    _patch_provider(monkeypatch, failure=OAuthProtocolError("bad code", "invalid_grant"))

    state = _state_from(await _start(session_factory, settings, cookie, server))
    with pytest.raises(ConnectedAppError) as raised:
        await _complete(session_factory, settings, cookie, state=state)

    assert raised.value.code == "token_exchange_failed"
    assert "invalid_grant" not in str(raised.value)
    async with session_factory() as session:
        assert (await session.scalars(select(DownstreamConnection))).all() == []


@pytest.mark.asyncio
async def test_reconnect_replaces_the_existing_connection(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)

    _patch_provider(
        monkeypatch, tokens=TokenSet("first", None, None, ("repo",)), account="first-account"
    )
    await _complete(
        session_factory,
        settings,
        cookie,
        state=_state_from(await _start(session_factory, settings, cookie, server)),
    )
    _patch_provider(
        monkeypatch, tokens=TokenSet("second", None, None, ("repo",)), account="second-account"
    )
    await _complete(
        session_factory,
        settings,
        cookie,
        state=_state_from(await _start(session_factory, settings, cookie, server)),
    )

    async with session_factory() as session:
        connections = (await session.scalars(select(DownstreamConnection))).all()
    assert len(connections) == 1
    assert connections[0].account_identifier == "second-account"


@pytest.mark.asyncio
async def test_disconnect_prevents_future_use_and_reports_revocation_limits(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)
    _patch_provider(monkeypatch)
    await _complete(
        session_factory,
        settings,
        cookie,
        state=_state_from(await _start(session_factory, settings, cookie, server)),
    )

    async with session_factory() as session:
        current = await _current(session, cookie)
        result = await disconnect(session, settings, current, server.id)
    assert result.removed is True
    assert result.revocation_supported is False
    assert result.provider_revoked is False
    assert await _broker_error(session_factory, settings, cookie, server) == "connection_required"

    async with session_factory() as session:
        again = await disconnect(session, settings, await _current(session, cookie), server.id)
    assert again.removed is False


@pytest.mark.asyncio
async def test_other_members_cannot_use_a_connection(
    session_factory: async_sessionmaker[AsyncSession],
    public_dns: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    alice = await _member(session_factory, organization)
    bob = await _member(session_factory, organization)
    alice_cookie = await _cookie(session_factory, alice, organization)
    bob_cookie = await _cookie(session_factory, bob, organization)
    _patch_provider(monkeypatch)
    await _complete(
        session_factory,
        settings,
        alice_cookie,
        state=_state_from(await _start(session_factory, settings, alice_cookie, server)),
    )

    assert (
        await _broker_error(session_factory, settings, bob_cookie, server) == "connection_required"
    )
    async with session_factory() as session:
        apps = await list_connected_apps(session, await _current(session, bob_cookie))
    bob_view = next(app for app in apps if app.server_id == server.id)
    assert bob_view.state == "available"
    assert bob_view.has_connection is False


@pytest.mark.asyncio
async def test_start_rejects_disabled_or_non_oauth_servers(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    admin_cookie = await _cookie(session_factory, admin, organization)
    server = await _server(session_factory, organization)
    await _configure_github(session_factory, settings, server, admin_cookie)
    plain = await _server(session_factory, organization, policy="none")
    alice = await _member(session_factory, organization)
    cookie = await _cookie(session_factory, alice, organization)

    async with session_factory() as session:
        await set_integration_enabled(
            session, settings, await _current(session, admin_cookie), server.id, False
        )
    with pytest.raises(ConnectedAppError) as disabled:
        await _start(session_factory, settings, cookie, server)
    assert disabled.value.code == "not_available"

    with pytest.raises(ConnectedAppError) as wrong_policy:
        await _start(session_factory, settings, cookie, plain)
    assert wrong_policy.value.code == "not_available"


@pytest.mark.asyncio
async def test_connections_require_a_human_browser_member(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )

    read_only_pat = AuthenticatedPrincipal(
        principal=admin,
        scopes=frozenset({"server:read"}),
        token=None,
        organization_id=organization.id,
        credential_context="pat",
    )
    service = await _member(session_factory, organization, identity_type="service")
    service_current = AuthenticatedPrincipal(
        principal=service,
        scopes=frozenset({"connection:manage_own"}),
        token=None,
        organization_id=organization.id,
    )
    outsider = await _member(
        session_factory,
        organization,
        role=None,
        instance_administrator=True,
        membership=False,
    )
    outsider_cookie = await _cookie(session_factory, outsider, organization)

    async with session_factory() as session:
        with pytest.raises(AuthorizationError):
            await start_connection(session, settings, read_only_pat, server.id)
    async with session_factory() as session:
        with pytest.raises(AuthorizationError):
            await start_connection(session, settings, service_current, server.id)
    async with session_factory() as session:
        authorization_url = await start_connection(
            session, settings, await _current(session, outsider_cookie), server.id
        )
    assert authorization_url.startswith("https://github.com/login/oauth/authorize?")

    instance_admin_pat = AuthenticatedPrincipal(
        principal=outsider,
        scopes=frozenset({"connection:manage_own"}),
        token=None,
        organization_id=organization.id,
        credential_context="pat",
    )
    async with session_factory() as session:
        with pytest.raises(AuthorizationError):
            await start_connection(session, settings, instance_admin_pat, server.id)


@pytest.mark.asyncio
async def test_other_organizations_cannot_reach_a_server(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    other = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization)
    await _configure_github(
        session_factory, settings, server, await _cookie(session_factory, admin, organization)
    )
    stranger = await _member(session_factory, other)
    cookie = await _cookie(session_factory, stranger, other)

    async with session_factory() as session:
        with pytest.raises(MissingResourceError):
            await start_connection(session, settings, await _current(session, cookie), server.id)


@pytest.mark.asyncio
async def test_members_cannot_change_administrator_configuration(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    server = await _server(session_factory, organization, policy="none")
    member = await _member(session_factory, organization, "consumer")
    cookie = await _cookie(session_factory, member, organization)

    async with session_factory() as session:
        current = await _current(session, cookie)
        with pytest.raises(AuthorizationError):
            await set_auth_policy(session, current, server.id, "per_user_oauth")
    async with session_factory() as session:
        current = await _current(session, cookie)
        with pytest.raises(AuthorizationError):
            await save_integration(session, settings, current, server.id, _github_input())
    async with session_factory() as session:
        current = await _current(session, cookie)
        with pytest.raises(AuthorizationError):
            await set_shared_credential(session, settings, current, server.id, "shared-value")


@pytest.mark.asyncio
async def test_sensitive_configuration_writes_require_server_and_credential_permissions(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    administrator = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization, policy="none")

    server_only = AuthenticatedPrincipal(
        principal=administrator,
        scopes=frozenset({"server:update"}),
        token=None,
        organization_id=organization.id,
    )
    credential_only = AuthenticatedPrincipal(
        principal=administrator,
        scopes=frozenset({"credential:create"}),
        token=None,
        organization_id=organization.id,
    )
    create_without_revoke = AuthenticatedPrincipal(
        principal=administrator,
        scopes=frozenset({"server:update", "credential:create"}),
        token=None,
        organization_id=organization.id,
    )

    async with session_factory() as session:
        with pytest.raises(AuthorizationError):
            await set_auth_policy(session, server_only, server.id, "shared_bearer")
        with pytest.raises(AuthorizationError):
            await save_integration(session, settings, server_only, server.id, _github_input())
        with pytest.raises(AuthorizationError):
            await set_integration_enabled(session, settings, server_only, server.id, True)
        with pytest.raises(AuthorizationError):
            await set_shared_credential(session, settings, server_only, server.id, "shared-value")
        with pytest.raises(AuthorizationError):
            await clear_shared_credential(session, create_without_revoke, server.id)
        with pytest.raises(AuthorizationError):
            await set_auth_policy(session, credential_only, server.id, "shared_bearer")


@pytest.mark.asyncio
async def test_self_service_connection_permission_allows_collection_and_group_grants_only_in_org(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    organization = await _organization(session_factory)
    other_organization = await _organization(session_factory)
    async with session_factory() as session:
        direct_principal = Principal(
            identifier=f"apps-user-{uuid4().hex}",
            display_name="Direct scoped member",
            identity_type="human",
        )
        group_principal = Principal(
            identifier=f"apps-user-{uuid4().hex}",
            display_name="Group scoped member",
            identity_type="human",
        )
        collection = Collection(
            organization_id=organization.id,
            slug=f"scoped-{uuid4().hex[:8]}",
            display_name="Scoped",
        )
        group = ExternalGroup(
            organization_id=organization.id,
            external_id="connected-apps-group",
            display_name="Connected Apps",
        )
        session.add_all([direct_principal, group_principal, collection, group])
        await session.flush()
        session.add_all(
            [
                OrganizationMembership(
                    organization_id=organization.id, principal_id=direct_principal.id
                ),
                OrganizationMembership(
                    organization_id=organization.id, principal_id=group_principal.id
                ),
            ]
        )
        session.add(
            RoleAssignment(
                organization_id=organization.id,
                principal_id=direct_principal.id,
                role="viewer",
                collection_id=collection.id,
            )
        )
        session.add(
            GroupRoleMapping(
                organization_id=organization.id,
                external_group_id=group.id,
                role="viewer",
                collection_id=collection.id,
            )
        )
        await session.commit()

        assert await self_service_action_allowed(
            session, direct_principal, organization.id, "connection:manage_own"
        )
        assert await self_service_action_allowed(
            session,
            group_principal,
            organization.id,
            "connection:manage_own",
            frozenset({"connected-apps-group"}),
        )
        assert not await self_service_action_allowed(
            session,
            group_principal,
            organization.id,
            "connection:manage_own",
            frozenset({"other-group"}),
        )
        assert not await self_service_action_allowed(
            session, group_principal, other_organization.id, "connection:manage_own"
        )


@pytest.mark.asyncio
async def test_integration_secret_is_encrypted_write_only_and_kept_when_blank(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    admin_cookie = await _cookie(session_factory, admin, organization)
    server = await _server(session_factory, organization)

    async with session_factory() as session:
        current = await _current(session, admin_cookie)
        await set_auth_policy(session, current, server.id, "per_user_oauth")
        view = await save_integration(session, settings, current, server.id, _github_input())
    assert view.has_client_secret is True
    assert GITHUB_SECRET not in repr(view)

    async with session_factory() as session:
        integration = await session.scalar(select(DownstreamOAuthIntegration))
        assert integration is not None
        assert integration.client_secret_sealed is not None
        assert GITHUB_SECRET.encode() not in integration.client_secret_sealed
        assert open_client_secret(settings, integration) == GITHUB_SECRET

    async with session_factory() as session:
        current = await _current(session, admin_cookie)
        await save_integration(
            session, settings, current, server.id, _github_input(client_secret=None)
        )
    async with session_factory() as session:
        integration = await session.scalar(select(DownstreamOAuthIntegration))
        assert integration is not None
        assert open_client_secret(settings, integration) == GITHUB_SECRET


@pytest.mark.asyncio
async def test_shared_credential_is_write_only_and_clearable(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    settings = _settings()
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    admin_cookie = await _cookie(session_factory, admin, organization)
    server = await _server(session_factory, organization, policy="shared_bearer")

    async with session_factory() as session:
        await set_shared_credential(
            session, settings, await _current(session, admin_cookie), server.id, "svc-token-value"
        )
    async with session_factory() as session:
        status = await get_server_authentication(
            session, await _current(session, admin_cookie), server.id
        )
    assert status.shared_credential_configured is True
    assert "svc-token-value" not in repr(status)

    async with session_factory() as session:
        await clear_shared_credential(session, await _current(session, admin_cookie), server.id)
    async with session_factory() as session:
        status = await get_server_authentication(
            session, await _current(session, admin_cookie), server.id
        )
    assert status.shared_credential_configured is False


@pytest.mark.asyncio
async def test_unknown_authentication_policy_is_rejected(
    session_factory: async_sessionmaker[AsyncSession], public_dns: None
) -> None:
    organization = await _organization(session_factory)
    admin = await _member(session_factory, organization, "owner")
    server = await _server(session_factory, organization, policy="none")

    async with session_factory() as session:
        current = await _current(session, await _cookie(session_factory, admin, organization))
        with pytest.raises(ConnectedAppError) as raised:
            await set_auth_policy(session, current, server.id, "shared_everything")
    assert raised.value.code == "invalid_policy"
