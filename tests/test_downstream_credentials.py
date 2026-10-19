import base64
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.auth import AuthenticatedPrincipal
from coyote_mcp.credential_vault import CredentialVaultError, SealedValue, open_sealed, seal
from coyote_mcp.credentials import (
    CONNECTION_STATUS_CONNECTED,
    CONNECTION_STATUS_REAUTHORIZATION,
    DownstreamCredentialBroker,
    client_secret_aad,
    connection_aad,
    open_tokens,
    seal_tokens,
    shared_credential_aad,
)
from coyote_mcp.downstream_errors import DownstreamAuthorizationError
from coyote_mcp.downstream_oauth import (
    OAuthConfigurationError,
    OAuthProtocolError,
    TokenSet,
    callback_redirect_uri,
    code_challenge_for,
    generate_code_verifier,
    generate_state,
    hash_state,
    parse_scopes,
    validate_oauth_endpoint,
)
from coyote_mcp.models import (
    DownstreamConnection,
    DownstreamOAuthIntegration,
    DownstreamSharedCredential,
    MCPServer,
    Organization,
    Principal,
)
from coyote_mcp.settings import Settings


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "credential_encryption_keys": {"v1": SecretStr(_key()), "v2": SecretStr(_key())},
        "credential_active_key_version": "v1",
        "downstream_oauth_redirect_base_url": "https://coyote.example.test",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(host: str, *args: object, **kwargs: object) -> list[tuple[object, ...]]:
        address = "10.0.0.5" if host.startswith("internal.") else "93.184.216.34"
        return [(None, None, None, None, (address, 0))]

    monkeypatch.setattr("coyote_mcp.security.socket.getaddrinfo", resolve)


def test_settings_accepts_coyote_downstream_configuration_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = _key()
    for name in (
        "CREDENTIAL_ENCRYPTION_KEYS",
        "CREDENTIAL_ACTIVE_KEY_VERSION",
        "DOWNSTREAM_OAUTH_REDIRECT_BASE_URL",
        "DOWNSTREAM_OAUTH_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COYOTE_CREDENTIAL_ENCRYPTION_KEYS", f'{{"v1":"{key}"}}')
    monkeypatch.setenv("COYOTE_CREDENTIAL_ACTIVE_KEY_VERSION", "v1")
    monkeypatch.setenv("COYOTE_DOWNSTREAM_OAUTH_REDIRECT_BASE_URL", "https://coyote.example.test")
    monkeypatch.setenv("COYOTE_DOWNSTREAM_OAUTH_TIMEOUT_SECONDS", "12.5")

    settings = Settings()

    assert settings.credential_encryption_keys["v1"].get_secret_value() == key
    assert settings.credential_active_key_version == "v1"
    assert settings.downstream_oauth_redirect_base_url == "https://coyote.example.test"
    assert settings.downstream_oauth_timeout_seconds == 12.5


# --- Credential vault -----------------------------------------------------------------


def test_vault_round_trip_and_key_rotation_metadata() -> None:
    settings = _settings()
    aad = b"context-a"

    sealed = seal(settings, b"secret-value", aad)

    assert sealed.key_version == "v1"
    assert b"secret-value" not in sealed.sealed
    assert open_sealed(settings, sealed, aad) == b"secret-value"

    rotated = seal(settings.model_copy(update={"credential_active_key_version": "v2"}), b"x", aad)
    assert rotated.key_version == "v2"
    # Older key versions remain readable during rotation.
    assert open_sealed(settings, rotated, aad) == b"x"


def test_vault_rejects_wrong_associated_data_and_tampering() -> None:
    settings = _settings()
    sealed = seal(settings, b"secret-value", b"context-a")

    with pytest.raises(CredentialVaultError):
        open_sealed(settings, sealed, b"context-b")

    tampered = bytearray(sealed.sealed)
    tampered[-1] ^= 0x01
    with pytest.raises(CredentialVaultError):
        open_sealed(settings, SealedValue(sealed.key_version, bytes(tampered)), b"context-a")


def test_vault_fails_closed_for_unknown_or_malformed_keys() -> None:
    settings = _settings()
    sealed = seal(settings, b"secret-value", b"context")

    with pytest.raises(CredentialVaultError, match="not configured"):
        open_sealed(settings, SealedValue("missing", sealed.sealed), b"context")

    malformed = _settings(credential_encryption_keys={"v1": SecretStr("not-a-32-byte-key")})
    with pytest.raises(CredentialVaultError):
        seal(malformed, b"value", b"context")

    unset = _settings(credential_active_key_version=None)
    with pytest.raises(CredentialVaultError, match="No active"):
        seal(unset, b"value", b"context")


def test_token_material_repr_is_redacted() -> None:
    tokens = TokenSet(access_token="gho_secret", refresh_token="ghr_secret", expires_at=None)

    assert "gho_secret" not in repr(tokens)
    assert "ghr_secret" not in repr(tokens)


# --- OAuth protocol helpers -----------------------------------------------------------


def test_pkce_challenge_matches_rfc_7636_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    assert code_challenge_for(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_state_and_verifier_are_random_and_state_is_hashed() -> None:
    first, second = generate_state(), generate_state()

    assert first != second
    assert len(first) >= 43
    assert len(generate_code_verifier()) >= 43
    assert hash_state(first) != first
    assert hash_state(first) == hash_state(first)


def test_redirect_uri_is_derived_from_configured_base_only() -> None:
    settings = _settings(downstream_oauth_redirect_base_url="https://coyote.example.test/")

    assert callback_redirect_uri(settings) == (
        "https://coyote.example.test/console/connected-apps/callback"
    )
    with pytest.raises(OAuthConfigurationError):
        callback_redirect_uri(_settings(downstream_oauth_redirect_base_url=None))
    with pytest.raises(OAuthConfigurationError):
        callback_redirect_uri(_settings(downstream_oauth_redirect_base_url="javascript:alert(1)"))


@pytest.mark.parametrize(
    "base",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ],
)
def test_local_http_redirect_uri_requires_explicit_development_configuration(base: str) -> None:
    settings = _settings(
        downstream_oauth_redirect_base_url=base,
        allow_insecure_endpoints=True,
    )

    assert callback_redirect_uri(settings) == f"{base}/console/connected-apps/callback"

    with pytest.raises(OAuthConfigurationError, match="must use HTTPS"):
        callback_redirect_uri(settings.model_copy(update={"allow_insecure_endpoints": False}))
    with pytest.raises(OAuthConfigurationError, match="must use HTTPS"):
        callback_redirect_uri(settings.model_copy(update={"environment": "production"}))


@pytest.mark.parametrize(
    "base",
    [
        "http://192.168.1.10:8000",
        "http://10.0.0.5:8000",
        "http://127.0.0.2:8000",
        "http://coyote.local:8000",
        "http://smoke-mcp:8000",
    ],
)
def test_http_redirect_uri_rejects_non_loopback_hosts_even_with_development_enabled(
    base: str,
) -> None:
    settings = _settings(
        downstream_oauth_redirect_base_url=base,
        allow_insecure_endpoints=True,
        allow_private_endpoints=True,
    )

    with pytest.raises(OAuthConfigurationError, match="must use HTTPS"):
        callback_redirect_uri(settings)


def test_oauth_endpoints_reject_query_fragments_and_private_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _public_dns(monkeypatch)
    settings = _settings()

    validate_oauth_endpoint("https://github.com/login/oauth/access_token", settings)
    with pytest.raises(OAuthConfigurationError):
        validate_oauth_endpoint("https://github.com/token?redirect=evil", settings)
    with pytest.raises(OAuthConfigurationError):
        validate_oauth_endpoint("https://github.com/token#fragment", settings)
    with pytest.raises(OAuthConfigurationError):
        validate_oauth_endpoint("https://internal.example.test/token", settings)


def test_scope_parsing_accepts_space_or_comma_separated_text() -> None:
    assert parse_scopes("repo, read:user") == ("read:user", "repo")
    assert parse_scopes(["repo", "read:user", "repo"]) == ("read:user", "repo")
    assert parse_scopes(None) == ()


def test_token_set_reports_expiry_with_skew() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    assert TokenSet("a", None, now + timedelta(seconds=30)).is_expired(now) is True
    assert TokenSet("a", None, now + timedelta(hours=1)).is_expired(now) is False
    assert TokenSet("a", None, None).is_expired(now) is False


def test_protocol_error_carries_only_oauth_code() -> None:
    error = OAuthProtocolError("Token request was rejected.", code="invalid_grant")

    assert error.code == "invalid_grant"
    assert "invalid_grant" not in str(error)


# --- Credential broker ----------------------------------------------------------------


async def _seed_server(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    policy: str,
    organization_name: str = "Alpha",
) -> tuple[Organization, MCPServer]:
    async with session_factory() as session:
        organization = Organization(slug=f"org-{uuid4().hex}", display_name=organization_name)
        session.add(organization)
        await session.flush()
        server = MCPServer(
            organization_id=organization.id,
            name=f"srv-{uuid4().hex[:8]}",
            display_name="Downstream",
            endpoint="https://downstream.example.test/mcp",
            status="ready",
            auth_policy=policy,
        )
        session.add(server)
        await session.commit()
        return organization, server


async def _principal(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    identity_type: str = "human",
) -> Principal:
    async with session_factory() as session:
        principal = Principal(
            identifier=f"user-{uuid4().hex}",
            display_name="User",
            identity_type=identity_type,
        )
        session.add(principal)
        await session.commit()
        return principal


def _authenticated(principal: Principal, organization: Organization) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        principal=principal,
        scopes=frozenset(),
        token=None,
        organization_id=organization.id,
    )


async def _connect(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    organization: Organization,
    server: MCPServer,
    principal: Principal,
    access_token: str,
    refresh_token: str | None,
    expires_at: datetime | None,
    status: str = CONNECTION_STATUS_CONNECTED,
) -> None:
    sealed = seal_tokens(
        settings,
        TokenSet(access_token, refresh_token, expires_at, ("repo",)),
        organization_id=organization.id,
        server_id=server.id,
        principal_id=principal.id,
    )
    async with session_factory() as session:
        session.add(
            DownstreamConnection(
                organization_id=organization.id,
                server_id=server.id,
                principal_id=principal.id,
                status=status,
                key_version=sealed.key_version,
                sealed_tokens=sealed.sealed,
                scopes=["repo"],
                access_token_expires_at=expires_at,
            )
        )
        await session.commit()


async def _integration(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    organization: Organization,
    server: MCPServer,
    token_endpoint: str = "https://github.com/login/oauth/access_token",
) -> None:
    async with session_factory() as session:
        session.add(
            DownstreamOAuthIntegration(
                organization_id=organization.id,
                server_id=server.id,
                provider="github",
                authorization_endpoint="https://github.com/login/oauth/authorize",
                token_endpoint=token_endpoint,
                client_id="client-id",
                enabled=True,
            )
        )
        await session.commit()


async def _store_shared(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    organization: Organization,
    server: MCPServer,
    value: str,
) -> None:
    sealed = seal(
        settings, value.encode("utf-8"), shared_credential_aad(organization.id, server.id)
    )
    async with session_factory() as session:
        session.add(
            DownstreamSharedCredential(
                organization_id=organization.id,
                server_id=server.id,
                key_version=sealed.key_version,
                sealed_value=sealed.sealed,
            )
        )
        await session.commit()


async def _authorize(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    current: AuthenticatedPrincipal,
    server: MCPServer,
) -> dict[str, str]:
    async with session_factory() as session:
        loaded = await session.get(MCPServer, server.id)
        assert loaded is not None
        authorization = await DownstreamCredentialBroker(settings).authorize(
            session, current, loaded
        )
        return dict(authorization.headers)


@pytest.mark.asyncio
async def test_no_auth_policy_sends_no_downstream_credentials(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="none")
    principal = await _principal(session_factory)

    headers = await _authorize(
        session_factory, settings, _authenticated(principal, organization), server
    )

    assert headers == {}


@pytest.mark.asyncio
async def test_shared_bearer_fails_closed_when_credential_is_missing(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="shared_bearer")
    principal = await _principal(session_factory)

    with pytest.raises(DownstreamAuthorizationError) as raised:
        await _authorize(session_factory, settings, _authenticated(principal, organization), server)

    assert "credential_not_configured" in str(raised.value)


@pytest.mark.asyncio
async def test_shared_bearer_credential_is_bound_to_its_server(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="shared_bearer")
    _, other_server = await _seed_server(session_factory, policy="shared_bearer")
    principal = await _principal(session_factory)
    await _store_shared(
        session_factory, settings, organization=organization, server=server, value="svc-token"
    )

    headers = await _authorize(
        session_factory, settings, _authenticated(principal, organization), server
    )
    assert headers == {"Authorization": "Bearer svc-token"}

    with pytest.raises(DownstreamAuthorizationError):
        await _authorize(
            session_factory,
            settings,
            _authenticated(principal, organization),
            other_server,
        )


@pytest.mark.asyncio
async def test_per_user_oauth_requires_the_callers_own_connection(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="per_user_oauth")
    await _integration(session_factory, settings, organization=organization, server=server)
    alice = await _principal(session_factory)
    bob = await _principal(session_factory)
    await _connect(
        session_factory,
        settings,
        organization=organization,
        server=server,
        principal=alice,
        access_token="alice-token",
        refresh_token=None,
        expires_at=None,
    )

    alice_headers = await _authorize(
        session_factory, settings, _authenticated(alice, organization), server
    )
    assert alice_headers == {"Authorization": "Bearer alice-token"}

    with pytest.raises(DownstreamAuthorizationError, match="connection_required"):
        await _authorize(session_factory, settings, _authenticated(bob, organization), server)


@pytest.mark.asyncio
async def test_per_user_oauth_never_falls_back_to_shared_credential(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="per_user_oauth")
    await _integration(session_factory, settings, organization=organization, server=server)
    principal = await _principal(session_factory)
    await _store_shared(
        session_factory, settings, organization=organization, server=server, value="shared"
    )

    with pytest.raises(DownstreamAuthorizationError, match="connection_required"):
        await _authorize(session_factory, settings, _authenticated(principal, organization), server)


@pytest.mark.asyncio
async def test_service_principals_fail_closed_on_per_user_servers(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="per_user_oauth")
    service = await _principal(session_factory, identity_type="service")
    await _connect(
        session_factory,
        settings,
        organization=organization,
        server=server,
        principal=service,
        access_token="service-token",
        refresh_token=None,
        expires_at=None,
    )

    with pytest.raises(DownstreamAuthorizationError, match="service_principal_not_permitted"):
        await _authorize(session_factory, settings, _authenticated(service, organization), server)


@pytest.mark.asyncio
async def test_connections_are_bound_to_their_organization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    alpha, server = await _seed_server(session_factory, policy="per_user_oauth")
    beta, _ = await _seed_server(session_factory, policy="per_user_oauth", organization_name="Beta")
    principal = await _principal(session_factory)
    await _connect(
        session_factory,
        settings,
        organization=alpha,
        server=server,
        principal=principal,
        access_token="alpha-token",
        refresh_token=None,
        expires_at=None,
    )

    with pytest.raises(DownstreamAuthorizationError, match="server_unavailable"):
        await _authorize(session_factory, settings, _authenticated(principal, beta), server)


@pytest.mark.asyncio
async def test_expired_connection_without_refresh_token_fails_closed(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="per_user_oauth")
    await _integration(session_factory, settings, organization=organization, server=server)
    principal = await _principal(session_factory)
    await _connect(
        session_factory,
        settings,
        organization=organization,
        server=server,
        principal=principal,
        access_token="old-token",
        refresh_token=None,
        expires_at=datetime.now(UTC) - timedelta(minutes=5),
    )

    with pytest.raises(DownstreamAuthorizationError, match="connection_expired"):
        await _authorize(session_factory, settings, _authenticated(principal, organization), server)


@pytest.mark.asyncio
async def test_expired_connection_refreshes_and_reseals_rotated_tokens(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="per_user_oauth")
    principal = await _principal(session_factory)
    await _integration(session_factory, settings, organization=organization, server=server)
    await _connect(
        session_factory,
        settings,
        organization=organization,
        server=server,
        principal=principal,
        access_token="old-token",
        refresh_token="refresh-1",
        expires_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    calls: list[str] = []

    async def fake_refresh(_settings: Settings, **kwargs: object) -> TokenSet:
        calls.append(str(kwargs["refresh_token"]))
        return TokenSet(
            "new-token",
            "refresh-2",
            datetime.now(UTC) + timedelta(hours=1),
            ("repo",),
        )

    monkeypatch.setattr("coyote_mcp.credentials.refresh_tokens", fake_refresh)

    headers = await _authorize(
        session_factory, settings, _authenticated(principal, organization), server
    )

    assert headers == {"Authorization": "Bearer new-token"}
    assert calls == ["refresh-1"]
    async with session_factory() as session:
        stored = await session.scalar(select(DownstreamConnection))
        assert stored is not None
        assert open_tokens(settings, stored).refresh_token == "refresh-2"


@pytest.mark.asyncio
async def test_rejected_refresh_marks_connection_for_reauthorization(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="per_user_oauth")
    principal = await _principal(session_factory)
    await _integration(session_factory, settings, organization=organization, server=server)
    await _connect(
        session_factory,
        settings,
        organization=organization,
        server=server,
        principal=principal,
        access_token="old-token",
        refresh_token="revoked-refresh",
        expires_at=datetime.now(UTC) - timedelta(minutes=5),
    )

    async def rejected(_settings: Settings, **kwargs: object) -> TokenSet:
        raise OAuthProtocolError("Token request was rejected.", code="invalid_grant")

    monkeypatch.setattr("coyote_mcp.credentials.refresh_tokens", rejected)

    with pytest.raises(DownstreamAuthorizationError):
        await _authorize(session_factory, settings, _authenticated(principal, organization), server)

    async with session_factory() as session:
        stored = await session.scalar(select(DownstreamConnection))
        assert stored is not None
        assert stored.status == CONNECTION_STATUS_REAUTHORIZATION


@pytest.mark.asyncio
async def test_connection_tokens_are_bound_to_org_server_and_principal(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _settings()
    organization, server = await _seed_server(session_factory, policy="per_user_oauth")
    principal = await _principal(session_factory)
    await _connect(
        session_factory,
        settings,
        organization=organization,
        server=server,
        principal=principal,
        access_token="token",
        refresh_token=None,
        expires_at=None,
    )
    async with session_factory() as session:
        stored = await session.scalar(select(DownstreamConnection))
    assert stored is not None

    # Swapping the row to a different principal must fail authentication.
    swapped = DownstreamConnection(
        organization_id=stored.organization_id,
        server_id=stored.server_id,
        principal_id=uuid4(),
        key_version=stored.key_version,
        sealed_tokens=stored.sealed_tokens,
    )
    with pytest.raises(CredentialVaultError):
        open_tokens(settings, swapped)
    assert connection_aad(organization.id, server.id, principal.id) != connection_aad(
        organization.id, server.id, swapped.principal_id
    )


def test_aad_domains_are_separated() -> None:
    org, server = uuid4(), uuid4()

    assert shared_credential_aad(org, server) != client_secret_aad(org, server)


def test_redacted_secret_never_appears_in_settings_repr() -> None:
    key = _key()
    settings = _settings(credential_encryption_keys={"v1": SecretStr(key)})

    assert key not in repr(settings.credential_encryption_keys)
