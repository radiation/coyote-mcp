from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp import oidc
from coyote_mcp.app import app
from coyote_mcp.auth import ALL_ACTIONS, _hash_secret, issue_pat
from coyote_mcp.db import get_session
from coyote_mcp.models import (
    BrowserSession,
    OIDCLoginTransaction,
    Organization,
    OrganizationMembership,
    Principal,
    RoleAssignment,
)
from coyote_mcp.settings import OIDCProviderConfiguration, Settings


def configured_provider(
    monkeypatch: pytest.MonkeyPatch,
    redirect_uri: str = "http://test/auth/oidc/callback",
) -> OIDCProviderConfiguration:
    monkeypatch.setenv("OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("OIDC_CLIENT_ID", "client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("OIDC_REDIRECT_URI", redirect_uri)
    monkeypatch.setenv("OIDC_GROUP_CLAIM", "groups")
    monkeypatch.setenv("OIDC_JIT_PROVISIONING_ENABLED", "true")
    return Settings().oidc_provider()


@pytest.mark.asyncio
async def test_oidc_authorization_code_flow_provisions_unprivileged_user(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with session_factory() as session:
        organization = Organization(slug="sso", display_name="SSO")
        session.add(organization)
        await session.flush()
        owner = Principal(
            identifier="owner",
            display_name="Owner",
            enabled=True,
        )
        session.add(owner)
        await session.flush()
        session.add(OrganizationMembership(organization_id=organization.id, principal_id=owner.id))
        session.add(
            RoleAssignment(organization_id=organization.id, principal_id=owner.id, role="owner")
        )
        await session.commit()
        _, owner_token = await issue_pat(
            session,
            owner,
            organization.id,
            "owner",
            set(ALL_ACTIONS),
            timedelta(days=1),
            Settings(),
        )

    provider = configured_provider(monkeypatch)

    async def discovery(_: OIDCProviderConfiguration) -> dict[str, object]:
        return {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize?prompt=login",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/keys",
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }

    async def validate(
        _: OIDCProviderConfiguration, __: dict[str, object], ___: str, ____: str
    ) -> dict[str, object]:
        return {
            "sub": "subject",
            "email": "person@example.test",
            "name": "Person",
            "groups": ["engineering"],
        }

    async def exchange(
        _: OIDCProviderConfiguration,
        __: str,
        data: dict[str, str],
        basic_auth: tuple[str, str] | None,
    ) -> dict[str, object]:
        assert "client_secret" not in data
        assert basic_auth == ("client", "secret")
        return {"id_token": "validated-by-test"}

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(oidc, "_discovery", discovery)
    monkeypatch.setattr(oidc, "validate_oidc_endpoint", lambda *args: None)
    monkeypatch.setattr(oidc, "validate_id_token", validate)
    monkeypatch.setattr(oidc, "_exchange_code", exchange)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            login = await client.get("/auth/oidc/login")
            assert login.status_code == 302, login.text
            authorization_query = parse_qs(urlparse(login.headers["location"]).query)
            state = authorization_query["state"][0]
            concurrent_login = await client.get("/auth/oidc/login")
            replacement_state = parse_qs(urlparse(concurrent_login.headers["location"]).query)[
                "state"
            ][0]
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as another_browser:
                cross_browser_callback = await another_browser.get(
                    f"/auth/oidc/callback?code=code&state={state}"
                )
            callback = await client.get(f"/auth/oidc/callback?code=code&state={state}")
            replayed_callback = await client.get(f"/auth/oidc/callback?code=code&state={state}")
            landing = await client.get(callback.headers["location"])
            rotated_callback = await client.get(
                f"/auth/oidc/callback?code=replacement&state={replacement_state}"
            )
            csrf = await client.get("/auth/oidc/csrf")
            session_read = await client.get("/api/v1/servers")
            session_mutation_without_csrf = await client.post(
                "/api/v1/servers",
                json={
                    "name": "session-without-csrf",
                    "display_name": "Session without CSRF",
                    "endpoint": "https://example.com/mcp",
                },
            )
            invalid_bearer = await client.get(
                "/api/v1/servers", headers={"Authorization": "Bearer invalid"}
            )
            bearer_mutation = await client.post(
                "/api/v1/servers",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "name": "bearer-session",
                    "display_name": "Bearer Session",
                    "endpoint": "https://example.com/mcp",
                },
            )
            logout_without_csrf = await client.post("/auth/oidc/logout")
    finally:
        app.dependency_overrides.clear()

    assert callback.status_code == 303
    assert landing.status_code == 200
    assert authorization_query["prompt"] == ["login"]
    assert authorization_query["client_id"] == ["client"]
    assert authorization_query["redirect_uri"] == [provider.redirect_uri]
    assert rotated_callback.status_code == 303
    assert concurrent_login.status_code == 302
    assert cross_browser_callback.status_code == 400
    assert replayed_callback.status_code == 400
    assert csrf.status_code == 200
    assert session_read.status_code == 403
    assert session_mutation_without_csrf.status_code == 403
    assert invalid_bearer.status_code == 401
    assert bearer_mutation.status_code == 201
    assert logout_without_csrf.status_code == 403
    async with session_factory() as session:
        principal = await session.scalar(
            Principal.__table__.select().where(Principal.identifier.like("oidc:%"))
        )
    assert principal is not None
    persisted = (await session.scalars(select(BrowserSession))).all()
    assert len(persisted) == 2
    assert sum(item.revoked_at is not None for item in persisted) == 1
    cookie_value = client.cookies.get(Settings().browser_session_cookie_name)
    assert cookie_value is not None
    assert "subject" not in cookie_value
    assert all(cookie_value not in item.token_hash for item in persisted)


@pytest.mark.asyncio
async def test_oidc_state_lifecycle_requires_matching_bound_browser(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    configured_provider(monkeypatch)
    exchanged_codes: list[str] = []

    async def discovery(_: OIDCProviderConfiguration) -> dict[str, object]:
        return {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/keys",
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }

    async def validate(
        _: OIDCProviderConfiguration, __: dict[str, object], ___: str, ____: str
    ) -> dict[str, object]:
        return {"sub": "subject", "groups": []}

    async def exchange(
        _: OIDCProviderConfiguration,
        __: str,
        data: dict[str, str],
        ___: tuple[str, str] | None,
    ) -> dict[str, object]:
        exchanged_codes.append(data["code"])
        return {"id_token": "validated-by-test"}

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(oidc, "_discovery", discovery)
    monkeypatch.setattr(oidc, "validate_id_token", validate)
    monkeypatch.setattr(oidc, "_exchange_code", exchange)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            login = await client.get("/auth/oidc/login")
            state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
            binding_cookie_name = oidc._oidc_binding_cookie_name(state)
            binding_secret = client.cookies.get(binding_cookie_name)
            assert binding_secret is not None
            async with session_factory() as session:
                committed_transaction = await session.scalar(
                    select(OIDCLoginTransaction).where(
                        OIDCLoginTransaction.state_hash == _hash_secret(state)
                    )
                )
            assert committed_transaction is not None

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as unbound_browser:
                missing_cookie = await unbound_browser.get(
                    f"/auth/oidc/callback?code=missing&state={state}"
                )
                mismatched_cookie = await unbound_browser.get(
                    f"/auth/oidc/callback?code=mismatched&state={state}",
                    headers={"Cookie": f"{binding_cookie_name}=wrong"},
                )
                missing_transaction = await unbound_browser.get(
                    "/auth/oidc/callback?code=unknown&state=unknown-state",
                    headers={
                        "Cookie": (
                            f"{oidc._oidc_binding_cookie_name('unknown-state')}=unrelated-binding"
                        )
                    },
                )

            successful_callback = await client.get(f"/auth/oidc/callback?code=good&state={state}")
            replayed_callback = await client.get(
                f"/auth/oidc/callback?code=replay&state={state}",
                headers={"Cookie": f"{binding_cookie_name}={binding_secret}"},
            )

            expired_login = await client.get("/auth/oidc/login")
            expired_state = parse_qs(urlparse(expired_login.headers["location"]).query)["state"][0]
            async with session_factory() as session:
                await session.execute(
                    update(OIDCLoginTransaction)
                    .where(OIDCLoginTransaction.state_hash == _hash_secret(expired_state))
                    .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
                )
                await session.commit()
            expired_callback = await client.get(
                f"/auth/oidc/callback?code=expired&state={expired_state}"
            )
    finally:
        app.dependency_overrides.clear()

    assert missing_cookie.status_code == 400
    assert mismatched_cookie.status_code == 400
    assert missing_transaction.status_code == 400
    assert successful_callback.status_code == 303
    assert replayed_callback.status_code == 400
    assert expired_callback.status_code == 400
    assert exchanged_codes == ["good"]
    async with session_factory() as session:
        expired_transaction = await session.scalar(
            select(OIDCLoginTransaction).where(
                OIDCLoginTransaction.state_hash == _hash_secret(expired_state)
            )
        )
    assert expired_transaction is not None
    assert expired_transaction.consumed_at is None
    state_diagnostics = [
        record.getMessage()
        for record in caplog.records
        if record.name == "coyote_mcp.oidc" and "OIDC state validation failed" in record.message
    ]
    assert (
        "OIDC state validation failed category=missing_browser_binding_cookie" in state_diagnostics
    )
    assert "OIDC state validation failed category=binding_hash_mismatch" in state_diagnostics
    assert "OIDC state validation failed category=missing_transaction" in state_diagnostics
    assert "OIDC state validation failed category=expired_transaction" in state_diagnostics
    assert "OIDC state validation failed category=already_consumed" in state_diagnostics
    login_diagnostics = [
        record.getMessage()
        for record in caplog.records
        if record.name == "coyote_mcp.oidc" and "OIDC login transaction committed" in record.message
    ]
    assert login_diagnostics == [
        "OIDC login transaction committed callback_scheme=http callback_host=test",
        "OIDC login transaction committed callback_scheme=http callback_host=test",
    ]


@pytest.mark.asyncio
async def test_oidc_binding_cookie_is_not_shared_between_localhost_and_loopback(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    configured_provider(monkeypatch, "http://localhost:8000/auth/oidc/callback")

    async def discovery(_: OIDCProviderConfiguration) -> dict[str, object]:
        return {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/keys",
        }

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(oidc, "_discovery", discovery)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as loopback_client:
            login = await loopback_client.get("/auth/oidc/login")
            state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
            assert loopback_client.cookies.get(oidc._oidc_binding_cookie_name(state)) is not None
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000"
            ) as localhost_client:
                callback = await localhost_client.get(
                    f"/auth/oidc/callback?code=code&state={state}"
                )
    finally:
        app.dependency_overrides.clear()

    assert callback.status_code == 400


@pytest.mark.asyncio
async def test_oidc_callback_logs_safe_identity_validation_diagnostics(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    configured_provider(monkeypatch)

    async def discovery(_: OIDCProviderConfiguration) -> dict[str, object]:
        return {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/keys",
        }

    async def validate(
        _: OIDCProviderConfiguration, __: dict[str, object], ___: str, ____: str
    ) -> dict[str, object]:
        raise oidc.OIDCIdentityValidationError("issuer", "unexpected issuer")

    async def exchange(*_: object, **__: object) -> dict[str, object]:
        return {"id_token": "id-token-sentinel"}

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(oidc, "_discovery", discovery)
    monkeypatch.setattr(oidc, "validate_id_token", validate)
    monkeypatch.setattr(oidc, "_exchange_code", exchange)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            login = await client.get("/auth/oidc/login")
            state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
            callback = await client.get(
                f"/auth/oidc/callback?code=authorization-code-sentinel&state={state}"
            )
    finally:
        app.dependency_overrides.clear()

    assert callback.status_code == 401
    assert callback.json() == {"detail": "OIDC identity validation failed."}
    diagnostics = [
        record.getMessage()
        for record in caplog.records
        if record.name == "coyote_mcp.oidc" and "OIDC identity validation failed" in record.message
    ]
    assert diagnostics == [
        "OIDC identity validation failed category=issuer "
        "exception_class=OIDCIdentityValidationError"
    ]
    assert "authorization-code-sentinel" not in caplog.text
    assert "id-token-sentinel" not in caplog.text


@pytest.mark.asyncio
async def test_oidc_callback_logs_safe_identity_resolution_diagnostics(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    configured_provider(monkeypatch)
    monkeypatch.setenv("OIDC_JIT_PROVISIONING_ENABLED", "false")

    async def discovery(_: OIDCProviderConfiguration) -> dict[str, object]:
        return {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/keys",
        }

    async def validate(
        _: OIDCProviderConfiguration, __: dict[str, object], ___: str, ____: str
    ) -> dict[str, object]:
        return {"sub": "unregistered-subject", "groups": []}

    async def exchange(*_: object, **__: object) -> dict[str, object]:
        return {"id_token": "id-token-sentinel"}

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(oidc, "_discovery", discovery)
    monkeypatch.setattr(oidc, "validate_id_token", validate)
    monkeypatch.setattr(oidc, "_exchange_code", exchange)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            login = await client.get("/auth/oidc/login")
            state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
            callback = await client.get(
                f"/auth/oidc/callback?code=authorization-code-sentinel&state={state}"
            )
    finally:
        app.dependency_overrides.clear()

    assert callback.status_code == 401
    diagnostics = [
        record.getMessage()
        for record in caplog.records
        if record.name == "coyote_mcp.oidc" and "OIDC identity validation failed" in record.message
    ]
    assert diagnostics == [
        "OIDC identity validation failed category=identity_not_registered "
        "exception_class=ExternalIdentityResolutionError"
    ]
    assert "authorization-code-sentinel" not in caplog.text
    assert "id-token-sentinel" not in caplog.text


@pytest.mark.asyncio
async def test_id_token_validation_checks_discovery_signature_and_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = configured_provider(monkeypatch)
    claims = {
        "iss": "https://issuer.example",
        "aud": "client",
        "nonce": "nonce",
        "sub": "subject",
        "exp": (datetime.now(UTC) + timedelta(minutes=5)).timestamp(),
    }

    class Client:
        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, _: str, **__: object) -> httpx.Response:
            return httpx.Response(
                200,
                json={"keys": []},
                request=httpx.Request("GET", "https://issuer.example/keys"),
            )

    monkeypatch.setattr(oidc.httpx, "AsyncClient", lambda **_: Client())
    monkeypatch.setattr(oidc, "validate_oidc_endpoint", lambda *args: None)
    monkeypatch.setattr(oidc.jwk.KeySet, "import_key_set", lambda _: object())
    monkeypatch.setattr(oidc.jwt, "decode", lambda *args, **kwargs: SimpleNamespace(claims=claims))
    validated = await oidc.validate_id_token(
        provider, {"jwks_uri": "https://issuer.example/keys"}, "token", "nonce"
    )
    assert validated["sub"] == "subject"
    claims["nonce"] = "wrong"
    with pytest.raises(ValueError, match="nonce"):
        await oidc.validate_id_token(
            provider, {"jwks_uri": "https://issuer.example/keys"}, "token", "nonce"
        )
    with pytest.raises(ValueError, match="JWKS"):
        await oidc.validate_id_token(provider, {}, "token", "nonce")
    claims["nonce"] = "nonce"
    claims["exp"] = 0
    with pytest.raises(ValueError, match="expired"):
        await oidc.validate_id_token(
            provider, {"jwks_uri": "https://issuer.example/keys"}, "token", "nonce"
        )
    claims["exp"] = (datetime.now(UTC) + timedelta(minutes=5)).timestamp()
    claims["nbf"] = (datetime.now(UTC) + timedelta(minutes=5)).timestamp()
    with pytest.raises(ValueError, match="not yet valid"):
        await oidc.validate_id_token(
            provider, {"jwks_uri": "https://issuer.example/keys"}, "token", "nonce"
        )
    claims.pop("nbf")
    claims["iss"] = "https://unexpected.example"
    with pytest.raises(oidc.OIDCIdentityValidationError, match="issuer") as error:
        await oidc.validate_id_token(
            provider, {"jwks_uri": "https://issuer.example/keys"}, "token", "nonce"
        )
    assert error.value.category == "issuer"
    claims["iss"] = "https://issuer.example"
    claims["aud"] = ["client", "other-client"]
    with pytest.raises(ValueError, match="authorized party"):
        await oidc.validate_id_token(
            provider, {"jwks_uri": "https://issuer.example/keys"}, "token", "nonce"
        )


@pytest.mark.asyncio
async def test_google_id_token_accepts_documented_bare_host_issuer_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = OIDCProviderConfiguration(
        issuer="https://accounts.google.com",
        client_id="client",
        client_secret="secret",
        redirect_uri="http://test/auth/oidc/callback",
        allowed_organization=None,
        group_claim=None,
        trusted_endpoint_hosts=("www.googleapis.com",),
        jit_provisioning_enabled=False,
    )
    claims = {
        "iss": "accounts.google.com",
        "aud": "client",
        "nonce": "nonce",
        "sub": "subject",
        "exp": (datetime.now(UTC) + timedelta(minutes=5)).timestamp(),
    }

    class Client:
        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, _: str, **__: object) -> httpx.Response:
            return httpx.Response(
                200,
                json={"keys": []},
                request=httpx.Request("GET", "https://www.googleapis.com/oauth2/v3/certs"),
            )

    monkeypatch.setattr(oidc.httpx, "AsyncClient", lambda **_: Client())
    monkeypatch.setattr(oidc, "validate_oidc_endpoint", lambda *args: None)
    monkeypatch.setattr(oidc.jwk.KeySet, "import_key_set", lambda _: object())
    monkeypatch.setattr(oidc.jwt, "decode", lambda *args, **kwargs: SimpleNamespace(claims=claims))

    validated = await oidc.validate_id_token(
        provider, {"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"}, "token", "nonce"
    )

    assert validated["sub"] == "subject"


def test_oidc_settings_reject_missing_or_invalid_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert oidc._pkce_challenge("verifier") != "verifier"
    for variable in (
        "OIDC_ISSUER",
        "OIDC_CLIENT_ID",
        "OIDC_CLIENT_SECRET",
        "OIDC_REDIRECT_URI",
    ):
        monkeypatch.delenv(variable, raising=False)
    with pytest.raises(ValueError, match="OIDC_ISSUER"):
        Settings(_env_file=None).oidc_provider()
    with pytest.raises(ValueError, match="invalid issuer or redirect URI"):
        Settings(
            oidc_issuer="https://issuer.example",
            oidc_client_id="client",
            oidc_client_secret="secret",
            oidc_redirect_uri="https://console.example/not-a-callback",
        ).oidc_provider()


@pytest.mark.asyncio
async def test_oidc_discovery_and_token_exchange_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []
    provider = configured_provider(monkeypatch)

    class Client:
        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, **__: object) -> httpx.Response:
            requested_urls.append(url)
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example",
                    "authorization_endpoint": "https://issuer.example/authorize",
                    "token_endpoint": "https://issuer.example/token",
                    "jwks_uri": "https://issuer.example/keys",
                },
                request=httpx.Request(
                    "GET", "https://issuer.example/.well-known/openid-configuration"
                ),
            )

        async def post(self, _: str, data: dict[str, str], **__: object) -> httpx.Response:
            assert data["code"] == "code"
            return httpx.Response(
                200,
                json={"id_token": "token"},
                request=httpx.Request("POST", "https://issuer.example/token"),
            )

    monkeypatch.setattr(oidc.httpx, "AsyncClient", lambda **_: Client())
    monkeypatch.setattr(oidc, "validate_oidc_endpoint", lambda *args: None)
    assert (await oidc._discovery(provider))["issuer"] == "https://issuer.example"
    assert requested_urls == ["https://issuer.example/.well-known/openid-configuration"]
    assert await oidc._exchange_code(
        provider, "https://issuer.example/token", {"code": "code"}
    ) == {"id_token": "token"}
