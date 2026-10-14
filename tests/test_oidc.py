import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp import oidc
from coyote_mcp.app import app
from coyote_mcp.auth import ALL_ACTIONS, issue_pat
from coyote_mcp.db import get_session
from coyote_mcp.models import (
    BrowserSession,
    IdentityProvider,
    Organization,
    Principal,
    RoleAssignment,
)
from coyote_mcp.settings import Settings


@pytest.mark.asyncio
async def test_oidc_authorization_code_flow_provisions_unprivileged_user(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with session_factory() as session:
        organization = Organization(slug="sso", display_name="SSO")
        session.add(organization)
        await session.flush()
        provider = IdentityProvider(
            organization_id=organization.id,
            name="Test",
            issuer="https://issuer.example",
            client_id="client",
            client_secret_reference="env:TEST_OIDC_SECRET",
            group_claim="groups",
            jit_provisioning_enabled=True,
        )
        session.add(provider)
        owner = Principal(
            organization_id=organization.id,
            identifier="owner",
            display_name="Owner",
            enabled=True,
        )
        session.add(owner)
        await session.flush()
        session.add(
            RoleAssignment(organization_id=organization.id, principal_id=owner.id, role="owner")
        )
        await session.commit()
        _, owner_token = await issue_pat(
            session, owner, "owner", set(ALL_ACTIONS), timedelta(days=1), Settings()
        )

    async def discovery(_: IdentityProvider) -> dict[str, object]:
        return {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/keys",
        }

    async def validate(
        _: IdentityProvider, __: dict[str, object], ___: str, ____: str
    ) -> dict[str, object]:
        return {
            "sub": "subject",
            "email": "person@example.test",
            "name": "Person",
            "groups": ["engineering"],
        }

    async def exchange(_: IdentityProvider, __: str, ___: dict[str, str]) -> dict[str, object]:
        return {"id_token": "validated-by-test"}

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    monkeypatch.setenv("TEST_OIDC_SECRET", "secret")
    monkeypatch.setattr(oidc, "_discovery", discovery)
    monkeypatch.setattr(oidc, "validate_oidc_endpoint", lambda *args: None)
    monkeypatch.setattr(oidc, "validate_id_token", validate)
    monkeypatch.setattr(oidc, "_exchange_code", exchange)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            login = await client.get("/auth/oidc/sso/login")
            assert login.status_code == 302, login.text
            state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
            concurrent_login = await client.get("/auth/oidc/sso/login")
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as another_browser:
                cross_browser_callback = await another_browser.get(
                    f"/auth/oidc/callback?code=code&state={state}"
                )
            callbacks = await asyncio.gather(
                client.get(f"/auth/oidc/callback?code=code&state={state}"),
                client.get(f"/auth/oidc/callback?code=code&state={state}"),
            )
            callback = next(response for response in callbacks if response.status_code == 303)
            replayed_callback = next(
                response for response in callbacks if response.status_code != 303
            )
            csrf = await client.get("/auth/oidc/csrf")
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
    assert concurrent_login.status_code == 302
    assert cross_browser_callback.status_code == 400
    assert replayed_callback.status_code == 400
    assert csrf.status_code == 200
    assert invalid_bearer.status_code == 401
    assert bearer_mutation.status_code == 201
    assert logout_without_csrf.status_code == 403
    async with session_factory() as session:
        principal = await session.scalar(
            Principal.__table__.select().where(
                Principal.identifier == "oidc:https://issuer.example:subject"
            )
        )
    assert principal is not None
    persisted = await session.scalar(select(BrowserSession))
    assert persisted is not None
    cookie_value = client.cookies.get(Settings().browser_session_cookie_name)
    assert cookie_value is not None
    assert "subject" not in cookie_value
    assert cookie_value not in persisted.token_hash


@pytest.mark.asyncio
async def test_id_token_validation_checks_discovery_signature_and_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = IdentityProvider(
        organization_id=Organization(slug="oidc", display_name="OIDC").id,
        name="Test",
        issuer="https://issuer.example",
        client_id="client",
        client_secret_reference="env:TEST",
    )
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
    with pytest.raises(ValueError, match="issuer or audience"):
        await oidc.validate_id_token(
            provider, {"jwks_uri": "https://issuer.example/keys"}, "token", "nonce"
        )
    claims["iss"] = "https://issuer.example"
    claims["aud"] = ["client", "other-client"]
    with pytest.raises(ValueError, match="authorized party"):
        await oidc.validate_id_token(
            provider, {"jwks_uri": "https://issuer.example/keys"}, "token", "nonce"
        )


def test_oidc_secret_reference_and_pkce() -> None:
    assert oidc._pkce_challenge("verifier") != "verifier"
    with pytest.raises(ValueError, match="env:"):
        oidc._secret("vault:secret")
    with pytest.raises(ValueError, match="not configured"):
        oidc._secret("env:DOES_NOT_EXIST")


@pytest.mark.asyncio
async def test_oidc_discovery_and_token_exchange_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = IdentityProvider(
        organization_id=Organization(slug="helpers", display_name="Helpers").id,
        name="Test",
        issuer="https://issuer.example",
        client_id="client",
        client_secret_reference="env:TEST",
    )

    class Client:
        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, _: str, **__: object) -> httpx.Response:
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
    assert await oidc._exchange_code(
        provider, "https://issuer.example/token", {"code": "code"}
    ) == {"id_token": "token"}
