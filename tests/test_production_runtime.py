import base64
import os
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from coyote_mcp import app as app_module
from coyote_mcp.runtime import RequestIDMiddleware, TrustedProxyHeadersMiddleware, request_id
from coyote_mcp.settings import Settings


def production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "production",
        "database_url": "postgresql+asyncpg://coyote:password@postgres.example.test/coyote_mcp",
        "session_secret_key": "s" * 32,
        "public_base_url": "https://gateway.example.test",
        "allowed_hosts": ["gateway.example.test"],
        "trusted_proxy_networks": ["10.0.0.0/8"],
        "allow_insecure_endpoints": False,
        "allow_private_endpoints": False,
        "allowed_insecure_endpoint_hosts": [],
        "allowed_private_endpoint_hosts": [],
        "allow_insecure_oidc": False,
        "allow_private_oidc": False,
        "oidc_enabled": False,
        "oidc_issuer": None,
        "oidc_client_id": None,
        "oidc_client_secret": None,
        "oidc_redirect_uri": None,
        "oidc_allowed_organization": None,
        "oidc_group_claim": None,
        "oidc_trusted_endpoint_hosts": [],
        "oidc_jit_provisioning_enabled": False,
        "downstream_credentials_enabled": False,
        "downstream_oauth_enabled": False,
        "credential_encryption_keys": {},
        "credential_active_key_version": None,
        "downstream_oauth_redirect_base_url": None,
    }
    values.update(overrides)
    aliases = {
        "public_base_url": "COYOTE_PUBLIC_BASE_URL",
        "allowed_hosts": "COYOTE_ALLOWED_HOSTS",
        "trusted_proxy_networks": "COYOTE_TRUSTED_PROXY_NETWORKS",
        "oidc_enabled": "COYOTE_OIDC_ENABLED",
        "downstream_credentials_enabled": "COYOTE_DOWNSTREAM_CREDENTIALS_ENABLED",
        "downstream_oauth_enabled": "COYOTE_DOWNSTREAM_OAUTH_ENABLED",
        "credential_encryption_keys": "COYOTE_CREDENTIAL_ENCRYPTION_KEYS",
        "credential_active_key_version": "COYOTE_CREDENTIAL_ACTIVE_KEY_VERSION",
        "downstream_oauth_redirect_base_url": "COYOTE_DOWNSTREAM_OAUTH_REDIRECT_BASE_URL",
    }
    for field, alias in aliases.items():
        values[alias] = values.pop(field)
    with patch.dict(os.environ, {}, clear=True):
        return Settings(_env_file=None, **values)  # type: ignore[arg-type]


def runtime_app(settings: Settings) -> FastAPI:
    application = FastAPI()
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.effective_allowed_hosts,
        www_redirect=False,
    )
    application.add_middleware(
        TrustedProxyHeadersMiddleware,
        trusted_proxy_networks=tuple(settings.trusted_proxy_networks),
    )
    application.add_middleware(
        RequestIDMiddleware,
        trusted_proxy_networks=tuple(settings.trusted_proxy_networks),
    )

    @application.get("/")
    async def details(request: Request) -> dict[str, str | None]:
        return {
            "scheme": request.url.scheme,
            "state_request_id": request.state.request_id,
            "context_request_id": request_id(),
        }

    return application


def test_development_defaults_remain_available() -> None:
    settings = Settings()

    assert settings.is_development is True
    assert settings.effective_allowed_hosts == ("*",)
    assert settings.public_origin is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"database_url": "postgresql+asyncpg://coyote:localdev-only@localhost:5432/coyote_mcp"},
            "DATABASE_URL",
        ),
        ({"public_base_url": None}, "PUBLIC_BASE_URL"),
        ({"allowed_hosts": ["*"]}, "ALLOWED_HOSTS"),
        ({"trusted_proxy_networks": []}, "TRUSTED_PROXY_NETWORKS"),
        ({"allow_private_endpoints": True}, "Development-only"),
    ],
)
def test_production_configuration_rejects_missing_or_unsafe_values(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        production_settings(**overrides)


def test_production_configuration_requires_configured_oidc_when_enabled() -> None:
    with pytest.raises(ValueError, match="OIDC_ISSUER"):
        production_settings(oidc_enabled=True)


def test_production_configuration_validates_optional_credential_features() -> None:
    secret = "not-a-key"
    with pytest.raises(ValueError, match="Credential encryption key configuration") as error:
        production_settings(
            downstream_credentials_enabled=True,
            credential_encryption_keys={"v1": SecretStr(secret)},
            credential_active_key_version="v1",
        )

    assert secret not in str(error.value)


def test_production_configuration_rejects_disabled_feature_configuration() -> None:
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    with pytest.raises(ValueError, match="downstream credentials to be enabled"):
        production_settings(credential_encryption_keys={"v1": SecretStr(key)})
    with pytest.raises(ValueError, match="downstream OAuth to be enabled"):
        production_settings(
            downstream_credentials_enabled=True,
            credential_encryption_keys={"v1": SecretStr(key)},
            credential_active_key_version="v1",
            downstream_oauth_redirect_base_url="https://gateway.example.test",
        )


def test_production_configuration_accepts_disabled_optional_features() -> None:
    settings = production_settings()

    assert settings.downstream_credentials_enabled is False
    assert settings.downstream_oauth_enabled is False


def test_production_configuration_requires_oauth_callback_on_public_origin() -> None:
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    with pytest.raises(ValueError, match="Downstream OAuth redirect"):
        production_settings(
            downstream_credentials_enabled=True,
            downstream_oauth_enabled=True,
            credential_encryption_keys={"v1": SecretStr(key)},
            credential_active_key_version="v1",
            downstream_oauth_redirect_base_url="https://other.example.test",
        )


@pytest.mark.asyncio
async def test_untrusted_forwarded_headers_are_ignored_and_request_id_is_replaced() -> None:
    application = runtime_app(production_settings())
    supplied_id = "upstream-request-123"
    transport = httpx.ASGITransport(app=application, client=("192.168.1.5", 4321))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://gateway.example.test"
    ) as client:
        response = await client.get(
            "/",
            headers={"X-Forwarded-Proto": "https", "X-Request-ID": supplied_id},
        )

    assert response.status_code == 200
    assert response.json()["scheme"] == "http"
    assert response.headers["x-request-id"] != supplied_id
    assert response.json()["state_request_id"] == response.headers["x-request-id"]
    assert response.json()["context_request_id"] == response.headers["x-request-id"]


@pytest.mark.asyncio
async def test_trusted_proxy_can_supply_forwarded_scheme_and_request_id() -> None:
    application = runtime_app(production_settings())
    supplied_id = "upstream-request-123"
    transport = httpx.ASGITransport(app=application, client=("10.1.2.3", 4321))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://gateway.example.test"
    ) as client:
        response = await client.get(
            "/",
            headers={"X-Forwarded-Proto": "https", "X-Request-ID": supplied_id},
        )

    assert response.status_code == 200
    assert response.json()["scheme"] == "https"
    assert response.headers["x-request-id"] == supplied_id


@pytest.mark.asyncio
async def test_invalid_host_is_rejected_before_application_handling() -> None:
    application = runtime_app(production_settings())
    transport = httpx.ASGITransport(app=application, client=("10.1.2.3", 4321))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://attacker.example.test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 400


def test_application_lifespan_disposes_database_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    disposed = False

    async def dispose() -> None:
        nonlocal disposed
        disposed = True

    monkeypatch.setattr(app_module, "dispose_engine", dispose)
    with TestClient(app_module.app):
        pass

    assert disposed is True
