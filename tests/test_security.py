import os
from unittest.mock import patch

import httpx
import httpx2
import pytest

from coyote_mcp.discovery import PinnedDestinationTransport, PinnedMCPDestinationTransport
from coyote_mcp.security import (
    ResolvedEndpoint,
    UnsafeEndpointError,
    UntrustedOIDCEndpointError,
    validate_endpoint,
    validate_oidc_endpoint,
)
from coyote_mcp.settings import DEVELOPMENT_SESSION_SECRET, Settings


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.com/mcp",
        "https://127.0.0.1/mcp",
        "https://user:password@example.com/mcp",
        "file:///tmp/mcp",
    ],
)
def test_unsafe_endpoint_is_rejected(endpoint: str) -> None:
    with pytest.raises(UnsafeEndpointError):
        validate_endpoint(endpoint, Settings(allow_insecure_endpoints=False))


def test_explicit_development_configuration_allows_private_http_endpoint() -> None:
    validate_endpoint(
        "http://127.0.0.1:9000/mcp",
        Settings(allow_insecure_endpoints=True, allow_private_endpoints=True),
    )


def test_explicit_host_allowlists_allow_only_the_configured_local_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "coyote_mcp.security.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("172.18.0.5", 0))],
    )
    settings = Settings(
        allowed_insecure_endpoint_hosts=["smoke-mcp"],
        allowed_private_endpoint_hosts=["smoke-mcp"],
    )

    validate_endpoint("http://smoke-mcp:8001/mcp", settings)
    with pytest.raises(UnsafeEndpointError):
        validate_endpoint("https://other-private-host:8001/mcp", settings)
    with pytest.raises(UnsafeEndpointError):
        validate_endpoint("http://other-private-host:8001/mcp", settings)


def test_oidc_endpoint_requires_https_and_provider_trust_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "coyote_mcp.security.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 0))],
    )
    validate_oidc_endpoint(
        "https://issuer.example/keys",
        "https://issuer.example",
        [],
        Settings(),
    )
    with pytest.raises(UntrustedOIDCEndpointError, match="HTTPS"):
        validate_oidc_endpoint(
            "http://issuer.example/keys",
            "https://issuer.example",
            [],
            Settings(),
        )
    with pytest.raises(UntrustedOIDCEndpointError, match="trust boundary"):
        validate_oidc_endpoint(
            "https://attacker.example/keys",
            "https://issuer.example",
            [],
            Settings(),
        )


def test_production_requires_strong_external_session_secret() -> None:
    def settings(session_secret_key: str) -> Settings:
        with patch.dict(os.environ, {}, clear=True):
            return Settings(
                _env_file=None,
                environment="production",
                database_url="postgresql+asyncpg://coyote:password@postgres.example/coyote_mcp",
                public_base_url="https://gateway.example",
                allowed_hosts=["gateway.example"],
                trusted_proxy_networks=["10.0.0.0/8"],
                oidc_enabled=False,
                downstream_credentials_enabled=False,
                downstream_oauth_enabled=False,
                session_secret_key=session_secret_key,
            )

    with pytest.raises(ValueError, match="SESSION_SECRET_KEY"):
        settings(DEVELOPMENT_SESSION_SECRET)
    with pytest.raises(ValueError, match="SESSION_SECRET_KEY"):
        settings("too-short")
    assert settings("a" * 32).is_development is False


@pytest.mark.asyncio
async def test_pinned_transport_uses_resolved_ip_and_preserves_tls_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, httpx.Request] = {}

    async def capture_request(
        transport: httpx.AsyncHTTPTransport, request: httpx.Request
    ) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, request=request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", capture_request)
    transport = PinnedDestinationTransport(
        ResolvedEndpoint(hostname="public.example", address="198.51.100.10", port=None)
    )

    await transport.handle_async_request(httpx.Request("GET", "https://public.example/mcp"))

    request = captured["request"]
    assert request.url.host == "198.51.100.10"
    assert request.headers["host"] == "public.example"
    assert request.extensions["sni_hostname"] == "public.example"


@pytest.mark.asyncio
async def test_pinned_transport_rejects_unexpected_destination() -> None:
    transport = PinnedDestinationTransport(
        ResolvedEndpoint(hostname="public.example", address="198.51.100.10", port=None)
    )

    with pytest.raises(UnsafeEndpointError):
        await transport.handle_async_request(httpx.Request("GET", "https://other.example/mcp"))


@pytest.mark.asyncio
async def test_pinned_transport_rejects_unexpected_port() -> None:
    transport = PinnedDestinationTransport(
        ResolvedEndpoint(hostname="public.example", address="198.51.100.10", port=8443)
    )

    with pytest.raises(UnsafeEndpointError):
        await transport.handle_async_request(httpx.Request("GET", "https://public.example/mcp"))


@pytest.mark.asyncio
async def test_pinned_mcp_transport_uses_resolved_ip_and_preserves_tls_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, httpx2.Request] = {}

    async def capture_request(
        transport: httpx2.AsyncHTTPTransport, request: httpx2.Request
    ) -> httpx2.Response:
        captured["request"] = request
        return httpx2.Response(200, request=request)

    monkeypatch.setattr(httpx2.AsyncHTTPTransport, "handle_async_request", capture_request)
    transport = PinnedMCPDestinationTransport(
        ResolvedEndpoint(hostname="public.example", address="198.51.100.10", port=8443)
    )

    await transport.handle_async_request(httpx2.Request("GET", "https://public.example:8443/mcp"))

    request = captured["request"]
    assert request.url.host == "198.51.100.10"
    assert request.headers["host"] == "public.example:8443"
    assert request.extensions["sni_hostname"] == "public.example"


@pytest.mark.asyncio
async def test_pinned_mcp_transport_rejects_unexpected_destination() -> None:
    transport = PinnedMCPDestinationTransport(
        ResolvedEndpoint(hostname="public.example", address="198.51.100.10", port=None)
    )

    with pytest.raises(UnsafeEndpointError):
        await transport.handle_async_request(httpx2.Request("GET", "https://other.example/mcp"))


@pytest.mark.asyncio
async def test_pinned_mcp_transport_rejects_unexpected_port() -> None:
    transport = PinnedMCPDestinationTransport(
        ResolvedEndpoint(hostname="public.example", address="198.51.100.10", port=8443)
    )

    with pytest.raises(UnsafeEndpointError):
        await transport.handle_async_request(httpx2.Request("GET", "https://public.example/mcp"))
