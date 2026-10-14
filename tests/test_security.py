import httpx
import pytest

from coyote_mcp.discovery import PinnedDestinationTransport
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
        validate_endpoint(endpoint, Settings())


def test_explicit_development_configuration_allows_private_http_endpoint() -> None:
    validate_endpoint(
        "http://127.0.0.1:9000/mcp",
        Settings(allow_insecure_endpoints=True, allow_private_endpoints=True),
    )


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
    with pytest.raises(ValueError, match="SESSION_SECRET_KEY"):
        Settings(environment="production", session_secret_key=DEVELOPMENT_SESSION_SECRET)
    with pytest.raises(ValueError, match="SESSION_SECRET_KEY"):
        Settings(environment="production", session_secret_key="too-short")
    assert Settings(environment="production", session_secret_key="a" * 32).is_development is False


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
