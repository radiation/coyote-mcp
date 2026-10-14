import httpx
import pytest

from coyote_mcp.discovery import PinnedDestinationTransport
from coyote_mcp.security import ResolvedEndpoint, UnsafeEndpointError, validate_endpoint
from coyote_mcp.settings import Settings


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
