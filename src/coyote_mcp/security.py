import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from coyote_mcp.settings import Settings


class UnsafeEndpointError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedEndpoint:
    hostname: str
    address: str
    port: int | None


def resolve_endpoint(endpoint: str, settings: Settings) -> ResolvedEndpoint:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeEndpointError("Endpoint must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise UnsafeEndpointError("Endpoint URLs must not include credentials.")
    if parsed.scheme != "https" and not settings.allow_insecure_endpoints:
        raise UnsafeEndpointError(
            "Only HTTPS endpoints are allowed outside explicitly configured development."
        )
    try:
        addresses = socket.getaddrinfo(parsed.hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise UnsafeEndpointError("Endpoint hostname could not be resolved.") from error

    resolved_addresses = sorted({str(address[4][0]) for address in addresses})
    if not resolved_addresses:
        raise UnsafeEndpointError("Endpoint hostname could not be resolved.")
    for address in resolved_addresses:
        ip = ipaddress.ip_address(address)
        if not settings.allow_private_endpoints and not ip.is_global:
            raise UnsafeEndpointError("Endpoint destination must be publicly routable.")
    return ResolvedEndpoint(
        hostname=parsed.hostname,
        address=resolved_addresses[0],
        port=parsed.port,
    )


def validate_endpoint(endpoint: str, settings: Settings) -> None:
    resolve_endpoint(endpoint, settings)
