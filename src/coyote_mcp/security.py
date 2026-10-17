import ipaddress
import socket
from collections.abc import Collection
from dataclasses import dataclass
from urllib.parse import urlparse

from coyote_mcp.settings import Settings


class UnsafeEndpointError(ValueError):
    pass


class UntrustedOIDCEndpointError(UnsafeEndpointError):
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
    if (
        parsed.scheme != "https"
        and not settings.allow_insecure_endpoints
        and parsed.hostname not in settings.allowed_insecure_endpoint_hosts
    ):
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
        if (
            not ip.is_global
            and not settings.allow_private_endpoints
            and parsed.hostname not in settings.allowed_private_endpoint_hosts
        ):
            raise UnsafeEndpointError("Endpoint destination must be publicly routable.")
    return ResolvedEndpoint(
        hostname=parsed.hostname,
        address=resolved_addresses[0],
        port=parsed.port,
    )


def validate_endpoint(endpoint: str, settings: Settings) -> None:
    resolve_endpoint(endpoint, settings)


def validate_oidc_endpoint(
    endpoint: str, issuer: str, trusted_hosts: Collection[str], settings: Settings
) -> ResolvedEndpoint:
    parsed = urlparse(endpoint)
    issuer_parsed = urlparse(issuer)
    if not parsed.hostname or not issuer_parsed.hostname:
        raise UntrustedOIDCEndpointError("OIDC endpoints must use absolute URLs.")
    insecure_local_oidc = settings.is_development and settings.allow_insecure_oidc
    if parsed.scheme != "https" and not insecure_local_oidc:
        raise UntrustedOIDCEndpointError("OIDC endpoints must use HTTPS.")
    if parsed.username or parsed.password:
        raise UntrustedOIDCEndpointError("OIDC endpoints must not include credentials.")
    approved_hosts = {issuer_parsed.hostname, *trusted_hosts}
    if parsed.hostname not in approved_hosts:
        raise UntrustedOIDCEndpointError("OIDC endpoint is outside the provider trust boundary.")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise UntrustedOIDCEndpointError("OIDC endpoint hostname could not be resolved.") from error
    resolved_addresses = {str(item[4][0]) for item in addresses}
    if not resolved_addresses:
        raise UntrustedOIDCEndpointError("OIDC endpoint hostname could not be resolved.")
    for address in resolved_addresses:
        if (
            not (settings.is_development and settings.allow_private_oidc)
            and not ipaddress.ip_address(address).is_global
        ):
            raise UntrustedOIDCEndpointError("OIDC endpoint must resolve to a public address.")
    return ResolvedEndpoint(parsed.hostname, sorted(resolved_addresses)[0], parsed.port)
