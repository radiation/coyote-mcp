"""Reusable OAuth 2.0 authorization-code client (PKCE) for approved downstream integrations.

Every outbound request is validated with the same destination rules used for MCP
endpoints and is sent through the pinned transport with redirects disabled. The
redirect URI is always derived from administrator configuration, never from request
input. Token material is never included in exception messages or reprs.
"""

import base64
import hashlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

from coyote_mcp.discovery import PinnedDestinationTransport
from coyote_mcp.security import UnsafeEndpointError, resolve_endpoint
from coyote_mcp.settings import Settings

CALLBACK_PATH = "/console/connected-apps/callback"
TRANSACTION_LIFETIME = timedelta(minutes=10)
TOKEN_EXPIRY_SKEW = timedelta(seconds=60)
MAX_IDENTIFIER_LENGTH = 255

GITHUB_PROVIDER = "github"
GENERIC_PROVIDER = "generic"
PROVIDERS = frozenset({GITHUB_PROVIDER, GENERIC_PROVIDER})
ICON_KEYS = frozenset({GITHUB_PROVIDER, GENERIC_PROVIDER})


class OAuthConfigurationError(RuntimeError):
    pass


class OAuthProtocolError(RuntimeError):
    """A provider rejected or returned an invalid response. ``code`` is an OAuth error code."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ProviderPreset:
    authorization_endpoint: str
    token_endpoint: str
    account_endpoint: str | None
    revocation_endpoint: str | None = None


# GitHub OAuth Apps do not publish RFC 8414 metadata and do not offer RFC 7009
# revocation, so their endpoints are configured explicitly.
PROVIDER_PRESETS: dict[str, ProviderPreset] = {
    GITHUB_PROVIDER: ProviderPreset(
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        account_endpoint="https://api.github.com/user",
    ),
}


@dataclass(frozen=True, repr=False)
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_at: datetime | None
    scopes: tuple[str, ...] = field(default_factory=tuple)

    def __repr__(self) -> str:
        return "TokenSet(<redacted>)"

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return self.expires_at - TOKEN_EXPIRY_SKEW <= (now or datetime.now(UTC))


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def generate_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def code_challenge_for(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def hash_state(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def callback_redirect_uri(settings: Settings) -> str:
    base = settings.downstream_oauth_redirect_base_url
    if not base:
        raise OAuthConfigurationError("Downstream OAuth redirect base URL is not configured.")
    parsed = urlparse(base)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise OAuthConfigurationError("Downstream OAuth redirect base URL must be absolute.")
    if parsed.scheme == "http" and not _local_http_redirect_allowed(settings, parsed.hostname):
        raise OAuthConfigurationError(
            "Downstream OAuth redirects must use HTTPS except for explicitly enabled "
            "development loopback callbacks."
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OAuthConfigurationError("Downstream OAuth redirect base URL is malformed.")
    if parsed.path not in {"", "/"}:
        raise OAuthConfigurationError("Downstream OAuth redirect base URL must be an origin.")
    return f"{parsed.scheme}://{parsed.netloc}{CALLBACK_PATH}"


def _local_http_redirect_allowed(settings: Settings, hostname: str) -> bool:
    return (
        settings.is_development
        and settings.allow_insecure_endpoints
        and hostname in {"localhost", "127.0.0.1", "::1"}
    )


def validate_oauth_endpoint(endpoint: str, settings: Settings) -> None:
    parsed = urlparse(endpoint)
    if parsed.query or parsed.fragment:
        raise OAuthConfigurationError("OAuth endpoints must not include query or fragment.")
    try:
        resolve_endpoint(endpoint, settings)
    except UnsafeEndpointError as error:
        raise OAuthConfigurationError(str(error)) from error


def build_authorization_url(
    authorization_endpoint: str,
    *,
    client_id: str,
    redirect_uri: str,
    scopes: tuple[str, ...],
    state: str,
    code_challenge: str,
) -> str:
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{authorization_endpoint}?{query}"


def parse_scopes(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        raw_items = [str(item) for item in value]
    elif isinstance(value, str):
        raw_items = value.replace(",", " ").split()
    else:
        return ()
    return tuple(sorted({item.strip() for item in raw_items if item.strip()}))


def _parse_token_payload(payload: object, now: datetime) -> TokenSet:
    if not isinstance(payload, dict):
        raise OAuthProtocolError("Token response was malformed.")
    if "error" in payload:
        # Some providers return errors with HTTP 200; report only the OAuth error code.
        raise OAuthProtocolError("Token request was rejected.", code=str(payload["error"]))
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise OAuthProtocolError("Token response did not include an access token.")
    refresh_token = payload.get("refresh_token")
    expires_in = payload.get("expires_in")
    expires_at = None
    if isinstance(expires_in, int) and expires_in > 0:
        expires_at = now + timedelta(seconds=expires_in)
    return TokenSet(
        access_token=access_token,
        refresh_token=refresh_token if isinstance(refresh_token, str) and refresh_token else None,
        expires_at=expires_at,
        scopes=parse_scopes(payload.get("scope")),
    )


async def _post_form(
    settings: Settings, endpoint: str, data: Mapping[str, str], failure_message: str
) -> Any:
    validate_oauth_endpoint(endpoint, settings)
    resolved = resolve_endpoint(endpoint, settings)
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=settings.downstream_oauth_timeout_seconds,
        transport=PinnedDestinationTransport(resolved),
        trust_env=False,
    ) as client:
        try:
            response = await client.post(
                endpoint, data=dict(data), headers={"Accept": "application/json"}
            )
        except httpx.HTTPError as error:
            raise OAuthProtocolError(failure_message) from error
    try:
        payload = response.json()
    except ValueError as error:
        raise OAuthProtocolError(failure_message) from error
    if response.status_code >= 400 and not (isinstance(payload, dict) and "error" in payload):
        raise OAuthProtocolError(failure_message)
    return payload


async def exchange_authorization_code(
    settings: Settings,
    *,
    token_endpoint: str,
    client_id: str,
    client_secret: str | None,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> TokenSet:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret
    payload = await _post_form(
        settings, token_endpoint, data, "Authorization code exchange failed."
    )
    return _parse_token_payload(payload, datetime.now(UTC))


async def refresh_tokens(
    settings: Settings,
    *,
    token_endpoint: str,
    client_id: str,
    client_secret: str | None,
    refresh_token: str,
) -> TokenSet:
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    if client_secret:
        data["client_secret"] = client_secret
    payload = await _post_form(settings, token_endpoint, data, "Token refresh failed.")
    return _parse_token_payload(payload, datetime.now(UTC))


async def revoke_token(
    settings: Settings,
    *,
    revocation_endpoint: str,
    client_id: str,
    client_secret: str | None,
    token: str,
) -> None:
    data = {"token": token, "client_id": client_id}
    if client_secret:
        data["client_secret"] = client_secret
    await _post_form(settings, revocation_endpoint, data, "Token revocation failed.")


async def fetch_account_identifier(
    settings: Settings, *, account_endpoint: str, access_token: str
) -> str | None:
    """Return a non-secret account label (for example a GitHub login), or None."""
    validate_oauth_endpoint(account_endpoint, settings)
    resolved = resolve_endpoint(account_endpoint, settings)
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=settings.downstream_oauth_timeout_seconds,
        transport=PinnedDestinationTransport(resolved),
        trust_env=False,
    ) as client:
        try:
            response = await client.get(
                account_endpoint,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
            )
        except httpx.HTTPError:
            return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    for claim in ("login", "preferred_username", "sub"):
        value = payload.get(claim)
        if isinstance(value, str) and value:
            return value[:MAX_IDENTIFIER_LENGTH]
    return None
