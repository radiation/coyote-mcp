from __future__ import annotations

import base64
import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from joserfc import jwk, jwt
from joserfc.errors import JoseError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import (
    _hash_secret,
    authenticate_browser_session,
    csrf_token_valid,
    issue_browser_session,
    resolve_external_identity,
    rotate_csrf_token,
)
from coyote_mcp.db import get_session
from coyote_mcp.discovery import PinnedDestinationTransport
from coyote_mcp.models import IdentityProvider, OIDCLoginTransaction
from coyote_mcp.security import UntrustedOIDCEndpointError, validate_oidc_endpoint
from coyote_mcp.settings import Settings, oidc_client_secret_reference

router = APIRouter(prefix="/auth/oidc", tags=["oidc"])
Session = Annotated[AsyncSession, Depends(get_session)]


def _set_browser_session_cookie(response: RedirectResponse, token: str) -> None:
    settings = Settings()
    response.set_cookie(
        settings.browser_session_cookie_name,
        token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        secure=not settings.is_development,
        samesite="lax",
        path="/",
    )


def _delete_browser_session_cookie(response: Response) -> None:
    response.delete_cookie(Settings().browser_session_cookie_name, path="/")


def _oidc_binding_cookie_name(state: str) -> str:
    return f"{Settings().oidc_binding_cookie_name}_{_hash_secret(state)[:16]}"


def _set_oidc_binding_cookie(response: RedirectResponse, state: str, secret: str) -> None:
    settings = Settings()
    response.set_cookie(
        _oidc_binding_cookie_name(state),
        secret,
        max_age=600,
        httponly=True,
        secure=not settings.is_development,
        samesite="lax",
        path="/",
    )


def _delete_oidc_binding_cookie(response: Response, state: str) -> None:
    response.delete_cookie(_oidc_binding_cookie_name(state), path="/")


def _secret(provider: IdentityProvider) -> str:
    expected_reference = oidc_client_secret_reference(provider.id)
    if provider.client_secret_reference != expected_reference:
        raise ValueError("OIDC client secret binding is not approved.")
    value = os.environ.get(expected_reference.removeprefix("env:"))
    if not value:
        raise ValueError("OIDC client secret reference is not configured.")
    return value


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def _discovery(provider: IdentityProvider) -> dict[str, Any]:
    issuer = provider.issuer
    discovery_endpoint = validate_oidc_endpoint(
        issuer, issuer, provider.trusted_endpoint_hosts, Settings()
    )
    async with httpx.AsyncClient(
        timeout=Settings().oidc_discovery_timeout_seconds,
        follow_redirects=False,
        transport=PinnedDestinationTransport(discovery_endpoint),
        trust_env=False,
    ) as client:
        response = await client.get(
            f"{issuer.rstrip('/')}/.well-known/openid-configuration", follow_redirects=False
        )
    response.raise_for_status()
    document = response.json()
    if not isinstance(document, dict) or document.get("issuer") != issuer:
        raise ValueError("OIDC discovery issuer did not match the configured issuer.")
    for endpoint_name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        metadata_endpoint = document.get(endpoint_name)
        if not isinstance(metadata_endpoint, str):
            raise ValueError(f"OIDC discovery metadata lacks {endpoint_name}.")
        validate_oidc_endpoint(
            metadata_endpoint, issuer, provider.trusted_endpoint_hosts, Settings()
        )
    return document


async def _exchange_code(
    provider: IdentityProvider,
    token_endpoint: str,
    data: dict[str, str],
    basic_auth: tuple[str, str] | None = None,
) -> dict[str, Any]:
    endpoint = validate_oidc_endpoint(
        token_endpoint, provider.issuer, provider.trusted_endpoint_hosts, Settings()
    )
    async with httpx.AsyncClient(
        timeout=Settings().oidc_discovery_timeout_seconds,
        follow_redirects=False,
        transport=PinnedDestinationTransport(endpoint),
        trust_env=False,
    ) as client:
        if basic_auth is None:
            response = await client.post(token_endpoint, data=data)
        else:
            response = await client.post(token_endpoint, data=data, auth=basic_auth)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("OIDC token endpoint returned an invalid response.")
    return payload


async def validate_id_token(
    provider: IdentityProvider, discovery: dict[str, Any], id_token: str, nonce: str
) -> dict[str, Any]:
    jwks_uri = discovery.get("jwks_uri")
    if not isinstance(jwks_uri, str):
        raise ValueError("OIDC discovery metadata lacks JWKS.")
    endpoint = validate_oidc_endpoint(
        jwks_uri, provider.issuer, provider.trusted_endpoint_hosts, Settings()
    )
    async with httpx.AsyncClient(
        timeout=Settings().oidc_discovery_timeout_seconds,
        follow_redirects=False,
        transport=PinnedDestinationTransport(endpoint),
        trust_env=False,
    ) as client:
        response = await client.get(jwks_uri)
    response.raise_for_status()
    try:
        key_set = jwk.KeySet.import_key_set(response.json())
        payload = dict(jwt.decode(id_token, key_set, algorithms=["RS256", "ES256", "PS256"]).claims)
    except (JoseError, TypeError, ValueError) as error:
        raise ValueError("OIDC ID token signature is invalid.") from error
    expires_at = payload.get("exp")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, int | float)
        or expires_at <= datetime.now(UTC).timestamp()
    ):
        raise ValueError("OIDC ID token is expired or missing an expiry.")
    not_before = payload.get("nbf")
    if isinstance(not_before, bool) or (
        isinstance(not_before, int | float) and not_before > datetime.now(UTC).timestamp()
    ):
        raise ValueError("OIDC ID token is not yet valid.")
    audience = payload.get("aud")
    if isinstance(audience, str):
        audiences = {audience}
    elif (
        isinstance(audience, list) and audience and all(isinstance(item, str) for item in audience)
    ):
        audiences = set(audience)
    else:
        raise ValueError("OIDC ID token audience is invalid.")
    if payload.get("iss") != provider.issuer or provider.client_id not in audiences:
        raise ValueError("OIDC ID token issuer or audience is invalid.")
    if len(audiences) > 1 and payload.get("azp") != provider.client_id:
        raise ValueError("OIDC ID token authorized party is invalid.")
    if payload.get("nonce") != nonce:
        raise ValueError("OIDC ID token nonce is invalid.")
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise ValueError("OIDC ID token subject is invalid.")
    return payload


@router.get("/login")
async def login(request: Request, session: Session) -> RedirectResponse:
    providers = list(
        (
            await session.scalars(
                select(IdentityProvider).where(IdentityProvider.enabled.is_(True)).limit(2)
            )
        ).all()
    )
    if len(providers) != 1:
        raise HTTPException(
            status_code=503,
            detail="OIDC instance configuration must contain exactly one enabled provider.",
        )
    provider = providers[0]
    try:
        discovery = await _discovery(provider)
    except (httpx.HTTPError, UntrustedOIDCEndpointError, ValueError) as error:
        raise HTTPException(status_code=502, detail="OIDC provider discovery failed.") from error
    authorization_endpoint = discovery.get("authorization_endpoint")
    if not isinstance(authorization_endpoint, str):
        raise HTTPException(
            status_code=502, detail="OIDC provider is missing an authorization endpoint."
        )
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    browser_binding = secrets.token_urlsafe(32)
    transaction = OIDCLoginTransaction(
        provider_id=provider.id,
        state_hash=_hash_secret(state),
        browser_binding_hash=_hash_secret(browser_binding),
        nonce=nonce,
        pkce_verifier=verifier,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    session.add(transaction)
    await session.commit()
    callback = str(request.url_for("oidc_callback"))
    query = urlencode(
        {
            "client_id": provider.client_id,
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": callback,
            "state": state,
            "nonce": nonce,
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    delimiter = "&" if urlsplit(authorization_endpoint).query else "?"
    response = RedirectResponse(
        f"{authorization_endpoint}{delimiter}{query}", status_code=status.HTTP_302_FOUND
    )
    _set_oidc_binding_cookie(response, state, browser_binding)
    return response


@router.get("/callback", name="oidc_callback")
async def callback(request: Request, code: str, state: str, session: Session) -> RedirectResponse:
    now = datetime.now(UTC)
    binding_secret = request.cookies.get(_oidc_binding_cookie_name(state))
    if binding_secret is None:
        raise HTTPException(status_code=400, detail="OIDC state validation failed.")
    result = await session.execute(
        update(OIDCLoginTransaction)
        .where(
            OIDCLoginTransaction.state_hash == _hash_secret(state),
            OIDCLoginTransaction.browser_binding_hash == _hash_secret(binding_secret),
            OIDCLoginTransaction.consumed_at.is_(None),
            OIDCLoginTransaction.expires_at > now,
        )
        .values(consumed_at=now)
        .returning(
            OIDCLoginTransaction.provider_id,
            OIDCLoginTransaction.nonce,
            OIDCLoginTransaction.pkce_verifier,
        )
    )
    transaction = result.one_or_none()
    await session.commit()
    if transaction is None:
        raise HTTPException(status_code=400, detail="OIDC state validation failed.")
    provider_id, nonce, pkce_verifier = transaction
    provider = await session.get(IdentityProvider, provider_id)
    if provider is None or not provider.enabled:
        raise HTTPException(status_code=403, detail="Identity provider is disabled.")
    try:
        discovery = await _discovery(provider)
    except (httpx.HTTPError, UntrustedOIDCEndpointError, ValueError) as error:
        raise HTTPException(status_code=502, detail="OIDC provider discovery failed.") from error
    token_endpoint = discovery.get("token_endpoint")
    if not isinstance(token_endpoint, str):
        raise HTTPException(status_code=502, detail="OIDC provider is missing a token endpoint.")
    advertised_auth_methods = discovery.get("token_endpoint_auth_methods_supported")
    if advertised_auth_methods is None:
        auth_method = "client_secret_basic"
    elif (
        isinstance(advertised_auth_methods, list)
        and all(isinstance(method, str) for method in advertised_auth_methods)
        and "client_secret_basic" in advertised_auth_methods
    ):
        auth_method = "client_secret_basic"
    elif (
        isinstance(advertised_auth_methods, list)
        and all(isinstance(method, str) for method in advertised_auth_methods)
        and "client_secret_post" in advertised_auth_methods
    ):
        auth_method = "client_secret_post"
    else:
        raise HTTPException(
            status_code=502,
            detail="OIDC provider does not support a configured client authentication method.",
        )
    try:
        client_secret = _secret(provider)
        token_request = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": str(request.url_for("oidc_callback")),
            "code_verifier": pkce_verifier,
        }
        if auth_method == "client_secret_post":
            token_request["client_id"] = provider.client_id
            token_request["client_secret"] = client_secret
        token_response = await _exchange_code(
            provider,
            token_endpoint,
            token_request,
            (provider.client_id, client_secret) if auth_method == "client_secret_basic" else None,
        )
    except (httpx.HTTPError, UntrustedOIDCEndpointError, ValueError) as error:
        raise HTTPException(status_code=502, detail="OIDC token exchange failed.") from error
    id_token = token_response.get("id_token")
    if not isinstance(id_token, str):
        raise HTTPException(status_code=401, detail="OIDC provider did not return an ID token.")
    try:
        claims = await validate_id_token(provider, discovery, id_token, nonce)
        if (
            provider.allowed_organization
            and claims.get("organization") != provider.allowed_organization
        ):
            raise ValueError("OIDC identity does not belong to the configured organization.")
        group_claim = provider.group_claim
        groups_value = claims.get(group_claim) if group_claim else []
        incomplete = claims.get("hasgroups") is True or isinstance(claims.get("_claim_names"), dict)
        if not isinstance(groups_value, list) or not all(
            isinstance(group, str) for group in groups_value
        ):
            groups_value = []
            incomplete = True
        principal = await resolve_external_identity(
            session,
            issuer=provider.issuer,
            subject=claims["sub"],
            email=claims.get("email") if isinstance(claims.get("email"), str) else None,
            display_name=claims.get("name") if isinstance(claims.get("name"), str) else None,
            jit_provisioning_enabled=provider.jit_provisioning_enabled,
        )
    except ValueError as error:
        raise HTTPException(status_code=401, detail="OIDC identity validation failed.") from error
    existing_session = await authenticate_browser_session(
        session, request.cookies.get(Settings().browser_session_cookie_name, "")
    )
    if existing_session is not None and existing_session.browser_session is not None:
        existing_session.browser_session.revoked_at = datetime.now(UTC)
        await session.commit()
    browser_session, session_token = await issue_browser_session(
        session, principal, [] if incomplete else groups_value, provider.id, Settings()
    )
    await rotate_csrf_token(session, browser_session)
    response = RedirectResponse("/console", status_code=status.HTTP_303_SEE_OTHER)
    _set_browser_session_cookie(response, session_token)
    _delete_oidc_binding_cookie(response, state)
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, session: Session) -> Response:
    authenticated = await authenticate_browser_session(
        session, request.cookies.get(Settings().browser_session_cookie_name, "")
    )
    if authenticated is None or authenticated.browser_session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    if not csrf_token_valid(authenticated.browser_session, request.headers.get("x-csrf-token")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed.")
    authenticated.browser_session.revoked_at = datetime.now(UTC)
    await session.commit()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _delete_browser_session_cookie(response)
    return response


@router.get("/csrf")
async def csrf_token(request: Request, session: Session) -> JSONResponse:
    authenticated = await authenticate_browser_session(
        session, request.cookies.get(Settings().browser_session_cookie_name, "")
    )
    if authenticated is None or authenticated.browser_session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    token = await rotate_csrf_token(session, authenticated.browser_session)
    return JSONResponse({"csrf_token": token})
