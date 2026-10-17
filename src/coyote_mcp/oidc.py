from __future__ import annotations

import base64
import hashlib
import hmac
import logging
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
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import (
    ExternalIdentityResolutionError,
    _hash_secret,
    authenticate_browser_session,
    csrf_token_valid,
    issue_browser_session,
    resolve_external_identity,
    rotate_csrf_token,
)
from coyote_mcp.db import get_session
from coyote_mcp.discovery import PinnedDestinationTransport
from coyote_mcp.models import OIDCLoginTransaction
from coyote_mcp.security import UntrustedOIDCEndpointError, validate_oidc_endpoint
from coyote_mcp.settings import OIDCProviderConfiguration, Settings

router = APIRouter(prefix="/auth/oidc", tags=["oidc"])
Session = Annotated[AsyncSession, Depends(get_session)]
logger = logging.getLogger(__name__)


class OIDCIdentityValidationError(ValueError):
    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


def _issuer_matches(configured_issuer: str, token_issuer: object) -> bool:
    if configured_issuer == "https://accounts.google.com":
        return token_issuer in {"https://accounts.google.com", "accounts.google.com"}
    return token_issuer == configured_issuer


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


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def _log_state_validation_failure(
    session: AsyncSession, state_hash: str, binding_hash: str, now: datetime
) -> None:
    try:
        transaction = await session.scalar(
            select(OIDCLoginTransaction).where(OIDCLoginTransaction.state_hash == state_hash)
        )
    except SQLAlchemyError as error:
        logger.warning(
            "OIDC state validation failed category=database_lookup exception_class=%s",
            type(error).__name__,
        )
        return
    if transaction is None:
        category = "missing_transaction"
    elif not hmac.compare_digest(transaction.browser_binding_hash, binding_hash):
        category = "binding_hash_mismatch"
    else:
        expires_at = transaction.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            category = "expired_transaction"
        elif transaction.consumed_at is not None:
            category = "already_consumed"
        else:
            category = "transaction_condition_mismatch"
    logger.warning("OIDC state validation failed category=%s", category)


async def _discovery(provider: OIDCProviderConfiguration) -> dict[str, Any]:
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
    provider: OIDCProviderConfiguration,
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
    provider: OIDCProviderConfiguration, discovery: dict[str, Any], id_token: str, nonce: str
) -> dict[str, Any]:
    jwks_uri = discovery.get("jwks_uri")
    if not isinstance(jwks_uri, str):
        raise OIDCIdentityValidationError("jwks_metadata", "OIDC discovery metadata lacks JWKS.")
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
        raise OIDCIdentityValidationError(
            "signature", "OIDC ID token signature is invalid."
        ) from error
    expires_at = payload.get("exp")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, int | float)
        or expires_at <= datetime.now(UTC).timestamp()
    ):
        raise OIDCIdentityValidationError(
            "expiry", "OIDC ID token is expired or missing an expiry."
        )
    not_before = payload.get("nbf")
    if isinstance(not_before, bool) or (
        isinstance(not_before, int | float) and not_before > datetime.now(UTC).timestamp()
    ):
        raise OIDCIdentityValidationError("not_before", "OIDC ID token is not yet valid.")
    audience = payload.get("aud")
    if isinstance(audience, str):
        audiences = {audience}
    elif (
        isinstance(audience, list) and audience and all(isinstance(item, str) for item in audience)
    ):
        audiences = set(audience)
    else:
        raise OIDCIdentityValidationError("audience", "OIDC ID token audience is invalid.")
    if not _issuer_matches(provider.issuer, payload.get("iss")):
        raise OIDCIdentityValidationError("issuer", "OIDC ID token issuer is invalid.")
    if provider.client_id not in audiences:
        raise OIDCIdentityValidationError("audience", "OIDC ID token audience is invalid.")
    if len(audiences) > 1 and payload.get("azp") != provider.client_id:
        raise OIDCIdentityValidationError(
            "authorized_party", "OIDC ID token authorized party is invalid."
        )
    if payload.get("nonce") != nonce:
        raise OIDCIdentityValidationError("nonce", "OIDC ID token nonce is invalid.")
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise OIDCIdentityValidationError("subject", "OIDC ID token subject is invalid.")
    return payload


@router.get("/login")
async def login(request: Request, session: Session) -> RedirectResponse:
    settings = Settings()
    try:
        provider = settings.oidc_provider()
    except ValueError as error:
        raise HTTPException(
            status_code=503,
            detail="OIDC instance configuration is invalid.",
        ) from error
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
        state_hash=_hash_secret(state),
        browser_binding_hash=_hash_secret(browser_binding),
        nonce=nonce,
        pkce_verifier=verifier,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    session.add(transaction)
    try:
        await session.commit()
    except SQLAlchemyError as error:
        logger.warning(
            "OIDC login transaction persistence failed category=database_commit exception_class=%s",
            type(error).__name__,
        )
        raise
    redirect_parts = urlsplit(provider.redirect_uri)
    logger.warning(
        "OIDC login transaction committed callback_scheme=%s callback_host=%s",
        redirect_parts.scheme,
        redirect_parts.netloc,
    )
    query = urlencode(
        {
            "client_id": provider.client_id,
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": provider.redirect_uri,
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
        logger.warning("OIDC state validation failed category=missing_browser_binding_cookie")
        raise HTTPException(status_code=400, detail="OIDC state validation failed.")
    state_hash = _hash_secret(state)
    binding_hash = _hash_secret(binding_secret)
    try:
        result = await session.execute(
            update(OIDCLoginTransaction)
            .where(
                OIDCLoginTransaction.state_hash == state_hash,
                OIDCLoginTransaction.browser_binding_hash == binding_hash,
                OIDCLoginTransaction.consumed_at.is_(None),
                OIDCLoginTransaction.expires_at > now,
            )
            .values(consumed_at=now)
            .returning(
                OIDCLoginTransaction.nonce,
                OIDCLoginTransaction.pkce_verifier,
            )
        )
        transaction = result.one_or_none()
        await session.commit()
    except SQLAlchemyError as error:
        logger.warning(
            "OIDC state validation failed category=database_transaction exception_class=%s",
            type(error).__name__,
        )
        raise
    if transaction is None:
        await _log_state_validation_failure(session, state_hash, binding_hash, now)
        raise HTTPException(status_code=400, detail="OIDC state validation failed.")
    nonce, pkce_verifier = transaction
    try:
        provider = Settings().oidc_provider()
    except ValueError as error:
        raise HTTPException(
            status_code=503, detail="OIDC instance configuration is invalid."
        ) from error
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
        client_secret = provider.client_secret
        token_request = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": provider.redirect_uri,
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
        category = (
            error.category
            if isinstance(error, OIDCIdentityValidationError)
            else (
                error.category
                if isinstance(error, ExternalIdentityResolutionError)
                else "identity_resolution"
            )
        )
        exception = error.__cause__ or error
        logger.warning(
            "OIDC identity validation failed category=%s exception_class=%s",
            category,
            type(exception).__name__,
        )
        raise HTTPException(status_code=401, detail="OIDC identity validation failed.") from error
    existing_session = await authenticate_browser_session(
        session, request.cookies.get(Settings().browser_session_cookie_name, "")
    )
    if existing_session is not None and existing_session.browser_session is not None:
        existing_session.browser_session.revoked_at = datetime.now(UTC)
        await session.commit()
    browser_session, session_token = await issue_browser_session(
        session, principal, [] if incomplete else groups_value, Settings()
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
