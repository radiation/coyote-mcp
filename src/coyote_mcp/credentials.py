"""Downstream credential broker and encrypted credential storage.

The broker runs after Coyote authorization has already succeeded. It selects the one
credential that belongs to the caller's organization, server, and (for per-user
connections) principal, and returns it as request headers. It never falls back to a
different credential when the expected one is missing, expired, or invalid.
"""

import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import AuthenticatedPrincipal
from coyote_mcp.credential_vault import (
    CredentialVaultError,
    SealedValue,
    associated_data,
    open_sealed,
    seal,
)
from coyote_mcp.downstream_errors import DownstreamAuthorizationError
from coyote_mcp.downstream_oauth import (
    OAuthConfigurationError,
    OAuthProtocolError,
    TokenSet,
    refresh_tokens,
)
from coyote_mcp.models import (
    DownstreamConnection,
    DownstreamOAuthIntegration,
    DownstreamSharedCredential,
    MCPServer,
)
from coyote_mcp.settings import Settings

POLICY_NONE = "none"
POLICY_SHARED_BEARER = "shared_bearer"
POLICY_PER_USER_OAUTH = "per_user_oauth"
AUTH_POLICIES = frozenset({POLICY_NONE, POLICY_SHARED_BEARER, POLICY_PER_USER_OAUTH})

CONNECTION_STATUS_CONNECTED = "connected"
CONNECTION_STATUS_REAUTHORIZATION = "reauthorization_required"

CONNECT_MESSAGE = "Connect this app in My Profile > Connected Apps, then retry the request."
REAUTHORIZE_MESSAGE = (
    "The connection to this app is no longer valid. Reconnect it in My Profile > Connected Apps."
)
_REFRESH_REJECTED_CODES = frozenset({"invalid_grant", "invalid_client", "unauthorized_client"})


@dataclass(frozen=True)
class DownstreamAuthorization:
    policy: str
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    connection_id: UUID | None = None
    credential_revision: int | None = None


@asynccontextmanager
async def scoped_session(session: AsyncSession) -> AsyncIterator[AsyncSession]:
    """Open a short-lived session on the same engine.

    Credential reads, refreshes, and downstream HTTP calls must not hold a request
    transaction open, so each step uses its own session.
    """
    if session.bind is None:
        raise RuntimeError("Database session is not bound.")
    async with AsyncSession(bind=session.bind, expire_on_commit=False) as scoped:
        yield scoped


def shared_credential_aad(organization_id: UUID, server_id: UUID) -> bytes:
    return associated_data("shared-credential", organization_id, server_id)


def client_secret_aad(organization_id: UUID, server_id: UUID) -> bytes:
    return associated_data("oauth-client-secret", organization_id, server_id)


def connection_aad(organization_id: UUID, server_id: UUID, principal_id: UUID) -> bytes:
    return associated_data("downstream-connection", organization_id, server_id, principal_id)


def transaction_verifier_aad(organization_id: UUID, server_id: UUID, state_hash: str) -> bytes:
    return associated_data("oauth-verifier", organization_id, server_id, state_hash)


def seal_tokens(
    settings: Settings,
    tokens: TokenSet,
    *,
    organization_id: UUID,
    server_id: UUID,
    principal_id: UUID,
) -> SealedValue:
    payload = {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at.isoformat() if tokens.expires_at else None,
        "scopes": list(tokens.scopes),
    }
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return seal(
        settings,
        plaintext,
        connection_aad(organization_id, server_id, principal_id),
    )


def open_tokens(
    settings: Settings,
    connection: DownstreamConnection,
) -> TokenSet:
    plaintext = open_sealed(
        settings,
        SealedValue(key_version=connection.key_version, sealed=connection.sealed_tokens),
        connection_aad(connection.organization_id, connection.server_id, connection.principal_id),
    )
    payload: dict[str, Any] = json.loads(plaintext)
    expires_at = payload.get("expires_at")
    return TokenSet(
        access_token=str(payload["access_token"]),
        refresh_token=payload.get("refresh_token"),
        expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
        scopes=tuple(payload.get("scopes", ())),
    )


def open_client_secret(settings: Settings, integration: DownstreamOAuthIntegration) -> str | None:
    if integration.client_secret_sealed is None or integration.client_secret_key_version is None:
        return None
    plaintext = open_sealed(
        settings,
        SealedValue(
            key_version=integration.client_secret_key_version,
            sealed=integration.client_secret_sealed,
        ),
        client_secret_aad(integration.organization_id, integration.server_id),
    )
    return plaintext.decode("utf-8")


class DownstreamCredentialBroker:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def authorize(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        server: MCPServer,
    ) -> DownstreamAuthorization:
        """Resolve the downstream credential for an already-authorized Coyote request."""
        if server.organization_id != current.require_organization_id():
            raise DownstreamAuthorizationError("server_unavailable", "Server is not available.")
        if server.auth_policy == POLICY_NONE:
            return DownstreamAuthorization(policy=POLICY_NONE)
        if not self._settings.downstream_credentials_available:
            raise DownstreamAuthorizationError(
                "credential_not_configured", "Downstream credentials are disabled."
            )
        if server.auth_policy == POLICY_SHARED_BEARER:
            return await self._shared_bearer(session, server)
        if server.auth_policy == POLICY_PER_USER_OAUTH:
            if not self._settings.downstream_oauth_available:
                raise DownstreamAuthorizationError(
                    "connection_required", "Downstream OAuth is disabled."
                )
            return await self._per_user_oauth(session, current, server)
        raise DownstreamAuthorizationError(
            "authorization_not_configured", "Server authentication policy is not supported."
        )

    async def record_rejection(
        self,
        session: AsyncSession,
        authorization: DownstreamAuthorization,
        status_code: int,
    ) -> None:
        """Mark a per-user connection for reauthorization after an upstream 401.

        Shared and unauthenticated policies have no per-user state to update. Other
        upstream statuses are reported to the caller without changing stored state.
        """
        if (
            status_code != 401
            or authorization.connection_id is None
            or authorization.credential_revision is None
        ):
            return
        async with scoped_session(session) as db, db.begin():
            await db.execute(
                update(DownstreamConnection)
                .where(
                    DownstreamConnection.id == authorization.connection_id,
                    DownstreamConnection.status == CONNECTION_STATUS_CONNECTED,
                    DownstreamConnection.credential_revision == authorization.credential_revision,
                )
                .values(status=CONNECTION_STATUS_REAUTHORIZATION)
            )

    async def _shared_bearer(
        self, session: AsyncSession, server: MCPServer
    ) -> DownstreamAuthorization:
        async with scoped_session(session) as db:
            stored = await db.scalar(
                select(DownstreamSharedCredential).where(
                    DownstreamSharedCredential.server_id == server.id,
                    DownstreamSharedCredential.organization_id == server.organization_id,
                )
            )
        if stored is None:
            raise DownstreamAuthorizationError(
                "credential_not_configured",
                "The administrator has not configured a service credential for this server.",
            )
        try:
            secret = open_sealed(
                self._settings,
                SealedValue(key_version=stored.key_version, sealed=stored.sealed_value),
                shared_credential_aad(server.organization_id, server.id),
            )
        except CredentialVaultError:
            raise DownstreamAuthorizationError(
                "credential_unavailable", "The stored service credential could not be used."
            ) from None
        return DownstreamAuthorization(
            policy=POLICY_SHARED_BEARER,
            headers={"Authorization": f"Bearer {secret.decode('utf-8')}"},
        )

    async def _per_user_oauth(
        self,
        session: AsyncSession,
        current: AuthenticatedPrincipal,
        server: MCPServer,
    ) -> DownstreamAuthorization:
        # Service principals never inherit a human's downstream identity, and per-user
        # servers never fall back to a shared credential.
        if current.principal.identity_type != "human":
            raise DownstreamAuthorizationError(
                "service_principal_not_permitted",
                "Service principals cannot use per-user connections for this server.",
            )
        organization_id = server.organization_id
        async with scoped_session(session) as db:
            integration = await db.scalar(
                select(DownstreamOAuthIntegration).where(
                    DownstreamOAuthIntegration.server_id == server.id,
                    DownstreamOAuthIntegration.organization_id == organization_id,
                )
            )
        if integration is None or not integration.enabled:
            raise DownstreamAuthorizationError(
                "authorization_not_configured",
                "This app is not available for connection.",
            )

        connection_id, credential_revision, tokens = await self._current_tokens(
            session, server, current.principal.id, integration.revision
        )
        if tokens.is_expired():
            tokens = await self._refresh(session, connection_id, integration)
        return DownstreamAuthorization(
            policy=POLICY_PER_USER_OAUTH,
            headers={"Authorization": f"Bearer {tokens.access_token}"},
            connection_id=connection_id,
            credential_revision=credential_revision,
        )

    async def _current_tokens(
        self,
        session: AsyncSession,
        server: MCPServer,
        principal_id: UUID,
        integration_revision: int,
    ) -> tuple[UUID, int, TokenSet]:
        async with scoped_session(session) as db:
            connection = await db.scalar(
                select(DownstreamConnection).where(
                    DownstreamConnection.organization_id == server.organization_id,
                    DownstreamConnection.server_id == server.id,
                    DownstreamConnection.principal_id == principal_id,
                )
            )
            if connection is None:
                raise DownstreamAuthorizationError("connection_required", CONNECT_MESSAGE)
            if connection.status != CONNECTION_STATUS_CONNECTED:
                raise DownstreamAuthorizationError("connection_required", REAUTHORIZE_MESSAGE)
            if connection.integration_revision != integration_revision:
                raise DownstreamAuthorizationError("connection_required", REAUTHORIZE_MESSAGE)
            connection_id = connection.id
            credential_revision = connection.credential_revision
            tokens = _open_connection_tokens(self._settings, connection)
        if tokens.is_expired() and tokens.refresh_token is None:
            raise DownstreamAuthorizationError(
                "connection_expired",
                "The connection to this app has expired. Reconnect it in My Profile > "
                "Connected Apps.",
            )
        return connection_id, credential_revision, tokens

    async def _refresh(
        self,
        session: AsyncSession,
        connection_id: UUID,
        integration: DownstreamOAuthIntegration,
    ) -> TokenSet:
        """Refresh under a row lock so concurrent requests cannot rotate the same token twice.

        The lock is held across the token request, which serializes refreshes for one
        connection. The transaction commits the reauthorization status before the error
        is raised, so a rejected refresh token is not retried on every request.
        """
        now = datetime.now(UTC)
        async with scoped_session(session) as db, db.begin():
            connection = await db.scalar(
                select(DownstreamConnection)
                .where(DownstreamConnection.id == connection_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if connection is None or connection.status != CONNECTION_STATUS_CONNECTED:
                raise DownstreamAuthorizationError("connection_required", CONNECT_MESSAGE)
            tokens = _open_connection_tokens(self._settings, connection)
            if not tokens.is_expired(now):
                return tokens
            if tokens.refresh_token is None:
                raise DownstreamAuthorizationError(
                    "connection_expired", "The connection to this app has expired."
                )
            try:
                client_secret = open_client_secret(self._settings, integration)
                refreshed = await refresh_tokens(
                    self._settings,
                    token_endpoint=integration.token_endpoint,
                    client_id=integration.client_id,
                    client_secret=client_secret,
                    refresh_token=tokens.refresh_token,
                )
            except OAuthProtocolError as error:
                if error.code not in _REFRESH_REJECTED_CODES:
                    raise DownstreamAuthorizationError(
                        "token_refresh_failed",
                        "The connection could not be refreshed. Try again later.",
                    ) from None
                connection.status = CONNECTION_STATUS_REAUTHORIZATION
            except OAuthConfigurationError, CredentialVaultError:
                raise DownstreamAuthorizationError(
                    "token_refresh_failed",
                    "The connection could not be refreshed. Try again later.",
                ) from None
            else:
                rotated = TokenSet(
                    access_token=refreshed.access_token,
                    refresh_token=refreshed.refresh_token or tokens.refresh_token,
                    expires_at=refreshed.expires_at,
                    scopes=refreshed.scopes or tokens.scopes,
                )
                sealed = seal_tokens(
                    self._settings,
                    rotated,
                    organization_id=connection.organization_id,
                    server_id=connection.server_id,
                    principal_id=connection.principal_id,
                )
                connection.key_version = sealed.key_version
                connection.sealed_tokens = sealed.sealed
                connection.access_token_expires_at = rotated.expires_at
                connection.scopes = list(rotated.scopes)
                connection.last_refreshed_at = now
                return rotated
        raise DownstreamAuthorizationError("connection_required", REAUTHORIZE_MESSAGE)


def _open_connection_tokens(settings: Settings, connection: DownstreamConnection) -> TokenSet:
    try:
        return open_tokens(settings, connection)
    except CredentialVaultError, ValueError, KeyError:
        raise DownstreamAuthorizationError(
            "credential_unavailable", "The stored connection could not be used."
        ) from None
