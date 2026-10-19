"""Downstream authentication administration and self-service Connected Apps.

Every operation is organization-scoped and authorized in this module, so the
HTTP console cannot bypass it. Secrets are accepted as write-only input and are
never returned by any function here.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.audit import AuditAction, AuditTargetType, record_principal_audit_event
from coyote_mcp.auth import AuthenticatedPrincipal, authorize, self_service_action_allowed
from coyote_mcp.catalog import AuthorizationError, MissingResourceError, get_server
from coyote_mcp.credential_vault import CredentialVaultError, SealedValue, open_sealed, seal
from coyote_mcp.credentials import (
    AUTH_POLICIES,
    CONNECTION_STATUS_CONNECTED,
    CONNECTION_STATUS_REAUTHORIZATION,
    POLICY_PER_USER_OAUTH,
    client_secret_aad,
    open_client_secret,
    open_tokens,
    seal_tokens,
    shared_credential_aad,
    transaction_verifier_aad,
)
from coyote_mcp.downstream_oauth import (
    GITHUB_PROVIDER,
    PROVIDER_PRESETS,
    PROVIDERS,
    TRANSACTION_LIFETIME,
    OAuthConfigurationError,
    OAuthProtocolError,
    TokenSet,
    build_authorization_url,
    callback_redirect_uri,
    code_challenge_for,
    exchange_authorization_code,
    fetch_account_identifier,
    generate_code_verifier,
    generate_state,
    hash_state,
    revoke_token,
    validate_oauth_endpoint,
)
from coyote_mcp.models import (
    DownstreamConnection,
    DownstreamOAuthIntegration,
    DownstreamOAuthTransaction,
    DownstreamSharedCredential,
    MCPServer,
)
from coyote_mcp.security import UnsafeEndpointError
from coyote_mcp.settings import Settings

CONNECTED_APP_ACTION = "connection:manage_own"

STATE_AVAILABLE = "available"
STATE_CONNECTED = "connected"
STATE_EXPIRED = "expired"
STATE_AUTHORIZATION_REQUIRED = "authorization_required"
STATE_DISABLED = "disabled"

MAX_SCOPES = 32
MAX_SCOPE_LENGTH = 100
MAX_CLIENT_ID_LENGTH = 255
MAX_CLIENT_SECRET_LENGTH = 1024
MAX_ENDPOINT_LENGTH = 2048
MAX_SHARED_CREDENTIAL_LENGTH = 4096
_SCOPE_PATTERN = re.compile(r"[A-Za-z0-9_.:/\-]{1,100}")
INVALID_CALLBACK_MESSAGE = (
    "This authorization request is invalid or has expired. Start the connection again."
)


class ConnectedAppError(ValueError):
    """A user-facing failure. The message never contains secrets or provider payloads."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class ConnectedAppView:
    server_id: UUID
    server_name: str
    provider: str | None
    state: str
    has_connection: bool
    account_identifier: str | None
    scopes: tuple[str, ...]
    expires_at: datetime | None


@dataclass(frozen=True)
class IntegrationView:
    provider: str
    client_id: str
    has_client_secret: bool
    scopes: tuple[str, ...]
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str | None
    account_endpoint: str | None
    enabled: bool
    configuration_error: str | None


@dataclass(frozen=True)
class ServerAuthenticationView:
    server_id: UUID
    server_name: str
    auth_policy: str
    shared_credential_configured: bool
    shared_credential_updated_at: datetime | None
    integration: IntegrationView | None
    connected_count: int
    reauthorization_required_count: int


@dataclass(frozen=True)
class IntegrationInput:
    provider: str
    client_id: str
    # Blank keeps the stored secret. The value is write-only.
    client_secret: str | None = field(repr=False)
    scopes: str
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str
    account_endpoint: str
    enabled: bool


@dataclass(frozen=True)
class DisconnectResult:
    removed: bool
    revocation_supported: bool
    provider_revoked: bool


def _as_utc(value: datetime | None) -> datetime | None:
    # SQLite returns naive datetimes; treat them as UTC like the rest of the codebase.
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _parse_scopes_text(text: str) -> tuple[str, ...]:
    scopes: list[str] = []
    for token in re.split(r"[\s,]+", text.strip()):
        if not token:
            continue
        if not _SCOPE_PATTERN.fullmatch(token):
            raise ConnectedAppError(
                "invalid_scope",
                "Scopes may contain only letters, digits, and the characters : _ . / -.",
            )
        if token not in scopes:
            scopes.append(token)
    if len(scopes) > MAX_SCOPES:
        raise ConnectedAppError("invalid_scope", f"No more than {MAX_SCOPES} scopes are allowed.")
    return tuple(scopes)


def _validated_endpoint(settings: Settings, value: str, *, required: bool, label: str) -> str:
    endpoint = value.strip()
    if not endpoint:
        if required:
            raise ConnectedAppError("invalid_endpoint", f"{label} is required.")
        return ""
    if len(endpoint) > MAX_ENDPOINT_LENGTH:
        raise ConnectedAppError("invalid_endpoint", f"{label} is too long.")
    try:
        validate_oauth_endpoint(endpoint, settings)
    except OAuthConfigurationError as error:
        raise ConnectedAppError("invalid_endpoint", f"{label}: {error}") from error
    return endpoint


def _integration_problems(settings: Settings, integration: DownstreamOAuthIntegration) -> list[str]:
    problems: list[str] = []
    if not integration.client_id:
        problems.append("Client ID is required.")
    if integration.client_secret_sealed is None:
        problems.append("Client secret is required.")
    try:
        callback_redirect_uri(settings)
    except OAuthConfigurationError as error:
        problems.append(str(error))
    return problems


def _integration_view(integration: DownstreamOAuthIntegration) -> IntegrationView:
    return IntegrationView(
        provider=integration.provider,
        client_id=integration.client_id,
        has_client_secret=integration.client_secret_sealed is not None,
        scopes=tuple(integration.scopes or []),
        authorization_endpoint=integration.authorization_endpoint,
        token_endpoint=integration.token_endpoint,
        revocation_endpoint=integration.revocation_endpoint,
        account_endpoint=integration.account_endpoint,
        enabled=integration.enabled,
        configuration_error=integration.configuration_error,
    )


async def _authorized_server_actions(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID, *actions: str
) -> MCPServer:
    server = await get_server(session, current.require_organization_id(), server_id)
    for action in actions:
        if action not in current.scopes:
            raise AuthorizationError("Insufficient permissions.")
        decision = await authorize(
            session,
            current.principal,
            action,
            server,
            verified_group_ids=current.verified_group_ids,
            credential_context=current.credential_context,
        )
        if not decision.allowed:
            raise AuthorizationError("Insufficient permissions.")
    return server


async def _authorized_server(
    session: AsyncSession, current: AuthenticatedPrincipal, action: str, server_id: UUID
) -> MCPServer:
    return await _authorized_server_actions(session, current, server_id, action)


async def _authorized_member(session: AsyncSession, current: AuthenticatedPrincipal) -> UUID:
    """Authorize a human member to manage their own connections in the active organization.

    Enabled members need a direct or verified-group role grant. Browser-session
    instance administrators may also manage only their own connections.
    """
    organization_id = current.require_organization_id()
    if current.principal.identity_type != "human" or CONNECTED_APP_ACTION not in current.scopes:
        raise AuthorizationError("Insufficient permissions.")
    if not await self_service_action_allowed(
        session,
        current.principal,
        organization_id,
        CONNECTED_APP_ACTION,
        current.verified_group_ids,
        current.credential_context,
    ):
        raise AuthorizationError("Insufficient permissions.")
    return organization_id


async def _integration_for(
    session: AsyncSession, organization_id: UUID, server_id: UUID
) -> DownstreamOAuthIntegration | None:
    return await session.scalar(
        select(DownstreamOAuthIntegration).where(
            DownstreamOAuthIntegration.organization_id == organization_id,
            DownstreamOAuthIntegration.server_id == server_id,
        )
    )


async def set_auth_policy(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID, policy: str
) -> MCPServer:
    if policy not in AUTH_POLICIES:
        raise ConnectedAppError("invalid_policy", "Unsupported authentication policy.")
    server = await _authorized_server_actions(
        session, current, server_id, "server:update", "credential:create"
    )
    if server.auth_policy != policy:
        server.auth_policy = policy
        await record_principal_audit_event(
            session,
            organization_id=server.organization_id,
            actor=current.principal,
            action=AuditAction.POLICY_UPDATED,
            target_type=AuditTargetType.SERVER,
            target_id=server.id,
            metadata={"changed_fields": "auth_policy"},
        )
    await session.commit()
    return server


async def get_server_authentication(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID
) -> ServerAuthenticationView:
    server = await _authorized_server(session, current, "server:read", server_id)
    organization_id = server.organization_id
    credential = await session.scalar(
        select(DownstreamSharedCredential).where(
            DownstreamSharedCredential.organization_id == organization_id,
            DownstreamSharedCredential.server_id == server_id,
        )
    )
    integration = await _integration_for(session, organization_id, server_id)
    rows = (
        await session.execute(
            select(DownstreamConnection.status, func.count())
            .where(
                DownstreamConnection.organization_id == organization_id,
                DownstreamConnection.server_id == server_id,
            )
            .group_by(DownstreamConnection.status)
        )
    ).all()
    counts = {status: count for status, count in rows}
    return ServerAuthenticationView(
        server_id=server.id,
        server_name=server.name,
        auth_policy=server.auth_policy,
        shared_credential_configured=credential is not None,
        shared_credential_updated_at=credential.updated_at if credential else None,
        integration=_integration_view(integration) if integration else None,
        connected_count=counts.get(CONNECTION_STATUS_CONNECTED, 0),
        reauthorization_required_count=counts.get(CONNECTION_STATUS_REAUTHORIZATION, 0),
    )


async def save_integration(
    session: AsyncSession,
    settings: Settings,
    current: AuthenticatedPrincipal,
    server_id: UUID,
    data: IntegrationInput,
) -> IntegrationView:
    server = await _authorized_server_actions(
        session, current, server_id, "server:update", "credential:create"
    )
    organization_id = server.organization_id
    provider = data.provider.strip().lower()
    if provider not in PROVIDERS:
        raise ConnectedAppError("invalid_provider", "Unsupported provider.")
    client_id = data.client_id.strip()
    if (
        not client_id
        or len(client_id) > MAX_CLIENT_ID_LENGTH
        or any(c.isspace() for c in client_id)
    ):
        raise ConnectedAppError(
            "invalid_client_id", "Client ID is required and must not contain whitespace."
        )
    scopes = _parse_scopes_text(data.scopes)

    if provider == GITHUB_PROVIDER:
        # GitHub's endpoints are fixed; any endpoint fields submitted for it are ignored.
        preset = PROVIDER_PRESETS[GITHUB_PROVIDER]
        authorization_endpoint = preset.authorization_endpoint
        token_endpoint = preset.token_endpoint
        revocation_endpoint = preset.revocation_endpoint or ""
        account_endpoint = preset.account_endpoint or ""
    else:
        authorization_endpoint = _validated_endpoint(
            settings, data.authorization_endpoint, required=True, label="Authorization endpoint"
        )
        token_endpoint = _validated_endpoint(
            settings, data.token_endpoint, required=True, label="Token endpoint"
        )
        revocation_endpoint = _validated_endpoint(
            settings, data.revocation_endpoint, required=False, label="Revocation endpoint"
        )
        account_endpoint = _validated_endpoint(
            settings, data.account_endpoint, required=False, label="Account endpoint"
        )

    integration = await _integration_for(session, organization_id, server_id)
    is_new = integration is None
    if integration is None:
        integration = DownstreamOAuthIntegration(
            organization_id=organization_id, server_id=server_id
        )
    previous = (
        integration.provider,
        integration.client_id,
        integration.authorization_endpoint,
        integration.token_endpoint,
        integration.revocation_endpoint,
        integration.account_endpoint,
        tuple(integration.scopes or []),
    )

    secret = data.client_secret or ""
    if secret:
        if len(secret) > MAX_CLIENT_SECRET_LENGTH or secret != secret.strip():
            raise ConnectedAppError("invalid_client_secret", "The client secret is not valid.")
        try:
            sealed = seal(
                settings, secret.encode("utf-8"), client_secret_aad(organization_id, server_id)
            )
        except CredentialVaultError as error:
            raise ConnectedAppError(
                "encryption_unavailable", "Credential encryption is not configured."
            ) from error
        integration.client_secret_key_version = sealed.key_version
        integration.client_secret_sealed = sealed.sealed

    integration.provider = provider
    integration.icon_key = provider
    integration.client_id = client_id
    integration.authorization_endpoint = authorization_endpoint
    integration.token_endpoint = token_endpoint
    integration.revocation_endpoint = revocation_endpoint or None
    integration.account_endpoint = account_endpoint or None
    integration.scopes = list(scopes)
    replacement = previous != (
        integration.provider,
        integration.client_id,
        integration.authorization_endpoint,
        integration.token_endpoint,
        integration.revocation_endpoint,
        integration.account_endpoint,
        tuple(integration.scopes or []),
    ) or bool(secret)
    if not is_new and replacement:
        integration.revision += 1
        await session.execute(
            delete(DownstreamOAuthTransaction).where(
                DownstreamOAuthTransaction.organization_id == organization_id,
                DownstreamOAuthTransaction.server_id == server_id,
                DownstreamOAuthTransaction.consumed_at.is_(None),
            )
        )
        await session.execute(
            update(DownstreamConnection)
            .where(
                DownstreamConnection.organization_id == organization_id,
                DownstreamConnection.server_id == server_id,
            )
            .values(status=CONNECTION_STATUS_REAUTHORIZATION)
        )

    problems = _integration_problems(settings, integration)
    if data.enabled and problems:
        raise ConnectedAppError("configuration_incomplete", "; ".join(problems))
    enabled_changed = integration.enabled != data.enabled
    integration.enabled = data.enabled
    integration.configuration_error = "; ".join(problems)[:255] or None

    if is_new:
        session.add(integration)
    if is_new or replacement or enabled_changed:
        await record_principal_audit_event(
            session,
            organization_id=organization_id,
            actor=current.principal,
            action=AuditAction.POLICY_UPDATED,
            target_type=AuditTargetType.SERVER,
            target_id=server.id,
            metadata={"changed_fields": "oauth_integration"},
        )
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise ConnectedAppError(
            "conflict", "This integration was changed by someone else. Reload and try again."
        ) from error
    return _integration_view(integration)


async def set_integration_enabled(
    session: AsyncSession,
    settings: Settings,
    current: AuthenticatedPrincipal,
    server_id: UUID,
    enabled: bool,
) -> IntegrationView:
    server = await _authorized_server_actions(
        session, current, server_id, "server:update", "credential:create"
    )
    integration = await _integration_for(session, server.organization_id, server_id)
    if integration is None:
        raise MissingResourceError("This server has no OAuth integration configured.")
    problems = _integration_problems(settings, integration)
    if enabled and problems:
        raise ConnectedAppError("configuration_incomplete", "; ".join(problems))
    changed = integration.enabled != enabled
    integration.enabled = enabled
    integration.configuration_error = "; ".join(problems)[:255] or None
    if changed:
        await record_principal_audit_event(
            session,
            organization_id=server.organization_id,
            actor=current.principal,
            action=AuditAction.POLICY_UPDATED,
            target_type=AuditTargetType.SERVER,
            target_id=server.id,
            metadata={"changed_fields": "oauth_integration_enabled"},
        )
    await session.commit()
    return _integration_view(integration)


async def set_shared_credential(
    session: AsyncSession,
    settings: Settings,
    current: AuthenticatedPrincipal,
    server_id: UUID,
    value: str,
) -> None:
    server = await _authorized_server_actions(
        session, current, server_id, "server:update", "credential:create"
    )
    if (
        not value
        or len(value) > MAX_SHARED_CREDENTIAL_LENGTH
        or any(character.isspace() for character in value)
    ):
        raise ConnectedAppError(
            "invalid_credential", "Enter a single credential value without whitespace."
        )
    organization_id = server.organization_id
    try:
        sealed = seal(
            settings, value.encode("utf-8"), shared_credential_aad(organization_id, server_id)
        )
    except CredentialVaultError as error:
        raise ConnectedAppError(
            "encryption_unavailable", "Credential encryption is not configured."
        ) from error
    credential = await session.scalar(
        select(DownstreamSharedCredential).where(
            DownstreamSharedCredential.organization_id == organization_id,
            DownstreamSharedCredential.server_id == server_id,
        )
    )
    if credential is None:
        session.add(
            DownstreamSharedCredential(
                organization_id=organization_id,
                server_id=server_id,
                key_version=sealed.key_version,
                sealed_value=sealed.sealed,
            )
        )
    else:
        credential.key_version = sealed.key_version
        credential.sealed_value = sealed.sealed
    await record_principal_audit_event(
        session,
        organization_id=organization_id,
        actor=current.principal,
        action=AuditAction.CREDENTIAL_CREATED,
        target_type=AuditTargetType.CREDENTIAL,
        target_id=server.id,
        metadata={"credential_kind": "shared_bearer", "key_version": sealed.key_version},
    )
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise ConnectedAppError(
            "conflict", "The credential changed. Reload and try again."
        ) from error


async def clear_shared_credential(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID
) -> None:
    server = await _authorized_server_actions(
        session, current, server_id, "server:update", "credential:revoke"
    )
    credential = await session.scalar(
        select(DownstreamSharedCredential).where(
            DownstreamSharedCredential.organization_id == server.organization_id,
            DownstreamSharedCredential.server_id == server.id,
        )
    )
    if credential is not None:
        await session.delete(credential)
        await record_principal_audit_event(
            session,
            organization_id=server.organization_id,
            actor=current.principal,
            action=AuditAction.CREDENTIAL_REVOKED,
            target_type=AuditTargetType.CREDENTIAL,
            target_id=server.id,
            metadata={"credential_kind": "shared_bearer"},
        )
    await session.commit()


def _connection_state(
    server: MCPServer,
    integration: DownstreamOAuthIntegration | None,
    connection: DownstreamConnection | None,
    now: datetime,
) -> str:
    if not server.enabled or integration is None or not integration.enabled:
        return STATE_DISABLED
    if connection is None:
        return STATE_AVAILABLE
    if connection.status == CONNECTION_STATUS_REAUTHORIZATION:
        return STATE_AUTHORIZATION_REQUIRED
    expires_at = _as_utc(connection.access_token_expires_at)
    if expires_at is not None and expires_at <= now:
        return STATE_EXPIRED
    return STATE_CONNECTED


async def list_connected_apps(
    session: AsyncSession, current: AuthenticatedPrincipal
) -> list[ConnectedAppView]:
    """List per-user OAuth apps in the active organization with the caller's connection state.

    Listing reflects administrator approval and the caller's own connection only. It does
    not grant tool access; execution re-checks authorization on every call.
    """
    organization_id = await _authorized_member(session, current)
    now = datetime.now(UTC)
    servers = (
        await session.scalars(
            select(MCPServer)
            .where(
                MCPServer.organization_id == organization_id,
                MCPServer.auth_policy == POLICY_PER_USER_OAUTH,
            )
            .order_by(MCPServer.name)
        )
    ).all()
    integrations = {
        integration.server_id: integration
        for integration in (
            await session.scalars(
                select(DownstreamOAuthIntegration).where(
                    DownstreamOAuthIntegration.organization_id == organization_id
                )
            )
        ).all()
    }
    connections = {
        connection.server_id: connection
        for connection in (
            await session.scalars(
                select(DownstreamConnection).where(
                    DownstreamConnection.organization_id == organization_id,
                    DownstreamConnection.principal_id == current.principal.id,
                )
            )
        ).all()
    }
    views: list[ConnectedAppView] = []
    for server in servers:
        integration = integrations.get(server.id)
        connection = connections.get(server.id)
        views.append(
            ConnectedAppView(
                server_id=server.id,
                server_name=server.name,
                provider=integration.provider if integration else None,
                state=_connection_state(server, integration, connection, now),
                has_connection=connection is not None,
                account_identifier=connection.account_identifier if connection else None,
                scopes=tuple(connection.scopes or []) if connection else (),
                expires_at=_as_utc(connection.access_token_expires_at) if connection else None,
            )
        )
    return views


async def start_connection(
    session: AsyncSession,
    settings: Settings,
    current: AuthenticatedPrincipal,
    server_id: UUID,
) -> str:
    """Create a single-use OAuth transaction and return the provider authorization URL."""
    organization_id = await _authorized_member(session, current)
    browser = current.browser_session
    if browser is None or current.credential_context != "browser_session":
        raise ConnectedAppError(
            "browser_session_required", "Connections can only be started from a browser session."
        )
    if not settings.downstream_oauth_available:
        raise ConnectedAppError("not_available", "Downstream OAuth is disabled.")
    server = await get_server(session, organization_id, server_id)
    integration = await _integration_for(session, organization_id, server_id)
    if (
        not server.enabled
        or server.auth_policy != POLICY_PER_USER_OAUTH
        or integration is None
        or not integration.enabled
    ):
        raise ConnectedAppError("not_available", "This app is not available for connection.")
    problems = _integration_problems(settings, integration)
    if problems:
        raise ConnectedAppError("configuration_error", "; ".join(problems))
    try:
        redirect_uri = callback_redirect_uri(settings)
    except OAuthConfigurationError as error:
        raise ConnectedAppError("configuration_error", str(error)) from error

    state = generate_state()
    verifier = generate_code_verifier()
    state_hash = hash_state(state)
    now = datetime.now(UTC)
    try:
        sealed = seal(
            settings,
            verifier.encode("ascii"),
            transaction_verifier_aad(organization_id, server_id, state_hash),
        )
    except CredentialVaultError as error:
        raise ConnectedAppError(
            "encryption_unavailable", "Credential encryption is not configured."
        ) from error
    await session.execute(
        delete(DownstreamOAuthTransaction).where(
            DownstreamOAuthTransaction.principal_id == current.principal.id,
            DownstreamOAuthTransaction.expires_at <= now,
        )
    )
    session.add(
        DownstreamOAuthTransaction(
            state_hash=state_hash,
            browser_session_id=browser.id,
            principal_id=current.principal.id,
            organization_id=organization_id,
            server_id=server_id,
            integration_revision=integration.revision,
            key_version=sealed.key_version,
            sealed_verifier=sealed.sealed,
            expires_at=now + TRANSACTION_LIFETIME,
        )
    )
    await record_principal_audit_event(
        session,
        organization_id=organization_id,
        actor=current.principal,
        action=AuditAction.CONNECTION_STARTED,
        target_type=AuditTargetType.CONNECTION,
        target_id=None,
        metadata={"provider": integration.provider},
    )
    await session.commit()
    return build_authorization_url(
        integration.authorization_endpoint,
        client_id=integration.client_id,
        redirect_uri=redirect_uri,
        scopes=tuple(integration.scopes or []),
        state=state,
        code_challenge=code_challenge_for(verifier),
    )


def _open_verifier(
    settings: Settings,
    *,
    key_version: str,
    sealed: bytes,
    organization_id: UUID,
    server_id: UUID,
    state_hash: str,
) -> str:
    try:
        plaintext = open_sealed(
            settings,
            SealedValue(key_version=key_version, sealed=sealed),
            transaction_verifier_aad(organization_id, server_id, state_hash),
        )
    except CredentialVaultError as error:
        raise ConnectedAppError("invalid_callback", INVALID_CALLBACK_MESSAGE) from error
    return plaintext.decode("ascii")


async def _account_identifier(
    settings: Settings, integration: DownstreamOAuthIntegration, access_token: str
) -> str | None:
    if not integration.account_endpoint:
        return None
    try:
        return await fetch_account_identifier(
            settings, account_endpoint=integration.account_endpoint, access_token=access_token
        )
    except OAuthConfigurationError, UnsafeEndpointError:
        return None


async def _store_connection(
    session: AsyncSession,
    *,
    organization_id: UUID,
    server_id: UUID,
    principal_id: UUID,
    integration_revision: int,
    sealed: SealedValue,
    scopes: list[str],
    account_identifier: str | None,
    expires_at: datetime | None,
    actor: AuthenticatedPrincipal,
    provider: str,
) -> None:
    """Create or replace the caller's connection in one transaction.

    The unique constraint on (organization, server, principal) resolves concurrent
    inserts; the loser retries as an update.
    """
    now = datetime.now(UTC)
    for attempt in range(2):
        connection = await session.scalar(
            select(DownstreamConnection)
            .where(
                DownstreamConnection.organization_id == organization_id,
                DownstreamConnection.server_id == server_id,
                DownstreamConnection.principal_id == principal_id,
            )
            .with_for_update()
        )
        if connection is None:
            connection = DownstreamConnection(
                organization_id=organization_id,
                server_id=server_id,
                principal_id=principal_id,
                integration_revision=integration_revision,
                credential_revision=1,
                status=CONNECTION_STATUS_CONNECTED,
                key_version=sealed.key_version,
                sealed_tokens=sealed.sealed,
                scopes=scopes,
                account_identifier=account_identifier,
                access_token_expires_at=expires_at,
                last_refreshed_at=now,
            )
            session.add(connection)
        else:
            connection.status = CONNECTION_STATUS_CONNECTED
            connection.integration_revision = integration_revision
            connection.credential_revision += 1
            connection.key_version = sealed.key_version
            connection.sealed_tokens = sealed.sealed
            connection.scopes = scopes
            connection.account_identifier = account_identifier
            connection.access_token_expires_at = expires_at
            connection.last_refreshed_at = now
        try:
            await session.flush()
            await record_principal_audit_event(
                session,
                organization_id=organization_id,
                actor=actor.principal,
                action=AuditAction.CONNECTION_CONNECTED,
                target_type=AuditTargetType.CONNECTION,
                target_id=connection.id,
                metadata={"provider": provider},
            )
            await session.commit()
        except IntegrityError:
            await session.rollback()
            if attempt == 1:
                raise ConnectedAppError(
                    "conflict", "The connection changed while it was being saved. Try again."
                ) from None
            continue
        return


async def complete_connection(
    session: AsyncSession,
    settings: Settings,
    current: AuthenticatedPrincipal,
    *,
    state: str | None,
    code: str | None,
    error: str | None,
) -> str:
    """Consume a callback exactly once and store the resulting connection.

    Returns the downstream server name for display.
    """
    organization_id = await _authorized_member(session, current)
    browser = current.browser_session
    if browser is None or current.credential_context != "browser_session":
        raise ConnectedAppError(
            "browser_session_required", "Connections can only be completed from a browser session."
        )
    if not settings.downstream_oauth_available:
        raise ConnectedAppError("not_available", "Downstream OAuth is disabled.")
    if not state:
        raise ConnectedAppError("invalid_callback", INVALID_CALLBACK_MESSAGE)

    state_hash = hash_state(state)
    now = datetime.now(UTC)
    # Consume the transaction atomically. Only a matching, unexpired, unconsumed row
    # bound to this browser session, principal, and organization is claimed.
    consumed = (
        await session.execute(
            update(DownstreamOAuthTransaction)
            .where(
                DownstreamOAuthTransaction.state_hash == state_hash,
                DownstreamOAuthTransaction.organization_id == organization_id,
                DownstreamOAuthTransaction.principal_id == current.principal.id,
                DownstreamOAuthTransaction.browser_session_id == browser.id,
                DownstreamOAuthTransaction.consumed_at.is_(None),
                DownstreamOAuthTransaction.expires_at > now,
            )
            .values(consumed_at=now)
            .returning(
                DownstreamOAuthTransaction.server_id,
                DownstreamOAuthTransaction.integration_revision,
                DownstreamOAuthTransaction.key_version,
                DownstreamOAuthTransaction.sealed_verifier,
            )
        )
    ).first()
    await session.commit()
    if consumed is None:
        raise ConnectedAppError("invalid_callback", INVALID_CALLBACK_MESSAGE)
    server_id = consumed.server_id
    integration_revision = consumed.integration_revision
    key_version = consumed.key_version
    sealed_verifier = consumed.sealed_verifier

    if error is not None:
        raise ConnectedAppError(
            "authorization_denied",
            "The provider did not grant access. Connect again to retry.",
        )
    if not code:
        raise ConnectedAppError("invalid_callback", INVALID_CALLBACK_MESSAGE)

    server = await get_server(session, organization_id, server_id)
    integration = await _integration_for(session, organization_id, server_id)
    if (
        not server.enabled
        or server.auth_policy != POLICY_PER_USER_OAUTH
        or integration is None
        or not integration.enabled
    ):
        raise ConnectedAppError("not_available", "This app is no longer available for connection.")
    if integration.revision != integration_revision:
        raise ConnectedAppError("invalid_callback", INVALID_CALLBACK_MESSAGE)
    problems = _integration_problems(settings, integration)
    if problems:
        raise ConnectedAppError("configuration_error", "; ".join(problems))

    verifier = _open_verifier(
        settings,
        key_version=key_version,
        sealed=sealed_verifier,
        organization_id=organization_id,
        server_id=server_id,
        state_hash=state_hash,
    )
    try:
        client_secret = open_client_secret(settings, integration)
        redirect_uri = callback_redirect_uri(settings)
        tokens: TokenSet = await exchange_authorization_code(
            settings,
            token_endpoint=integration.token_endpoint,
            client_id=integration.client_id,
            client_secret=client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=verifier,
        )
    except (
        CredentialVaultError,
        OAuthConfigurationError,
        OAuthProtocolError,
        UnsafeEndpointError,
    ) as failure:
        raise ConnectedAppError(
            "token_exchange_failed", "The connection could not be completed. Try again."
        ) from failure

    account_identifier = await _account_identifier(settings, integration, tokens.access_token)
    try:
        sealed = seal_tokens(
            settings,
            tokens,
            organization_id=organization_id,
            server_id=server_id,
            principal_id=current.principal.id,
        )
    except CredentialVaultError as failure:
        raise ConnectedAppError(
            "encryption_unavailable", "Credential encryption is not configured."
        ) from failure
    await _store_connection(
        session,
        organization_id=organization_id,
        server_id=server_id,
        principal_id=current.principal.id,
        integration_revision=integration.revision,
        sealed=sealed,
        scopes=list(tokens.scopes),
        account_identifier=account_identifier,
        expires_at=tokens.expires_at,
        actor=current,
        provider=integration.provider,
    )
    return server.name


async def disconnect(
    session: AsyncSession,
    settings: Settings,
    current: AuthenticatedPrincipal,
    server_id: UUID,
) -> DisconnectResult:
    """Delete the caller's local connection, then attempt provider revocation.

    Local deletion is authoritative: future calls fail even if revocation fails or is
    unsupported.
    """
    organization_id = await _authorized_member(session, current)
    server = await get_server(session, organization_id, server_id)
    connection = await session.scalar(
        select(DownstreamConnection).where(
            DownstreamConnection.organization_id == organization_id,
            DownstreamConnection.server_id == server.id,
            DownstreamConnection.principal_id == current.principal.id,
        )
    )
    if connection is None:
        return DisconnectResult(removed=False, revocation_supported=False, provider_revoked=False)

    integration = await _integration_for(session, organization_id, server_id)
    revocation_supported = integration is not None and integration.revocation_endpoint is not None
    token: str | None = None
    client_id = ""
    client_secret: str | None = None
    revocation_endpoint = ""
    if integration is not None and revocation_supported:
        try:
            tokens = open_tokens(settings, connection)
            token = tokens.refresh_token or tokens.access_token
            client_secret = open_client_secret(settings, integration)
        except CredentialVaultError, ValueError, KeyError, TypeError:
            token = None
        client_id = integration.client_id
        revocation_endpoint = integration.revocation_endpoint or ""

    await session.delete(connection)
    await record_principal_audit_event(
        session,
        organization_id=organization_id,
        actor=current.principal,
        action=AuditAction.CONNECTION_DISCONNECTED,
        target_type=AuditTargetType.CONNECTION,
        target_id=connection.id,
        metadata={
            "provider": integration.provider if integration is not None else "unknown",
            "revocation_result": "not_attempted",
        },
    )
    await session.commit()

    provider_revoked = False
    if token is not None and revocation_endpoint:
        try:
            await revoke_token(
                settings,
                revocation_endpoint=revocation_endpoint,
                client_id=client_id,
                client_secret=client_secret,
                token=token,
            )
        except OAuthConfigurationError, OAuthProtocolError, UnsafeEndpointError:
            provider_revoked = False
        else:
            provider_revoked = True
    return DisconnectResult(
        removed=True,
        revocation_supported=revocation_supported,
        provider_revoked=provider_revoked,
    )
