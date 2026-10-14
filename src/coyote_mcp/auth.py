from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from coyote_mcp.models import (
    BrowserSession,
    Collection,
    ExternalGroup,
    ExternalIdentity,
    GroupRoleMapping,
    Organization,
    PersonalAccessToken,
    Principal,
    RoleAssignment,
)
from coyote_mcp.settings import Settings

ALL_ACTIONS = frozenset(
    {
        "server:read",
        "server:create",
        "server:update",
        "server:sync",
        "collection:read",
        "collection:create",
        "collection:update",
        "collection:manage_members",
        "tool:discover",
        "tool:describe",
        "tool:execute",
        "credential:create",
        "credential:revoke",
        "policy:manage",
    }
)
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "owner": ALL_ACTIONS,
    "administrator": ALL_ACTIONS - {"policy:manage"},
    "maintainer": frozenset(
        {
            "server:read",
            "server:create",
            "server:update",
            "server:sync",
            "collection:read",
            "collection:create",
            "collection:update",
            "collection:manage_members",
            "tool:discover",
            "tool:describe",
            "credential:create",
            "credential:revoke",
        }
    ),
    "consumer": frozenset(
        {"server:read", "collection:read", "tool:discover", "tool:describe", "tool:execute"}
    ),
    "viewer": frozenset({"server:read", "collection:read", "tool:discover", "tool:describe"}),
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    principal: Principal
    scopes: frozenset[str]
    token: PersonalAccessToken | None
    verified_group_ids: frozenset[str] = frozenset()
    browser_session: BrowserSession | None = None
    identity_provider_id: UUID | None = None


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _external_principal_identifier(issuer: str, subject: str) -> str:
    digest = hashlib.sha256(f"{issuer}\x00{subject}".encode()).hexdigest()
    return f"oidc:{digest}"


def _token_parts(value: str) -> tuple[str, str] | None:
    if not value.startswith("coyote_pat_"):
        return None
    parts = value.split("_", 3)
    if len(parts) != 4 or not parts[2] or not parts[3]:
        return None
    return parts[2], parts[3]


def _browser_session_parts(value: str) -> tuple[str, str] | None:
    if not value.startswith("coyote_session_"):
        return None
    parts = value.split("_", 3)
    if len(parts) != 4 or not parts[2] or not parts[3]:
        return None
    return parts[2], parts[3]


async def authenticate_token(session: AsyncSession, value: str) -> AuthenticatedPrincipal | None:
    parts = _token_parts(value)
    if parts is None:
        return None
    token_id, secret = parts
    result = await session.execute(
        select(PersonalAccessToken, Principal)
        .join(Principal, PersonalAccessToken.principal_id == Principal.id)
        .where(PersonalAccessToken.token_id == token_id)
    )
    row = result.one_or_none()
    if row is None:
        return None
    token, principal = row
    now = datetime.now(UTC)
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if (
        not hmac.compare_digest(token.secret_hash, _hash_secret(secret))
        or token.revoked_at is not None
        or expires_at <= now
        or not principal.enabled
    ):
        return None
    token.last_used_at = now
    await session.commit()
    return AuthenticatedPrincipal(principal=principal, scopes=frozenset(token.scopes), token=token)


async def issue_browser_session(
    session: AsyncSession,
    principal: Principal,
    verified_group_ids: list[str],
    identity_provider_id: UUID,
    settings: Settings,
) -> tuple[BrowserSession, str]:
    token_id = secrets.token_hex(12)
    secret = secrets.token_urlsafe(32)
    browser_session = BrowserSession(
        organization_id=principal.organization_id,
        principal_id=principal.id,
        identity_provider_id=identity_provider_id,
        token_id=token_id,
        token_hash=_hash_secret(secret),
        verified_group_ids=verified_group_ids,
        expires_at=datetime.now(UTC) + timedelta(seconds=settings.session_max_age_seconds),
    )
    session.add(browser_session)
    await session.commit()
    await session.refresh(browser_session)
    return browser_session, f"coyote_session_{token_id}_{secret}"


async def authenticate_browser_session(
    session: AsyncSession, value: str
) -> AuthenticatedPrincipal | None:
    parts = _browser_session_parts(value)
    if parts is None:
        return None
    token_id, secret = parts
    result = await session.execute(
        select(BrowserSession, Principal)
        .join(Principal, BrowserSession.principal_id == Principal.id)
        .where(BrowserSession.token_id == token_id)
    )
    row = result.one_or_none()
    if row is None:
        return None
    browser_session, principal = row
    now = datetime.now(UTC)
    expires_at = browser_session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if (
        not hmac.compare_digest(browser_session.token_hash, _hash_secret(secret))
        or browser_session.revoked_at is not None
        or expires_at <= now
        or not principal.enabled
        or browser_session.organization_id != principal.organization_id
    ):
        return None
    last_activity_at = browser_session.last_activity_at
    if last_activity_at.tzinfo is None:
        last_activity_at = last_activity_at.replace(tzinfo=UTC)
    if now - last_activity_at >= timedelta(minutes=5):
        browser_session.last_activity_at = now
        await session.commit()
    return AuthenticatedPrincipal(
        principal=principal,
        scopes=ALL_ACTIONS,
        token=None,
        verified_group_ids=frozenset(browser_session.verified_group_ids),
        browser_session=browser_session,
        identity_provider_id=browser_session.identity_provider_id,
    )


async def rotate_csrf_token(session: AsyncSession, browser_session: BrowserSession) -> str:
    token = secrets.token_urlsafe(32)
    browser_session.csrf_token_hash = _hash_secret(token)
    await session.commit()
    return token


def csrf_token_valid(browser_session: BrowserSession, token: str | None) -> bool:
    return (
        token is not None
        and browser_session.csrf_token_hash is not None
        and hmac.compare_digest(browser_session.csrf_token_hash, _hash_secret(token))
    )


async def issue_pat(
    session: AsyncSession,
    principal: Principal,
    name: str,
    scopes: set[str],
    lifetime: timedelta,
    settings: Settings,
    *,
    commit: bool = True,
) -> tuple[PersonalAccessToken, str]:
    if not principal.enabled:
        raise ValueError("Disabled principals cannot receive credentials.")
    assignments = (
        await session.scalars(
            select(RoleAssignment).where(
                RoleAssignment.principal_id == principal.id,
                RoleAssignment.organization_id == principal.organization_id,
            )
        )
    ).all()
    principal_permissions = frozenset().union(
        *(ROLE_PERMISSIONS.get(assignment.role, frozenset()) for assignment in assignments)
    )
    if not scopes or not scopes.issubset(principal_permissions):
        raise ValueError("Token scopes must contain recognized actions.")
    if lifetime <= timedelta() or lifetime > timedelta(seconds=settings.pat_max_lifetime_seconds):
        raise ValueError("Token lifetime exceeds the configured maximum.")
    token_id = secrets.token_hex(12)
    secret = secrets.token_urlsafe(32)
    plaintext = f"coyote_pat_{token_id}_{secret}"
    token = PersonalAccessToken(
        organization_id=principal.organization_id,
        principal_id=principal.id,
        token_id=token_id,
        secret_hash=_hash_secret(secret),
        name=name,
        scopes=sorted(scopes),
        expires_at=datetime.now(UTC) + lifetime,
    )
    session.add(token)
    if commit:
        await session.commit()
    else:
        await session.flush()
    await session.refresh(token)
    return token, plaintext


async def effective_permissions(
    session: AsyncSession,
    principal: Principal,
    verified_group_ids: frozenset[str] = frozenset(),
    identity_provider_id: UUID | None = None,
) -> frozenset[str]:
    assignments = (
        await session.scalars(
            select(RoleAssignment).where(
                RoleAssignment.principal_id == principal.id,
                RoleAssignment.organization_id == principal.organization_id,
            )
        )
    ).all()
    roles = {assignment.role for assignment in assignments if assignment.collection_id is None}
    if verified_group_ids and identity_provider_id is not None:
        group_roles = await session.scalars(
            select(GroupRoleMapping.role)
            .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
            .where(
                GroupRoleMapping.organization_id == principal.organization_id,
                GroupRoleMapping.collection_id.is_(None),
                ExternalGroup.external_id.in_(verified_group_ids),
                ExternalGroup.identity_provider_id == identity_provider_id,
            )
        )
        roles.update(group_roles.all())
    return frozenset().union(*(ROLE_PERMISSIONS.get(role, frozenset()) for role in roles))


async def resolve_external_identity(
    session: AsyncSession,
    *,
    organization_id: UUID,
    issuer: str,
    subject: str,
    email: str | None,
    display_name: str | None,
    jit_provisioning_enabled: bool,
) -> Principal:
    identity = await session.scalar(
        select(ExternalIdentity)
        .options(joinedload(ExternalIdentity.principal))
        .where(
            ExternalIdentity.organization_id == organization_id,
            ExternalIdentity.issuer == issuer,
            ExternalIdentity.subject == subject,
        )
    )
    if identity is None:
        if not jit_provisioning_enabled:
            raise ValueError("No external identity is registered for this account.")
        principal = Principal(
            organization_id=organization_id,
            identifier=_external_principal_identifier(issuer, subject),
            display_name=display_name or email or subject,
            identity_type="human",
            enabled=True,
        )
        identity = ExternalIdentity(
            organization_id=organization_id,
            principal=principal,
            issuer=issuer,
            subject=subject,
            email=email,
            display_name=display_name,
        )
        session.add(identity)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            identity = await session.scalar(
                select(ExternalIdentity)
                .options(joinedload(ExternalIdentity.principal))
                .where(
                    ExternalIdentity.organization_id == organization_id,
                    ExternalIdentity.issuer == issuer,
                    ExternalIdentity.subject == subject,
                )
            )
            if identity is None:
                raise
            principal = identity.principal
        else:
            await session.refresh(principal)
    else:
        principal = identity.principal
        identity.email = email
        identity.display_name = display_name
        if display_name:
            principal.display_name = display_name
    if not principal.enabled:
        raise ValueError("The mapped principal is disabled.")
    if identity is not None and principal.id is not None:
        await session.commit()
        await session.refresh(principal)
    return principal


async def authorize(
    session: AsyncSession,
    principal: Principal,
    action: str,
    resource: object | None = None,
    context: dict[str, object] | None = None,
    verified_group_ids: frozenset[str] = frozenset(),
    identity_provider_id: UUID | None = None,
) -> Decision:
    if action not in ALL_ACTIONS:
        return Decision(False, "unknown_action")
    if not principal.enabled:
        return Decision(False, "principal_disabled")
    organization_id: UUID
    collection_id: UUID | None
    if resource is None:
        if context != {"organization_id": principal.organization_id}:
            return Decision(False, "missing_resource_context")
        organization_id = principal.organization_id
        collection_id = None
    elif isinstance(resource, Organization):
        organization_id = resource.id
        collection_id = None
    else:
        candidate_organization_id = getattr(resource, "organization_id", None)
        candidate_collection_id = getattr(resource, "collection_id", None)
        collection_id = (
            candidate_collection_id if isinstance(candidate_collection_id, UUID) else None
        )
        if not isinstance(candidate_organization_id, UUID):
            return Decision(False, "missing_resource_context")
        organization_id = candidate_organization_id
        if isinstance(resource, Collection):
            collection_id = resource.id
    if organization_id != principal.organization_id:
        return Decision(False, "organization_mismatch")
    assignments = (
        await session.scalars(
            select(RoleAssignment).where(
                RoleAssignment.principal_id == principal.id,
                RoleAssignment.organization_id == principal.organization_id,
            )
        )
    ).all()
    role_scopes = [(assignment.role, assignment.collection_id) for assignment in assignments]
    if verified_group_ids and identity_provider_id is not None:
        group_assignments = await session.execute(
            select(GroupRoleMapping.role, GroupRoleMapping.collection_id)
            .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
            .where(
                GroupRoleMapping.organization_id == principal.organization_id,
                ExternalGroup.external_id.in_(verified_group_ids),
                ExternalGroup.identity_provider_id == identity_provider_id,
            )
        )
        role_scopes.extend(group_assignments.all())
    for role, assigned_collection_id in role_scopes:
        if assigned_collection_id is not None:
            collection = await session.get(Collection, assigned_collection_id)
            if collection is None or collection.organization_id != principal.organization_id:
                continue
        permissions = ROLE_PERMISSIONS.get(role, frozenset())
        if action not in permissions:
            continue
        if assigned_collection_id is None:
            return Decision(True, f"organization_role:{role}")
        if isinstance(collection_id, UUID) and assigned_collection_id == collection_id:
            return Decision(True, f"collection_role:{role}")
    return Decision(False, "missing_permission")
