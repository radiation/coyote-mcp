from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Sequence
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
    InstanceAdministrator,
    Organization,
    OrganizationMembership,
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
    organization_id: UUID | None
    verified_group_ids: frozenset[str] = frozenset()
    browser_session: BrowserSession | None = None
    identity_provider_id: UUID | None = None

    def require_organization_id(self) -> UUID:
        if self.organization_id is None:
            raise ValueError("An active organization must be selected.")
        return self.organization_id


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _external_principal_identifier(issuer: str, subject: str) -> str:
    digest = hashlib.sha256(f"{issuer}\x00{subject}".encode()).hexdigest()
    return f"oidc:{digest}"


def _token_parts(value: str, prefix: str) -> tuple[str, str] | None:
    if not value.startswith(prefix):
        return None
    parts = value.split("_", 3)
    return (parts[2], parts[3]) if len(parts) == 4 and parts[2] and parts[3] else None


async def _enabled_membership(
    session: AsyncSession, principal_id: UUID, organization_id: UUID
) -> OrganizationMembership | None:
    return await session.scalar(
        select(OrganizationMembership)
        .join(Organization, OrganizationMembership.organization_id == Organization.id)
        .where(
            OrganizationMembership.principal_id == principal_id,
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.enabled.is_(True),
            Organization.enabled.is_(True),
        )
    )


async def authenticate_token(session: AsyncSession, value: str) -> AuthenticatedPrincipal | None:
    parts = _token_parts(value, "coyote_pat_")
    if parts is None:
        return None
    token_id, secret = parts
    row = (
        await session.execute(
            select(PersonalAccessToken, Principal)
            .join(Principal, PersonalAccessToken.principal_id == Principal.id)
            .where(PersonalAccessToken.token_id == token_id)
        )
    ).one_or_none()
    if row is None:
        return None
    token, principal = row
    expires_at = (
        token.expires_at.replace(tzinfo=UTC)
        if token.expires_at.tzinfo is None
        else token.expires_at
    )
    if (
        not hmac.compare_digest(token.secret_hash, _hash_secret(secret))
        or token.revoked_at is not None
        or expires_at <= datetime.now(UTC)
        or not principal.enabled
        or await _enabled_membership(session, principal.id, token.organization_id) is None
    ):
        return None
    token.last_used_at = datetime.now(UTC)
    await session.commit()
    return AuthenticatedPrincipal(principal, frozenset(token.scopes), token, token.organization_id)


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
    parts = _token_parts(value, "coyote_session_")
    if parts is None:
        return None
    token_id, secret = parts
    row = (
        await session.execute(
            select(BrowserSession, Principal)
            .join(Principal, BrowserSession.principal_id == Principal.id)
            .where(BrowserSession.token_id == token_id)
        )
    ).one_or_none()
    if row is None:
        return None
    browser_session, principal = row
    expires_at = browser_session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if (
        not hmac.compare_digest(browser_session.token_hash, _hash_secret(secret))
        or browser_session.revoked_at is not None
        or expires_at <= datetime.now(UTC)
        or not principal.enabled
    ):
        return None
    activity_at = browser_session.last_activity_at
    if activity_at.tzinfo is None:
        activity_at = activity_at.replace(tzinfo=UTC)
    if datetime.now(UTC) - activity_at >= timedelta(minutes=5):
        browser_session.last_activity_at = datetime.now(UTC)
        await session.commit()
    return AuthenticatedPrincipal(
        principal,
        ALL_ACTIONS,
        None,
        browser_session.active_organization_id,
        frozenset(browser_session.verified_group_ids),
        browser_session,
        browser_session.identity_provider_id,
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


async def available_organizations(
    session: AsyncSession, principal: Principal
) -> list[Organization]:
    return list(
        (
            await session.scalars(
                select(Organization)
                .join(OrganizationMembership)
                .where(
                    OrganizationMembership.principal_id == principal.id,
                    OrganizationMembership.enabled.is_(True),
                    Organization.enabled.is_(True),
                )
                .order_by(Organization.display_name, Organization.slug)
            )
        ).all()
    )


async def select_active_organization(
    session: AsyncSession, current: AuthenticatedPrincipal, organization_id: UUID
) -> bool:
    if current.browser_session is None or not current.principal.enabled:
        return False
    if await _enabled_membership(session, current.principal.id, organization_id) is None:
        return False
    current.browser_session.active_organization_id = organization_id
    await session.commit()
    return True


async def issue_pat(
    session: AsyncSession,
    principal: Principal,
    organization_id: UUID,
    name: str,
    scopes: set[str],
    lifetime: timedelta,
    settings: Settings,
    *,
    commit: bool = True,
) -> tuple[PersonalAccessToken, str]:
    if (
        not principal.enabled
        or await _enabled_membership(session, principal.id, organization_id) is None
    ):
        raise ValueError("Principal does not have an enabled organization membership.")
    assignments = (
        await session.scalars(
            select(RoleAssignment).where(
                RoleAssignment.principal_id == principal.id,
                RoleAssignment.organization_id == organization_id,
            )
        )
    ).all()
    permissions = frozenset().union(
        *(ROLE_PERMISSIONS.get(item.role, frozenset()) for item in assignments)
    )
    if not scopes or not scopes.issubset(permissions):
        raise ValueError("Token scopes must contain recognized actions.")
    if lifetime <= timedelta() or lifetime > timedelta(seconds=settings.pat_max_lifetime_seconds):
        raise ValueError("Token lifetime exceeds the configured maximum.")
    token_id, secret = secrets.token_hex(12), secrets.token_urlsafe(32)
    token = PersonalAccessToken(
        organization_id=organization_id,
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
    return token, f"coyote_pat_{token_id}_{secret}"


async def effective_permissions(
    session: AsyncSession,
    principal: Principal,
    organization_id: UUID,
    verified_group_ids: frozenset[str] = frozenset(),
    identity_provider_id: UUID | None = None,
) -> frozenset[str]:
    roles = set(
        (
            await session.scalars(
                select(RoleAssignment.role).where(
                    RoleAssignment.principal_id == principal.id,
                    RoleAssignment.organization_id == organization_id,
                    RoleAssignment.collection_id.is_(None),
                )
            )
        ).all()
    )
    if verified_group_ids and identity_provider_id is not None:
        roles.update(
            (
                await session.scalars(
                    select(GroupRoleMapping.role)
                    .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
                    .where(
                        GroupRoleMapping.organization_id == organization_id,
                        GroupRoleMapping.collection_id.is_(None),
                        ExternalGroup.external_id.in_(verified_group_ids),
                        ExternalGroup.identity_provider_id == identity_provider_id,
                    )
                )
            ).all()
        )
    return frozenset().union(*(ROLE_PERMISSIONS.get(role, frozenset()) for role in roles))


async def authorized_collection_ids(
    session: AsyncSession,
    principal: Principal,
    action: str,
    collections: Sequence[Collection],
    verified_group_ids: frozenset[str] = frozenset(),
    identity_provider_id: UUID | None = None,
) -> frozenset[UUID]:
    if action not in ALL_ACTIONS or not principal.enabled or not collections:
        return frozenset()
    organization_ids = {collection.organization_id for collection in collections}
    if len(organization_ids) != 1:
        return frozenset()
    organization_id = next(iter(organization_ids))
    if await _enabled_membership(session, principal.id, organization_id) is None:
        return frozenset()
    candidate_ids = {collection.id for collection in collections}
    scopes = list(
        (
            await session.execute(
                select(RoleAssignment.role, RoleAssignment.collection_id).where(
                    RoleAssignment.principal_id == principal.id,
                    RoleAssignment.organization_id == organization_id,
                )
            )
        ).all()
    )
    if verified_group_ids and identity_provider_id is not None:
        scopes.extend(
            (
                await session.execute(
                    select(GroupRoleMapping.role, GroupRoleMapping.collection_id)
                    .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
                    .where(
                        GroupRoleMapping.organization_id == organization_id,
                        ExternalGroup.external_id.in_(verified_group_ids),
                        ExternalGroup.identity_provider_id == identity_provider_id,
                    )
                )
            ).all()
        )
    authorized: set[UUID] = set()
    for role, collection_id in scopes:
        if action not in ROLE_PERMISSIONS.get(role, frozenset()):
            continue
        if collection_id is None:
            return frozenset(candidate_ids)
        if collection_id in candidate_ids:
            authorized.add(collection_id)
    return frozenset(authorized)


async def resolve_external_identity(
    session: AsyncSession,
    *,
    issuer: str,
    subject: str,
    email: str | None,
    display_name: str | None,
    jit_provisioning_enabled: bool,
) -> Principal:
    identity = await session.scalar(
        select(ExternalIdentity)
        .options(joinedload(ExternalIdentity.principal))
        .where(ExternalIdentity.issuer == issuer, ExternalIdentity.subject == subject)
    )
    if identity is None:
        if not jit_provisioning_enabled:
            raise ValueError("No external identity is registered for this account.")
        principal = Principal(
            identifier=_external_principal_identifier(issuer, subject),
            display_name=display_name or email or subject,
            identity_type="human",
        )
        identity = ExternalIdentity(
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
                .where(ExternalIdentity.issuer == issuer, ExternalIdentity.subject == subject)
            )
            if identity is None:
                raise
            principal = identity.principal
        else:
            await session.refresh(principal)
    else:
        principal = identity.principal
        identity.email, identity.display_name = email, display_name
        if display_name:
            principal.display_name = display_name
    if not principal.enabled:
        raise ValueError("The mapped principal is disabled.")
    await session.commit()
    await session.refresh(principal)
    return principal


async def is_instance_administrator(session: AsyncSession, principal: Principal) -> bool:
    return principal.enabled and await session.get(InstanceAdministrator, principal.id) is not None


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
    if resource is None:
        organization_id = context.get("organization_id") if context else None
        collection_id: UUID | None = None
        if not isinstance(organization_id, UUID):
            return Decision(False, "missing_resource_context")
    elif isinstance(resource, Organization):
        organization_id, collection_id = resource.id, None
    else:
        organization_id = getattr(resource, "organization_id", None)
        collection_id = getattr(resource, "collection_id", None)
        if isinstance(resource, Collection):
            collection_id = resource.id
        if not isinstance(organization_id, UUID):
            return Decision(False, "missing_resource_context")
    if await _enabled_membership(session, principal.id, organization_id) is None:
        return Decision(False, "missing_membership")
    scopes = list(
        (
            await session.execute(
                select(RoleAssignment.role, RoleAssignment.collection_id).where(
                    RoleAssignment.principal_id == principal.id,
                    RoleAssignment.organization_id == organization_id,
                )
            )
        ).all()
    )
    if verified_group_ids and identity_provider_id is not None:
        scopes.extend(
            (
                await session.execute(
                    select(GroupRoleMapping.role, GroupRoleMapping.collection_id)
                    .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
                    .where(
                        GroupRoleMapping.organization_id == organization_id,
                        ExternalGroup.external_id.in_(verified_group_ids),
                        ExternalGroup.identity_provider_id == identity_provider_id,
                    )
                )
            ).all()
        )
    for role, assigned_collection_id in scopes:
        if action not in ROLE_PERMISSIONS.get(role, frozenset()):
            continue
        if assigned_collection_id is None:
            return Decision(True, f"organization_role:{role}")
        if isinstance(collection_id, UUID) and assigned_collection_id == collection_id:
            return Decision(True, f"collection_role:{role}")
    return Decision(False, "missing_permission")
