from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from coyote_mcp.audit import AuditAction, AuditTargetType, record_principal_audit_event
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
        "connection:manage_own",
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
            "connection:manage_own",
        }
    ),
    "consumer": frozenset(
        {
            "server:read",
            "collection:read",
            "tool:discover",
            "tool:describe",
            "tool:execute",
            "connection:manage_own",
        }
    ),
    "viewer": frozenset(
        {
            "server:read",
            "collection:read",
            "tool:discover",
            "tool:describe",
            "connection:manage_own",
        }
    ),
}
CredentialContext = Literal["browser_session", "pat"]


class ExternalIdentityResolutionError(ValueError):
    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


class OrganizationBootstrapError(ValueError):
    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


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
    credential_context: CredentialContext = "browser_session"

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


async def enabled_membership(
    session: AsyncSession, principal_id: UUID, organization_id: UUID
) -> OrganizationMembership | None:
    return await _enabled_membership(session, principal_id, organization_id)


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


async def _enabled_organization(session: AsyncSession, organization_id: UUID) -> bool:
    return (
        await session.scalar(
            select(Organization.id).where(
                Organization.id == organization_id,
                Organization.enabled.is_(True),
            )
        )
        is not None
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
    return AuthenticatedPrincipal(
        principal,
        frozenset(token.scopes),
        token,
        token.organization_id,
        credential_context="pat",
    )


async def issue_browser_session(
    session: AsyncSession,
    principal: Principal,
    verified_group_ids: list[str],
    settings: Settings,
) -> tuple[BrowserSession, str]:
    token_id = secrets.token_hex(12)
    secret = secrets.token_urlsafe(32)
    browser_session = BrowserSession(
        principal_id=principal.id,
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
        "browser_session",
    )


def csrf_token_for(browser_session: BrowserSession, settings: Settings) -> str:
    message = f"{browser_session.token_hash}\x00{browser_session.csrf_epoch}".encode()
    return hmac.new(
        settings.session_secret_key.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()


def csrf_token_valid(
    browser_session: BrowserSession, token: str | None, settings: Settings
) -> bool:
    # hmac.compare_digest raises TypeError for non-ASCII str operands, so reject them first.
    if token is None or not token.isascii():
        return False
    return hmac.compare_digest(csrf_token_for(browser_session, settings), token)


async def available_organizations(
    session: AsyncSession, current: AuthenticatedPrincipal
) -> list[Organization]:
    if current.credential_context == "browser_session" and await is_instance_administrator(
        session, current.principal
    ):
        statement = select(Organization).where(Organization.enabled.is_(True))
    else:
        statement = (
            select(Organization)
            .join(OrganizationMembership)
            .where(
                OrganizationMembership.principal_id == current.principal.id,
                OrganizationMembership.enabled.is_(True),
                Organization.enabled.is_(True),
            )
        )
    return list(
        (
            await session.scalars(statement.order_by(Organization.display_name, Organization.slug))
        ).all()
    )


async def select_active_organization(
    session: AsyncSession, current: AuthenticatedPrincipal, organization_id: UUID
) -> bool:
    if (
        current.credential_context != "browser_session"
        or current.browser_session is None
        or not current.principal.enabled
    ):
        return False
    if not await _enabled_organization(session, organization_id):
        return False
    if not await is_instance_administrator(session, current.principal) and (
        await _enabled_membership(session, current.principal.id, organization_id) is None
    ):
        return False
    # The epoch bump shares this commit with the organization change, so a form
    # rendered for the previous organization cannot authenticate against the new one.
    current.browser_session.active_organization_id = organization_id
    current.browser_session.csrf_epoch += 1
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
    actor: Principal | None = None,
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
    if actor is not None:
        await session.flush()
        await record_principal_audit_event(
            session,
            organization_id=organization_id,
            actor=actor,
            action=AuditAction.CREDENTIAL_CREATED,
            target_type=AuditTargetType.CREDENTIAL,
            target_id=token.id,
            metadata={"credential_kind": "pat"},
        )
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
    credential_context: CredentialContext = "browser_session",
) -> frozenset[str]:
    if credential_context == "browser_session" and await is_instance_administrator(
        session, principal
    ):
        return ALL_ACTIONS
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
    if verified_group_ids:
        roles.update(
            (
                await session.scalars(
                    select(GroupRoleMapping.role)
                    .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
                    .where(
                        GroupRoleMapping.organization_id == organization_id,
                        GroupRoleMapping.collection_id.is_(None),
                        ExternalGroup.external_id.in_(verified_group_ids),
                    )
                )
            ).all()
        )
    return frozenset().union(*(ROLE_PERMISSIONS.get(role, frozenset()) for role in roles))


async def has_action_grant_in_organization(
    session: AsyncSession,
    principal: Principal,
    action: str,
    organization_id: UUID,
    verified_group_ids: frozenset[str] = frozenset(),
    credential_context: CredentialContext = "pat",
) -> bool:
    """Return whether the principal holds the action via an org-wide or collection-scoped role."""
    if action not in ALL_ACTIONS or not principal.enabled:
        return False
    if not await _enabled_organization(session, organization_id):
        return False
    if credential_context == "browser_session" and await is_instance_administrator(
        session, principal
    ):
        return True
    if await _enabled_membership(session, principal.id, organization_id) is None:
        return False
    roles = list(
        (
            await session.scalars(
                select(RoleAssignment.role).where(
                    RoleAssignment.principal_id == principal.id,
                    RoleAssignment.organization_id == organization_id,
                )
            )
        ).all()
    )
    if verified_group_ids:
        roles.extend(
            (
                await session.scalars(
                    select(GroupRoleMapping.role)
                    .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
                    .where(
                        GroupRoleMapping.organization_id == organization_id,
                        ExternalGroup.external_id.in_(verified_group_ids),
                    )
                )
            ).all()
        )
    return any(action in ROLE_PERMISSIONS.get(role, frozenset()) for role in roles)


async def authorized_collection_ids(
    session: AsyncSession,
    principal: Principal,
    action: str,
    collections: Sequence[Collection],
    verified_group_ids: frozenset[str] = frozenset(),
    credential_context: CredentialContext = "pat",
) -> frozenset[UUID]:
    if action not in ALL_ACTIONS or not principal.enabled or not collections:
        return frozenset()
    organization_ids = {collection.organization_id for collection in collections}
    if len(organization_ids) != 1:
        return frozenset()
    organization_id = next(iter(organization_ids))
    if not await _enabled_organization(session, organization_id):
        return frozenset()
    candidate_ids = {collection.id for collection in collections}
    if credential_context == "browser_session" and await is_instance_administrator(
        session, principal
    ):
        return frozenset(candidate_ids)
    if await _enabled_membership(session, principal.id, organization_id) is None:
        return frozenset()
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
    if verified_group_ids:
        scopes.extend(
            (
                await session.execute(
                    select(GroupRoleMapping.role, GroupRoleMapping.collection_id)
                    .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
                    .where(
                        GroupRoleMapping.organization_id == organization_id,
                        ExternalGroup.external_id.in_(verified_group_ids),
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
            raise ExternalIdentityResolutionError(
                "identity_not_registered", "No external identity is registered for this account."
            )
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
        mapped_principal = await session.get(Principal, identity.principal_id)
        if mapped_principal is None:
            raise ExternalIdentityResolutionError(
                "mapped_principal_missing", "The mapped principal no longer exists."
            )
        principal = mapped_principal
        identity.email, identity.display_name = email, display_name
        if display_name:
            principal.display_name = display_name
    if not principal.enabled:
        raise ExternalIdentityResolutionError(
            "mapped_principal_disabled", "The mapped principal is disabled."
        )
    await session.commit()
    await session.refresh(principal)
    return principal


async def is_instance_administrator(session: AsyncSession, principal: Principal) -> bool:
    return principal.enabled and await session.get(InstanceAdministrator, principal.id) is not None


async def create_initial_organization(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    *,
    slug: str,
    display_name: str,
) -> Organization:
    if (
        current.credential_context != "browser_session"
        or current.browser_session is None
        or not await is_instance_administrator(session, current.principal)
    ):
        raise OrganizationBootstrapError(
            "instance_administrator_required",
            "An enabled instance administrator is required to create the first organization.",
        )
    organization = Organization(slug=slug, display_name=display_name)
    session.add(organization)
    try:
        await session.flush()
        session.add(
            OrganizationMembership(
                organization_id=organization.id,
                principal_id=current.principal.id,
                enabled=True,
            )
        )
        session.add(
            RoleAssignment(
                organization_id=organization.id,
                principal_id=current.principal.id,
                role="owner",
            )
        )
        current.browser_session.active_organization_id = organization.id
        current.browser_session.csrf_epoch += 1
        await record_principal_audit_event(
            session,
            organization_id=organization.id,
            actor=current.principal,
            action=AuditAction.ORGANIZATION_CREATED,
            target_type=AuditTargetType.ORGANIZATION,
            target_id=organization.id,
            metadata={"organization_slug": organization.slug},
        )
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        await session.refresh(current.principal)
        await session.refresh(current.browser_session)
        raise OrganizationBootstrapError(
            "duplicate_slug", "An organization with this slug already exists."
        ) from error
    await session.refresh(organization)
    return organization


async def authorize(
    session: AsyncSession,
    principal: Principal,
    action: str,
    resource: object | None = None,
    context: dict[str, object] | None = None,
    verified_group_ids: frozenset[str] = frozenset(),
    credential_context: CredentialContext = "browser_session",
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
    if not await _enabled_organization(session, organization_id):
        return Decision(False, "organization_disabled")
    if credential_context == "browser_session" and await is_instance_administrator(
        session, principal
    ):
        return Decision(True, "instance_administrator")
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
    if verified_group_ids:
        scopes.extend(
            (
                await session.execute(
                    select(GroupRoleMapping.role, GroupRoleMapping.collection_id)
                    .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
                    .where(
                        GroupRoleMapping.organization_id == organization_id,
                        ExternalGroup.external_id.in_(verified_group_ids),
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


async def self_service_action_allowed(
    session: AsyncSession,
    principal: Principal,
    organization_id: UUID,
    action: str,
    verified_group_ids: frozenset[str] = frozenset(),
    credential_context: CredentialContext = "browser_session",
) -> bool:
    """Allow a member to act on their own resources in an organization.

    Self-service actions (such as managing one's own downstream connections) are
    not scoped to a collection or organization resource, so any role grant that
    includes the action, at any scope, is sufficient. Callers must still verify
    that the action concerns only the authenticated principal.
    """
    if action not in ALL_ACTIONS or not principal.enabled:
        return False
    if not await _enabled_organization(session, organization_id):
        return False
    if credential_context == "browser_session" and await is_instance_administrator(
        session, principal
    ):
        return True
    if await _enabled_membership(session, principal.id, organization_id) is None:
        return False
    roles = set(
        (
            await session.scalars(
                select(RoleAssignment.role).where(
                    RoleAssignment.principal_id == principal.id,
                    RoleAssignment.organization_id == organization_id,
                )
            )
        ).all()
    )
    if verified_group_ids:
        roles.update(
            (
                await session.scalars(
                    select(GroupRoleMapping.role)
                    .join(ExternalGroup, GroupRoleMapping.external_group_id == ExternalGroup.id)
                    .where(
                        GroupRoleMapping.organization_id == organization_id,
                        ExternalGroup.external_id.in_(verified_group_ids),
                    )
                )
            ).all()
        )
    return any(action in ROLE_PERMISSIONS.get(role, frozenset()) for role in roles)
