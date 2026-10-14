from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.models import (
    Collection,
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
    token: PersonalAccessToken


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _token_parts(value: str) -> tuple[str, str] | None:
    if not value.startswith("coyote_pat_"):
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
    token_id = secrets.token_urlsafe(12)
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


async def authorize(
    session: AsyncSession,
    principal: Principal,
    action: str,
    resource: object | None = None,
    context: dict[str, object] | None = None,
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
    for assignment in assignments:
        if assignment.collection_id is not None:
            collection = await session.get(Collection, assignment.collection_id)
            if collection is None or collection.organization_id != principal.organization_id:
                continue
        permissions = ROLE_PERMISSIONS.get(assignment.role, frozenset())
        if action not in permissions:
            continue
        if assignment.collection_id is None:
            return Decision(True, f"organization_role:{assignment.role}")
        if isinstance(collection_id, UUID) and assignment.collection_id == collection_id:
            return Decision(True, f"collection_role:{assignment.role}")
    return Decision(False, "missing_permission")
