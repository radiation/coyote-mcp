from datetime import UTC, datetime, timedelta

import pytest

from coyote_mcp.auth import ALL_ACTIONS, authenticate_token, authorize, issue_pat
from coyote_mcp.models import Collection, Organization, Principal, RoleAssignment
from coyote_mcp.settings import Settings


async def create_principal(session, organization: Organization, role: str = "owner") -> Principal:
    principal = Principal(
        organization_id=organization.id, identifier="principal", display_name="Principal"
    )
    session.add(principal)
    await session.flush()
    session.add(
        RoleAssignment(organization_id=organization.id, principal_id=principal.id, role=role)
    )
    await session.commit()
    return principal


@pytest.mark.asyncio
async def test_pat_authentication_revocation_and_disabled_principal(
    session, organization: Organization
) -> None:
    principal = await create_principal(session, organization)
    token, plaintext = await issue_pat(
        session, principal, "test", set(ALL_ACTIONS), timedelta(days=1), Settings()
    )
    authenticated = await authenticate_token(session, plaintext)
    assert authenticated is not None
    assert await authenticate_token(session, "not-a-token") is None
    token.revoked_at = datetime.now(UTC)
    await session.commit()
    assert await authenticate_token(session, plaintext) is None

    token, plaintext = await issue_pat(
        session, principal, "replacement", {"server:read"}, timedelta(days=1), Settings()
    )
    principal.enabled = False
    await session.commit()
    assert token.secret_hash not in plaintext
    assert await authenticate_token(session, plaintext) is None


@pytest.mark.asyncio
async def test_pat_scope_attenuation_and_expiry(session, organization: Organization) -> None:
    principal = await create_principal(session, organization, "viewer")
    with pytest.raises(ValueError, match="Token scopes"):
        await issue_pat(
            session, principal, "too-broad", {"server:create"}, timedelta(days=1), Settings()
        )
    with pytest.raises(ValueError, match="lifetime"):
        await issue_pat(session, principal, "expired", {"server:read"}, timedelta(), Settings())


@pytest.mark.asyncio
async def test_authorize_requires_tenant_context_and_enforces_collection_scope(
    session, organization: Organization
) -> None:
    principal = await create_principal(session, organization, "viewer")
    collection = Collection(organization_id=organization.id, slug="visible", display_name="Visible")
    session.add(collection)
    await session.commit()

    assert (await authorize(session, principal, "server:read")).reason == "missing_resource_context"
    assert (await authorize(session, principal, "unknown", collection)).reason == "unknown_action"
    assert (await authorize(session, principal, "collection:read", collection)).allowed
    principal.enabled = False
    await session.commit()
    assert (
        await authorize(session, principal, "collection:read", collection)
    ).reason == "principal_disabled"


@pytest.mark.asyncio
async def test_collection_role_cannot_manage_organization_server(
    session, organization: Organization
) -> None:
    collection = Collection(organization_id=organization.id, slug="team", display_name="Team")
    principal = Principal(
        organization_id=organization.id, identifier="member", display_name="Member"
    )
    session.add_all([collection, principal])
    await session.flush()
    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=principal.id,
            role="maintainer",
            collection_id=collection.id,
        )
    )
    await session.commit()
    assert (await authorize(session, principal, "collection:update", collection)).allowed
    assert (
        await authorize(
            session, principal, "server:create", context={"organization_id": organization.id}
        )
    ).reason == "missing_permission"
