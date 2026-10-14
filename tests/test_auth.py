from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from coyote_mcp.auth import (
    ALL_ACTIONS,
    authenticate_browser_session,
    authenticate_token,
    authorize,
    issue_browser_session,
    issue_pat,
    resolve_external_identity,
)
from coyote_mcp.models import (
    Collection,
    ExternalGroup,
    GroupRoleMapping,
    Organization,
    Principal,
    RoleAssignment,
)
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


@pytest.mark.asyncio
async def test_external_identity_jit_does_not_link_matching_email(
    session, organization: Organization
) -> None:
    existing = Principal(
        organization_id=organization.id, identifier="existing", display_name="Existing"
    )
    session.add(existing)
    await session.commit()
    provisioned = await resolve_external_identity(
        session,
        organization_id=organization.id,
        issuer="https://issuer.example",
        subject="subject-1",
        email="shared@example.test",
        display_name="Provisioned",
        jit_provisioning_enabled=True,
    )
    assert provisioned.id != existing.id
    resolved = await resolve_external_identity(
        session,
        organization_id=organization.id,
        issuer="https://issuer.example",
        subject="subject-1",
        email="changed@example.test",
        display_name="Updated",
        jit_provisioning_enabled=False,
    )
    assert resolved.id == provisioned.id
    assert resolved.display_name == "Updated"


@pytest.mark.asyncio
async def test_external_identity_respects_organization_and_disabled_principal(
    session, organization: Organization
) -> None:
    second = Organization(slug="second", display_name="Second")
    session.add(second)
    await session.commit()
    first = await resolve_external_identity(
        session,
        organization_id=organization.id,
        issuer="https://issuer.example",
        subject="same-subject",
        email=None,
        display_name=None,
        jit_provisioning_enabled=True,
    )
    second_principal = await resolve_external_identity(
        session,
        organization_id=second.id,
        issuer="https://issuer.example",
        subject="same-subject",
        email=None,
        display_name=None,
        jit_provisioning_enabled=True,
    )
    assert first.id != second_principal.id
    first.enabled = False
    await session.commit()
    with pytest.raises(ValueError, match="disabled"):
        await resolve_external_identity(
            session,
            organization_id=organization.id,
            issuer="https://issuer.example",
            subject="same-subject",
            email=None,
            display_name=None,
            jit_provisioning_enabled=False,
        )


@pytest.mark.asyncio
async def test_verified_groups_grant_roles_and_missing_claims_remove_access(
    session, organization: Organization
) -> None:
    principal = Principal(
        organization_id=organization.id, identifier="group-user", display_name="Group User"
    )
    group = ExternalGroup(
        organization_id=organization.id,
        identity_provider_id=uuid4(),
        external_id="engineering-id",
        display_name="Engineering",
    )
    collection = Collection(organization_id=organization.id, slug="team", display_name="Team")
    session.add_all([principal, group, collection])
    await session.flush()
    session.add(
        GroupRoleMapping(
            organization_id=organization.id,
            external_group_id=group.id,
            role="viewer",
            collection_id=collection.id,
        )
    )
    await session.commit()
    assert (
        await authorize(
            session,
            principal,
            "collection:read",
            collection,
            verified_group_ids=frozenset({"engineering-id"}),
            identity_provider_id=group.identity_provider_id,
        )
    ).allowed
    assert (
        await authorize(
            session, principal, "collection:read", collection, verified_group_ids=frozenset()
        )
    ).reason == "missing_permission"


@pytest.mark.asyncio
async def test_browser_session_uses_hashed_verifier_and_enforces_revocation_and_expiry(
    session, organization: Organization
) -> None:
    principal = await create_principal(session, organization)
    browser_session, token = await issue_browser_session(
        session, principal, ["verified-group"], uuid4(), Settings()
    )
    assert token not in browser_session.token_hash
    authenticated = await authenticate_browser_session(session, token)
    assert authenticated is not None
    assert authenticated.verified_group_ids == frozenset({"verified-group"})
    browser_session.revoked_at = datetime.now(UTC)
    await session.commit()
    assert await authenticate_browser_session(session, token) is None
    browser_session.revoked_at = None
    browser_session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.commit()
    assert await authenticate_browser_session(session, token) is None


@pytest.mark.asyncio
async def test_browser_session_activity_writes_are_throttled(
    session, organization: Organization
) -> None:
    principal = await create_principal(session, organization)
    browser_session, token = await issue_browser_session(
        session, principal, [], uuid4(), Settings()
    )
    original_activity = browser_session.last_activity_at
    assert await authenticate_browser_session(session, token) is not None
    await session.refresh(browser_session)
    assert browser_session.last_activity_at == original_activity
    browser_session.last_activity_at = datetime.now(UTC) - timedelta(minutes=6)
    await session.commit()
    assert await authenticate_browser_session(session, token) is not None
    await session.refresh(browser_session)
    assert browser_session.last_activity_at > original_activity


@pytest.mark.asyncio
async def test_group_mapping_requires_matching_identity_provider(
    session, organization: Organization
) -> None:
    principal = Principal(
        organization_id=organization.id, identifier="provider-user", display_name="Provider User"
    )
    provider_a = uuid4()
    provider_b = uuid4()
    group_a = ExternalGroup(
        organization_id=organization.id,
        identity_provider_id=provider_a,
        external_id="shared-group",
        display_name="Provider A",
    )
    group_b = ExternalGroup(
        organization_id=organization.id,
        identity_provider_id=provider_b,
        external_id="shared-group",
        display_name="Provider B",
    )
    collection = Collection(
        organization_id=organization.id, slug="provider", display_name="Provider"
    )
    session.add_all([principal, group_a, group_b, collection])
    await session.flush()
    session.add(
        GroupRoleMapping(
            organization_id=organization.id,
            external_group_id=group_a.id,
            role="viewer",
            collection_id=collection.id,
        )
    )
    await session.commit()
    assert (
        await authorize(
            session,
            principal,
            "collection:read",
            collection,
            verified_group_ids=frozenset({"shared-group"}),
            identity_provider_id=provider_a,
        )
    ).allowed
    assert (
        await authorize(
            session,
            principal,
            "collection:read",
            collection,
            verified_group_ids=frozenset({"shared-group"}),
            identity_provider_id=provider_b,
        )
    ).reason == "missing_permission"
