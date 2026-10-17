from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from coyote_mcp.auth import (
    ALL_ACTIONS,
    authenticate_browser_session,
    authenticate_token,
    authorize,
    authorized_collection_ids,
    issue_browser_session,
    issue_pat,
    resolve_external_identity,
)
from coyote_mcp.models import (
    Collection,
    ExternalGroup,
    GroupRoleMapping,
    Organization,
    OrganizationMembership,
    Principal,
    RoleAssignment,
)
from coyote_mcp.settings import Settings


async def create_principal(session, organization: Organization, role: str = "owner") -> Principal:
    principal = Principal(identifier="principal", display_name="Principal")
    session.add(principal)
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
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
        session, principal, organization.id, "test", set(ALL_ACTIONS), timedelta(days=1), Settings()
    )
    authenticated = await authenticate_token(session, plaintext)
    assert authenticated is not None
    assert await authenticate_token(session, "not-a-token") is None
    token.revoked_at = datetime.now(UTC)
    await session.commit()
    assert await authenticate_token(session, plaintext) is None

    token, plaintext = await issue_pat(
        session,
        principal,
        organization.id,
        "replacement",
        {"server:read"},
        timedelta(days=1),
        Settings(),
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
            session,
            principal,
            organization.id,
            "too-broad",
            {"server:create"},
            timedelta(days=1),
            Settings(),
        )
    with pytest.raises(ValueError, match="lifetime"):
        await issue_pat(
            session, principal, organization.id, "expired", {"server:read"}, timedelta(), Settings()
        )


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
async def test_authorized_collection_ids_batches_organization_and_collection_grants(
    session, organization: Organization
) -> None:
    visible = Collection(organization_id=organization.id, slug="visible", display_name="Visible")
    hidden = Collection(organization_id=organization.id, slug="hidden", display_name="Hidden")
    collection_principal = Principal(
        identifier="collection-principal", display_name="Collection Principal"
    )
    session.add_all([visible, hidden, collection_principal])
    await session.flush()
    session.add(
        OrganizationMembership(
            organization_id=organization.id, principal_id=collection_principal.id
        )
    )
    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=collection_principal.id,
            role="consumer",
            collection_id=visible.id,
        )
    )
    await session.commit()

    collection_scope = await authorized_collection_ids(
        session,
        collection_principal,
        "tool:discover",
        [visible, hidden],
    )
    assert collection_scope == {visible.id}

    organization_principal = await create_principal(session, organization, "consumer")
    organization_scope = await authorized_collection_ids(
        session,
        organization_principal,
        "tool:discover",
        [visible, hidden],
    )
    assert organization_scope == {visible.id, hidden.id}


@pytest.mark.asyncio
async def test_collection_role_cannot_manage_organization_server(
    session, organization: Organization
) -> None:
    collection = Collection(organization_id=organization.id, slug="team", display_name="Team")
    principal = Principal(identifier="member", display_name="Member")
    session.add_all([collection, principal])
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
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
async def test_collection_scoped_role_can_issue_attenuated_pat(
    session, organization: Organization
) -> None:
    collection = Collection(organization_id=organization.id, slug="execute", display_name="Execute")
    principal = Principal(identifier="collection-user", display_name="Collection User")
    session.add_all([collection, principal])
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=principal.id,
            role="consumer",
            collection_id=collection.id,
        )
    )
    await session.commit()

    token, _ = await issue_pat(
        session,
        principal,
        organization.id,
        "collection-execute",
        {"tool:execute"},
        timedelta(days=1),
        Settings(),
    )

    assert token.scopes == ["tool:execute"]


@pytest.mark.asyncio
async def test_external_identity_jit_does_not_link_matching_email(
    session, organization: Organization
) -> None:
    existing = Principal(identifier="existing", display_name="Existing")
    session.add(existing)
    await session.commit()
    provisioned = await resolve_external_identity(
        session,
        issuer="https://issuer.example",
        subject="subject-1",
        email="shared@example.test",
        display_name="Provisioned",
        jit_provisioning_enabled=True,
    )
    assert provisioned.id != existing.id
    resolved = await resolve_external_identity(
        session,
        issuer="https://issuer.example",
        subject="subject-1",
        email="changed@example.test",
        display_name="Updated",
        jit_provisioning_enabled=False,
    )
    assert resolved.id == provisioned.id
    assert resolved.display_name == "Updated"


@pytest.mark.asyncio
async def test_jit_provisioning_uses_bounded_identifier_for_long_subject(
    session, organization: Organization
) -> None:
    subject = "subject-" + ("x" * 1024)
    principal = await resolve_external_identity(
        session,
        issuer="https://issuer.example/" + ("path/" * 40),
        subject=subject,
        email=None,
        display_name=None,
        jit_provisioning_enabled=True,
    )

    assert principal.identifier.startswith("oidc:")
    assert len(principal.identifier) <= 255


@pytest.mark.asyncio
async def test_external_identity_is_global_and_respects_disabled_principal(
    session, organization: Organization
) -> None:
    second = Organization(slug="second", display_name="Second")
    session.add(second)
    await session.commit()
    first = await resolve_external_identity(
        session,
        issuer="https://issuer.example",
        subject="same-subject",
        email=None,
        display_name=None,
        jit_provisioning_enabled=True,
    )
    second_principal = await resolve_external_identity(
        session,
        issuer="https://issuer.example",
        subject="same-subject",
        email=None,
        display_name=None,
        jit_provisioning_enabled=True,
    )
    assert first.id == second_principal.id
    first.enabled = False
    await session.commit()
    with pytest.raises(ValueError, match="disabled"):
        await resolve_external_identity(
            session,
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
    principal = Principal(identifier="group-user", display_name="Group User")
    group = ExternalGroup(
        organization_id=organization.id,
        identity_provider_id=uuid4(),
        external_id="engineering-id",
        display_name="Engineering",
    )
    collection = Collection(organization_id=organization.id, slug="team", display_name="Team")
    session.add_all([principal, group, collection])
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
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
    principal = Principal(identifier="provider-user", display_name="Provider User")
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
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
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
