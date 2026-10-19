from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp import auth
from coyote_mcp.audit import AuditPersistenceError
from coyote_mcp.auth import (
    ALL_ACTIONS,
    ExternalIdentityResolutionError,
    OrganizationBootstrapError,
    authenticate_browser_session,
    authenticate_token,
    authorize,
    authorized_collection_ids,
    available_organizations,
    create_initial_organization,
    csrf_token_for,
    csrf_token_valid,
    effective_permissions,
    issue_browser_session,
    issue_pat,
    resolve_external_identity,
    select_active_organization,
)
from coyote_mcp.models import (
    BrowserSession,
    Collection,
    ExternalGroup,
    GroupRoleMapping,
    InstanceAdministrator,
    Organization,
    OrganizationMembership,
    PersonalAccessToken,
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
async def test_pat_audit_failure_rolls_back_token(
    session, organization: Organization, monkeypatch: pytest.MonkeyPatch
) -> None:
    principal = await create_principal(session, organization)

    async def failing_audit(*args: object, **kwargs: object) -> None:
        raise AuditPersistenceError("audit storage unavailable")

    monkeypatch.setattr(auth, "record_principal_audit_event", failing_audit)
    with pytest.raises(AuditPersistenceError):
        await issue_pat(
            session,
            principal,
            organization.id,
            "audited-token",
            {"server:read"},
            timedelta(days=1),
            Settings(),
            actor=principal,
        )
    await session.rollback()

    assert (
        await session.scalar(
            select(PersonalAccessToken).where(PersonalAccessToken.name == "audited-token")
        )
        is None
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
async def test_jit_provisioning_creates_no_membership_role_or_instance_administrator(
    session, organization: Organization
) -> None:
    principal = await resolve_external_identity(
        session,
        issuer="https://issuer.example",
        subject="unprivileged-subject",
        email=None,
        display_name=None,
        jit_provisioning_enabled=True,
    )

    assert (
        await session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.principal_id == principal.id
            )
        )
        is None
    )
    assert (
        await session.scalar(
            select(RoleAssignment).where(RoleAssignment.principal_id == principal.id)
        )
        is None
    )
    assert await session.get(InstanceAdministrator, principal.id) is None


@pytest.mark.asyncio
async def test_external_identity_resolution_categories_missing_and_disabled_principals(
    session, organization: Organization
) -> None:
    with pytest.raises(ExternalIdentityResolutionError) as missing_identity:
        await resolve_external_identity(
            session,
            issuer="https://issuer.example",
            subject="missing-subject",
            email=None,
            display_name=None,
            jit_provisioning_enabled=False,
        )
    assert missing_identity.value.category == "identity_not_registered"

    principal = await resolve_external_identity(
        session,
        issuer="https://issuer.example",
        subject="disabled-subject",
        email=None,
        display_name=None,
        jit_provisioning_enabled=True,
    )
    principal.enabled = False
    await session.commit()

    with pytest.raises(ExternalIdentityResolutionError) as disabled_principal:
        await resolve_external_identity(
            session,
            issuer="https://issuer.example",
            subject="disabled-subject",
            email=None,
            display_name=None,
            jit_provisioning_enabled=False,
        )
    assert disabled_principal.value.category == "mapped_principal_disabled"


@pytest.mark.asyncio
async def test_instance_administrator_authorizes_enabled_ownerless_organizations(
    session, organization: Organization
) -> None:
    administrator = Principal(identifier="instance-admin", display_name="Instance Administrator")
    session.add(administrator)
    await session.flush()
    session.add(InstanceAdministrator(principal_id=administrator.id))
    await session.commit()

    for action in ALL_ACTIONS:
        decision = await authorize(
            session, administrator, action, context={"organization_id": organization.id}
        )
        assert decision.allowed
        assert decision.reason == "instance_administrator"
    assert (
        await session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.principal_id == administrator.id
            )
        )
        is None
    )
    assert (
        await session.scalar(
            select(RoleAssignment).where(RoleAssignment.principal_id == administrator.id)
        )
        is None
    )


@pytest.mark.asyncio
async def test_instance_administrator_can_create_multiple_organizations(
    session, organization: Organization
) -> None:
    administrator = Principal(identifier="bootstrap-admin", display_name="Bootstrap Administrator")
    session.add(administrator)
    await session.flush()
    session.add(InstanceAdministrator(principal_id=administrator.id))
    await session.commit()
    _, browser_token = await issue_browser_session(session, administrator, [], Settings())
    current = await authenticate_browser_session(session, browser_token)

    assert current is not None
    first = await create_initial_organization(
        session, current, slug="first-bootstrap", display_name="First Bootstrap"
    )
    second = await create_initial_organization(
        session, current, slug="second-bootstrap", display_name="Second Bootstrap"
    )
    owner_organizations = set(
        (
            await session.scalars(
                select(RoleAssignment.organization_id).where(
                    RoleAssignment.principal_id == administrator.id,
                    RoleAssignment.role == "owner",
                    RoleAssignment.collection_id.is_(None),
                )
            )
        ).all()
    )

    assert {first.id, second.id}.issubset(owner_organizations)
    assert current.browser_session is not None
    assert current.browser_session.active_organization_id == second.id


@pytest.mark.asyncio
async def test_instance_administrator_does_not_bypass_pat_or_collection_publication_boundaries(
    session, organization: Organization
) -> None:
    administrator = await create_principal(session, organization)
    session.add(InstanceAdministrator(principal_id=administrator.id))
    other_organization = Organization(slug="other-boundary", display_name="Other Boundary")
    session.add(other_organization)
    await session.flush()
    collection = Collection(
        organization_id=other_organization.id, slug="unpublished", display_name="Unpublished"
    )
    session.add(collection)
    await session.commit()

    _, token = await issue_pat(
        session,
        administrator,
        organization.id,
        "single-organization",
        {"tool:discover"},
        timedelta(days=1),
        Settings(),
    )
    authenticated = await authenticate_token(session, token)

    assert authenticated is not None
    assert authenticated.organization_id == organization.id
    assert not await authorized_collection_ids(
        session, administrator, "tool:discover", [collection]
    )


@pytest.mark.asyncio
async def test_instance_administrator_narrow_pat_does_not_inherit_browser_superuser_access(
    session, organization: Organization
) -> None:
    administrator = await create_principal(session, organization, "viewer")
    session.add(InstanceAdministrator(principal_id=administrator.id))
    await session.commit()
    _, token = await issue_pat(
        session,
        administrator,
        organization.id,
        "read-only-instance-admin",
        {"server:read"},
        timedelta(days=1),
        Settings(),
    )
    pat_current = await authenticate_token(session, token)

    assert pat_current is not None
    assert pat_current.credential_context == "pat"
    assert not (
        await authorize(
            session,
            administrator,
            "server:create",
            context={"organization_id": organization.id},
            credential_context=pat_current.credential_context,
        )
    ).allowed
    assert "server:create" not in await effective_permissions(
        session,
        administrator,
        organization.id,
        credential_context=pat_current.credential_context,
    )


@pytest.mark.asyncio
async def test_instance_administrator_browser_context_expands_organizations_but_pat_does_not(
    session, organization: Organization
) -> None:
    administrator = await create_principal(session, organization)
    other = Organization(slug="other-context", display_name="Other Context")
    session.add_all([other, InstanceAdministrator(principal_id=administrator.id)])
    await session.commit()
    _, browser_token = await issue_browser_session(session, administrator, [], Settings())
    _, pat_token = await issue_pat(
        session,
        administrator,
        organization.id,
        "organization-reader",
        {"server:read"},
        timedelta(days=1),
        Settings(),
    )

    browser_current = await authenticate_browser_session(session, browser_token)
    pat_current = await authenticate_token(session, pat_token)

    assert browser_current is not None
    assert pat_current is not None
    assert {item.id for item in await available_organizations(session, browser_current)} == {
        organization.id,
        other.id,
    }
    assert [item.id for item in await available_organizations(session, pat_current)] == [
        organization.id
    ]
    assert not await select_active_organization(session, pat_current, other.id)
    assert await select_active_organization(session, browser_current, other.id)


@pytest.mark.asyncio
async def test_organization_switch_persists_org_and_csrf_epoch_together(
    session_factory: async_sessionmaker[AsyncSession], session, organization: Organization
) -> None:
    administrator = await create_principal(session, organization)
    other = Organization(slug="switch-target", display_name="Switch Target")
    session.add_all([other, InstanceAdministrator(principal_id=administrator.id)])
    await session.commit()
    _, browser_token = await issue_browser_session(session, administrator, [], Settings())
    current = await authenticate_browser_session(session, browser_token)
    assert current is not None and current.browser_session is not None
    settings = Settings()
    browser_session_id = current.browser_session.id
    old_token = csrf_token_for(current.browser_session, settings)
    old_epoch = current.browser_session.csrf_epoch
    assert csrf_token_valid(current.browser_session, old_token, settings)

    assert await select_active_organization(session, current, other.id)

    async with session_factory() as fresh:
        stored = await fresh.get(BrowserSession, browser_session_id)
    assert stored is not None
    assert stored.active_organization_id == other.id
    assert stored.csrf_epoch == old_epoch + 1
    assert not csrf_token_valid(stored, old_token, settings)
    assert csrf_token_valid(stored, csrf_token_for(stored, settings), settings)


@pytest.mark.asyncio
async def test_initial_organization_creation_rotates_csrf_epoch_and_rolls_back_on_duplicate(
    session_factory: async_sessionmaker[AsyncSession], session
) -> None:
    administrator = Principal(identifier="bootstrap-csrf", display_name="Bootstrap Administrator")
    session.add(administrator)
    await session.flush()
    session.add(InstanceAdministrator(principal_id=administrator.id))
    await session.commit()
    browser_session, browser_token = await issue_browser_session(
        session, administrator, [], Settings()
    )
    current = await authenticate_browser_session(session, browser_token)
    assert current is not None and current.browser_session is not None
    settings = Settings()
    old_token = csrf_token_for(current.browser_session, settings)
    epoch_before = current.browser_session.csrf_epoch

    created = await create_initial_organization(
        session, current, slug="csrf-bootstrap", display_name="CSRF Bootstrap"
    )
    epoch_after_create = current.browser_session.csrf_epoch
    created_id = created.id
    assert epoch_after_create == epoch_before + 1
    assert not csrf_token_valid(current.browser_session, old_token, settings)

    with pytest.raises(OrganizationBootstrapError) as error:
        await create_initial_organization(
            session, current, slug="csrf-bootstrap", display_name="Duplicate"
        )
    assert error.value.category == "duplicate_slug"
    assert current.browser_session.csrf_epoch == epoch_after_create
    async with session_factory() as fresh:
        stored = await fresh.get(BrowserSession, browser_session.id)
    assert stored is not None
    assert stored.csrf_epoch == epoch_after_create
    assert stored.active_organization_id == created_id


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
        session, principal, ["verified-group"], Settings()
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
    browser_session, token = await issue_browser_session(session, principal, [], Settings())
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
async def test_group_mapping_grants_only_matching_verified_group(
    session, organization: Organization
) -> None:
    principal = Principal(identifier="provider-user", display_name="Provider User")
    group = ExternalGroup(
        organization_id=organization.id,
        external_id="shared-group",
        display_name="Engineering",
    )
    collection = Collection(
        organization_id=organization.id, slug="provider", display_name="Provider"
    )
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
            verified_group_ids=frozenset({"shared-group"}),
        )
    ).allowed
    assert (
        await authorize(
            session,
            principal,
            "collection:read",
            collection,
            verified_group_ids=frozenset({"other-group"}),
        )
    ).reason == "missing_permission"
