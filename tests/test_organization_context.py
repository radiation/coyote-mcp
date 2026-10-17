import asyncio
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from coyote_mcp.auth import AuthenticatedPrincipal, authorize
from coyote_mcp.models import Organization, OrganizationMembership, Principal, RoleAssignment


@pytest.mark.asyncio
async def test_organization_context_is_immutable_for_shared_global_principal(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as setup_session:
        first = Organization(slug="first", display_name="First")
        second = Organization(slug="second", display_name="Second")
        principal = Principal(identifier="shared", display_name="Shared")
        setup_session.add_all([first, second, principal])
        await setup_session.flush()
        setup_session.add_all(
            [
                OrganizationMembership(organization_id=first.id, principal_id=principal.id),
                OrganizationMembership(organization_id=second.id, principal_id=principal.id),
                RoleAssignment(organization_id=first.id, principal_id=principal.id, role="viewer"),
                RoleAssignment(organization_id=second.id, principal_id=principal.id, role="owner"),
            ]
        )
        await setup_session.commit()
        principal_id = principal.id
        first_id = first.id
        second_id = second.id

    async with session_factory() as first_session, session_factory() as second_session:
        shared_principal = await first_session.get(Principal, principal_id)
        assert shared_principal is not None
        first_context = AuthenticatedPrincipal(
            shared_principal, frozenset({"server:read"}), None, first_id
        )
        second_context = AuthenticatedPrincipal(
            shared_principal, frozenset({"server:create"}), None, second_id
        )

        async def decision(session: AsyncSession, organization_id: UUID, action: str) -> bool:
            return (
                await authorize(
                    session,
                    shared_principal,
                    action,
                    context={"organization_id": organization_id},
                )
            ).allowed

        first_allowed, second_allowed = await asyncio.gather(
            decision(first_session, first_context.require_organization_id(), "server:read"),
            decision(second_session, second_context.require_organization_id(), "server:create"),
        )

    assert first_allowed
    assert second_allowed
    assert first_context.organization_id == first_id
    assert second_context.organization_id == second_id
    assert not hasattr(shared_principal, "organization_id")
