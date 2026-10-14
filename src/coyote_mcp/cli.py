import asyncio
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from coyote_mcp.auth import ALL_ACTIONS, issue_pat
from coyote_mcp.db import SessionLocal
from coyote_mcp.models import Organization, Principal, RoleAssignment
from coyote_mcp.settings import Settings


async def bootstrap_admin() -> int:
    settings = Settings()
    async with SessionLocal() as session:
        organization = await session.scalar(
            select(Organization).where(Organization.slug == settings.default_organization_slug)
        )
        try:
            if organization is None:
                organization = Organization(
                    slug=settings.default_organization_slug,
                    display_name=settings.default_organization_display_name,
                )
                session.add(organization)
                await session.flush()
            owner = await session.scalar(
                select(Principal).where(
                    Principal.organization_id == organization.id,
                    Principal.identifier == "bootstrap-admin",
                )
            )
            if owner is not None:
                await session.rollback()
                print("Bootstrap already completed; use the documented recovery procedure.")
                return 1
            owner = Principal(
                organization_id=organization.id,
                identifier="bootstrap-admin",
                display_name="Bootstrap Administrator",
                identity_type="human",
            )
            session.add(owner)
            await session.flush()
            session.add(
                RoleAssignment(organization_id=organization.id, principal_id=owner.id, role="owner")
            )
            await session.flush()
            _, plaintext = await issue_pat(
                session,
                owner,
                "bootstrap",
                set(ALL_ACTIONS),
                timedelta(seconds=settings.pat_max_lifetime_seconds),
                settings,
                commit=False,
            )
            await session.commit()
        except IntegrityError:
            await session.rollback()
            print("Bootstrap already completed; use the documented recovery procedure.")
            return 1
        print("Store this bootstrap PAT now; it will not be displayed again:")
        print(plaintext)
        return 0


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="coyote-mcp")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("bootstrap-admin")
    args = parser.parse_args()
    if args.command == "bootstrap-admin":
        raise SystemExit(asyncio.run(bootstrap_admin()))
