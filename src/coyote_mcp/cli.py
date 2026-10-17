import asyncio

from coyote_mcp.auth import resolve_external_identity
from coyote_mcp.db import SessionLocal
from coyote_mcp.models import InstanceAdministrator


async def bootstrap_instance_administrator(issuer: str, subject: str) -> int:
    """Record a trusted OIDC issuer/subject binding as an instance administrator.

    This operator-only recovery command does not validate an OIDC assertion and
    never emits a browser credential or PAT. Normal browser login validates OIDC
    claims before issuing a session.
    """
    async with SessionLocal() as session:
        principal = await resolve_external_identity(
            session,
            issuer=issuer,
            subject=subject,
            email=None,
            display_name=None,
            jit_provisioning_enabled=True,
        )
        if await session.get(InstanceAdministrator, principal.id) is None:
            session.add(InstanceAdministrator(principal_id=principal.id))
            await session.commit()
        print(f"Instance administrator bound to principal {principal.identifier}.")
    return 0


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="coyote-mcp")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("bootstrap-instance-admin", "recover-instance-admin"):
        command_parser = subcommands.add_parser(command)
        command_parser.add_argument("--issuer", required=True)
        command_parser.add_argument("--subject", required=True)
    args = parser.parse_args()
    if args.command in {"bootstrap-instance-admin", "recover-instance-admin"}:
        raise SystemExit(asyncio.run(bootstrap_instance_administrator(args.issuer, args.subject)))
