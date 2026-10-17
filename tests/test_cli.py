from sqlalchemy import select

from coyote_mcp import cli
from coyote_mcp.models import ExternalIdentity, InstanceAdministrator


class SessionContext:
    def __init__(self, session) -> None:
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        return None


async def test_bootstrap_instance_administrator_creates_binding(
    session, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(cli, "SessionLocal", lambda: SessionContext(session))

    assert await cli.bootstrap_instance_administrator("https://issuer.example", "subject-123") == 0
    output = capsys.readouterr().out
    assert "Instance administrator bound" in output

    identity = await session.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.issuer == "https://issuer.example",
            ExternalIdentity.subject == "subject-123",
        )
    )
    assert identity is not None
    assert await session.get(InstanceAdministrator, identity.principal_id) is not None

    assert await cli.bootstrap_instance_administrator("https://issuer.example", "subject-123") == 0
    assert "Instance administrator bound" in capsys.readouterr().out
