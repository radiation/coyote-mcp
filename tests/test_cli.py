from coyote_mcp import cli
from coyote_mcp.models import PersonalAccessToken


class SessionContext:
    def __init__(self, session) -> None:
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        return None


async def test_bootstrap_admin_creates_once_and_never_reprints_token(
    session, monkeypatch, capsys
) -> None:
    async def issue_bootstrap_pat(
        database_session, principal, name, scopes, lifetime, settings, *, commit
    ):
        assert database_session is session
        assert principal.identifier == "bootstrap-admin"
        assert name == "bootstrap"
        assert scopes == cli.ALL_ACTIONS
        assert lifetime.total_seconds() == settings.pat_max_lifetime_seconds
        assert commit is False
        return PersonalAccessToken(), "coyote_pat_test_secret"

    monkeypatch.setattr(cli, "SessionLocal", lambda: SessionContext(session))
    monkeypatch.setattr(cli, "issue_pat", issue_bootstrap_pat)

    assert await cli.bootstrap_admin() == 0
    assert "coyote_pat_test_secret" in capsys.readouterr().out

    assert await cli.bootstrap_admin() == 1
    output = capsys.readouterr().out
    assert "Bootstrap already completed" in output
    assert "coyote_pat_test_secret" not in output
