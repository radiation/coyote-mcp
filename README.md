# coyote-mcp

Collection-aware enterprise MCP gateway **starter**, not a production-ready gateway.

## Principles

- Collections are many-to-many organizational/discovery groups; membership does not grant permissions.
- Keep a stable discovery API and selectively expose curated native MCP tools.
- Separate control plane metadata from invocation-time authorization.
- Do not invoke arbitrary registered remote endpoints without SSRF protections and verified credentials.
- Tool schemas and labels are untrusted until publisher-approved.

## Bootstrap

```bash
uv python install 3.14
uv sync
uv run pre-commit install --hook-type pre-commit --hook-type pre-push
docker compose up --build -d
```

Compose starts PostgreSQL, runs the Alembic migration as a one-shot service, and
starts the app only after migrations complete successfully. The application source
and Alembic files are mounted for development, and Uvicorn reloads on source changes.
Visit `http://localhost:8000/healthz`. MCP is mounted at `/mcp/`.

Alembic configuration is in the repository-root `alembic.ini`; the environment
and revision scripts are under `alembic/` and `alembic/versions/`.

## Checks

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src/
uv run pytest
```

## Explicitly not implemented yet

- Server registration API and endpoint validation
- Downstream server connection, reconciliation, and tool invocation
- PAT/OIDC authentication and authorization
- Search, embedding index, and collection filtering
- HTMX dashboard (Jinja2 is provisioned only)
- Metrics, audits, and production hardening

The tables are an intentionally small first migration. Tool schema versioning, server credentials, metadata trust, collection membership rules, tenants, and policy records will follow after we agree on their semantics.
