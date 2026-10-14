# coyote-mcp

Collection-aware enterprise MCP gateway. Phase 1 persists downstream server
registrations, discovers their advertised tools, and exposes a PostgreSQL-backed
catalog grouped into collections.

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

## Registry and catalog

The REST API is development-bound to `127.0.0.1:8000` by Compose. Authentication
and authorization are deliberately not part of this phase, so do not expose its
administrative routes publicly.

Register a Streamable HTTP MCP server (registration does not contact the server):

```bash
curl -X POST http://localhost:8000/api/v1/servers \
  -H 'content-type: application/json' \
  -d '{
    "name": "weather",
    "display_name": "Weather",
    "endpoint": "https://mcp.example.com/mcp"
  }'
```

Create a collection and add that server using the IDs returned by the API:

```bash
curl -X POST http://localhost:8000/api/v1/collections \
  -H 'content-type: application/json' \
  -d '{"slug":"engineering","display_name":"Engineering tools"}'

curl -X POST http://localhost:8000/api/v1/collections/<collection-id>/servers \
  -H 'content-type: application/json' \
  -d '{"server_id":"<server-id>"}'
```

Synchronize advertised tools, then query the persisted catalog:

```bash
curl -X POST http://localhost:8000/api/v1/servers/<server-id>/sync
curl http://localhost:8000/api/v1/servers/<server-id>/tools?limit=50&offset=0
curl http://localhost:8000/api/v1/collections/<collection-id>/tools?limit=50&offset=0
```

Only public HTTPS endpoints are accepted by default. Internal-network servers and
plain HTTP require both `ALLOW_PRIVATE_ENDPOINTS=true` and
`ALLOW_INSECURE_ENDPOINTS=true` as explicit deployment configuration. Redirects
are not followed during discovery; this prevents a safe public endpoint from
redirecting to an unsafe destination. Credentials must be provided through a
future secret-management/authentication mechanism, never embedded in an endpoint URL.

## Checks

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src/
uv run pytest
```

To run the optional PostgreSQL integration suite against the Compose database
after `docker compose up --build -d`:

```bash
POSTGRES_INTEGRATION_URL='postgresql+asyncpg://coyote:localdev-only@127.0.0.1:5432/coyote_mcp' \
  uv run pytest tests/test_postgres_integration.py
```

## Explicitly not implemented yet

- Tool execution routing
- PAT/OIDC authentication and authorization
- Search, embedding index, and collection filtering
- HTMX dashboard (Jinja2 is provisioned only)
- Metrics, audits, and production hardening

Discovery currently supports Streamable HTTP only. Catalog results come from the
database and do not make downstream requests; failed discovery leaves the prior
tool catalog intact.

Each synchronization claims a PostgreSQL row lock briefly, increments a server
generation counter, then performs network discovery without holding the lock.
Completion re-locks the row and applies results only when its generation remains
current. This prevents stale or concurrent syncs from overwriting newer catalog
state while keeping long network operations out of database transactions.
