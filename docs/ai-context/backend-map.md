# Backend map

## Modules

| Area | Current responsibility |
| --- | --- |
| `app.py` | Builds FastAPI/FastMCP applications, mounts REST/OIDC routes, authenticates PAT-only MCP requests, and serves global plus request-scoped collection MCP endpoints. |
| `console.py` | Server-rendered `/console` routes. Resolves browser sessions only, persists selection/switching of an active organization server-side with CSRF protection, and reuses centralized authorization for organization-scoped pages. |
| `api.py` | Authenticated control-plane endpoints for catalog, PATs, service principals, groups, and mappings. |
| `catalog.py` | Organization-scoped server, collection, membership, catalog, and collection tool-publication queries. |
| `discovery.py` | Streamable HTTP tool discovery, pinned HTTP transport, reconciliation, and generation-safe sync. |
| `gateway.py` | Publication-gated persisted-catalog MCP search, description, collection endpoint publication, execution-time authorization snapshots, spawned and resource-bounded schema validation, escaped lexical search, bounded downstream invocation, and result sanitization. Global and native endpoints resolve enabled collection publication records for discovery and invocation. |
| `auth.py` | PAT/browser authentication, immutable authenticated organization context, session lifecycle, memberships, roles, group mappings, centralized authorization, and batched collection-grant evaluation. |
| `oidc.py` | Settings-configured single-provider OIDC discovery, PKCE login, browser binding, code exchange, ID-token validation, and logout/CSRF flows. |
| `security.py` | Destination, public-address, scheme, and OIDC trust-boundary validation. |
| `models.py` | SQLAlchemy persistence model and tenant-scoped constraints. |
| `schemas.py` | Pydantic API request/response contracts. |
| `db.py`, `settings.py` | Async database session factory and environment-only OIDC configuration rules. |
| `cli.py` | Operator-only trusted issuer/subject binding for instance-administrator bootstrap and recovery; it never issues a PAT or browser session. |
| `scripts/mock_mcp_server.py` | Compose-profile-only FastMCP mock exposing deterministic echo, addition, and failure tools. |
| `scripts/smoke_mcp.py` | Live local smoke runner: temporary tenant bootstrap/cleanup plus REST and authenticated MCP workflow validation. |
| `alembic/` | Additive schema history through the current identity, session, and provider-secret revisions. |

## Key execution paths

1. A REST request resolves a PAT or browser session in `dependencies.py`; API
   endpoints call `api.require`, which delegates policy evaluation to
   `auth.authorize`.
2. Server synchronization validates and DNS-pins the endpoint, discovers tools
   through FastMCP, then reconciles persisted tools only if its generation is
   current.
3. An MCP client presents a PAT to `/mcp`; FastMCP exposes universal search,
   describe, and execute tools. Each operation reloads persisted records and
   re-evaluates centralized authorization before it returns metadata or invokes
   a DNS-pinned registered endpoint.
4. OIDC login loads the single instance provider from validated environment
   settings, stores a short-lived transaction and browser binding server-side, then atomically
   consumes it, validates the ID token, resolves a global `(issuer, subject)`
   identity, and issues an opaque persisted session. The console selects the
   active enabled organization membership with a CSRF-protected POST.
5. A browser request to `/console` resolves that persisted session, evaluates
   page permission through `auth.authorize`, then renders Jinja2 HTML. HTMX
   requests receive only the content fragment; no console route mutates data in
   Phase 4A.

## Extension points

- Add protected control-plane operations through the existing API dependency and
  `require` path, with service-level authorization.
- Add persistence through a new Alembic revision and matching SQLAlchemy model,
  constraints, Pydantic contracts, and tests.
- Add downstream transport/auth support only through the validated discovery
   boundary. Execution currently supports registered unauthenticated Streamable
   HTTP servers only.
- `tests/test_gateway.py` hosts a deterministic local FastMCP Streamable HTTP
   server with Uvicorn for execution integration tests. It verifies discovery,
   description, execution, structured tool errors, timeout/connection failures,
   result-size bounds, and absence of forwarded coyote PAT headers.
- `docker compose --profile smoke` starts a separate internal `smoke-mcp`
   FastMCP service. The application only allowlists that hostname for private
   HTTP destinations; `scripts/smoke_mcp.py` exercises the running Compose
   control plane and MCP endpoint, then removes its unique temporary tenants.
