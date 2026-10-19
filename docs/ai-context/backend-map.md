# Backend map

## Modules

| Area | Current responsibility |
| --- | --- |
| `app.py` | Builds FastAPI/FastMCP applications, mounts REST/OIDC routes, authenticates PAT-only MCP requests, and serves global plus request-scoped collection MCP endpoints. |
| `audit.py` | Central append-only audit-event persistence service. It validates enum-backed actions and bounded allowlisted metadata, adds and flushes events in a caller-owned transaction, and never commits independently. |
| `console.py` | Server-rendered `/console` routes. Resolves browser sessions only, persists selection/switching of an active organization server-side with CSRF protection, and reuses centralized authorization for organization-scoped pages. `GET /console/organizations` always renders the selector for an authenticated browser session, including sessions with an active organization. Instance administrators can select any enabled organization and create departments. Server, collection, membership, and tool-publication pages delegate all state changes to `catalog.py` services. |
| `api.py` | Authenticated control-plane endpoints for catalog, PATs, service principals, groups, and mappings. |
| `catalog.py` | Organization-scoped server, collection, membership, catalog, and collection tool-publication queries and mutations. Publication services check for alias and tool conflicts, use savepoints for constraint violations, and bound list queries. |
| `discovery.py` | Streamable HTTP tool discovery, pinned HTTP transport, reconciliation, and generation-safe sync. |
| `credential_vault.py` | AES-256-GCM sealing with key versions and domain-prefixed AAD. Used only for downstream secrets, tokens, and PKCE verifiers. |
| `credentials.py` | Credential broker for `none`, `shared_bearer`, and `per_user_oauth`. Returns per-call authorization headers, rejects service-principal personal credentials, and marks rejected connections for reauthorization. |
| `downstream_oauth.py` | Reusable OAuth authorization-code protocol pieces: PKCE, state, the GitHub preset, validated token exchange, and token-set redaction. |
| `downstream_errors.py` | Leaf module with the sanitized downstream authorization error type, shared without an import cycle. |
| `connected_apps.py` | Self-service Connected Apps and administrator integration services: start, complete, and disconnect connections, plus policy and shared-credential writes. |
| `gateway.py` | Publication-gated persisted-catalog MCP search, description, collection endpoint publication, execution-time authorization snapshots, spawned and resource-bounded schema validation, escaped lexical search, bounded downstream invocation, and result sanitization. Global and native endpoints resolve enabled collection publication records for discovery and invocation. Execution attaches only the broker-selected downstream credential for the caller. |
| `auth.py` | PAT/browser authentication, immutable authenticated organization context, session lifecycle, memberships, roles, group mappings, browser-session-only instance-admin authorization, organization creation, and batched collection-grant evaluation. |
| `oidc.py` | Settings-configured single-provider OIDC discovery, PKCE login, browser binding, code exchange, ID-token validation, and logout/CSRF flows. |
| `security.py` | Destination, public-address, scheme, and OIDC trust-boundary validation. |
| `models.py` | SQLAlchemy persistence model and tenant-scoped constraints, including immutable audit-event schema constraints. |
| `schemas.py` | Pydantic API request/response contracts. |
| `db.py`, `settings.py`, `runtime.py` | Async database session factory and shutdown disposal; development-compatible but fail-closed production settings; trusted-proxy forwarding, host validation, canonical public origin, and request correlation. |
| `cli.py` | Operator-only trusted issuer/subject binding for instance-administrator bootstrap and recovery; it never issues a PAT or browser session. |
| `scripts/mock_mcp_server.py` | Compose-profile-only FastMCP mock exposing deterministic echo, addition, and failure tools. |
| `scripts/smoke_mcp.py` | Live local smoke runner: temporary tenant bootstrap/cleanup plus REST and authenticated MCP workflow validation. |
| `alembic/` | Additive schema history through the downstream credential revision (`0019`: policy column, shared credentials, OAuth integrations, connections, and transactions). |

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
   active enabled organization with a CSRF-protected POST. An authenticated
   browser session can reopen the selector at `GET /console/organizations`,
   even when an organization is already active. A global instance administrator
   can select any enabled organization without a membership and create
   departments through the console; creation atomically grants an owner
   membership only in the new department and selects it in the session.
5. A browser request to `/console` resolves that persisted session, evaluates
   page permission through `auth.authorize`, then renders Jinja2 HTML. HTMX
   requests receive only the content fragment. Console writes pass CSRF
   validation, resolve the active organization, and call catalog or
   organization services for authorization and persistence. Current writes
   cover instance-admin department creation, server registration, edit, enable,
   disable, discovery refresh, and removal, collection create/edit/enable and
   membership changes, and tool publication create, edit, and unpublish.
6. Production ingress validates the `Host` header, accepts forwarded scheme and
   upstream request IDs only when the direct peer is an allowlisted proxy
   network, generates a request ID otherwise, and returns it as
   `X-Request-ID`. Console collection endpoint display uses the configured
   public origin rather than request-derived host data.

## Extension points

- Add protected control-plane operations through the existing API dependency and
  `require` path, with service-level authorization.
- Add persistence through a new Alembic revision and matching SQLAlchemy model,
  constraints, Pydantic contracts, and tests.
- Add downstream transport/auth support only through the validated discovery
   boundary and the credential broker. Authentication policies are `none`,
   `shared_bearer`, and `per_user_oauth`; new policies must be added to the
   broker, the policy check constraint, and the authorization tests together.
- `tests/test_gateway.py` hosts a deterministic local FastMCP Streamable HTTP
   server with Uvicorn for execution integration tests. It verifies discovery,
   description, execution, structured tool errors, timeout/connection failures,
   result-size bounds, and absence of forwarded coyote PAT headers.
- `docker compose --profile smoke` starts a separate internal `smoke-mcp`
   FastMCP service. The application only allowlists that hostname for private
   HTTP destinations; `scripts/smoke_mcp.py` exercises the running Compose
   control plane and MCP endpoint, then removes its unique temporary tenants.
