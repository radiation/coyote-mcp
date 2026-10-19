# coyote-mcp

[![CI](https://github.com/radiation/coyote-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/radiation/coyote-mcp/actions/workflows/ci.yml)
[![CodeQL](https://github.com/radiation/coyote-mcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/radiation/coyote-mcp/actions/workflows/codeql.yml)
[![Codecov](https://codecov.io/gh/radiation/coyote-mcp/graph/badge.svg)](https://codecov.io/gh/radiation/coyote-mcp)

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

## Phase 2A authentication and authorization

Phase 2A introduces one configured organization boundary. The `0004` migration
creates the `default` organization and assigns every existing server, collection,
tool membership, principal, role assignment, and credential to it. Existing
installations must apply the migration before starting the app:

```bash
uv run alembic upgrade head
```

No privileged credential is created during startup or migration. Establish the
initial instance administrator through the trusted OIDC issuer/subject binding
described in [Enterprise identity](#enterprise-identity). Issue PATs only through
an authenticated administrative flow and store them in an approved secret
manager. Lost administrator access requires a deliberate break-glass database
recovery performed by an operator. There is no application backdoor.

All `/api/v1` catalog and management endpoints now require a PAT:

```bash
curl http://localhost:8000/api/v1/servers \
  -H "Authorization: Bearer $COYOTE_PAT"
```

Create and display a new PAT once using an existing credential:

```bash
curl -X POST http://localhost:8000/api/v1/me/pats \
  -H "Authorization: Bearer $COYOTE_PAT" \
  -H 'content-type: application/json' \
  -d '{"name":"ci","scopes":["server:read","tool:discover"],"lifetime_seconds":2592000}'
```

PATs are opaque `coyote_pat_` bearer tokens. Only a SHA-256 verifier is stored;
tokens have a required, configurable maximum lifetime (90 days by default), and
are rejected immediately after expiry, revocation, or principal disablement.
Requested scopes are attenuated against the principal's role permissions.

Built-in roles are `owner`, `administrator`, `maintainer`, `consumer`, and
`viewer`. Owners manage every action, administrators manage all operational
actions except policy management, maintainers manage registry and collections,
consumers discover/describe/execute tools, and viewers discover/describe tools.
Assignments can be organization-wide or collection-scoped. Collection-scoped
assignments grant permissions only for that collection and never organization-wide
server management. Authorization defaults to deny; hidden cross-organization
resources return 404.

FastMCP protocol endpoints are deliberately disabled with `503` in this phase,
because the protocol adapter cannot yet enforce the shared policy layer. Health
checks remain unauthenticated. Phase 2A does not include OIDC, group
synchronization, OAuth token exchange, ABAC/policy DSLs, administration UI, or
MCP tool execution routing.

## Enterprise identity

Each deployment uses one enterprise OpenID Connect provider. It is configured
only through settings, not through a database record or control-plane API. For
local development, copy `.env.example` to `.env` and set these values:

```dotenv
OIDC_ISSUER=https://login.example.com
OIDC_CLIENT_ID=replace-with-client-id
OIDC_CLIENT_SECRET=replace-with-client-secret
OIDC_REDIRECT_URI=http://localhost:8000/auth/oidc/callback
```

Register the exact `OIDC_REDIRECT_URI` with the provider. The deployed callback
route is always `/auth/oidc/callback`; settings reject a URI with another path,
a query string, or a fragment. Production injects the same `OIDC_*` settings
through its secret manager, uses an HTTPS issuer and callback, and must set a
high-entropy `SESSION_SECRET_KEY` of at least 32 characters. `.env` is ignored
by Git and must never be committed. For local development with the callback at
`http://localhost:8000/auth/oidc/callback`, begin login at
`http://localhost:8000`, not `http://127.0.0.1:8000`: the browser-binding cookie
is host-only and is intentionally not shared between those origins.

Optional settings are `OIDC_ALLOWED_ORGANIZATION`, `OIDC_GROUP_CLAIM`,
`OIDC_TRUSTED_ENDPOINT_HOSTS` (a JSON list), and
`OIDC_JIT_PROVISIONING_ENABLED`. Trusted endpoint hosts are only needed when a
provider's discovery metadata references a host other than the issuer host.

Apply migrations, then record the trusted issuer/subject binding for the first
instance administrator:

```bash
uv run alembic upgrade head
uv run coyote-mcp bootstrap-instance-admin \
  --issuer https://login.example.com \
  --subject <trusted-subject>
```

Fresh deployments have no organizations after migration. The bootstrapped
instance administrator creates the first department from `/console`.

This operator-only command does not validate an OIDC assertion and never emits a
browser credential or PAT. Normal browser login begins at `/auth/oidc/login` and
validates the OIDC assertion before issuing a session.

After the bootstrapped administrator signs in at `/console`, they can select any
enabled organization and use the CSRF-protected form to create a department.
Instance administrators administer enabled organizations without synthetic
memberships or owner roles, which supports ownerless-department recovery.
Creation atomically grants the new department's enabled membership and
organization-scoped `owner` role, then selects it in the server-side browser
session. Ordinary authenticated users can select only their enabled memberships
and cannot use the creation endpoint directly. PATs remain scoped to a single
organization, and MCP discovery/execution still requires explicit publication.

The authorization-code exchange uses PKCE S256, state, and nonce. Discovery
metadata and JWKS are retrieved from the configured issuer; the application
validates the signature, issuer, audience, expiry, subject, and nonce before
establishing a session. Missing or invalid OIDC settings fail closed. Browser
session cookies are opaque, HTTP-only, `SameSite=Lax`, and server-side; session
mutations, including logout, require the `X-CSRF-Token` returned by `GET /auth/oidc/csrf`. Bearer
authentication takes precedence whenever an `Authorization` header is present:
an invalid bearer token returns `401` and never falls back to a browser session.
Browser sessions are not accepted by MCP; the protocol endpoint requires a PAT.

External accounts are bound immutably by `(issuer, subject)`. Email is display
metadata only and is never used to link accounts. Users receive access through
explicit organization memberships, RBAC assignments, or validated group-claim
mappings. Set `OIDC_JIT_PROVISIONING_ENABLED` only when first-login provisioning
is intended; provisioned humans receive no roles. Disabled principals,
organizations, or memberships cannot authenticate into an organization.

External group IDs come only from the validated ID-token group claim. Map a
stable external group ID to one or more built-in roles at organization or
collection scope; direct principal assignments continue to work alongside those
mappings. Group-derived access fails closed when claims are absent, malformed,
or marked incomplete. Browser sessions persist only a hashed opaque verifier,
active organization, and CSRF material; they never persist ID or refresh tokens.
OIDC state, nonce, and PKCE verifier are stored in a separate short-lived,
single-use transaction bound to an initiating-browser HttpOnly cookie.

OIDC discovery, authorization, token, and JWKS URLs must be HTTPS except for
explicit local development overrides. Every endpoint must resolve to a public
address unless the local override is enabled; redirects are disabled and
requests are DNS-pinned. Endpoints must use the issuer host or an explicitly
configured trusted endpoint host.

Owners can create, list, disable, and revoke scoped PATs for service principals.
Service principals use `identity_type=service` and are distinct from user
sessions. Credential scopes are constrained to the service principal's direct
roles and the administering owner's effective permissions; no service-principal
endpoint permits self-assignment or privilege escalation. OAuth client
credentials, token exchange, and delegated workload execution are deferred to
Phase 3.

## Registry and catalog

The REST API is development-bound to `127.0.0.1:8000` by Compose. It requires
an authenticated, authorized PAT even in development.

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
plain HTTP require either explicit broad development configuration or a matching
entry in `ALLOWED_PRIVATE_ENDPOINT_HOSTS` and
`ALLOWED_INSECURE_ENDPOINT_HOSTS`, respectively. The host allowlists are the
preferred way to permit a known local service without enabling access to all
private or insecure destinations. Redirects are not followed during discovery;
this prevents a safe public endpoint from redirecting to an unsafe destination.
Credentials must be provided through a future secret-management/authentication
mechanism, never embedded in an endpoint URL.

## Phase 3A MCP gateway

`/mcp` is a FastMCP Streamable HTTP endpoint. It accepts only coyote PAT bearer
tokens, rejecting missing, invalid, expired, revoked, disabled-principal, and
browser-session credentials. The installed MCP SDK supports protocol versions
`2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, and `2026-07-28`.

After protocol negotiation, the gateway publishes exactly three tools:

- `coyote_search_tools(query, collection_slug?, limit?)` returns compact active
  catalog records for currently authorized collections, without schemas.
- `coyote_describe_tool(tool_id, collection_slug?)` returns the published input
  schema and authorized metadata for one active catalog tool.
- `coyote_execute_tool(tool_id, arguments, collection_slug?)` validates stored
  JSON Schema input and invokes the registered Streamable HTTP server.

The gateway filters tenants and authorization before pagination or metadata
returns. It reloads the persisted tool and current authorization for every
description and execution request. A collection-scoped grant requires the
matching collection context and active membership, so a multi-collection tool
cannot be invoked through a collection the caller cannot use. Execution only
uses registered, ready Streamable HTTP destinations and preserves the existing
DNS pinning, public-address checks, redirect restrictions, timeout, and bounded
response protections. The coyote PAT is never forwarded downstream.

For local MCP integration tests, `tests/test_gateway.py` uses FastMCP's real
Streamable HTTP client against the ASGI application, a deterministic SQLite
catalog fixture, and a Uvicorn-hosted local FastMCP downstream server; it has no
external identity-provider or LLM dependency. The configured response-size
limit is checked after FastMCP has materialized a downstream result because the
current public FastMCP transport does not provide a compatible streaming hook.

Phase 3A supports unauthenticated downstream servers only. Downstream credential
delegation, audit/cancellation, fine-grained per-tool deny policies, native tool
aggregation, the HTMX dashboard, pgvector/RAG, and a custom OAuth authorization
server remain out of scope. Tool annotations are untrusted and do not establish
safety.

## Phase 3B.2 collection endpoints

`/mcp/collections/{slug}` is a virtual PAT-authenticated endpoint bound to one
enabled, authorized collection. Collections default to `discovery` exposure,
which publishes the three universal gateway tools while forcing their collection
context to the URL slug. Discovery endpoints continue to publish only the three
universal gateway tools, but their search, description, and execution operations
return only enabled collection tool-publication records. `native` exposure also
publishes only those records for persisted, active tools on ready member
servers. The policy is `Discover -> Curate -> Publish -> Authorize -> Execute`:
synchronization and collection membership populate eligibility only; they never
make a tool visible or executable. Each publication has an administrator-selected,
MCP-compatible alias and optional description override; it remains stable when a
downstream server is renamed and always executes the original downstream identity.

Native publication requires both `tool:discover` and `tool:execute` for the
collection. Administrators list available catalog tools at
`GET /api/v1/collections/{id}/tools`, then create, list, update, disable, or
remove records at `/api/v1/collections/{id}/publications`. Aliases are unique
within a collection and conflicts are rejected; no collision suffixes or silent
renames are generated. Newly synchronized tools remain unpublished by default,
while schema synchronization preserves publication settings. Migration `0012`
creates the publication schema only: both fresh and upgraded collections start
with no publications until an administrator creates them. Global discovery
returns the collection context and published alias for each result. Global
description or execution of a tool published in multiple authorized collections
requires an explicit collection context. Native `tools/list` is rebuilt from
persisted records for every request and does not query
downstream servers. `COYOTE_MAX_NATIVE_TOOLS_PER_COLLECTION` defaults to `100`;
a larger final authorized publication set is rejected as a whole, never truncated.
The installed FastMCP transport does not provide a safe per-principal
`tools/list_changed` broadcaster, so clients refresh `tools/list` to observe
catalog, membership, availability, and exposure changes.

## Phase 4A administration console

`/console` is a read-only, server-rendered administration console. It uses the
existing server-side browser session and centralized RBAC evaluation; it does
not accept PAT bearer credentials and has no separate login mechanism. An
unauthenticated request redirects to `/console/login`, which forwards a supplied
organization slug to the existing `/auth/oidc/login` flow.

The overview requires both `server:read` and `collection:read`, and returns
organization-scoped aggregate counts for registered and ready servers, active
catalog tools, collections, and enabled publications. It also shows recent
server health from persisted registry data. The other console destinations
(`servers`, `collections`, `tools`, `publications`, `principals`, and `tokens`)
are RBAC-protected placeholders for later CRUD phases.

Console pages are complete HTML responses by default. Requests with the HTMX
`HX-Request: true` header receive only the main-content fragment, so future
table and form interactions can update `#console-content` without replacing the
shell. HTMX is loaded from the version-pinned
`https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js` URL; update the explicit
version deliberately when upgrading it. There is no Node build pipeline.

## Phase 4C downstream authentication and Connected Apps

Each registered server has an authentication policy: `none` (the default, used
by DeepWiki), `shared_bearer` (an administrator-stored service credential), or
`per_user_oauth` (each user connects their own account). Administrators set the
policy and manage integrations and shared credentials from the server's
Authentication page in the console.

Users manage connections from **My Profile → Connected Apps**. Connect starts an
OAuth authorization-code flow with PKCE, and Reconnect and Disconnect are
available from the same page. Ordinary enabled members can use these pages.
Coyote never shows tokens or client secrets.

Credentials are sealed with AES-256-GCM. Configure these settings before
connecting an OAuth app or storing a shared credential:

- `COYOTE_CREDENTIAL_ENCRYPTION_KEYS`: a JSON object mapping a version name to a
  base64url-encoded 32-byte key. Generate a key with
  `python -c "import secrets,base64;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"`.
- `COYOTE_CREDENTIAL_ACTIVE_KEY_VERSION`: the version used for new writes.
- `COYOTE_DOWNSTREAM_OAUTH_REDIRECT_BASE_URL`: the public origin used to build the exact
  callback URI `<origin>/console/connected-apps/callback`. Register that URI with
  the OAuth app.

The unprefixed names remain accepted as legacy aliases, but new deployments and
Compose configuration must use the `COYOTE_` names. To rotate, add a new version
to the key map, set it as active, and restart.
Keep old versions until no row needs them. Rows are re-sealed when they are next
written; no automated re-seal command is provided yet.

For local GitHub OAuth development, register
`http://localhost:8000/console/connected-apps/callback` as the OAuth App
callback, set `COYOTE_DOWNSTREAM_OAUTH_REDIRECT_BASE_URL=http://localhost:8000`,
and set `ALLOW_INSECURE_ENDPOINTS=true` while `ENVIRONMENT=development`. HTTP is
accepted only for `localhost`, `127.0.0.1`, or `::1`; private addresses,
container hostnames, and every non-loopback host must use HTTPS.

GitHub is the first provider. Create a GitHub **OAuth App** (not a GitHub App,
which remains a future capability) with the callback URI above, and enter its
client ID and client secret in the server's Authentication page. Requested
scopes are configured by the administrator. Disconnect removes Coyote's stored
credentials, but it cannot revoke the grant at GitHub because no revocation
endpoint is used. Revoke the grant in GitHub settings when needed.

Service principals cannot use personal connections. A browser-session instance
administrator may manage only their own downstream connections in an enabled
organization without a membership; this exception never applies to PATs and
never permits impersonation. A missing or expired connection returns a structured
`connection_required` error to MCP callers.

## Local end-to-end smoke test

The optional `smoke` Compose profile starts an internal FastMCP server with
`echo`, `add`, and a deterministic failing tool. It has no published host port;
only the Compose network can reach it. The application receives narrow private
and insecure destination exceptions for the `smoke-mcp` hostname only.

```bash
docker compose --profile smoke up --build -d
uv run python scripts/smoke_mcp.py
docker compose --profile smoke down
```

The runner creates two unique temporary organizations and short-lived PATs,
registers and synchronizes the internal server through the REST API, creates a
collection and service principal, explicitly publishes the smoke tools and later
unpublishes `echo`, then
uses a real FastMCP client to list, search, describe, execute `echo` and `add`,
and preserve the failing-tool error.
It also verifies cross-organization invisibility and that a revoked service PAT
can no longer establish an MCP session. Temporary resources are deleted in a
`finally` block; the runner never prints bearer tokens. It requires the local
PostgreSQL port exposed by Compose and uses `DATABASE_URL` if supplied.

For a manual MCP Inspector session, provision a PAT through an authenticated
administrative flow. Configure MCP Inspector with Streamable HTTP URL
`http://127.0.0.1:8000/mcp` and an `Authorization: Bearer <PAT>` header. The
mock server is test-only and is not a downstream-authentication or Phase 3B
exercise.

## Checks

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src/
uv run pytest
```

GitHub Actions runs the same lint, formatting, strict type-checking, Alembic
migration, and full test suite on pushes to `main`, pull requests targeting
`main`, and manual dispatches. It uses Python 3.14 and a health-checked pgvector
PostgreSQL service. CI validates only; it does not run the auto-fixing hooks.

### Coverage

CI collects branch coverage for `coyote_mcp`, prints missing lines in the terminal
report, writes `coverage.xml` and `junit.xml`, and requires at least **80%**
coverage. Both reports are uploaded as workflow artifacts when available,
including after a test failure. A non-blocking GitHub check publishes JUnit
results when `checks: write` is available, and the workflow summary records the
test outcome and coverage percentage.

Codecov uploads `coverage.xml` only when the `CODECOV_TOKEN` Actions secret is
available; configure the same secret as a Dependabot secret to report Dependabot
pull requests. This avoids exposing credentials to untrusted fork pull requests,
which still run tests and upload artifacts. Codecov project coverage is enforced
at 80%; patch coverage is initially informational. Reproduce the coverage check
locally with:

```bash
uv run pytest --cov=coyote_mcp --cov-report=term-missing --cov-report=xml
```

### PostgreSQL integration tests

To run the PostgreSQL integration suite locally, start the database, apply
migrations, then explicitly provide its URL. The URL is required so these tests
cannot be mistaken for normal SQLite unit tests:

```bash
docker compose up -d postgres
DATABASE_URL='postgresql+asyncpg://coyote:localdev-only@127.0.0.1:5432/coyote_mcp' \
  uv run alembic upgrade head
POSTGRES_INTEGRATION_URL='postgresql+asyncpg://coyote:localdev-only@127.0.0.1:5432/coyote_mcp' \
  uv run pytest tests/test_postgres_integration.py
```

## Contributor and developer documentation

Read [AGENTS.md](AGENTS.md) before contributing. It links the architectural
invariants in [architecture guardrails](docs/architecture-guardrails.md) and
the concise, source-grounded [AI context](docs/ai-context/) for product,
backend, domain, security, priorities, and prompt guidance.

CodeQL runs separately from CI on pull requests and pushes to `main`, weekly,
and on demand. After the first hosted scan completes, review results in the
repository's **Security** tab under **Code scanning alerts**. A repository
administrator can then add the CodeQL analysis check as a required `main`
branch-protection status check.

### Dependency updates and branch protection

Dependabot checks Python dependencies (from `pyproject.toml` and the committed
`uv.lock`), GitHub Actions, and Docker images weekly. Python minor and patch
updates are grouped; major Python dependency updates remain separate. GitHub
Actions and Docker updates are grouped separately, while Dependabot security
updates retain their normal urgent handling.

To protect `main`, a repository administrator should open **Settings > Branches >
Add branch protection rule**, target `main`, require pull requests before merging,
and enable **Require status checks to pass before merging**. Select the `Validate`
CI status check as required (and optionally require the branch to be up to date).

## Explicitly not implemented yet

- Tool execution routing
- Search, embedding index, and collection filtering
- Console CRUD workflows for servers, collections, publications, principals,
  tokens, and identity providers
- Metrics, audits, and production hardening

Discovery currently supports Streamable HTTP only. Catalog results come from the
database and do not make downstream requests; failed discovery leaves the prior
tool catalog intact.

Each synchronization claims a PostgreSQL row lock briefly, increments a server
generation counter, then performs network discovery without holding the lock.
Completion re-locks the row and applies results only when its generation remains
current. This prevents stale or concurrent syncs from overwriting newer catalog
state while keeping long network operations out of database transactions.
