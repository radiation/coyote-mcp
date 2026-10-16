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

No privileged credential is created during startup or migration. Bootstrap the
initial owner once, after migrations complete:

```bash
uv run coyote-mcp bootstrap-admin
# Or in Compose:
docker compose run --rm app uv run coyote-mcp bootstrap-admin
```

The command prints a bearer token exactly once and refuses to generate another
owner or bootstrap token after success. Store it in an approved secret manager.
Lost administrator access requires a deliberate break-glass database recovery
performed by an operator: create or re-enable a principal, assign `owner` within
the configured organization, and issue a replacement credential through the
same audited operational procedure. There is no application backdoor.

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

## Phase 2B enterprise identity

Phase 2B adds organization-scoped OpenID Connect configuration, external identity
bindings, verified-group role mappings, and managed service principals. Apply the
additive migration before configuring an identity provider:

```bash
uv run alembic upgrade head
```

An owner configures an OIDC provider through the control-plane API. Each
organization currently has at most one enabled provider (the schema supports
multiple provider records for a future selection policy). Configure its issuer,
client ID, optional group claim, optional provider organization claim, and a
client-secret binding of `env:auto`. The application derives a provider- and
organization-specific reference such as
`env:COYOTE_OIDC_CLIENT_SECRET_<ORG_UUID>_<PROVIDER_UUID>`; an operator must
populate that exact environment variable in the deployment secret manager.
Arbitrary environment references are rejected, so an organization owner cannot
cause another deployment secret to be sent to a token endpoint. The application
never persists raw client secrets, ID tokens, or refresh tokens.

Users begin login at `/auth/oidc/{organization-slug}/login`. The authorization
code exchange uses PKCE S256, state, and nonce. Discovery metadata and JWKS are
retrieved from the configured issuer; the application validates signature,
issuer, audience, expiry, subject, and nonce before establishing a session.
Production deployments must set `ENVIRONMENT` to a non-development value and
provide a high-entropy `SESSION_SECRET_KEY` of at least 32 characters; startup
rejects the development fallback secret outside development. Session cookies then
require HTTPS, are HTTP-only, and use `SameSite=Lax`. Browser session mutations,
including logout, require the `X-CSRF-Token` value stored in the session. Bearer
authentication takes precedence whenever an `Authorization` header is present:
an invalid bearer token returns `401` and never falls back to a browser session.
Browser sessions are not accepted by MCP; the protocol endpoint requires a PAT.

External accounts are bound immutably by `(organization, issuer, subject)`.
Email is display metadata only and is never used to link accounts. Set
`jit_provisioning_enabled` only when first-login provisioning is intended:
provisioned humans receive no roles. Disabled mapped principals cannot log in.

External group IDs come only from the validated ID-token group claim. Map a
stable provider group ID to one or more built-in roles at organization or
collection scope; direct principal assignments continue to work alongside those
mappings. Group-derived access is evaluated for the authenticated session only.
If the provider signals overage/incomplete claims or the configured group claim
is absent/malformed, group-derived access fails closed; direct assignments are
unaffected. Changes take effect at the next successful login or session expiry
(eight hours by default), so administrators should use short session lifetimes
where group removal must take effect quickly. Browser sessions are persisted in
PostgreSQL and the cookie contains only an opaque, hashed-verifier token; it
contains no principal details, group IDs, CSRF material, or OIDC tokens. Sessions
expire, update activity on use, rotate on successful login, are revoked on
logout, and are rejected immediately when their principal is disabled. OIDC
state, nonce, and PKCE verifier are stored in a separate short-lived,
single-use transaction that is atomically consumed by the callback and bound to
an initiating-browser HttpOnly cookie. This prevents a callback initiated in one
browser from establishing a session in another. Session activity is persisted at
most once every five minutes while expiry and revocation are checked on every
request. Obtain a
fresh CSRF value from `GET /auth/oidc/csrf` before session-authenticated
state-changing requests. SCIM and directory synchronization are deliberately
deferred.

OIDC discovery, authorization, token, and JWKS URLs must be HTTPS unless both
development mode and explicit local OIDC overrides are enabled. Every endpoint
must resolve to a public address (unless the local override is set), redirects
are disabled, requests are DNS-pinned, and endpoints must use the issuer host or
an explicitly configured `trusted_endpoint_hosts` entry. This prevents discovery
metadata from redirecting credentials to an unrelated host while still allowing
an approved enterprise provider boundary.

External groups are identity-provider scoped. The same external group ID can be
mapped separately for different providers, but a verified claim is evaluated
only against mappings for the provider that authenticated the session. Legacy
groups that cannot be unambiguously backfilled to one provider remain unbound
and therefore grant no group-derived access.

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

For a manual MCP Inspector session, first bootstrap an owner PAT once:

```bash
docker compose run --rm app uv run coyote-mcp bootstrap-admin
```

Configure MCP Inspector with Streamable HTTP URL
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
