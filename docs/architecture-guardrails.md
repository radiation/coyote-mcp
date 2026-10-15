# Architecture guardrails

This document defines invariants for coyote-mcp. **Implemented** statements are
verified against the current application; **planned** statements describe work
that must preserve these invariants.

## Implemented invariants

- **Organizations are isolation boundaries.** Organizations scope principals,
  servers, collections, credentials, identity providers, groups, and sessions.
  Cross-organization catalog lookups do not reveal resources.
- **Collections organize capabilities, not access.** A collection groups server
  tools for discovery. Collection membership never independently grants access;
  only a role assignment or group-role mapping can grant a collection scope.
- **Authorization is centralized and default-deny.** `auth.authorize` evaluates
  an enabled principal, known action, matching organization, roles, and optional
  collection scope. Callers must enforce that decision in application services,
  not exclusively in HTTP handlers. Collection-list authorization uses the same
  policy data through a batched helper so unscoped discovery does not issue one
  role lookup per collection.
- **PAT scopes attenuate permissions.** PAT creation requires requested scopes
  to be a subset of the principal's direct role permissions; a request must
  satisfy both its token scope and current role evaluation.
- **External identities use issuer and subject.** The immutable identity key is
  `(organization, issuer, subject)`; email is display metadata and never the
  linking key.
- **OIDC groups are provider-scoped.** Group mappings include an identity
  provider. Only verified groups from the provider that authenticated the
  browser session participate in authorization.
- **Browser sessions and OIDC transactions are server-side.** PostgreSQL stores
  hashed opaque session/binding secrets, CSRF hashes, verified group IDs, OIDC
  state, nonce, and PKCE verifier. OIDC transactions are single-use and bound
  to the initiating browser.
- **Sensitive values are not persisted in plaintext.** PAT and session
  verifiers are hashed. OIDC client secrets are read from a provider-specific
  environment reference; ID, refresh, and client-secret values are not stored.
- **The database is the authoritative registry.** Catalog reads use persisted
  records rather than probing downstream servers.
- **Discovery protects catalog integrity.** Remote discovery validates the
  destination, disables redirects, pins DNS resolution, and uses generation
  checks with row locking. A failed or superseded discovery cannot overwrite
  the existing tool catalog.
- **Downstream servers are untrusted boundaries.** Tool labels, schemas, and
  annotations are untrusted metadata. Server endpoints reject embedded
  credentials and non-public/non-HTTPS destinations unless explicit broad
  development configuration or a matching hostname-specific allowlist permits
  them.
- **External network destinations require explicit validation.** Downstream
  and OIDC endpoints require allowed schemes, DNS resolution, public addresses
  by default, no credentials in URLs, redirect prevention, and destination
  pinning. OIDC endpoints must also remain on the issuer or explicitly trusted
  host boundary.
- **MCP gateway operations are PAT-only and authorization is current.** The
  Streamable HTTP endpoint at `/mcp` rejects absent, invalid, expired, revoked,
  and browser-session credentials. Discovery, description, and execution load
  the persisted catalog and re-evaluate PAT scopes and centralized authorization
  for the current principal. Collection-scoped execution requires the requested
  collection to contain the active tool's ready server.
- **MCP execution uses registered destinations only.** Execution validates the
  stored input schema, DNS-pins the registered endpoint, disables redirects, and
  does not forward the caller PAT. Downstream responses remain structured but
  are size-bounded; transport failures expose sanitized errors only. FastMCP
  4.1.0 does not expose a response-stream interception hook compatible with its
  Streamable HTTP client, so the result-size bound is enforced immediately after
  FastMCP deserializes the result rather than while its response body streams.
- **MCP network work does not hold registry read transactions.** Execution
  snapshots authorization and routing data in a dedicated short-lived session,
  which closes before validation or downstream network I/O. It does not commit
  or roll back mutations owned by the caller session.
- **Untrusted schemas cannot block gateway workers.** Stored JSON Schema checks
  run in a CPU-limited child process with a bounded wall-clock deadline. A
  validation timeout, worker failure, or unresolved external `$ref` rejects the
  invocation before any downstream request is made. Schema validation permits
  local references but never retrieves remote schemas.
- **Migrations are additive.** Alembic history is the durable schema contract;
  revisions must not be rewritten and should remain backward-compatible where
  practical.
- **Local smoke destinations are narrow exceptions.** The optional Compose
  `smoke-mcp` service is reachable only on the Compose network. Its plain-HTTP
  private address is accepted only when both destination hostname allowlists
  contain `smoke-mcp`; these settings do not permit arbitrary private or
  insecure endpoints.

## Planned functionality

- **Credentialed downstream integrations:** The registry has no general
  downstream credential storage or propagation mechanism yet. Any future
  mechanism must preserve the secret and destination protections above.
- **Console and semantic discovery:** An HTMX console, search/embedding index,
  auditing, metrics, and richer policy features are future work. They must use
  the database registry and centralized authorization rather than create a
  parallel policy path.
- **Fine-grained tool policy:** Tool-specific allow and deny policies are not
  implemented. Tool annotations are untrusted metadata and never imply safety.

## Review checklist

For every change, confirm that organization predicates and authorization are
present at the service boundary; no plaintext secret reaches storage or logs;
remote calls retain their destination validation; and any migration is a new,
additive revision with tests for the intended compatibility.
