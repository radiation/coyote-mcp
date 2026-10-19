# Architecture guardrails

This document defines invariants for coyote-mcp. **Implemented** statements are
verified against the current application; **planned** statements describe work
that must preserve these invariants.

## Implemented invariants

- **Organizations are isolation boundaries.** Organizations scope memberships,
  servers, collections, credentials, groups, and active browser-session context.
  Cross-organization catalog lookups do not reveal resources.
- **Collections organize capabilities, not access.** A collection groups server
  tools for discovery. Collection membership never independently grants access;
  only a role assignment or group-role mapping can grant a collection scope.
- **Authorization is centralized and default-deny.** `auth.authorize` evaluates
  an enabled principal, known action, and enabled organization. Explicit
  membership and roles remain required for ordinary principals. An enabled
  instance administrator is the sole shared override for browser-session
  organization administration and does not create synthetic memberships or
  owner roles. A browser-session instance administrator may use the narrowly
  scoped `connection:manage_own` self-service action for only their own
  downstream connections in an enabled organization; this exception does not
  apply to PATs, service principals, or tool execution. PAT-authenticated REST
  calls retain their explicit scopes and role evaluation. Callers must enforce
  that decision in application services, not exclusively in HTTP handlers.
  Collection-list authorization stays membership-based for PAT-authenticated MCP
  discovery and execution.
- **PAT scopes attenuate permissions.** PATs remain bound to one organization.
  PAT creation requires requested scopes to be a subset of the principal's
  direct role permissions; a request must satisfy both its token scope and
  current role evaluation. Instance-administrator status does not create a
  cross-organization PAT or bypass publication requirements.
- **External identities use issuer and subject.** The immutable identity key is
  `(issuer, subject)`; email is display metadata and never the
  linking key.
- **OIDC has one environment-configured instance provider.** Group mappings are
  organization-scoped. Only groups from validated ID-token claims participate
  in authorization.
- **Browser sessions and OIDC transactions are server-side.** PostgreSQL stores
  hashed opaque session/binding secrets, a CSRF rotation epoch (CSRF tokens are derived, not stored), verified group IDs, OIDC
  state, nonce, and PKCE verifier. OIDC transactions are single-use and bound
  to the initiating browser.
- **Sensitive values are not persisted in plaintext.** PAT and session
  verifiers are hashed. The OIDC client secret is injected through settings;
  ID, refresh, and client-secret values are not stored.
- **The database is the authoritative registry.** Catalog reads use persisted
  records rather than probing downstream servers.
- **Discovery protects catalog integrity.** Remote discovery validates the
  destination, disables redirects, pins DNS resolution, and uses generation
  checks with row locking. A failed or superseded discovery cannot overwrite
  the existing tool catalog. Changing a server endpoint increments the sync
  generation under the same row lock, so discovery against the previous
  endpoint cannot mark the server ready for the new one.
- **Server deletion is serialized against membership writes.** Deleting a
  server locks its row with `FOR UPDATE` before checking memberships and
  publications, and holds the lock through the delete. Membership inserts take
  `FOR KEY SHARE` on the server, so a concurrent insert either commits first and
  makes the delete refuse, or waits and then reports the server as missing. The
  cascading foreign keys never silently remove a membership committed after
  the check.
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
- **Production ingress is explicit.** Production requires an explicit external
  PostgreSQL asyncpg URL, canonical HTTPS public origin, explicit allowed-host
  list, and trusted proxy IP/CIDR list. Broad private/insecure endpoint settings
  and their host allowlists are development-only. Forwarded scheme and upstream
  request IDs are accepted only from a direct trusted proxy peer; collection
  endpoint display uses the configured canonical origin, never a forwarded host.
- **Migrations are release-owned.** Application replicas never run Alembic on
  startup. A singleton deployment release operation applies the additive
  migration history before application rollout.
- **MCP gateway operations are PAT-only, publication-gated, and authorization is current.** The
  Streamable HTTP endpoint at `/mcp` rejects absent, invalid, expired, revoked,
  and browser-session credentials. Discovery, description, and execution load
  the persisted catalog and re-evaluate PAT scopes and centralized authorization
  for the current principal. Discovery, description, and execution require an
  enabled publication in an authorized, enabled collection with an enabled
  membership, active tool, and ready server. Organization-wide permissions do
  not bypass publication. Collection-scoped execution requires that exact
  collection publication; an ambiguous global publication requires context.
- **Collection MCP endpoints are virtual, current, and isolated.**
  `/mcp/collections/{slug}` is served in-process and binds its collection from
  the URL rather than client tool arguments. Enabled collection access is
  re-evaluated for every request. Discovery-mode endpoints expose only the
  universal gateway tools with the bound collection context. Native-mode
  endpoints require both discovery and execution permission for publication,
  publish only explicitly enabled persisted publication records for ready,
  active tools from enabled memberships. Published aliases are unique within the
  collection, administrator-managed rather than server-derived, and retain the
  downstream tool identity for execution. Newly synchronized tools are
  default-deny for every gateway publication surface; the final authorized publication set is
  rejected if it exceeds the configured native-tool limit.
- **Collection publication changes are refresh-visible.** Native and discovery
  endpoint tool views are rebuilt from the current authorized catalog for every
  `tools/list`. FastMCP does not provide a safe principal-scoped broadcaster for
  these dynamic views, so this phase does not emit `tools/list_changed`.
- **MCP execution uses registered destinations only.** Execution validates the
  stored input schema, DNS-pins the registered endpoint, disables redirects, and
  does not forward the caller PAT. Downstream responses remain structured but
  are size-bounded; transport failures expose sanitized errors only. Execution
  attaches only the credential the broker selects for the caller's own
  organization, server, and principal, and never retries a tool call after a
  refresh or upstream rejection.
 FastMCP
  4.1.0 does not expose a response-stream interception hook compatible with its
  Streamable HTTP client, so the result-size bound is enforced immediately after
  FastMCP deserializes the result rather than while its response body streams.
- **MCP network work does not hold registry read transactions.** Execution
  snapshots authorization and routing data in a dedicated short-lived session,
  which closes before validation or downstream network I/O. It does not commit
  or roll back mutations owned by the caller session.
- **Untrusted schemas cannot block gateway workers.** Stored JSON Schema checks
  run in a spawned child process with a bounded wall-clock deadline and a Linux
  address-space limit. Worker setup failures, crashes, resource exhaustion, and
  deadline expiry are classified in internal logs and reject the invocation
  before any downstream request is made. Schema validation permits local
  references but never retrieves remote schemas.
- **Console administration uses shared services.** Console server, collection,
  membership, and publication writes call catalog or organization services after
  CSRF validation and organization-scoped authorization. Publication
  administration is default-deny: discovery never creates a publication, and
  unpublishing removes the tool from native and discovery MCP views and from
  execution authorization. Duplicate tools and aliases are checked before
  writes, with database constraints as the final guard.
- **Migrations are additive by default.** Alembic history is the durable schema
  contract; revisions must not be rewritten and should remain backward-compatible
  where practical. Greenfield corrective revisions may rebuild transient session,
  transaction, and group-mapping tables when removing obsolete authentication
  storage; `0014` intentionally does so without changing external identities.
  `0015` removes only the unused legacy `default` organization seed so fresh
  deployments begin without departments.
- **Local smoke destinations are narrow exceptions.** The optional Compose
  `smoke-mcp` service is reachable only on the Compose network. Its plain-HTTP
  private address is accepted only when both destination hostname allowlists
  contain `smoke-mcp`; these settings do not permit arbitrary private or
  insecure endpoints.

## Planned functionality

- **Credentialed downstream integrations are brokered.** Shared bearer and
  per-user OAuth credentials are sealed with AES-256-GCM using a separately
  configured key set, bound to organization, server, and principal, and never
  returned, logged, or forwarded from caller PATs or browser sessions. Execution
  and discovery obtain headers only through the credential broker; authorization
  checks do not depend on credential availability, and no shared credential
  substitutes for a missing per-user connection.
- **OAuth transactions are single-use and bound.** Authorization-code flows use
  PKCE S256 and a random state stored only as a hash, bound to browser session,
  principal, organization, and server. Callbacks claim the transaction atomically
  and fail closed when it is unknown, replayed, expired, or mismatched.
- **Remaining console and semantic discovery:** Semantic discovery, console audit
  views, metrics, principal and token administration, and richer policy
  features remain future work and must not create a parallel policy path.
- **Fine-grained tool policy:** Publication curation controls discovery and native visibility;
  per-principal tool-specific allow and deny policies are not implemented. Tool
  annotations are untrusted metadata and never imply safety.

## Review checklist

For every change, confirm that organization predicates and authorization are
present at the service boundary; no plaintext secret reaches storage or logs;
remote calls retain their destination validation; and any migration is a new,
additive revision with tests for the intended compatibility.
