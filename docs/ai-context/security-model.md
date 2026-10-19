# Security model

## Trust boundaries and authentication

The browser, PAT holder, OIDC provider, downstream MCP server, DNS, and
database are distinct trust boundaries. The database is the authoritative
registry; downstream schemas and responses are untrusted.

REST authentication accepts opaque PATs and browser sessions. MCP accepts only
opaque PAT bearer authentication and never falls back to browser cookies. PAT and session
secrets are displayed only at issuance and stored as SHA-256 verifiers. A bearer
header takes precedence over a browser session. Browser sessions are opaque,
HTTP-only, HTTPS outside development, CSRF-protected for mutation, persisted in
PostgreSQL, expiring, and revocable.

OIDC uses exactly one instance provider configured through validated environment
settings, discovery, PKCE S256, state, nonce, token signature/issuer/audience/
expiry validation, and a single-use transaction bound to an initiating-browser
cookie. Missing or invalid settings fail closed. The client secret is injected
through settings; ID tokens and refresh tokens are not persisted. The privileged CLI records a trusted `(issuer, subject)` instance
administrator binding; normal browser authentication always validates OIDC
claims before it issues a session.

Production ingress is a separate trust boundary. Production settings require a
canonical HTTPS public origin, explicit allowed hosts, and explicit trusted
proxy IP/CIDR networks. Host validation rejects unexpected `Host` headers.
Only a direct peer in a trusted proxy network can set `X-Forwarded-Proto` or
supply a validated `X-Request-ID`; all other client-supplied forwarded values
are ignored. The request ID is generated when no trusted valid value exists and
is returned in the response. Console MCP endpoint URLs use the canonical public
origin instead of request or forwarded host input.

## Authorization and tenancy

Authorization is centralized in `auth.authorize`, default-deny, and scoped to an
immutable organization context carried by the authenticated request, never by
the global `Principal` ORM object. Authorization rechecks enabled principals and
organizations. Ordinary principals also require enabled explicit membership and
organization or collection roles. An enabled global `InstanceAdministrator` is
the centralized browser-session superuser override and may select and administer
any enabled organization, including an ownerless organization, without synthetic
memberships or roles. Its CSRF-protected organization creation transaction adds
an enabled membership and owner role only in the new organization. Ordinary
authenticated users are denied when they call the creation or selection paths
outside their memberships.
PAT authentication remains organization-bound, requires an enabled membership,
and retains explicit PAT scopes plus organization-role evaluation; instance-admin
status does not elevate a PAT or create a cross-organization PAT.
MCP collection authorization remains membership- and publication-gated, so an
instance-administrator PAT cannot discover or execute unpublished tools.
Phase 4B console writes (server registration, edit, enable/disable, refresh,
removal, collection management, membership, and tool publication) require a
valid CSRF token before authorization, resolve the active organization from the
server-side session, and check the matching action through `auth.authorize`. Authorization runs before form
validation, and error responses (422 and 409) render only resources the caller
has already been authorized to read. A failed validation must never load and
render a server or collection the caller cannot update.
Instance-admin override applies only to browser sessions. Publication state
and publish, edit, and unpublish actions require `collection:update`, and
published-tool visibility in the console requires the same action. Console
collection pages separate authentication and organization selection from
permission checks: they authorize the requested collection through the
collection-aware service (`catalog.read_collection`, `require_collection_update`,
publication services), so a collection-scoped maintainer can manage that
collection without an organization-wide grant. The collection list is gated on
an organization-wide `collection:read` grant (any org-wide or collection-scoped
role). Members with no such grant receive forbidden, and the list is then filtered
per collection in one batched query (`authorized_collection_ids`). Organization-wide
operations (server pages, collection creation, tool catalog counts) keep
organization-level checks. Console pages render untrusted tool descriptions and downstream text through Jinja2
autoescaping. CSRF tokens are HMAC-SHA256 values derived from the browser
session's stored secret hash, a non-secret `csrf_epoch` counter, and the
configured session secret key. Nothing secret is stored, rendering does not
write to the database, and every form rendered in one session shares a valid
token, so several open forms can be submitted. The epoch is incremented only at
lifecycle boundaries (organization switch and first-organization creation).
The increment is committed in the same transaction as the active organization
change, so a stale form cannot authenticate against the new organization. This
invalidates forms opened before the switch. A new login creates a new session with a new token, and
tokens never validate across sessions. Console redirects are built from a fixed
`/console/...` prefix plus the identifier's string form, so request-derived values
cannot change the host. A single helper then accepts only local console paths made
of safe segments and falls back to `/console` for anything else.
PAT scopes further attenuate permissions. External identities use issuer plus
subject, not email. Groups are taken from validated ID-token claims and evaluated
against organization-scoped mappings.

## Downstream credentials and Connected Apps

Each registered server has one of three authentication policies. `none` sends no
downstream credential, which preserves unauthenticated servers such as DeepWiki.
`shared_bearer` uses an administrator-stored service credential for the whole
organization. `per_user_oauth` requires each human principal to connect their own
account; a shared credential is never substituted when a user's connection is
missing, expired, or revoked.

- **Encryption:** Credentials are sealed with AES-256-GCM. Keys come from
  `COYOTE_CREDENTIAL_ENCRYPTION_KEYS` (a JSON object mapping version to a base64url
  32-byte key) and `COYOTE_CREDENTIAL_ACTIVE_KEY_VERSION`. Keys are required before any
  secret or connection can be written; without them those operations fail closed. Each value's additional
  authenticated data binds the domain and its owner: `(organization, server)` for
  shared credentials and client secrets, `(organization, server, principal)` for
  connections, and `(organization, server, state hash)` for PKCE verifiers.
  Ciphertext moved between rows fails authentication.
- **Rotation:** Add a new key version to the map, make it active, and restart.
  Reads accept every configured version. Writes re-seal with the active version.
  Keep old versions until no row references them; a dedicated re-seal command is
  not implemented.
- **Redaction:** Stored values never appear in API responses, templates, logs,
  exception text, or tool results. Downstream 401 and 403 responses are mapped to
  sanitized errors, and the caller sees only a stable code.
- **Broker:** The credential broker resolves the policy, checks the server's
  organization, and selects the credential for the server and authenticated
  principal. It returns headers only for the single downstream call. Caller PATs and
  browser-session secrets are never forwarded, and clients do not receive the
  headers. Fail-closed codes include `connection_required`, `connection_expired`,
  `service_principal_not_permitted`, `credential_not_configured`, and
  `authorization_not_configured`.
- **Service principals** cannot start, complete, or use a personal connection, so
  `per_user_oauth` servers fail closed for them.
- **Instance administrators** using a browser session may manage only their own
  downstream connections in an enabled organization without an explicit
  membership. This self-service exception never applies to PATs, service
  principals, or another principal's connection. Authorization for a tool still
  requires the caller's own connection.
- **Refresh:** Refresh runs under a row lock (`SELECT ... FOR UPDATE` on
  PostgreSQL) and is held across the token request. Rejected grants
  (`invalid_grant`, `invalid_client`, `unauthorized_client`) mark the connection
  `reauthorization_required`. Refresh tokens are never returned or logged.
- **Retry safety:** The gateway never retries a tool execution after a token
  refresh or upstream rejection.
- **OAuth:** The authorization-code flow uses PKCE S256 and a 256-bit random state.
  Only the state hash is stored. Each transaction is bound to the browser session,
  principal, organization, and server, and expires after 10 minutes. The callback
  claims the transaction with one `UPDATE ... RETURNING`, so a replayed, unknown,
  expired, or mismatched callback fails. A provider error also consumes the
  transaction. Endpoints must be HTTPS public destinations, redirects are disabled,
  DNS is pinned, and the redirect URI is fixed to
  `COYOTE_DOWNSTREAM_OAUTH_REDIRECT_BASE_URL` plus `/console/connected-apps/callback`.
  HTTPS is required except when `ENVIRONMENT=development` and
  `ALLOW_INSECURE_ENDPOINTS=true`: only the literal loopback hosts `localhost`,
  `127.0.0.1`, and `::1` may then use HTTP. This exception applies only to the
  local callback origin, not provider authorization, token, account, or
  revocation endpoints.
- **Providers:** The GitHub preset overrides submitted endpoints with the
  documented `github.com` OAuth endpoints. Generic providers must supply every
  endpoint explicitly. Authorization-server metadata discovery (RFC 8414) and
  resource indicators (RFC 8707) are not implemented.
- **Revocation and disconnect:** Disconnect deletes the local connection first and
  then attempts revocation when a revocation endpoint is configured. GitHub
  OAuth Apps have no revocation endpoint here, so disconnect removes local
  credentials only and reports that the grant remains active at the provider.
  Replacing a connection does not revoke the previous grant.
- **Self-service:** `connection:manage_own` lets any enabled member with a
  direct or verified-group organization-wide or collection-scoped role manage
  their own connections. Every query is keyed by the caller's principal, so one
  user cannot read or change another user's connection.
- **Administration:** Configuring policy, integrations, and shared credentials
  requires `server:update` and `credential:*`. Secret fields are write-only: the
  console shows only whether a value is stored. These writes do not yet produce
  audit events.
- **Discovery for authenticated servers:** Synchronization uses the credential for
  the caller who starts it. For `shared_bearer`, that is the registered shared
  credential. For `per_user_oauth`, it is the caller's own connection. If that
  credential is missing or invalid, synchronization fails closed and the last-known
  catalog is kept. The service never uses an administrator's personal connection
  or a shared identity to decide what an individual user may call. Discovered tools
  remain catalog metadata; execution still checks the caller's publication,
  collection membership, and connection.
- **Icons:** Only a locally bundled allowlisted monogram is shown. Remote icons
  are never fetched, and administrator uploads are not supported.


Downstream discovery and OIDC calls validate destinations, reject embedded URL
credentials, require HTTPS/public routing by default, disable redirects, and
pin DNS destinations. Downstream MCP servers remain untrusted integration
boundaries.

Local Compose smoke testing is a constrained exception: the application
allowlists only the `smoke-mcp` hostname for private addressing and plain HTTP.
It does not enable `ALLOW_PRIVATE_ENDPOINTS` or `ALLOW_INSECURE_ENDPOINTS`, so
other internal or HTTP destinations remain rejected. The mock service has no
host-published port, and the smoke runner creates short-lived hashed PATs without
logging their plaintext values.

MCP uses FastMCP Streamable HTTP at `/mcp`. The installed MCP SDK supports
`2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, and `2026-07-28`.
Clients call fixed universal `coyote_search_tools`, `coyote_describe_tool`, and
`coyote_execute_tool` tools rather than receiving every downstream tool. Search
and description expose only enabled publications in authorized active catalog
collections. Execution loads the tool and its publication from PostgreSQL again,
requires an authorized collection context when a tool has multiple publications,
validates stored JSON Schema input, then invokes only the registered DNS-pinned
endpoint without forwarding the coyote PAT.

`/mcp/collections/{slug}` is also PAT-only and does not accept a client-supplied
organization context. An enabled collection in `discovery` mode exposes the
three universal tools with the URL collection bound server-side. An enabled
`native` collection exposes only explicitly enabled direct persisted tool
publications when the principal has
both `tool:discover` and `tool:execute` for that collection; discovery permission
alone cannot reveal directly executable tools. Published aliases are unique
within their collection, MCP-compatible, explicitly managed, and stable across
downstream server renames; clients cannot execute an unpublished tool by
guessing an ID or alias. Publication curation applies to both native endpoints
and the three-tool progressive discovery interface. The endpoint rejects, rather than
truncates, a final authorized publication set that exceeds
`COYOTE_MAX_NATIVE_TOOLS_PER_COLLECTION` (default `100`). Each `tools/list`
reloads the authorized catalog. No `tools/list_changed` notification is emitted
because the installed FastMCP version has no safe per-principal broadcast API.

Search trims surrounding whitespace, rejects overlong queries, and escapes SQL
`LIKE` wildcard characters before querying authorized collections. Stored JSON
Schemas are checked in a spawned child process with a bounded wall-clock
deadline and a Linux address-space limit before execution arguments are checked
against them; callers cannot supply a replacement schema. This prevents
pathological untrusted schema patterns from blocking the gateway event loop or
consuming unbounded worker memory. Worker setup failures, crashes, resource
exhaustion, and deadline expiry are internally classified but expose sanitized
client errors. Validation permits local `$ref` targets but uses a non-retrieving
registry, so remote references cannot bypass destination validation. FastMCP
tool-level errors remain structured results, and explicit JSON null values in
downstream structured content are preserved.
Expected timeout, protocol, and transport failures are
sanitized; unexpected failures are logged without bearer credentials or raw
request headers. The configured response-size limit is applied immediately
after FastMCP materializes a result. Its current public client transport does
not provide a compatible streaming response-limit hook.

## Security audit events

Migration `0021` provides a durable PostgreSQL audit ledger. Every row has an
organization ID, timestamp, actor snapshot, controlled action/outcome, target
snapshot, optional request ID, and allowlisted JSONB metadata. Actor and target
IDs intentionally have no foreign keys: deleting an originating principal or
target cannot rewrite or erase historical evidence. The organization reference
uses `RESTRICT`, and tenant-scoped readers must always predicate events by that
organization ID.

`audit.record_audit_event` accepts the caller's `AsyncSession`, flushes but
never commits, and propagates an `AuditPersistenceError`. A security-sensitive
mutation that emits an event through this service therefore commits atomically
with its event or rolls back both. The service accepts only enum-backed event
names/outcomes and per-event scalar metadata allowlists; it rejects arbitrary
objects, unsupported fields, and oversized content before storage. It never
automatically serializes exception text, credentials, bearer tokens, OAuth
codes, headers, request bodies, or downstream payloads.

Both the ORM and PostgreSQL triggers reject updates and deletes. This protects
against accidental application writes and ordinary database roles; it does not
prevent a privileged database operator from disabling triggers, changing the
schema, or directly altering data. Retention is intentionally deferred to a
separately authorized future policy.

P5-02B instruments successful security-sensitive mutations through their
existing transactions: organization bootstrap; PAT issue/revocation;
server, collection, membership, and publication changes; server authentication
policy, OAuth integration, shared credential, and connected-app lifecycle
changes; and the current service-principal and external-group role-mapping
administration endpoints. The actual authorized principal is the actor, and
the organization comes from the authorized tenant context rather than request
input. System actors remain explicit and are never substituted for a missing
human actor. No-op requests do not produce success events.

P5-02C must define explicit independent-write policy for authorization denials,
authentication failures, MCP outcomes, and read-only security events that occur
outside a mutation transaction. Execution cancellation and fine-grained
per-tool deny policies remain unimplemented. Tool annotations never establish
safety.

### Authentication and authorization denial auditing

P5-02C1 independently persists classified PAT and browser-session failures
only when a server-side credential/session record supplies a trustworthy
organization. It records a system actor, `authentication.failed`, the
authentication mechanism, and a bounded reason category; it never associates
an unauthenticated attempt with a principal. Completely unrecognized or
malformed credentials, unaffiliated browser sessions, and OIDC failures before
an organization can be safely established remain sanitized operational logs,
not tenant audit events. The tenant-scoped audit schema deliberately cannot
represent them without inventing an organization.

Central API and console authorization checks, plus denied MCP collection
endpoint access, independently write `authorization.denied` when they have an
authenticated principal and active organization. The audit row records that
principal's trustworthy actor snapshot, a requested action, a bounded policy
reason, and the request correlation ID. Cross-organization
lookups that intentionally return not-found to prevent resource enumeration
remain unaudited because no authorization decision is exposed.

Denial-event writes use a short-lived database session and transaction separate
from the request transaction. `COYOTE_INDEPENDENT_AUDIT_TIMEOUT_SECONDS`
defaults to a conservative two-second deadline covering session acquisition,
insert/flush, and commit. Timeout or persistence failure is sanitized to
operational logging and never changes an authentication failure or
authorization denial into success; parent-request cancellation still
propagates normally. Successful privileged mutations retain the
P5-02B caller-transaction, fail-closed guarantee; they do not use this path.
MCP execution-outcome auditing remains deferred.
