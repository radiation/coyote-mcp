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
server-side session, and check the matching action through `auth.authorize`.
Instance-admin override applies only to browser sessions. Publication state
and publish, edit, and unpublish actions require `collection:update`, and
published-tool visibility in the console requires the same action. Console
pages render untrusted tool descriptions and downstream text through Jinja2
autoescaping. CSRF tokens are HMAC-SHA256 values derived from the browser
session's stored secret hash, a non-secret `csrf_epoch` counter, and the
configured session secret key. Nothing secret is stored, rendering does not
write to the database, and every form rendered in one session shares a valid
token, so several open forms can be submitted. The epoch is incremented only at
lifecycle boundaries (organization switch), which invalidates forms opened
before the switch. A new login creates a new session with a new token, and
tokens never validate across sessions.
PAT scopes further attenuate permissions. External identities use issuer plus
subject, not email. Groups are taken from validated ID-token claims and evaluated
against organization-scoped mappings.

## Network safety and limitations

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

There are no downstream credential delegation, audit events, cancellation, or
fine-grained per-tool deny policies yet. Tool annotations never establish safety.
