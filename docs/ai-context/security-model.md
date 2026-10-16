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

OIDC uses discovery, PKCE S256, state, nonce, token signature/issuer/audience/
expiry validation, and a single-use transaction bound to an initiating-browser
cookie. Provider client secrets use a constrained environment-reference pattern;
ID tokens and refresh tokens are not persisted.

## Authorization and tenancy

Authorization is centralized in `auth.authorize`, default-deny, and scoped to
the principal's organization. Roles can be organization-wide or collection-wide.
PAT scopes further attenuate permissions. External identities use issuer plus
subject, not email. Groups are taken from validated ID-token claims and evaluated
only for mappings owned by the authenticating identity provider.

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
and description expose only authorized active catalog records. Execution loads
the tool from PostgreSQL again, requires an authorized collection context for
collection-scoped grants, validates stored JSON Schema input, then invokes only
the registered DNS-pinned endpoint without forwarding the coyote PAT.

`/mcp/collections/{slug}` is also PAT-only and does not accept a client-supplied
organization context. An enabled collection in `discovery` mode exposes the
three universal tools with the URL collection bound server-side. An enabled
`native` collection exposes direct persisted tools only when the principal has
both `tool:discover` and `tool:execute` for that collection; discovery permission
alone cannot reveal directly executable tools. Names are always qualified by the
registered server name, which avoids collisions without aliases. The endpoint
rejects, rather than truncates, a collection that exceeds
`COYOTE_MAX_NATIVE_TOOLS_PER_COLLECTION` (default `100`). Each `tools/list`
reloads the authorized catalog. No `tools/list_changed` notification is emitted
because the installed FastMCP version has no safe per-principal broadcast API.
Changing a registered server name therefore changes the published native MCP
tool names; stable aliases are deferred to Phase 3B.2.

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
