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

MCP uses FastMCP Streamable HTTP at `/mcp`. The installed MCP SDK supports
`2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, and `2026-07-28`.
Clients call fixed universal `coyote_search_tools`, `coyote_describe_tool`, and
`coyote_execute_tool` tools rather than receiving every downstream tool. Search
and description expose only authorized active catalog records. Execution loads
the tool from PostgreSQL again, requires an authorized collection context for
collection-scoped grants, validates stored JSON Schema input, then invokes only
the registered DNS-pinned endpoint without forwarding the coyote PAT.

Search trims surrounding whitespace, rejects overlong queries, and escapes SQL
`LIKE` wildcard characters before querying authorized collections. Stored JSON
Schemas are checked before execution arguments are checked against them;
callers cannot supply a replacement schema. FastMCP tool-level errors remain
structured results. Expected timeout, protocol, and transport failures are
sanitized; unexpected failures are logged without bearer credentials or raw
request headers. The configured response-size limit is applied immediately
after FastMCP materializes a result. Its current public client transport does
not provide a compatible streaming response-limit hook.

There are no downstream credential delegation, audit events, cancellation, or
fine-grained per-tool deny policies yet. Tool annotations never establish safety.
