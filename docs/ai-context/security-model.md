# Security model

## Trust boundaries and authentication

The browser, PAT holder, OIDC provider, downstream MCP server, DNS, and
database are distinct trust boundaries. The database is the authoritative
registry; downstream schemas and responses are untrusted.

REST authentication accepts opaque PATs and browser sessions. PAT and session
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

MCP protocol operations and tool execution are not yet enabled because their
authorization path is not implemented. Future work includes execution-time
authorization, downstream credential delegation, audit/metrics, richer policy,
and production hardening.
