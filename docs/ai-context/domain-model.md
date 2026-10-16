# Domain model

All primary entities are organization-scoped unless noted otherwise.

| Entity | Ownership, relationships, and constraints |
| --- | --- |
| Organization | Tenant/isolation root; slug is unique. |
| Principal | An enabled human or service identity belonging to one organization; identifier is unique per organization. |
| RoleAssignment | Grants a built-in role organization-wide or for one collection. Cross-tenant principal/collection pairs are constrained. |
| PAT | Belongs to a principal and organization; has a unique token ID, hashed verifier, attenuated scopes, expiry, and revocation state. |
| IdentityProvider | Belongs to an organization; issuer/name are unique per organization and at most one enabled provider exists per organization. |
| ExternalIdentity | Binds a principal to `(organization, issuer, subject)`; email is non-authoritative metadata. |
| ExternalGroup and GroupRoleMapping | A group belongs to an identity provider; mappings grant organization or collection-scoped built-in roles. |
| BrowserSession | Server-side session for a principal with hashed opaque verifier, CSRF hash, verified provider groups, expiry, activity, and revocation. |
| OIDCLoginTransaction | Short-lived, single-use server-side state/nonce/PKCE record bound to a browser and provider. |
| MCPServer | Registered downstream server with one organization, endpoint, transport, sync state, and tool generation. |
| Tool | Persisted advertised tool for one server; schema/annotations are untrusted metadata and active state is reconciliation-managed. |
| Collection | Organization-scoped capability/discovery grouping with an enabled state and an exposure mode: `discovery` for bound universal tools or `native` for direct persisted-tool publication. |
| CollectionMembership | Many-to-many server/collection link constrained so both resources belong to the same organization. |

Role assignment and collection membership are intentionally separate: a
collection link does not imply a permission grant.
