# Domain model

Catalog entities are organization-scoped. Identities are instance-wide and gain organization access only through explicit memberships.

| Entity | Ownership, relationships, and constraints |
| --- | --- |
| Organization | Tenant/isolation root; slug is unique and the enabled state gates all membership-based access. |
| AuditEvent | Immutable tenant-scoped security evidence with organization ID, timestamp, actor and target UUID snapshots, constrained action/outcome/type values, request correlation, and bounded allowlisted JSONB metadata. It has no actor or target foreign keys, preserving history after those records are removed; PostgreSQL blocks update/delete and organization deletion is restricted while events remain. |
| Principal | An enabled global human or service identity; identifier is instance-unique and has no mutable organization context. |
| OrganizationMembership | Explicit enabled link between one global principal and one enabled organization. Membership alone grants no permission. |
| InstanceAdministrator | Instance-wide browser-administration superuser binding for the configured OIDC issuer/subject. An enabled binding can administer every enabled organization without a membership or synthetic role, recover ownerless organizations, and create departments; creation atomically adds an owner membership only in the new department. PATs retain explicit scopes and role evaluation. |
| RoleAssignment | Grants a built-in role organization-wide or for one collection. Organization-wide roles are unique per principal, organization, and role; cross-tenant principal/collection pairs are constrained. |
| PAT | Belongs to a principal and organization; has a unique token ID, hashed verifier, attenuated scopes, expiry, and revocation state. |
| ExternalIdentity | Binds a principal globally to `(issuer, subject)`; email is non-authoritative metadata. |
| ExternalGroup and GroupRoleMapping | A group maps a validated claim value to organization or collection-scoped built-in roles. |
| BrowserSession | Server-side session for a principal with hashed opaque verifier, CSRF rotation epoch, verified group IDs, expiry, activity, revocation, and optional active organization ID. |
| OIDCLoginTransaction | Short-lived, single-use server-side state/nonce/PKCE record bound to a browser. |
| MCPServer | Registered downstream server with one organization, endpoint, transport, enabled state, sync state, tool generation, and `auth_policy` (`none`, `shared_bearer`, or `per_user_oauth`; default `none`). Disabled servers are excluded from gateway discovery and execution. |
| DownstreamSharedCredential | One sealed `shared_bearer` service credential per organization and server. Stores only the AES-GCM ciphertext and key version; values are never returned by any API, template, or log. |
| DownstreamOAuthIntegration | One per organization and server: provider (`github` or `generic`), authorization, token, revocation, and account endpoints, client ID, sealed client secret, requested scopes, and an enabled flag. Client secrets are never returned. |
| DownstreamConnection | One per organization, server, and principal. Holds sealed access and refresh tokens, status (`connected` or `reauthorization_required`), granted scopes, account identifier, token expiry, and refresh time. Bound to the global principal, not the browser session. |
| DownstreamOAuthTransaction | Single-use, short-lived OAuth record keyed by a hashed state. Bound to browser session, principal, organization, and server; holds a sealed PKCE verifier and a `consumed_at` marker claimed atomically on callback. |
| Tool | Persisted advertised tool for one server; schema/annotations are untrusted metadata and active state is reconciliation-managed. |
| Collection | Organization-scoped capability/discovery grouping with an enabled state and an exposure mode: `discovery` for bound universal tools or `native` for direct persisted-tool publication. |
| CollectionMembership | Many-to-many server/collection link constrained so both resources belong to the same organization. |
| CollectionToolPublication | Collection-scoped curation record for one tool on one member server. Composite foreign keys require the referenced server to be a member and the tool to belong to that server; aliases are unique per collection. It stores enabled state, stable published name, optional description override, and timestamps. Enabled records are required for discovery and execution. |

Role assignment and collection membership are intentionally separate: a
collection link does not imply a permission grant. Publications are created
only by an explicit administrator action (API or console); discovery never
creates one, so newly discovered tools are unpublished by default. Removing a
collection membership removes that server's publications in the collection.
