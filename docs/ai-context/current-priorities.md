# Current priorities

## Completed

- **Phase 1:** PostgreSQL-backed registration of Streamable HTTP MCP servers,
  generation-safe tool discovery, persisted catalog, and collections.
- **Phase 2:** Organization-scoped roles and PATs; service principals;
  enterprise OIDC identities, organization-scoped group mappings, server-side
  browser sessions, browser-bound OIDC transactions, and environment-injected
  client secrets.
- **Phase 3A:** PAT-authenticated FastMCP Streamable HTTP endpoint with
  universal PostgreSQL-backed search, description, and execution. Every MCP
  operation re-evaluates current authorization; collection-scoped execution is
  collection-bound, validated, DNS-pinned, timeout-bounded, and does not
  forward caller credentials. Hardening adds escaped/bounded lexical search,
  explicit schema validation, classified downstream failures, response-size
  bounds, deterministic local FastMCP execution tests, and spawned,
  address-space/time-bounded child-process validation for untrusted stored
  schemas with local-only `$ref` resolution. Worker setup failures, crashes,
  resource exhaustion, and deadline expiry are internally classified. Execution
  snapshots authorized routing data in a short-lived session before downstream
  I/O, avoiding held registry connections; downstream structured results
  preserve explicit JSON null values. Unscoped discovery batches tenant-scoped
  collection grant evaluation before result limiting.
- **Phase 3B.2:** Virtual PAT-authenticated collection endpoints support bound
  progressive discovery and curated native publication from the persisted
  catalog. Native collections default-deny newly synchronized tools and expose
  only enabled collection tool-publication records with stable administrator
  aliases and optional description overrides. Global and collection-bound
  progressive discovery, listing, description, and invocation share the same
  publication check; synchronization never publishes tools implicitly. The
  additive `0012` migration creates only the publication schema, so collections
  require explicit curation after migration. The current FastMCP transport lacks a safe per-principal
  `tools/list_changed` broadcast; refresh is the implemented update mechanism.
- **Quality and security infrastructure:** Python 3.14/uv, Ruff, strict mypy,
  pytest branch coverage (80% minimum), PostgreSQL integration tests, Docker
  Compose development, Dependabot, CI, and CodeQL configuration.
- **Local smoke coverage:** An optional Compose-only FastMCP mock and a live
  runner validate registration, sync, authenticated MCP discovery/description/
  execution, structured tool failures, tenant isolation, revoked-PAT denial,
  and temporary tenant cleanup. The runner provisions globally unique service
  principals with explicit owner memberships and organization-bound PATs. The
  profile uses hostname-specific private HTTP destination allowlists rather
  than broad SSRF development overrides.
- **Phase 4A:** A Jinja2/HTMX administration console provides an
  organization-scoped registry overview, persisted server-health list,
  browser-session-only authentication, centralized RBAC page checks, responsive
  dark styling, and placeholders for future management pages. Its shell exposes
  an active-session organization chooser for membership switching and
  instance-admin department creation. It has no separate credential path.
- **Phase 4A.1:** Global principals, explicit enabled organization memberships,
  server-side active browser-session organization selection, one environment-
  configured OIDC provider, instance administrators, and immutable request
  organization context are implemented. Migration `0013` is intentionally
  destructive for identity, role, credential, session, and provider data; it
  preserves organizations and catalog data. Configure OIDC settings, bind an instance
  administrator, and recreate memberships and roles after applying it.
- **OIDC schema correction:** Migration `0014` removes legacy database-provider
  coupling by rebuilding transient browser-session and login-transaction tables
  plus greenfield group mappings. It preserves global external identities and
  their `(issuer, subject)` binding while invalidating existing browser sessions,
  pending OIDC logins, and group-role mappings.
- **Organization bootstrap correction:** Migration `0015` removes the untouched
  legacy `default` seed, while preserving a default department with dependent
  data. Fresh deployments therefore begin without departments until an instance
  administrator creates one.
- **Organization role uniqueness correction:** Migration `0016` scopes
  organization-wide role uniqueness by principal, organization, and role. A
  global instance administrator can therefore receive an owner role when
  creating each new department.
- **Phase 4A instance administration:** Enabled instance administrators are
  browser-session superusers for every enabled organization and can recover
  ownerless departments without synthetic memberships or owner roles. They can
  select any department and create new ones; creation atomically grants the new
  department's owner membership and role. PATs remain single-department and MCP
  discovery/execution remains membership- and publication-gated.
- **Phase 4B server registry:** The console lists, registers, views, edits
  display name and endpoint, enables/disables, refreshes discovery for, and
  removes downstream servers for the active organization. Registration and
  edits reuse the existing endpoint validation and SSRF defenses. Migration
  `0017` adds `servers.enabled`; disabled servers are excluded from gateway
  discovery and execution. Servers are removed only when no collection
  membership or tool publication references them. Secrets and raw connection
  configuration are never rendered; endpoints show only scheme, host, and path.
- **Phase 4B collections:** The console lists, creates, edits, enables/disables,
  and manages membership for organization collections, and shows each
  collection's available and published tools. Membership is managed with the
  existing `collection:manage_members` action. Removing a server from a
  collection also removes its publications in that collection. The page shows
  the endpoint as `/mcp/collections/{slug}` derived from the request origin, so
  it must be checked behind a reverse proxy.
- **Phase 4B tool publication:** The Tool Catalog page lists bounded, paginated
  discovered tools. Publication state is shown only to principals with
  organization-wide `collection:update`. Each collection has a publications page
  that publishes an available tool with a stable alias, edits the alias,
  description override, and enabled state, and unpublishes a tool. Discovery
  never publishes a tool. Duplicate tools and aliases return 409, and
  publications for foreign or nonexistent tools return 422 without revealing
  which. Published-tool visibility requires `collection:update`. Publishing
  into a disabled collection is allowed, and the page warns that nothing is
  exposed until the collection is enabled.
- **Console CSRF lifecycle:** Console and API mutations use a token derived with
  HMAC-SHA256 from the browser session's stored secret hash, a `csrf_epoch`
  counter (migration `0018`), and the session secret key. Rendering reuses the
  token, so several open forms can each be submitted. Only lifecycle boundaries
  rotate it: an organization switch increments the epoch, and new sessions
  receive new tokens. Missing, invalid, and cross-session tokens are rejected.

## Next

- **Phase 3B:** Downstream credential integration, audit events, cancellation,
  and operational metrics for MCP execution.
- **Phase 3C:** Per-principal fine-grained tool policy, richer discovery, and
  semantic search without weakening the persisted-catalog boundary.
- **Later:** Semantic/search-based progressive discovery, console audit views,
  and remaining administration workflows (principal and token management)
  while preserving the database registry and policy model.

## Open technical decisions

- Downstream credential storage, authentication, and delegation model.
- Execution cancellation, audit retention, and policy-enforcement contract.
- Search/indexing design and how it exposes only currently authorized tools.
- Production operations: audit/event retention, metrics, and hardening scope.
