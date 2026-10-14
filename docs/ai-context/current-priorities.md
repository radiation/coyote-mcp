# Current priorities

## Completed

- **Phase 1:** PostgreSQL-backed registration of Streamable HTTP MCP servers,
  generation-safe tool discovery, persisted catalog, and collections.
- **Phase 2:** Organization-scoped roles and PATs; service principals;
  enterprise OIDC identities, provider-scoped group mappings, server-side
  browser sessions, browser-bound OIDC transactions, and provider-bound client
  secret references.
- **Quality and security infrastructure:** Python 3.14/uv, Ruff, strict mypy,
  pytest branch coverage (80% minimum), PostgreSQL integration tests, Docker
  Compose development, Dependabot, CI, and CodeQL configuration.

## Next

- **Phase 3:** Authenticated MCP discovery and execution with current
  authorization enforced at the service/execution boundary.
- **Later:** An HTMX operator console and semantic/search-based progressive
  discovery while preserving the database registry and policy model.

## Open technical decisions

- Downstream credential storage, authentication, and delegation model.
- Execution routing, cancellation, audit, and policy-enforcement contract.
- Search/indexing design and how it exposes only currently authorized tools.
- Production operations: audit/event retention, metrics, and hardening scope.
