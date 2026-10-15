# Current priorities

## Completed

- **Phase 1:** PostgreSQL-backed registration of Streamable HTTP MCP servers,
  generation-safe tool discovery, persisted catalog, and collections.
- **Phase 2:** Organization-scoped roles and PATs; service principals;
  enterprise OIDC identities, provider-scoped group mappings, server-side
  browser sessions, browser-bound OIDC transactions, and provider-bound client
  secret references.
- **Phase 3A:** PAT-authenticated FastMCP Streamable HTTP endpoint with
  universal PostgreSQL-backed search, description, and execution. Every MCP
  operation re-evaluates current authorization; collection-scoped execution is
  collection-bound, validated, DNS-pinned, timeout-bounded, and does not
  forward caller credentials. Hardening adds escaped/bounded lexical search,
  explicit schema validation, classified downstream failures, response-size
  bounds, and deterministic local FastMCP execution tests.
- **Quality and security infrastructure:** Python 3.14/uv, Ruff, strict mypy,
  pytest branch coverage (80% minimum), PostgreSQL integration tests, Docker
  Compose development, Dependabot, CI, and CodeQL configuration.

## Next

- **Phase 3B:** Downstream credential integration, audit events, cancellation,
  and operational metrics for MCP execution.
- **Phase 3C:** Fine-grained tool policy, selective native aggregation, and
  richer discovery without weakening the persisted-catalog boundary.
- **Later:** An HTMX operator console and semantic/search-based progressive
  discovery while preserving the database registry and policy model.

## Open technical decisions

- Downstream credential storage, authentication, and delegation model.
- Execution cancellation, audit retention, and policy-enforcement contract.
- Search/indexing design and how it exposes only currently authorized tools.
- Production operations: audit/event retention, metrics, and hardening scope.
