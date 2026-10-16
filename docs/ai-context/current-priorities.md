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
  and temporary tenant cleanup. The profile uses hostname-specific private HTTP
  destination allowlists rather than broad SSRF development overrides.

## Next

- **Phase 3B:** Downstream credential integration, audit events, cancellation,
  and operational metrics for MCP execution.
- **Phase 3C:** Per-principal fine-grained tool policy, richer discovery, and
  semantic search without weakening the persisted-catalog boundary.
- **Later:** An HTMX operator console and semantic/search-based progressive
  discovery while preserving the database registry and policy model.

## Open technical decisions

- Downstream credential storage, authentication, and delegation model.
- Execution cancellation, audit retention, and policy-enforcement contract.
- Search/indexing design and how it exposes only currently authorized tools.
- Production operations: audit/event retention, metrics, and hardening scope.
