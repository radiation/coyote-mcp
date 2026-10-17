# Product context

coyote-mcp is an enterprise MCP gateway that aggregates registered downstream
MCP servers into a governed catalog. It solves the operational problem of
finding tools across teams while retaining organization boundaries,
authorization, and safe remote discovery.

The persisted catalog contains collections, servers, and tool descriptions.
Phase 3A supplies a progressive MCP interface: clients search, describe, and
execute published and authorized catalog tools through three fixed gateway tools
rather than loading every downstream tool at once. Collections organize related
capabilities but do not grant permission; organization-scoped roles and enabled
collection publications both decide access.

The current product delivers the registry, catalog, PAT authorization,
enterprise OIDC foundations, PAT-authenticated MCP discovery/execution, and a
read-only browser-session administration console. The console is a Jinja2/HTMX
surface over persisted organization-scoped data and centralized RBAC; it has no
management mutations in Phase 4A. Subsequent work includes downstream credential
delegation, auditing and cancellation (Phase 3B), richer tool policy and
aggregation (Phase 3C), console CRUD workflows, and semantic tool discovery.

See [architecture guardrails](../architecture-guardrails.md) for invariants and
[current priorities](current-priorities.md) for status.
