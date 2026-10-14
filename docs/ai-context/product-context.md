# Product context

coyote-mcp is an enterprise MCP gateway that aggregates registered downstream
MCP servers into a governed catalog. It solves the operational problem of
finding tools across teams while retaining organization boundaries,
authorization, and safe remote discovery.

The persisted catalog contains collections, servers, and tool descriptions
today. A client-facing progressive MCP tool-discovery interface, where clients
discover those capabilities instead of loading every downstream tool at once,
is planned for Phase 3. Collections organize related capabilities but do not
grant permission; organization-scoped roles and policies decide access.

The current product delivers the registry, catalog, PAT authorization, and
enterprise OIDC foundations. The next roadmap step is authenticated MCP
discovery and execution that applies the same policy at invocation time.
Subsequent work includes an HTMX operator console and semantic tool discovery.

See [architecture guardrails](../architecture-guardrails.md) for invariants and
[current priorities](current-priorities.md) for status.
