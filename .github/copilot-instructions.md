# Copilot instructions for coyote-mcp

coyote-mcp is a collection-aware enterprise MCP gateway: it securely catalogs
downstream MCP tools and governs access within organization boundaries. Read
[AGENTS.md](../AGENTS.md), [architecture guardrails](../docs/architecture-guardrails.md),
and [AI context](../docs/ai-context/) before making changes.

Use Python 3.14 and `uv`; the stack is FastAPI, FastMCP, SQLAlchemy, Pydantic,
Alembic, and PostgreSQL. Follow Ruff formatting/import sorting, keep strict
mypy clean, add or update pytest coverage, and preserve the 80% branch-coverage
minimum.

Inspect existing code before adding abstractions or dependencies. Keep changes
backward-compatible unless the change explicitly requires otherwise. Enforce
authorization in application services, not only HTTP handlers. Preserve
organization isolation, default-deny authorization, scoped PAT attenuation,
server-side sessions/OIDC transactions, hashed secrets, and validated external
destinations. Treat downstream MCP servers as untrusted.

Update directly affected tests and documentation. Before completion run Ruff,
strict mypy, pytest coverage, relevant PostgreSQL integration tests, and
`docker compose config`; validate workflow changes with actionlint when
available.

Keep docs/ai-context/ and docs/architecture-guardrails.md synchronized with 
implementation changes, updating current-priorities.md after meaningful milestones. 
Documentation updates belong in the same PR.
