# coyote-mcp contributor guide

## Purpose and architecture

coyote-mcp is a collection-aware enterprise MCP gateway. It registers downstream
MCP servers, securely discovers their advertised tools, and exposes a
PostgreSQL-backed catalog with organization-scoped identity and authorization.
The current HTTP API is the control plane; MCP protocol execution remains
deliberately disabled until its policy enforcement is implemented.

Read [the architecture guardrails](docs/architecture-guardrails.md) and the
[AI context](docs/ai-context/) before changing behavior. They describe the
current implementation and explicitly identify planned work. Inspect the
existing code, tests, and migrations before adding an abstraction or dependency.

## Technology and quality baseline

- Python 3.14 is managed with `uv`; the service uses FastAPI, FastMCP,
  SQLAlchemy, Pydantic, Alembic, and PostgreSQL.
- Use Ruff for linting, formatting, and import sorting. Keep strict mypy clean.
- Tests use pytest and branch coverage must remain at least 80%.
- Use Docker Compose for local PostgreSQL, migration, and application workflows.
- Create Alembic migrations only for persistent-model changes. Committed or
  applied revisions are immutable; prefer additive, backward-compatible
  migrations, using expand-and-contract changes when necessary.

## Security and tenancy

- Organizations are isolation boundaries. Every data lookup, relationship, and
  authorization decision must remain organization-scoped.
- Authorization is centralized and defaults to deny. Enforce it in application
  services as well as HTTP handlers; HTTP routing alone is not a security
  boundary.
- Collections organize discovery and capabilities; membership never grants
  access by itself.
- Treat downstream MCP servers, tool metadata, remote endpoints, and OIDC
  metadata as untrusted input. Preserve destination validation, DNS pinning,
  redirect controls, and current-authorization checks.
- Never commit, log, or persist plaintext credentials, PATs, OIDC tokens, or
  browser-session secrets. Use the approved secret-reference pattern and
  hash opaque bearer/session secrets at rest.

## Change expectations

- Prefer backward-compatible, narrowly scoped changes. Update affected tests
  and user/developer documentation in the same change.
- Add tests for changed behavior, especially authorization, tenant isolation,
  authentication, migration, and remote-call paths.
- Before completion, run `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy src/`, and pytest with branch coverage. Run the PostgreSQL
  integration test and `docker compose config` when their relevant surfaces
  change. Validate GitHub Actions workflows with actionlint when available.

See [.github/copilot-instructions.md](.github/copilot-instructions.md) for the
concise Copilot-specific version of these rules.

## Documentation maintenance

Documentation is part of the deliverable, not a separate follow-up task.

- Update relevant files under `docs/ai-context/` whenever implementation changes affect architecture, domain models, security, module responsibilities, or planned functionality.
- Keep `docs/ai-context/current-priorities.md` current after every meaningful feature, milestone, or phase completion. Record completed work, outstanding limitations, active priorities, and next steps.
- Update `docs/architecture-guardrails.md` whenever architectural decisions or invariants change.
- Update `docs/ai-context/backend-map.md` and `domain-model.md` when modules, services, entities, or relationships change.
- Update `docs/ai-context/security-model.md` whenever authentication, authorization, tenant isolation, or trust boundaries change.
- Clearly distinguish implemented functionality from planned functionality. Never describe unfinished features as operational.
- Keep documentation changes in the same PR as the corresponding implementation.
- Before completing a task, review whether these documents need updating. If no changes are necessary, explicitly state that in the completion summary.
