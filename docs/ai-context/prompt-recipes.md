# Prompt recipes

Use these patterns after reading [AGENTS.md](../../AGENTS.md) and the relevant
architecture context.

## New feature

“Implement `<feature>` using the existing service and authorization patterns.
Inspect related code and tests first, keep it backward-compatible, update
documentation, and run the required validation.”

## Database change

“Add `<data model change>` with a new additive Alembic migration. Preserve
tenant foreign-key/uniqueness constraints where applicable, update models and
schemas, add migration and behavior tests, and do not alter existing revisions.”

## Security-sensitive change

“Implement `<change>` while preserving default-deny service-level authorization,
organization isolation, hashed secret handling, and explicit remote destination
validation. Add negative tests for unauthorized and cross-tenant access.”

## MCP integration

“Add `<integration>` through the validated downstream boundary. Treat remote
metadata as untrusted, preserve DNS pinning and redirect rules, do not embed
credentials in endpoints, and enforce current authorization before discovery or
execution.”

## Tests

“Add focused pytest coverage for `<behavior>`, including relevant edge cases,
authorization/tenant boundaries, and PostgreSQL behavior. Keep total branch
coverage at or above 80%.”

## Review or regression fix

“Review/fix `<issue>` with the smallest backward-compatible change. Identify
the root cause from existing code and tests, update directly affected
documentation, and run the repository validation commands.”
