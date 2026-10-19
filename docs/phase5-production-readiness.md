# Phase 5: Production Readiness Discovery and Gap Analysis

## Executive summary

The Phase 1-4 application has a strong security and tenancy foundation. It
already enforces current, default-deny authorization at service boundaries;
persists a curated catalog; treats downstream servers as untrusted; protects
outbound destinations with scheme, DNS, public-address, redirect, and pinning
controls; and keeps bearer/session secrets hashed. Downstream credentials and
OAuth tokens are sealed with versioned AES-256-GCM keys and owner-bound
additional authenticated data (AAD).

It is not ready to operate as a production internet-facing service. The main
blockers are operational rather than an identified authorization flaw: there is
no production deployment contract, database-backed readiness endpoint, request
limits or rate limiting, audit-event record, operational telemetry, retention
job, or recovery/rotation runbook. The current Compose definition is a local
development environment and must not be promoted as the production topology.

No Critical vulnerability was confirmed by this non-disruptive repository
review. Findings that depend on the runtime platform, such as network policy,
managed-database backups, secret-manager access controls, branch protection,
and hosted CodeQL alerts, are explicitly recorded as operational assumptions or
unknowns instead of defects.

## Scope and method

This review inspected the contributor guidance, architecture guardrails, AI
context, README, dependency and quality configuration, Docker/Compose assets,
all current Alembic revisions by presence and order, the principal runtime,
security, credential, gateway, OIDC, and persistence modules, and focused
tests. It did not contact external services, start containers, or alter
application behavior.

Severity describes production impact if the service is deployed as currently
represented in this repository:

| Severity | Meaning in this report |
| --- | --- |
| Critical | Confirmed, immediately exploitable confidentiality/integrity failure or likely irreversible data loss. None confirmed. |
| High | Production blocker or a material security/availability/auditability gap with a direct, plausible failure mode. |
| Medium | Important hardening or operational gap that should be addressed during Phase 5. |
| Low | Valuable improvement or clarification that can follow the production baseline. |

## Architecture baseline

### Runtime and routing

`src/coyote_mcp/app.py` constructs one FastAPI application, mounts the PAT-only
FastMCP endpoints at `/mcp` and `/mcp/collections/{slug}`, and mounts REST,
OIDC, and browser-console routers. `authenticate_mcp_requests` authenticates
the bearer PAT before FastMCP work and stores the immutable principal and bound
collection context in request-local context variables. The FastMCP tools create
per-operation database sessions.

`src/coyote_mcp/db.py:get_engine` creates the global async engine with
`pool_pre_ping=True`; `get_session` gives request handlers a session. The
application lifespan currently manages FastMCP lifespan objects only. The
engine is not explicitly disposed on shutdown.

### Authorization, tenancy, and browser identity

`src/coyote_mcp/auth.py:authorize` is the central default-deny policy check.
Organization ID is carried by `AuthenticatedPrincipal`, not inferred from an
unscoped global principal. PAT authentication in `authenticate_token` checks
hashes, expiry, revocation, enabled membership, and organization state.

OIDC is environment-configured in `src/coyote_mcp/settings.py:oidc_provider`.
`src/coyote_mcp/oidc.py` uses PKCE, nonce, a browser binding, server-side
single-use transactions, pinned no-redirect provider HTTP, and ID-token
signature/issuer/audience/expiry validation. Browser cookies are HttpOnly,
`SameSite=Lax`, host-prefixed and Secure outside development; mutations require
a derived CSRF token.

### Catalog and downstream execution

The database is authoritative for catalog reads. `DiscoveryService.sync` in
`src/coyote_mcp/discovery.py` uses a generation counter and row locks: it
commits the short state transition before remote I/O, then applies results only
when its generation is current. `GatewayService.execute_tool` in
`src/coyote_mcp/gateway.py` re-checks authorization and publication state,
snapshots routing before network work, validates untrusted schemas in a spawned
bounded worker, applies downstream timeouts and pinned transport, does not
forward the caller PAT, does not retry execution, and bounds the materialized
result.

`src/coyote_mcp/credentials.py:DownstreamCredentialBroker` supports `none`,
`shared_bearer`, and `per_user_oauth` policies without fallback from personal
credentials to shared ones. It uses short-lived sessions and serializes OAuth
refresh under a PostgreSQL row lock. `credential_vault.py` seals every
credential with AES-256-GCM and AAD that binds its purpose and owner.

### Existing capabilities to preserve

- Service-level centralized authorization, organization predicates, collection
  publication gating, and PAT attenuation.
- DNS-pinned, no-redirect outbound HTTP; public HTTPS defaults; host-specific
  local exceptions rather than broad insecure/private flags.
- Persisted catalog reads and sync generation checks, which prevent stale
  discovery from overwriting the current catalog.
- Opaque hashed PATs and browser sessions, PKCE/nonce/state OIDC protections,
  CSRF epoch rotation, and browser-session exclusion from MCP.
- Versioned credential key map, AES-GCM, AAD binding, write-only secret UI, and
  no execution retry after an upstream credential rejection.
- Additive Alembic history, PostgreSQL constraints, focused gateway tests, full
  CI lint/type/test/coverage validation, CodeQL, Dependabot, and the opt-in
  local Compose smoke workflow.

## Findings by workstream

### 5.1 Production configuration and deployment

| ID | Severity | Finding and evidence | Recommendation |
| --- | --- | --- | --- |
| P5-DEP-01 | High | There is no production deployment definition. `compose.yaml` is explicitly development-oriented: it mounts source and Alembic files, runs Uvicorn with `--reload`, uses local static database credentials, binds services to loopback, and supplies smoke-only private/insecure host exceptions. The only GitHub workflows are CI and CodeQL. | Define a separate production deployment contract and reference architecture. Keep development Compose intact; supply production image/run settings, external secret injection, one-shot migration orchestration, health probes, resource settings, and rollback procedure. |
| P5-DEP-02 | High | Required production configuration is only partially validated at process construction. `Settings.validate_session_secret` rejects the development session key outside development, but OIDC settings are validated when login is started and credential key settings when credentials are written. `database_url` has a local-development default. A misconfigured deployment can therefore start, pass `/healthz`, and fail on a privileged flow. | Introduce a production startup/config validation layer with explicit feature-aware requirements: database URL, session secret, public origin/proxy policy, OIDC settings when console login is enabled, and credential key map/active version when credentialed downstream policies are enabled. Do not require unused optional features. |
| P5-DEP-03 | Medium | `Dockerfile` uses a slim pinned-by-tag base image and locked dependencies, which is useful, but does not create/select a non-root runtime user, declare a health check, or document immutable image provenance. `compose.yaml` has no resource limits/restart policy for `app`. | Harden the runtime image to a non-root user and define a production health check. Select and document the orchestrator's CPU/memory limits, restart policy, image digest/update process, and termination grace period. |
| P5-DEP-04 | Medium | FastAPI has no trusted proxy/forwarded-header, allowed-host, HTTPS-redirect, or canonical public-origin configuration (`app.py`). The console derives collection endpoint display from request origin, as noted in `docs/ai-context/current-priorities.md`. | Make reverse-proxy trust and public URL explicit. Accept forwarded headers only from configured proxy networks, validate allowed hosts, and document TLS termination. Ensure the console uses a validated configured public origin where it must display an externally usable URL. |
| P5-DEP-05 | Medium | `migrate` waits for PostgreSQL health in development Compose and `app` waits for successful migration, but there is no documented production migration ownership, concurrency lock, rollback, or failed-migration procedure. Alembic revisions are additive, which is a strong starting point. | Run migrations as a singleton release step/job using the same immutable application image. Add deployment checks that prevent application rollout on migration failure, record the deployed revision, and require expand/contract compatibility before a rollback. |

Smallest practical deployment architecture: one stateless Coyote application
container behind an organization-managed TLS reverse proxy/load balancer, one
managed PostgreSQL 17+ service, and a secret manager. Run Alembic as a
single-release job before rolling application replicas. Use the platform's
native logs/metrics collector. No Kubernetes-specific controller or separate
observability platform is required for the first production release.

### 5.2 Secrets and credential management

| ID | Severity | Finding and evidence | Recommendation |
| --- | --- | --- | --- |
| P5-SEC-01 | High | Credential encryption keys can be rotated only by keeping every old key in `COYOTE_CREDENTIAL_ENCRYPTION_KEYS`; reads use the row's `key_version`, while writes use the active version (`credential_vault.py:_key`, `active_key_version`, `seal`, `open_sealed`). The README correctly says no automated re-seal command exists. Removing an old key before all rows are rewritten makes associated shared credentials, OAuth client secrets, tokens, or OAuth transactions unavailable. | Implement an authenticated, resumable re-seal operation with progress/reporting and tests for every encrypted model. Publish a two-phase rotation runbook: add new key, deploy with both, re-seal, verify zero old-version rows, then retire old key. Preserve backward-compatible reads until retirement. |
| P5-SEC-02 | High | Sensitive administrative and credential actions leave no durable audit trail. `docs/ai-context/security-model.md` explicitly states that configuration writes do not yet produce audit events; no audit model or audit logger exists in the source search. | Add append-only, tenant-scoped security audit events before production use. Record actor, organization, action, target type/ID, outcome, timestamp, request/correlation ID, and constrained reason metadata; never record plaintext secrets, bearer values, raw OAuth codes, or full downstream payloads. |
| P5-SEC-03 | Medium | Encryption and redaction controls are strong: AES-GCM and owner-bound AAD are in `credential_vault.py`; broker headers are excluded from `DownstreamAuthorization` repr; OAuth `TokenSet` repr is redacted; callers receive sanitized errors. However, no operational secret-injection reference, secret-manager policy, rotation schedule, or emergency revocation runbook exists. | Document secret sources and least-privilege access, define rotation ownership/SLOs, and exercise operator procedures for session-secret, OIDC secret, database credential, shared bearer, OAuth integration secret, PAT, and encryption-key compromise. |
| P5-SEC-04 | Medium | Disconnect deletes local OAuth credentials and attempts revocation only if the provider exposes a configured revocation endpoint (`downstream_oauth.py:revoke_token`, `connected_apps.py:disconnect`). GitHub OAuth Apps do not have a configured revocation endpoint, as documented. | Preserve the truthful UI behavior, add audit events for local disconnect/revocation result, and document provider-side revocation as a required operator/user step where remote revocation is unavailable. |

### 5.3 Security review and audit logging

| ID | Severity | Finding and evidence | Recommendation |
| --- | --- | --- | --- |
| P5-AUD-01 | High | Auditability is absent for permission, publication, credential, OAuth-connection, server endpoint, and administrative changes. This prevents reliable incident reconstruction despite correct preventive controls. | Deliver P5-02 (audit foundation) before production. Add tests that verify events are scoped, immutable, redacted, and emitted for success and policy-denied security-significant operations. |
| P5-AUD-02 | High | No application-level rate limiting, concurrency admission control, or request-body size policy is present in `app.py`; there is no proxy policy in repository configuration. An authenticated or unauthenticated caller can attempt high request rates, and gateway paths can trigger expensive schema-worker and downstream work. | Enforce a coarse request-size limit and route-aware rate/concurrency limits at the trusted edge; add application-level limits where enforcement must include tenant/principal identity or MCP execution cost. Explicitly cap concurrent schema workers and downstream executions. |
| P5-AUD-03 | Medium | Downstream SSRF defenses are substantial: `security.py:resolve_endpoint`, `discovery.py:PinnedDestinationTransport`, and OIDC/OAuth helpers reject credentials in URLs, restrict schemes, resolve/pin destinations, and disable redirects. This review found no confirmed SSRF bypass. The operational risk is unsafe deployment of broad `ALLOW_*` settings or overly broad hostname allowlists. | Preserve the code path. Make broad insecure/private settings invalid in production, inventory every allowlist entry at startup/audit time, and document a review process for each exception. |
| P5-AUD-04 | Medium | Browser sessions use Secure cookies outside development, HttpOnly, `SameSite=Lax`, server-side storage, CSRF checks, and one-time OIDC transactions (`oidc.py`). PAT authentication wins over cookie fallback. No confirmed CSRF/session flaw was found. | Add production browser acceptance tests through a TLS-terminating proxy and document expected cookie/proxy behavior. Consider a CSP and related browser response headers after validating console asset requirements. |
| P5-AUD-05 | Low | CI runs CodeQL security-and-quality queries and Dependabot checks uv, Actions, and Docker dependencies weekly. Hosted CodeQL alert state, secret scanning, branch-protection settings, and platform vulnerability scanning cannot be established from this repository. | Make CodeQL a protected required check after reviewing hosted results; confirm repository secret scanning/push protection and alert triage ownership. Add production image scanning/SBOM generation only as part of the deployment supply-chain increment, not as duplicate lint/test infrastructure. |

### 5.4 Observability and health

| ID | Severity | Finding and evidence | Recommendation |
| --- | --- | --- | --- |
| P5-OBS-01 | High | `/healthz` always returns `{"status":"ok"}` (`app.py:healthz`; `tests/test_health.py`) and does not check database availability, migration compatibility, or required configuration. It is liveness only, though it is not named/documented that way. | Retain a fast liveness endpoint and add a bounded, dependency-aware readiness endpoint. Readiness should verify database connectivity and expected Alembic revision; it should expose no secrets or detailed topology to unauthenticated callers. |
| P5-OBS-02 | High | Logging is standard-library, local, and mostly diagnostic. `gateway.py` and `oidc.py` log classified failures, but no structured format, correlation/request ID, logging configuration, or metrics exporter exists. Console dashboard counts are not operational metrics. | Add structured JSON logging with generated/adopted request ID and safe fields. Emit standard counters/histograms for HTTP, authentication/authorization denials, DB pool pressure, discovery, MCP execution, OAuth refresh, schema validation, and downstream latency/failures. Integrate through OpenTelemetry-compatible logging/metrics rather than a vendor SDK. |
| P5-OBS-03 | Medium | Sensitive values are deliberately absent from normal client errors and model reprs, but an end-to-end log redaction contract is not tested and the framework/server access logs are not configured here. | Define a log-event schema and explicit redaction test corpus for PATs, sessions, OAuth codes/tokens, credentials, Authorization headers, and downstream response/error bodies. Configure server/proxy access logs so query strings and sensitive headers are not retained. |
| P5-OBS-04 | Medium | No alert thresholds or SLOs are documented. | Start with alerts for readiness failure, elevated 5xx/401/403, database pool exhaustion, downstream timeout/error rate, schema-worker timeout/crash, OAuth refresh failure, migration failure, and audit-event write failure. Establish service-level indicators before tuning thresholds. |

### 5.5 PostgreSQL resilience

| ID | Severity | Finding and evidence | Recommendation |
| --- | --- | --- | --- |
| P5-DB-01 | High | Engine setup has only `pool_pre_ping=True` (`db.py:get_engine`). It does not set pool size/overflow, pool checkout timeout, connect timeout, statement/lock/idle transaction timeouts, or a shutdown disposal hook. Unbounded/default behavior is not an intentional production capacity policy. | Add settings-backed database pool and timeout policy, dispose the engine during application shutdown, and expose pool telemetry. Set server-side PostgreSQL timeouts through managed-DB configuration or connection options after measuring gateway and migration requirements. |
| P5-DB-02 | High | No backup, point-in-time recovery, restore verification, RPO/RTO, or encrypted-credential recovery procedure is in repository docs. Database loss also loses credential ciphertext; encrypted data cannot be recovered without the corresponding historical key versions. | Define managed PostgreSQL backup/PITR, restore drill frequency, RPO/RTO, and access controls. Back up/retain credential key versions independently but under an approved secret-recovery procedure. Validate restore against a non-production isolated environment. |
| P5-DB-03 | Medium | Short row locks are used correctly for discovery and catalog deletion; OAuth token refresh intentionally holds a connection lock across token HTTP to prevent concurrent rotation (`credentials.py:_refresh`). This is reasonable for correctness but needs capacity visibility and timeout testing. | Preserve lock semantics. Measure refresh wait time, set a bounded token request/transaction policy, test contention and cancellation, and document expected behavior under provider slowness. |
| P5-DB-04 | Medium | Models include expiring/revocable browser sessions, OIDC transactions, downstream OAuth transactions, expired PATs, disabled records, and persisted catalog history, but there is no cleanup job or retention policy. | Add a safe, batched, observable retention task with per-entity retention rules. It must not remove data needed for active authorization, incident response, or encrypted credential/key retirement verification. |
| P5-DB-05 | Medium | Alembic is tested in CI and integration tests assert the current head. Production migration concurrency and recovery are not exercised; operational migration ownership is unspecified. | Treat P5-DEP-05 as the controlling release procedure. Add a PostgreSQL validation for concurrent migration/job behavior where the chosen deploy platform cannot guarantee a singleton job. |

### 5.6 Reliability and performance

| ID | Severity | Finding and evidence | Recommendation |
| --- | --- | --- | --- |
| P5-REL-01 | Medium | Discovery, execution, OIDC, and downstream OAuth all have explicit settings-backed timeouts. Execution does not retry non-idempotent tools; gateway schema validation has a spawned process, 5-second default wall-clock limit, and Linux address-space limit. These are good controls, but no global overload protection exists. | Retain the current timeout/no-retry design. Add admission limits and cancellation/disconnect propagation tests, then establish per-route timeout budgets that include proxy and database constraints. |
| P5-REL-02 | Medium | Gateway execution releases the registry read session before network I/O, while credential operations use short-lived sessions. This avoids a common pool-exhaustion failure. However, unbounded concurrent client requests can still create sessions, schema-worker processes, and outbound clients. | Add bounded semaphores/queues for costly work and load tests that cover slow downstream servers, connection resets, response over-limit behavior, database pool exhaustion, and schema-worker exhaustion. |
| P5-REL-03 | Medium | `DiscoveryService.sync` preserves the last successful catalog on failure and rejects stale sync results. There is no automatic health probe/backoff or documented operator alerting for servers in `error`/stale state. | Make failure state visible through metrics/audits/console; decide whether sync remains explicitly operator-triggered or gains a bounded scheduler. Do not automatically retry tool execution. |
| P5-REL-04 | Low | Existing tests are unusually meaningful for an MVP: real local FastMCP execution, downstream auth isolation, timeout/failure handling, SSRF behavior, PostgreSQL sync races, and a Compose smoke runner. There is no load/soak suite or production-proxy browser acceptance test. | Add small, deterministic failure and load scenarios to Phase 5 validation, not an open-ended benchmark framework. Include graceful termination with in-flight MCP work and client disconnects. |

### 5.7 Operational readiness

| ID | Severity | Finding and evidence | Recommendation |
| --- | --- | --- | --- |
| P5-OPS-01 | High | README documents local bootstrap, local OIDC, Compose smoke, and developer checks, but not production install/configuration, secret injection, migration ownership, proxy/TLS, backup/restore, incident response, or upgrade/rollback. | Create a production operations guide and small runbooks alongside the implementation increments. Every runtime prerequisite must be explicit and testable. |
| P5-OPS-02 | High | Initial instance-administrator creation is deliberately an operator-only CLI process and there is no application backdoor. This is correct, but break-glass database recovery and post-bootstrap recovery are only described at a high level in README. | Write a dual-control break-glass runbook, including approval/audit steps, identity verification, exact post-recovery checks, and how to revoke temporary recovery access. |
| P5-OPS-03 | Medium | The README retains historical statements that conflict with the implemented Phase 3/4 gateway, console CRUD, and downstream credential features; for example, its final “Explicitly not implemented yet” section lists implemented capabilities. | Correct production-facing documentation as part of Phase 5. Keep docs/ai-context synchronized and clearly distinguish current behavior from deferred work. |
| P5-OPS-04 | Medium | The Compose smoke runner is a useful local acceptance test but is not deployment automation and relies on local Docker/ports. | Preserve it for developer/manual acceptance. Define a non-destructive post-deploy smoke procedure using a dedicated production-like tenant and explicitly published harmless test tool, or an equivalent platform health transaction. |

## Confirmed security posture and attack-surface assessment

No confirmed cross-organization authorization, PAT forwarding, SSRF bypass,
plaintext credential storage, OIDC transaction replay, or OAuth credential
fallback vulnerability was found in the reviewed paths. The following remain
the priority attack/failure surfaces for Phase 5 validation:

- Flooding `/mcp`, API, console, or login routes to consume application workers,
  connections, schema-validation child processes, and downstream capacity.
- A production proxy forwarding untrusted client `Forwarded`/`X-Forwarded-*`
  headers, producing incorrect public URLs or cookie/TLS behavior.
- A false-positive static health response keeping traffic on an application that
  cannot reach its database or has incompatible migration/configuration state.
- Premature removal of a credential encryption key causing sealed records to
  become undecryptable.
- Inability to reconstruct who changed a downstream endpoint, publication,
  authentication policy, or credential after an incident.
- PostgreSQL outage, connection exhaustion, failed release migration, or restore
  without retained encryption-key versions.

## Module organization and maintainability

File length alone is not a refactoring trigger. The current modules largely
follow practical service boundaries, and Phase 5 should not destabilize them
before protective controls are in place.

| Module | Assessment | Recommendation and timing |
| --- | --- | --- |
| `console.py` (1,835 lines) | It is a route/controller layer with repeated authorization, form parsing, rendering, and error-response patterns across server, collection, publication, profile, and authentication pages. Its mutations already delegate to services. | Split **during** Phase 5 only if adding audit instrumentation would otherwise duplicate logic. Proposed package: `console/routes/{organizations,servers,collections,publications,connected_apps}.py`, plus `console/rendering.py` and `console/forms.py`. Keep router composition and templates stable. Risk: route imports/circular dependencies and CSRF/authorization regressions; require browser and authorization regression tests. |
| `connected_apps.py` (988 lines) | It combines authorization helpers, admin configuration writes, connection lifecycle, OAuth transaction completion, secret sealing, and UI-view shaping. It is a high-value security-review surface. | Refactor **before or alongside** credential rotation/audit work. Proposed package: `downstream_auth/{authorization,integration_admin,connections,transactions,views}.py`, with credential cryptography remaining in `credential_vault.py`. Risk: transaction boundaries and error-code compatibility; migrate via thin compatibility exports and focused OAuth/tenant tests. |
| `catalog.py` (810 lines) | Cohesive organization-scoped catalog and publication service, including integrity-oriented locks and constraints. | Do not split before production deployment. After Phase 5, consider `catalog/{servers,collections,publications,queries}.py` only when service changes become difficult to review. Preserve a shared authorization boundary. |
| `auth.py` (768 lines) | Authenticates credentials, manages sessions/PATs, resolves memberships/groups/roles, and handles organization selection/bootstrap. These are related but security sensitive. | Do not refactor ahead of Phase 5. After the audit foundation, a careful split into `identity`, `sessions`, `tokens`, and `authorization` can make review easier. Risk: accidental policy duplication; `authorize` must remain the sole decision point. |
| `api.py` (669 lines) | Thin route adapter around catalog/auth services; size derives from endpoint count, not mixed persistence logic. | No pre-production refactor. Extract routers by resource only when adding related operational APIs, retaining shared `require`. |
| `gateway.py` (654 lines) | Cohesive execution boundary but combines query/publication resolution, subprocess schema validation, credential selection, and transport mapping. | Keep intact for the initial reliability increment. After its failure/metric behavior is covered, extract pure `schema_validation` and `downstream_transport` helpers. Risk: changing no-retry, redaction, or session-release semantics. |

Only the Connected Apps split is recommended before production if its planned
rotation/audit changes become unwieldy. The console split is optional during
Phase 5; all other refactors should follow the production baseline.

## Quality-gate baseline

The existing quality gates are meaningful and should be preserved rather than
duplicated:

- `.pre-commit-config.yaml` runs Ruff lint/format and strict mypy before commit,
  with pytest on pre-push.
- `pyproject.toml` enables strict mypy, Ruff checks, branch coverage, and an
  80% coverage floor.
- `.github/workflows/ci.yml` runs locked dependency installation, lint, format,
  mypy, Alembic migration, PostgreSQL-backed tests, coverage artifacts, and
  Codecov upload when a secret is available.
- `.github/workflows/codeql.yml` runs weekly and on changes with
  `security-and-quality`; Dependabot updates uv, Actions, and Docker weekly.
- The local smoke profile exercises real FastMCP discovery/execution and tenant
  isolation without exposing its mock server publicly.

Meaningful Phase 5 additions are production-image/deployment validation,
operational failure tests, audit-redaction tests, proxy/browser acceptance, and
backup/restore drills. Do not add a second lint/test stack or replace the
existing smoke coverage.

## Dependency-aware implementation sequence

1. **P5-01: Production configuration and deployment contract** establishes the
   explicit runtime boundary required by all later work.
2. **P5-02: Security audit-event foundation** supplies the durable evidence
   required for all subsequent administrative controls.
3. **P5-03: Readiness, structured logging, and edge protections** makes the
   deployed service observable and resilient to common overload/route failures.
4. **P5-04: PostgreSQL resilience and operational recovery** sets pool/timeouts,
   cleanup, backup/restore, and release procedures atop the production contract.
5. **P5-05: Credential lifecycle and encryption-key rotation** relies on audit,
   production secrets, and recovery decisions.
6. **P5-06: Reliability validation and controlled performance hardening** uses
   the preceding telemetry/limits to test realistic failure behavior.
7. **P5-07: Documentation, runbooks, and release readiness** is updated with
   every increment and closed with a full operator review.

Quick wins: accurate liveness/readiness naming, startup configuration validation,
non-root image, health check, structured request ID, production configuration
reference, and correcting stale README statements. Foundational changes: audit
events, key re-sealing, production deployment/migration ownership, database
recovery, and workload admission control.

## Increment-by-increment execution plan

### P5-01 - Production deployment and configuration contract (M)

**Status: verified on 2026-10-19.** Production configuration fails closed for an
explicit external database URL, canonical HTTPS origin, allowed hosts, trusted
proxy networks, unsafe destination exceptions, and enabled optional
identity/credential features. The Docker artifact runs as non-root, disables
Uvicorn proxy-header rewriting so application middleware evaluates the direct
peer address, and `compose.production.yaml` separates the singleton `release`
migration operation from the application. Production-image, real HTTP
proxy-spoofing, disposable PostgreSQL migration ownership, full test/coverage,
and static validation checks passed. See
[Production deployment](operations/production-deployment.md).

**Objective and scope:** Define the supported production topology, settings
contract, image behavior, proxy/TLS assumptions, release migration process, and
runtime hardening without changing existing development Compose behavior.

**Reuse:** `Settings`, current Dockerfile locked `uv` installation, additive
Alembic history, and the existing Compose migration ordering.

**Likely files/packages:** `settings.py`, `app.py`, `db.py`, `Dockerfile`, new
production deployment examples/templates as selected by humans, README,
operations docs, and affected setting/app tests.

**Approach:** Add feature-aware production settings validation; make production
origin/proxy/trusted-header policy explicit; run as non-root; add health check
and graceful application shutdown; document a singleton migration job and
rollback compatibility policy. Keep secret values injected only by environment
or the selected platform's secret mechanism.

**Dependencies:** None.

**Acceptance criteria:** A fresh production configuration fails before serving
traffic when required settings are invalid; an immutable non-root image runs
without source mounts/reload; a documented release sequence performs migrations
once; proxy/TLS behavior is specified and tested.

**Tests and validation:** Settings matrix tests, image inspection/run test in CI
or release pipeline, application shutdown test, `docker compose config` for
development preservation, and a reverse-proxy acceptance test appropriate to
the selected platform.

**Risks/breaking changes:** New production-required settings may prevent a
previously permissive deployment from starting. Use explicit environment mode
and migration documentation. Complexity: **M**.

### P5-02 - Append-only security audit events (L)

**P5-02A status: implemented on 2026-10-19. P5-02B status: implemented on
2026-10-19.** Migration `0021` adds the
tenant-scoped append-only audit ledger, and `audit.record_audit_event` writes
validated events through the caller's existing transaction. PostgreSQL triggers
reject updates and deletes; SQLAlchemy also rejects ordinary ORM mutation.
Audit records retain actor and target UUID snapshots without foreign keys, so
they remain interpretable if a principal or target is later removed. Event names,
outcomes, actor types, target types, and compact metadata fields are allowlisted.
P5-02B records successful events in the same transaction for the following
implementation inventory:

| Service boundary | Mutation and audit action | Target and safe metadata | Transaction ownership |
| --- | --- | --- | --- |
| `auth.create_initial_organization` | Organization bootstrap / `organization.created` | Organization; slug | Existing service transaction |
| `auth.issue_pat` (when an initiating actor is supplied) and API revocation handlers | PAT issue or revoke / `credential.created` or `credential.revoked` | Credential; `credential_kind=pat` | Existing service or API transaction |
| `catalog.register_server`, `update_server`, `set_server_enabled`, `delete_server` | Server registration, edit, state transition, removal | Server; name/transport or changed fields | Catalog service transaction |
| `catalog.register_collection`, `update_collection`, membership and publication methods | Collection, membership, and publication changes | Collection/publication; slugs, server IDs, aliases, changed fields | Catalog service transaction |
| `connected_apps` policy, integration, and shared-credential methods | Authentication policy and OAuth configuration, shared credential replacement/removal | Server/credential; changed field, credential kind/key version | Connected Apps service transaction |
| `connected_apps` connection lifecycle | OAuth start, connected credential storage, local disconnect | Connection; provider and local revocation state | Connected Apps service transaction |
| Identity-management API boundaries | Service-principal creation/disable and external-group role mapping | Principal/policy; identity type, role count, scope | Existing API-owned transaction |

No audit event is emitted for a no-op state request. Events are emitted after
authorization and before the owning commit; a failed audit flush therefore
prevents that commit. Metadata intentionally excludes plaintext PATs,
credentials, OAuth codes/tokens, client secrets, endpoints, and error bodies.

`complete_connection` retains its pre-existing short transaction that consumes
the single-use OAuth callback state before external token exchange. The durable
event covers the later successful local connection replacement and commits with
that credential state. Auditing the earlier consumption atomically would require
holding a database transaction across untrusted provider I/O, so it is not
given a non-atomic success event in P5-02B.

P5-02C1 independently persists attributable PAT/browser authentication
failures and centralized API, console, and MCP collection authorization denials.
Each uses a short-lived transaction distinct from the denied request, bounded
by the configurable two-second `COYOTE_INDEPENDENT_AUDIT_TIMEOUT_SECONDS`
deadline across acquisition, flush, and commit, and preserves the original
denied response if audit persistence fails or times out, while
sanitized operational logging makes evidence loss visible. The tenant-required
schema intentionally leaves malformed or unrecognized credentials,
unaffiliated sessions, pre-tenant OIDC failures, and non-disclosing
cross-organization not-found responses out of the ledger rather than assigning
an arbitrary organization. MCP execution outcomes, broader read-only security
activity, audit query/UI, export/retention, and asynchronous delivery remain
deferred to later P5-02C scope.

**Objective and scope:** Record security-significant administrative, identity,
credential, policy/publication, server, OAuth-connection, and execution events
without persisting secrets or downstream payloads.

**Reuse:** `AuthenticatedPrincipal`, service-level authorization, organization
IDs, existing models/migrations/test conventions, and classified error paths.

**Likely files/packages:** New audit service/model/schema, new Alembic revision,
`auth.py`, `catalog.py`, `connected_apps.py`, `gateway.py`, `oidc.py`, console/
API adapters, tests, security/domain/backend docs.

**Approach:** Use an append-only organization-scoped table with constrained
event types/outcomes and structured safe metadata. Centralize emission at the
service boundary rather than templates/routes. Decide explicitly whether denied
attempts and MCP executions are synchronous writes, buffered, or independently
durable; audit loss must be visible.

**Dependencies:** P5-01 for correlation IDs/logging conventions.

**Acceptance criteria:** All listed sensitive operations emit tenant-scoped,
redacted, immutable events with actor and outcome; cross-tenant access is
impossible; a query/export retention contract is documented.

**Tests and validation:** Unit/route/service negative tests, PostgreSQL
constraint tests, redaction tests, migration test, and performance test for
the chosen write path.

**Risks/breaking changes:** Write amplification and availability coupling.
Avoid recording raw secrets or unbounded request data. Complexity: **L**.

### P5-03 - Readiness, structured telemetry, and admission controls (L)

**Objective and scope:** Separate liveness/readiness, add safe structured logs
and metrics, and establish request-size/rate/concurrency controls at the edge
and application boundaries.

**Reuse:** `/healthz`, existing classified errors/log statements, settings
timeouts, `GatewayService` execution boundary, and standard ASGI middleware.

**Likely files/packages:** `app.py`, `settings.py`, `db.py`, `gateway.py`,
`discovery.py`, `oidc.py`, logging/metrics module, proxy/deployment docs,
focused tests.

**Approach:** Keep `/healthz` as cheap liveness or rename it clearly; add a
bounded database/revision readiness endpoint. Establish request IDs and JSON
events, OpenTelemetry-compatible metrics, application semaphores for expensive
work, and documented reverse-proxy request limits/rate limits. Do not log
headers, tokens, OAuth codes, or raw downstream content.

**Dependencies:** P5-01; P5-02 supplies audit/correlation convention but need
not block initial health/metrics work.

**Acceptance criteria:** Orchestrator can distinguish process from dependency
health; every request has a safe correlation ID; dashboards can show latency,
errors, pool pressure, and downstream outcomes; abusive input/concurrency is
bounded deterministically.

**Tests and validation:** Readiness failure test, logging-redaction test,
concurrency/request-limit tests, metric contract tests, and proxy configuration
acceptance test.

**Risks/breaking changes:** Rate/size limits can reject existing clients; expose
limits as documented settings and tune with data. Complexity: **L**.

### P5-04 - PostgreSQL resilience, retention, and recovery (L)

**Objective and scope:** Make database capacity, lifecycle, cleanup, migration,
backup, and restore procedures operationally reliable.

**Reuse:** `pool_pre_ping`, short-lived gateway/credential sessions, existing
row-lock patterns, PostgreSQL integration test fixture, Alembic CI step.

**Likely files/packages:** `db.py`, `settings.py`, application lifespan,
retention job/CLI as selected, tests, deployment and recovery runbooks.

**Approach:** Configure pool size/overflow/checkout/connect limits, dispose on
shutdown, set documented database statement/lock/idle policies, add batched
retention with observability, and write/execute a restore drill. Make migrations
a singleton release responsibility and document rollback constraints.

**Dependencies:** P5-01 and P5-03.

**Acceptance criteria:** Database outages/pool exhaustion become visible and
bounded; graceful shutdown releases resources; expired transient data is pruned
safely; restore meets agreed RPO/RTO; migrations have a tested ownership path.

**Tests and validation:** PostgreSQL integration tests for pool/lifecycle,
retention and lock contention; release migration simulation; documented
non-production backup restore drill.

**Risks/breaking changes:** Aggressive cleanup/timeouts can invalidate active
flows or cancel valid operations. Make schedules/thresholds configurable and
conservative. Complexity: **L**.

### P5-05 - Credential lifecycle and encryption-key rotation (M)

**Objective and scope:** Provide safe re-sealing, rotation visibility, and
incident procedures for every encrypted downstream record.

**Reuse:** Versioned key map, `SealedValue`, AAD helpers, credential broker,
transactional OAuth flows, and write-only console patterns.

**Likely files/packages:** `credential_vault.py`, `credentials.py`,
`connected_apps.py` or its extracted package, CLI/job, audit service, tests,
credential rotation runbook.

**Approach:** Inventory every row by key version, re-seal idempotently in small
transactions using the active key, retain failed rows for explicit retry, and
emit safe audit/metrics. Define session/OIDC/database-secret rotation separately
because those have different invalidation semantics.

**Dependencies:** P5-01, P5-02, P5-04.

**Acceptance criteria:** Operators can rotate a key without service outage or
loss of readable credentials; retirement is blocked/reported while old-version
rows remain; compromise/recovery steps are documented and exercised.

**Tests and validation:** Key-map compatibility, all encrypted entity types,
resume/retry, AAD mismatch, missing old key, PostgreSQL batch behavior, and
redacted audit/log coverage.

**Risks/breaking changes:** Incorrect re-sealing can cause unrecoverable access
loss. Require verified backups and retain old keys until an independently
verified zero-row report. Complexity: **M**.

### P5-06 - Failure-mode and performance validation (M)

**Objective and scope:** Turn the most realistic production failure scenarios
into deterministic automated tests and baseline measurements.

**Reuse:** Existing FastMCP local server tests, PostgreSQL race tests, Compose
smoke profile, downstream timeout/no-retry behavior, and new telemetry.

**Likely files/packages:** Gateway/discovery/credentials/app tests, scripts or
test fixtures, deployment smoke instructions.

**Approach:** Test slow/unavailable downstreams, client disconnects, graceful
termination, request floods, schema-worker exhaustion, OAuth refresh contention,
DB pool exhaustion, migration/readiness failure, and response/result limits.
Choose a small reproducible load tool only after defining target traffic and
SLOs.

**Dependencies:** P5-03 and P5-04; P5-05 for rotation failure cases.

**Acceptance criteria:** Documented failure modes fail safely within bounded
resource use, no PAT/credential leakage, actionable signals, and no unintended
execution retries.

**Tests and validation:** Focused integration/load suite in an isolated local or
CI environment; retain existing unit/PostgreSQL/smoke validation.

**Risks/breaking changes:** Flaky network/load tests. Keep deterministic local
fixtures and separate capacity benchmarks from required unit gates. Complexity:
**M**.

### P5-07 - Runbooks, deployment smoke, and production sign-off (M)

**Objective and scope:** Make the service operable without original-developer
knowledge and validate the complete production baseline.

**Reuse:** README bootstrap, CLI bootstrap, Compose smoke runner, existing docs,
and all earlier increment outputs.

**Likely files/packages:** README, `docs/operations/` or agreed equivalent,
`docs/ai-context/`, architecture guardrails where invariants change, deployment
automation and smoke script as appropriate.

**Approach:** Publish install/config, deploy/upgrade/rollback, database
backup/restore, credential/key rotation, incident triage, instance-admin
break-glass, alert response, and post-deploy smoke runbooks. Correct stale
historical README claims. Conduct a human operational tabletop/recovery review.

**Dependencies:** P5-01 through P5-06.

**Acceptance criteria:** A qualified operator can deploy, migrate, bootstrap,
monitor, recover, rotate credentials/keys, and roll back using documentation;
all Phase 5 exit criteria have recorded evidence.

**Tests and validation:** Documentation walkthrough, non-production recovery
drill, post-deploy smoke, and full repository quality gates.

**Risks/breaking changes:** Documentation can drift. Make runbook updates a
required acceptance item for future operational changes. Complexity: **M**.

## Phase 5 exit criteria

- A reviewed, repeatable production deployment exists for a non-root immutable
  image, managed PostgreSQL, secret manager, TLS proxy, singleton migration
  job, health probes, resource/restart limits, and documented rollback.
- Production settings fail closed before traffic for invalid required runtime,
  identity, secret, credential, and proxy configuration.
- Liveness, database/migration readiness, structured redacted logs, correlation
  IDs, standard metrics, dashboards, and actionable alerts are operating.
- Route and expensive-work admission controls bound request size, rate,
  concurrency, and downstream/schema-worker resource consumption.
- Append-only, tenant-scoped, redacted audit events cover sensitive admin,
  credential, OAuth, policy/publication, server, authentication, and MCP
  execution decisions according to an approved retention policy.
- Database pool/timeouts/shutdown behavior, retention, migration ownership,
  backup/PITR, restore, RPO, and RTO are defined and verified in a drill.
- Credential encryption rotation can re-seal all protected records safely;
  historical keys are retained/recoverable until verification completes.
- Focused failure-mode, proxy/browser, PostgreSQL, production-image, and
  post-deploy smoke validations pass alongside existing CI/CodeQL/coverage
  gates.
- Operators have reviewed runbooks for deployment, bootstrap/break-glass,
  incident response, recovery, upgrade/rollback, secret rotation, and key
  retirement; documentation accurately describes the implemented product.

## Open architectural decisions requiring human input

1. **Deployment platform and ingress owner:** Which environment supplies TLS,
   WAF/rate limits, trusted proxy networks, secret injection, image scanning,
   managed PostgreSQL/PITR, and workload scheduling?
2. **Audit contract:** Which actions require synchronous durable audit writes,
   how long events are retained, who can query/export them, and what are the
   privacy/compliance requirements?
3. **Availability policy:** What RPO/RTO, replica count, expected MCP execution
   volume, downstream concurrency, and acceptable degraded modes are required?
4. **Encryption-key custody:** Which secret manager/HSM owns versioned key
   material, how are historical versions recovered, and who authorizes emergency
   rotation/retirement?
5. **Public endpoint model:** Is Coyote exposed directly to clients, only via
   an internal gateway, or both? This determines exact rate-limit and proxy
   trust boundaries.
6. **Downstream credential policy:** Are provider-specific remote revocation,
   additional OAuth providers, GitHub Apps, automatic re-seal, and provider
   metadata discovery required for the first production deployment?

## Assumptions and unknowns

- Hosted branch-protection, CodeQL alerts, Dependabot merge policy, secret
  scanning/push protection, registry image scanning, and cloud IAM cannot be
  verified from repository content.
- Managed PostgreSQL encryption at rest, TLS, backups, network isolation,
  multi-zone availability, and restore capability are deployment decisions not
  implemented by this application.
- This review did not load-test FastMCP/ASGI cancellation behavior, execute
  database migrations, inspect deployment infrastructure, or test a real OIDC
  or downstream OAuth provider. These are validation requirements, not claims
  of current defects.