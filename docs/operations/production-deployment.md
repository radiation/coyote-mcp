# Production Deployment

## Scope

Coyote is deployed as one stateless application container behind a trusted TLS
reverse proxy and uses an externally managed PostgreSQL 17+ database. The
application container is not a public internet endpoint. Docker is the portable
artifact; [compose.production.yaml](../../compose.production.yaml) is a
reference deployment, not a substitute for platform backup, secret-management,
or ingress controls.

Development remains [compose.yaml](../../compose.yaml). Do not combine the two
files or promote the development source mounts, reload mode, local credentials,
or smoke-only downstream exceptions to production.

## Image

Build the locked runtime artifact:

```bash
docker build --tag registry.example/coyote-mcp:<immutable-version> .
```

The image installs only locked non-development dependencies, runs as the `coyote`
non-root user, serves with Uvicorn without reload, receives SIGTERM through the
container init process, and probes `/healthz`. Pin the released image by digest
in the deployment platform or `COYOTE_IMAGE`; do not use a mutable production
tag as a rollback record.

## Required configuration

Inject configuration through the deployment platform's environment/secret
mechanism. Do not place secret values in Compose files, image layers, repository
files, command history, or logs.

| Variable | Required | Requirement |
| --- | --- | --- |
| `ENVIRONMENT` | Yes | `production`. |
| `DATABASE_URL` | Yes | Explicit external `postgresql+asyncpg://` URL for PostgreSQL 17+. The development default is rejected. |
| `SESSION_SECRET_KEY` | Yes | A secret with at least 32 characters, distinct from the development default. |
| `COYOTE_PUBLIC_BASE_URL` | Yes | Canonical HTTPS origin, without path, query, fragment, or credentials. |
| `COYOTE_ALLOWED_HOSTS` | Yes | JSON list of explicit hostnames. It must contain the public-origin host; `*` is rejected. |
| `COYOTE_TRUSTED_PROXY_NETWORKS` | Yes | JSON list of exact proxy IPs and/or CIDRs permitted to supply forwarding and request-ID headers. |
| `COYOTE_OIDC_ENABLED` | Yes | Defaults to `true`. Set `false` to omit OIDC routes from the production application. |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` | When OIDC is enabled | The redirect URI must be `https://<public-host>/auth/oidc/callback`. |
| `COYOTE_DOWNSTREAM_CREDENTIALS_ENABLED` | No | Defaults to `false`. Set `true` before configuring or using shared bearer or per-user OAuth credentials; encrypted credential operations fail closed otherwise. |
| `COYOTE_CREDENTIAL_ENCRYPTION_KEYS` | When downstream credentials are enabled | JSON key-version map of base64url 32-byte values. Supply through a secret manager. |
| `COYOTE_CREDENTIAL_ACTIVE_KEY_VERSION` | When downstream credentials are enabled | A configured version in the key map. Retain every old key until credential re-sealing exists and reports no remaining rows. |
| `COYOTE_DOWNSTREAM_OAUTH_ENABLED` | No | Defaults to `false`; requires downstream credentials and blocks per-user OAuth connection/use when disabled. |
| `COYOTE_DOWNSTREAM_OAUTH_REDIRECT_BASE_URL` | When downstream OAuth is enabled | Must equal the canonical public HTTPS origin. |

Production startup rejects broad `ALLOW_INSECURE_ENDPOINTS`,
`ALLOW_PRIVATE_ENDPOINTS`, `ALLOW_INSECURE_OIDC`, `ALLOW_PRIVATE_OIDC`, and the
private/insecure downstream host allowlists. These remain development-only
controls. Settings validation never includes secret values in its errors.
Configuration for a disabled downstream credential or OAuth feature is rejected
at startup rather than accepted as dormant configuration.

## Reverse proxy and TLS trust contract

Terminate TLS at a reverse proxy that is directly adjacent to the Coyote
container. Publish only the proxy; reference Compose binds Coyote to
`127.0.0.1:${COYOTE_APP_PORT:-8000}` for a same-host proxy.

The proxy must:

1. Set the application-facing `Host` header to a member of
   `COYOTE_ALLOWED_HOSTS`.
2. Connect from an address included in `COYOTE_TRUSTED_PROXY_NETWORKS`.
3. Overwrite, not append, `X-Forwarded-Proto` with `https`.
4. Generate or validate `X-Request-ID`, then overwrite any client-supplied
   value before forwarding it.
5. Strip client-supplied forwarded headers at the public boundary.

Coyote ignores forwarded scheme and upstream request IDs unless the direct
ASGI peer is in a configured trusted proxy network. It never derives displayed
MCP collection URLs from forwarded host values: console pages use
`COYOTE_PUBLIC_BASE_URL`.

The production image starts Uvicorn with `--no-proxy-headers`. Do not remove
that option or configure Uvicorn forwarding independently: it would rewrite the
ASGI client address before Coyote can evaluate
`COYOTE_TRUSTED_PROXY_NETWORKS`, allowing a loopback-reachable client to claim a
trusted proxy address through `X-Forwarded-For`.

## Release procedure

Run release operations from an environment that can reach the managed database
and inject the required variables. The migration job must be a singleton; do
not run it independently in every application replica.

1. Build and record an immutable image digest.
2. Supply production configuration and validate it without serving traffic:

   ```bash
   docker compose -f compose.production.yaml run --rm migrate --help
   ```

   The command loads the same settings when Alembic imports the application
   metadata. Correct configuration errors before migration.
3. Verify managed PostgreSQL connectivity using the platform-approved database
   check and confirm a current backup exists.
4. Run the one release job:

   ```bash
   docker compose --profile release -f compose.production.yaml run --rm migrate
   ```

5. Record image digest, Alembic revision, timestamp, operator, and deployment
   identifier in the deployment system's release record.
6. Start or roll out the application:

   ```bash
   docker compose -f compose.production.yaml up -d app
   ```

7. Confirm the container health check, then request `/healthz` through the TLS
   proxy. Perform the approved non-destructive authenticated smoke check when
   one is available.

`/healthz` is process liveness in P5-01. Database readiness, metrics, and alert
integration remain P5-03 work.

## Rollback

Alembic revisions are additive by default. A rollback therefore means deploying
the prior compatible image, not automatically downgrading schema history.

1. Stop or roll back the application deployment to the previously recorded
   image digest.
2. Keep the migrated schema unless the release plan explicitly included and
   tested a compatible downgrade. Never run `alembic downgrade` as an incident
   reflex.
3. Validate `/healthz`, browser OIDC callback behavior, and an authenticated
   MCP request after rollback.
4. Record the outcome and preserve logs/releases for incident review.

Schema/data restoration, RPO/RTO, and key-recovery drills are P5-04 decisions.
Do not restore a credential database backup unless every encryption key version
referenced by its rows is also available through the approved secret-recovery
process.

## Reference Compose validation

Validate the reference file without starting services by setting representative
non-secret values:

```bash
COYOTE_IMAGE='registry.example/coyote-mcp@sha256:<digest>' \
DATABASE_URL='postgresql+asyncpg://coyote:password@postgres.example/coyote_mcp' \
SESSION_SECRET_KEY='<32-or-more-character-secret>' \
COYOTE_PUBLIC_BASE_URL='https://gateway.example' \
COYOTE_ALLOWED_HOSTS='["gateway.example"]' \
COYOTE_TRUSTED_PROXY_NETWORKS='["10.0.0.0/8"]' \
OIDC_ISSUER='https://issuer.example' \
OIDC_CLIENT_ID='client-id' \
OIDC_CLIENT_SECRET='<secret>' \
OIDC_REDIRECT_URI='https://gateway.example/auth/oidc/callback' \
docker compose -f compose.production.yaml config
```

Use deployment-platform secret references in actual releases rather than shell
literals.
