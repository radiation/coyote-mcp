# Backend map

## Modules

| Area | Current responsibility |
| --- | --- |
| `app.py` | Builds FastAPI/FastMCP applications, mounts REST/OIDC routes, and blocks MCP protocol requests pending shared enforcement. |
| `api.py` | Authenticated control-plane endpoints for catalog, PATs, service principals, identity providers, groups, and mappings. |
| `catalog.py` | Organization-scoped server, collection, membership, and catalog queries. |
| `discovery.py` | Streamable HTTP tool discovery, pinned HTTP transport, reconciliation, and generation-safe sync. |
| `auth.py` | PAT/browser authentication, session lifecycle, roles, group mappings, and centralized authorization. |
| `oidc.py` | OIDC discovery, PKCE login, browser binding, code exchange, ID-token validation, and logout/CSRF flows. |
| `security.py` | Destination, public-address, scheme, and OIDC trust-boundary validation. |
| `models.py` | SQLAlchemy persistence model and tenant-scoped constraints. |
| `schemas.py` | Pydantic API request/response contracts. |
| `db.py`, `settings.py` | Async database session factory and configuration/secret-reference rules. |
| `cli.py` | One-time bootstrap administrator/PAT workflow. |
| `alembic/` | Additive schema history through the current identity, session, and provider-secret revisions. |

## Key execution paths

1. A REST request resolves a PAT or browser session in `dependencies.py`; API
   endpoints call `api.require`, which delegates policy evaluation to
   `auth.authorize`.
2. Server synchronization validates and DNS-pins the endpoint, discovers tools
   through FastMCP, then reconciles persisted tools only if its generation is
   current.
3. OIDC login stores a short-lived transaction and browser binding server-side;
   the callback consumes it atomically, validates the ID token, resolves an
   `(issuer, subject)` identity, and issues an opaque persisted session.

## Extension points

- Add protected control-plane operations through the existing API dependency and
  `require` path, with service-level authorization.
- Add persistence through a new Alembic revision and matching SQLAlchemy model,
  constraints, Pydantic contracts, and tests.
- Add downstream transport/auth support only through the validated discovery
  boundary. MCP execution is a planned extension and must share authorization.
