import asyncio
import os
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from coyote_mcp import catalog, oidc
from coyote_mcp.app import app
from coyote_mcp.auth import AuthenticatedPrincipal
from coyote_mcp.db import get_session
from coyote_mcp.discovery import (
    DiscoveredTool,
    DiscoveryService,
    SyncSupersededError,
    reconcile_tools,
)
from coyote_mcp.models import (
    Collection,
    CollectionMembership,
    CollectionToolPublication,
    MCPServer,
    OIDCLoginTransaction,
    Organization,
    OrganizationMembership,
    Principal,
    RoleAssignment,
    Tool,
)
from coyote_mcp.schemas import (
    CollectionCreate,
    MembershipCreate,
    PublicationCreate,
    ServerCreate,
)
from coyote_mcp.settings import Settings

POSTGRES_INTEGRATION_URL = os.environ.get("POSTGRES_INTEGRATION_URL")
pytestmark = pytest.mark.postgres
ALEMBIC_CONFIG = Path(__file__).parents[1] / "alembic.ini"


@pytest.fixture
async def postgres_sessions() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    if POSTGRES_INTEGRATION_URL is None:
        pytest.skip("Set POSTGRES_INTEGRATION_URL to run PostgreSQL integration tests.")
    engine = create_async_engine(POSTGRES_INTEGRATION_URL)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.execute(text("TRUNCATE organizations CASCADE"))
    yield sessions
    async with engine.begin() as connection:
        await connection.execute(text("TRUNCATE organizations CASCADE"))
    await engine.dispose()


def server_request(name: str = "postgres") -> ServerCreate:
    return ServerCreate(
        name=name,
        display_name=name.title(),
        endpoint="https://example.com/mcp",
    )


def discovered_tool(name: str) -> DiscoveredTool:
    return DiscoveredTool(
        name=name,
        description=f"{name} description",
        input_schema={"type": "object", "properties": {"value": {"type": "string"}}},
        output_schema={"type": "string"},
        annotations={"readOnlyHint": True},
    )


async def publication_current(
    session: AsyncSession, organization: Organization, collection: Collection
) -> AuthenticatedPrincipal:
    principal = Principal(
        identifier=f"publication-administrator-{uuid4().hex}",
        display_name="Publication Administrator",
    )
    session.add(principal)
    await session.flush()
    session.add(OrganizationMembership(organization_id=organization.id, principal_id=principal.id))
    session.add(
        RoleAssignment(
            organization_id=organization.id,
            principal_id=principal.id,
            role="administrator",
            collection_id=collection.id,
        )
    )
    await session.commit()
    return AuthenticatedPrincipal(
        principal, frozenset({"collection:update"}), None, organization.id
    )


@pytest.mark.asyncio
async def test_postgres_migration_and_jsonb_persistence(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with postgres_sessions() as session:
        revision = await session.scalar(text("SELECT version_num FROM alembic_version"))
        assert (
            revision == ScriptDirectory.from_config(Config(str(ALEMBIC_CONFIG))).get_current_head()
        )
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        session.add(organization)
        await session.commit()
        server = await catalog.create_server(session, organization.id, server_request())
        tool = Tool(
            server_id=server.id,
            name="jsonb",
            description="JSONB test",
            input_schema={"type": "object"},
            output_schema={"type": "string"},
            annotations={"idempotentHint": True},
            fingerprint="a" * 64,
        )
        session.add(tool)
        await session.commit()
        persisted_type = await session.scalar(
            text("SELECT pg_typeof(input_schema)::text FROM tools WHERE id = :id"),
            {"id": tool.id},
        )

    assert persisted_type == "jsonb"


@pytest.mark.asyncio
async def test_postgres_oidc_login_transaction_uses_environment_provider_without_provider_id(
    postgres_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("OIDC_CLIENT_ID", "client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://test/auth/oidc/callback")

    async def discovery(_: object) -> dict[str, object]:
        return {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/keys",
        }

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with postgres_sessions() as session:
            yield session

    monkeypatch.setattr(oidc, "_discovery", discovery)
    app.dependency_overrides[get_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/auth/oidc/login")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 302
    async with postgres_sessions() as session:
        transaction = await session.scalar(select(OIDCLoginTransaction))
        legacy_provider_columns = await session.scalar(
            text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_name IN ('oidc_login_transactions', 'browser_sessions', "
                "'external_identities') AND column_name IN ('provider_id', 'identity_provider_id')"
            )
        )
        identity_binding_columns = (
            await session.execute(
                text(
                    "SELECT column_name, is_nullable FROM information_schema.columns "
                    "WHERE table_name = 'external_identities' "
                    "AND column_name IN ('issuer', 'subject') ORDER BY column_name"
                )
            )
        ).all()
        issuer_subject_constraints = await session.scalar(
            text(
                "SELECT count(*) FROM pg_constraint "
                "WHERE conname = 'uq_external_identities_issuer_subject'"
            )
        )

    assert transaction is not None
    assert transaction.browser_binding_hash
    assert transaction.nonce
    assert transaction.pkce_verifier
    assert legacy_provider_columns == 0
    assert identity_binding_columns == [("issuer", "NO"), ("subject", "NO")]
    assert issuer_subject_constraints == 1


@pytest.mark.asyncio
async def test_postgres_publication_survives_catalog_sync(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with postgres_sessions() as session:
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        session.add(organization)
        await session.commit()
        server = await catalog.create_server(session, organization.id, server_request())
        collection = await catalog.create_collection(
            session,
            organization.id,
            CollectionCreate(slug="native", display_name="Native", exposure_mode="native"),
        )
        await catalog.add_membership(
            session, organization.id, collection.id, MembershipCreate(server_id=server.id)
        )
        await reconcile_tools(session, server, [discovered_tool("published")])
        await session.commit()
        tool = await session.scalar(select(Tool).where(Tool.name == "published"))
        assert tool is not None
        current = await publication_current(session, organization, collection)
        publication = await catalog.publish_tool(
            session,
            current,
            collection.id,
            PublicationCreate(tool_id=tool.id, published_name="stable_published"),
        )
        await reconcile_tools(session, server, [discovered_tool("published")])
        await session.commit()
        persisted = await session.scalar(
            select(CollectionToolPublication).where(CollectionToolPublication.id == publication.id)
        )

    assert persisted is not None
    assert persisted.published_name == "stable_published"
    assert persisted.enabled is True


@pytest.mark.asyncio
async def test_postgres_catalog_sync_does_not_publish_tools(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with postgres_sessions() as session:
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        session.add(organization)
        await session.commit()
        server = await catalog.create_server(session, organization.id, server_request())
        collection = await catalog.create_collection(
            session,
            organization.id,
            CollectionCreate(slug="native", display_name="Native", exposure_mode="native"),
        )
        await catalog.add_membership(
            session, organization.id, collection.id, MembershipCreate(server_id=server.id)
        )
        await reconcile_tools(session, server, [discovered_tool("unpublished")])
        await session.commit()
        current = await publication_current(session, organization, collection)
        publications = await catalog.list_publications(
            session, current, collection.id, limit=10, offset=0
        )

    assert publications == []


@pytest.mark.asyncio
async def test_postgres_unique_tool_constraint(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with postgres_sessions() as session:
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        session.add(organization)
        await session.commit()
        server = await catalog.create_server(session, organization.id, server_request())
        for fingerprint in ("a" * 64, "b" * 64):
            session.add(
                Tool(
                    server_id=server.id,
                    name="duplicate",
                    description="duplicate",
                    input_schema={},
                    annotations={},
                    fingerprint=fingerprint,
                )
            )
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()


class OrderedDiscoveryClient:
    def __init__(self) -> None:
        self.first_started = asyncio.Event()
        self.release_first = asyncio.Event()
        self.calls = 0

    async def list_tools(
        self, endpoint: str, headers: Mapping[str, str] | None = None
    ) -> list[DiscoveredTool]:
        self.calls += 1
        if self.calls == 1:
            self.first_started.set()
            await self.release_first.wait()
            return [discovered_tool("stale")]
        return [discovered_tool("current")]


@pytest.mark.asyncio
async def test_postgres_concurrent_sync_rejects_stale_result(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with postgres_sessions() as setup_session:
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        setup_session.add(organization)
        await setup_session.commit()
        server = await catalog.create_server(setup_session, organization.id, server_request())
    client = OrderedDiscoveryClient()
    service = DiscoveryService(client, Settings())

    async def sync_once() -> MCPServer:
        async with postgres_sessions() as session:
            server_for_sync = await catalog.get_server(session, organization.id, server.id)
            return await service.sync(session, server_for_sync)

    first_sync = asyncio.create_task(sync_once())
    await client.first_started.wait()
    second_result = await sync_once()
    client.release_first.set()
    with pytest.raises(SyncSupersededError):
        await first_sync

    async with postgres_sessions() as verify_session:
        tools = await catalog.list_server_tools(verify_session, organization.id, server.id, 50, 0)

    assert second_result.status == "ready"
    assert [tool.name for tool in tools] == ["current"]


async def seed_server_with_collection(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> tuple[UUID, UUID, UUID, AuthenticatedPrincipal]:
    async with postgres_sessions() as session:
        organization = Organization(slug="postgres", display_name="PostgreSQL")
        session.add(organization)
        await session.commit()
        server = await catalog.create_server(
            session, organization.id, server_request("delete-race")
        )
        collection = await catalog.create_collection(
            session,
            organization.id,
            CollectionCreate(slug="delete-race", display_name="Delete Race"),
        )
        principal = Principal(identifier=f"owner-{uuid4().hex}", display_name="Owner")
        session.add(principal)
        await session.flush()
        session.add(
            OrganizationMembership(organization_id=organization.id, principal_id=principal.id)
        )
        session.add(
            RoleAssignment(organization_id=organization.id, principal_id=principal.id, role="owner")
        )
        await session.commit()
        current = AuthenticatedPrincipal(
            principal, frozenset({"server:update"}), None, organization.id
        )
        return organization.id, server.id, collection.id, current


@pytest.mark.asyncio
async def test_postgres_server_delete_waits_for_membership_insert(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    organization_id, server_id, collection_id, current = await seed_server_with_collection(
        postgres_sessions
    )
    async with postgres_sessions() as inserting_session:
        inserting_session.add(
            CollectionMembership(
                collection_id=collection_id,
                server_id=server_id,
                organization_id=organization_id,
                enabled=True,
            )
        )
        # The foreign-key check holds a KEY SHARE lock on the server row until commit.
        await inserting_session.flush()
        async with postgres_sessions() as deleting_session:
            delete_task = asyncio.create_task(
                catalog.delete_server(deleting_session, current, server_id)
            )
            await asyncio.sleep(0.2)
            assert not delete_task.done()
            await inserting_session.commit()
            with pytest.raises(catalog.ServerInUseError):
                await delete_task

    async with postgres_sessions() as verify_session:
        assert await verify_session.get(MCPServer, server_id) is not None
        assert (
            await verify_session.get(CollectionMembership, (collection_id, server_id)) is not None
        )


@pytest.mark.asyncio
async def test_postgres_membership_insert_waits_for_server_delete(
    postgres_sessions: async_sessionmaker[AsyncSession],
) -> None:
    organization_id, server_id, collection_id, _ = await seed_server_with_collection(
        postgres_sessions
    )
    async with postgres_sessions() as deleting_session:
        server = await deleting_session.scalar(
            select(MCPServer).where(MCPServer.id == server_id).with_for_update()
        )
        assert server is not None
        async with postgres_sessions() as adding_session:
            add_task = asyncio.create_task(
                catalog.add_membership(
                    adding_session,
                    organization_id,
                    collection_id,
                    MembershipCreate(server_id=server_id),
                )
            )
            await asyncio.sleep(0.2)
            assert not add_task.done()
            await deleting_session.delete(server)
            await deleting_session.commit()
            with pytest.raises(catalog.MissingResourceError):
                await add_task

    async with postgres_sessions() as verify_session:
        assert await verify_session.get(MCPServer, server_id) is None
        assert await verify_session.get(CollectionMembership, (collection_id, server_id)) is None
