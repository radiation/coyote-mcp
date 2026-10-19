from collections.abc import Mapping
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import AuthenticatedPrincipal, authorize
from coyote_mcp.credentials import DownstreamCredentialBroker
from coyote_mcp.discovery import get_discovery_service
from coyote_mcp.models import (
    Collection,
    CollectionMembership,
    CollectionToolPublication,
    MCPServer,
    Tool,
)
from coyote_mcp.schemas import (
    CollectionCreate,
    CollectionUpdate,
    MembershipCreate,
    PublicationCreate,
    PublicationUpdate,
    ServerCreate,
    ServerUpdate,
)
from coyote_mcp.security import validate_endpoint
from coyote_mcp.settings import Settings


class DuplicateResourceError(ValueError):
    pass


class MissingResourceError(LookupError):
    pass


class AuthorizationError(PermissionError):
    pass


class ServerInUseError(ValueError):
    pass


async def create_server(
    session: AsyncSession, organization_id: UUID, request: ServerCreate
) -> MCPServer:
    server = MCPServer(
        organization_id=organization_id,
        name=request.name,
        display_name=request.display_name,
        endpoint=str(request.endpoint),
        transport=request.transport,
    )
    try:
        async with session.begin_nested():
            session.add(server)
    except IntegrityError as error:
        raise DuplicateResourceError("A server with that name already exists.") from error
    await session.commit()
    await session.refresh(server)
    return server


async def get_server(session: AsyncSession, organization_id: UUID, server_id: UUID) -> MCPServer:
    server = await session.scalar(
        select(MCPServer).where(
            MCPServer.id == server_id, MCPServer.organization_id == organization_id
        )
    )
    if server is None:
        raise MissingResourceError("Server not found.")
    return server


async def _lock_server(
    session: AsyncSession, organization_id: UUID, server_id: UUID, *, key_share: bool = False
) -> MCPServer:
    # FOR UPDATE serializes endpoint changes and deletion. FOR KEY SHARE is what
    # foreign-key inserts take on the parent row, so membership inserts wait for it.
    statement = (
        select(MCPServer)
        .where(MCPServer.id == server_id, MCPServer.organization_id == organization_id)
        .with_for_update(key_share=key_share)
        .execution_options(populate_existing=True)
    )
    server = await session.scalar(statement)
    if server is None:
        raise MissingResourceError("Server not found.")
    return server


async def list_servers(
    session: AsyncSession, organization_id: UUID, limit: int, offset: int
) -> list[MCPServer]:
    return list(
        (
            await session.scalars(
                select(MCPServer)
                .where(MCPServer.organization_id == organization_id)
                .order_by(MCPServer.name)
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )


async def list_server_tools(
    session: AsyncSession, organization_id: UUID, server_id: UUID, limit: int, offset: int
) -> list[Tool]:
    await get_server(session, organization_id, server_id)
    return list(
        (
            await session.scalars(
                select(Tool)
                .join(MCPServer)
                .where(Tool.server_id == server_id, MCPServer.organization_id == organization_id)
                .order_by(Tool.name, Tool.id)
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )


async def _authorized_server(
    session: AsyncSession, current: AuthenticatedPrincipal, action: str, server_id: UUID
) -> MCPServer:
    server = await get_server(session, current.require_organization_id(), server_id)
    if action not in current.scopes:
        raise AuthorizationError("Insufficient permissions.")
    decision = await authorize(
        session,
        current.principal,
        action,
        server,
        verified_group_ids=current.verified_group_ids,
        credential_context=current.credential_context,
    )
    if not decision.allowed:
        raise AuthorizationError("Insufficient permissions.")
    return server


async def _authorize_organization_action(
    session: AsyncSession, current: AuthenticatedPrincipal, action: str
) -> None:
    if action not in current.scopes:
        raise AuthorizationError("Insufficient permissions.")
    decision = await authorize(
        session,
        current.principal,
        action,
        context={"organization_id": current.require_organization_id()},
        verified_group_ids=current.verified_group_ids,
        credential_context=current.credential_context,
    )
    if not decision.allowed:
        raise AuthorizationError("Insufficient permissions.")


async def register_server(
    session: AsyncSession, current: AuthenticatedPrincipal, request: ServerCreate
) -> MCPServer:
    await _authorize_organization_action(session, current, "server:create")
    validate_endpoint(str(request.endpoint), Settings())
    return await create_server(session, current.require_organization_id(), request)


async def require_server_update(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID
) -> MCPServer:
    return await _authorized_server(session, current, "server:update", server_id)


async def update_server(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID, request: ServerUpdate
) -> MCPServer:
    await _authorized_server(session, current, "server:update", server_id)
    endpoint: str | None = None
    if request.endpoint is not None:
        endpoint = str(request.endpoint)
        validate_endpoint(endpoint, Settings())
    locked_server = await _lock_server(session, current.require_organization_id(), server_id)
    if request.display_name is not None:
        locked_server.display_name = request.display_name
    if endpoint is not None and endpoint != locked_server.endpoint:
        locked_server.endpoint = endpoint
        locked_server.status = "pending"
        locked_server.last_sync_error = None
        # Invalidates any in-flight discovery that targeted the previous endpoint.
        locked_server.sync_generation += 1
    await session.commit()
    await session.refresh(locked_server)
    return locked_server


async def set_server_enabled(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID, enabled: bool
) -> MCPServer:
    server = await _authorized_server(session, current, "server:update", server_id)
    server.enabled = enabled
    await session.commit()
    await session.refresh(server)
    return server


async def delete_server(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID
) -> None:
    server = await _authorized_server(session, current, "server:update", server_id)
    # The row lock is held through the dependency checks and the delete, so a concurrent
    # membership insert waits instead of committing after the checks and being cascaded away.
    locked_server = await _lock_server(session, current.require_organization_id(), server.id)
    has_memberships = (
        await session.scalars(
            select(CollectionMembership.server_id)
            .where(CollectionMembership.server_id == locked_server.id)
            .limit(1)
        )
    ).first()
    has_publications = (
        await session.scalars(
            select(CollectionToolPublication.id)
            .where(CollectionToolPublication.server_id == locked_server.id)
            .limit(1)
        )
    ).first()
    if has_memberships is not None or has_publications is not None:
        raise ServerInUseError(
            "Remove this server from all collections and unpublish its tools before deleting it."
        )
    await session.delete(locked_server)
    await session.commit()


async def synchronize_server(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID
) -> MCPServer:
    server = await _authorized_server(session, current, "server:sync", server_id)
    return await discover_server(session, current, server)


async def discover_server(
    session: AsyncSession, current: AuthenticatedPrincipal, server: MCPServer
) -> MCPServer:
    """Refresh the catalog using the downstream credential for the syncing caller.

    Discovery uses the caller's own connection for per-user servers and never a shared
    or administrator identity to infer what individual users can access. If no valid
    connection exists, the sync fails closed and the last-known catalog is kept.
    """
    settings = Settings()
    broker = DownstreamCredentialBroker(settings)

    async def headers_provider() -> Mapping[str, str]:
        authorization = await broker.authorize(session, current, server)
        return authorization.headers

    return await get_discovery_service(settings).sync(
        session,
        server,
        headers_provider=headers_provider,
        deactivate_missing=server.auth_policy != "per_user_oauth",
    )


async def read_server(
    session: AsyncSession, current: AuthenticatedPrincipal, server_id: UUID
) -> MCPServer:
    return await _authorized_server(session, current, "server:read", server_id)


async def create_collection(
    session: AsyncSession, organization_id: UUID, request: CollectionCreate
) -> Collection:
    collection = Collection(
        organization_id=organization_id,
        slug=request.slug,
        display_name=request.display_name,
        description=request.description,
        exposure_mode=request.exposure_mode,
    )
    try:
        async with session.begin_nested():
            session.add(collection)
    except IntegrityError as error:
        raise DuplicateResourceError("A collection with that slug already exists.") from error
    await session.commit()
    await session.refresh(collection)
    return collection


async def register_collection(
    session: AsyncSession, current: AuthenticatedPrincipal, request: CollectionCreate
) -> Collection:
    await _authorize_organization_action(session, current, "collection:create")
    return await create_collection(session, current.require_organization_id(), request)


async def _authorized_collection(
    session: AsyncSession, current: AuthenticatedPrincipal, action: str, collection_id: UUID
) -> Collection:
    collection = await get_collection(session, current.require_organization_id(), collection_id)
    if action not in current.scopes:
        raise AuthorizationError("Insufficient permissions.")
    decision = await authorize(
        session,
        current.principal,
        action,
        collection,
        verified_group_ids=current.verified_group_ids,
        credential_context=current.credential_context,
    )
    if not decision.allowed:
        raise AuthorizationError("Insufficient permissions.")
    return collection


async def read_collection(
    session: AsyncSession, current: AuthenticatedPrincipal, collection_id: UUID
) -> Collection:
    return await _authorized_collection(session, current, "collection:read", collection_id)


async def update_collection(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    request: CollectionUpdate,
) -> Collection:
    collection = await require_collection_update(session, current, collection_id)
    for field, value in request.model_dump(exclude_unset=True).items():
        setattr(collection, field, value)
    await session.commit()
    await session.refresh(collection)
    return collection


async def require_collection_update(
    session: AsyncSession, current: AuthenticatedPrincipal, collection_id: UUID
) -> Collection:
    return await _authorized_collection(session, current, "collection:update", collection_id)


async def get_collection(
    session: AsyncSession, organization_id: UUID, collection_id: UUID
) -> Collection:
    collection = await session.scalar(
        select(Collection).where(
            Collection.id == collection_id, Collection.organization_id == organization_id
        )
    )
    if collection is None:
        raise MissingResourceError("Collection not found.")
    return collection


async def list_collections(
    session: AsyncSession, organization_id: UUID, limit: int, offset: int
) -> list[Collection]:
    return list(
        (
            await session.scalars(
                select(Collection)
                .where(Collection.organization_id == organization_id)
                .order_by(Collection.slug)
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )


async def add_membership(
    session: AsyncSession, organization_id: UUID, collection_id: UUID, request: MembershipCreate
) -> CollectionMembership:
    await get_collection(session, organization_id, collection_id)
    await _lock_server(session, organization_id, request.server_id, key_share=True)
    membership = CollectionMembership(
        collection_id=collection_id,
        server_id=request.server_id,
        organization_id=organization_id,
        enabled=request.enabled,
    )
    try:
        async with session.begin_nested():
            session.add(membership)
    except IntegrityError as error:
        raise DuplicateResourceError("That server is already a collection member.") from error
    await session.commit()
    await session.refresh(membership)
    return membership


async def add_collection_member(
    session: AsyncSession, current: AuthenticatedPrincipal, collection_id: UUID, server_id: UUID
) -> CollectionMembership:
    await _authorized_collection(session, current, "collection:manage_members", collection_id)
    return await add_membership(
        session,
        current.require_organization_id(),
        collection_id,
        MembershipCreate(server_id=server_id),
    )


async def remove_collection_member(
    session: AsyncSession, current: AuthenticatedPrincipal, collection_id: UUID, server_id: UUID
) -> None:
    await _authorized_collection(session, current, "collection:manage_members", collection_id)
    await remove_membership(session, current.require_organization_id(), collection_id, server_id)


async def list_collection_memberships(
    session: AsyncSession, organization_id: UUID, collection_id: UUID, limit: int
) -> list[tuple[CollectionMembership, MCPServer]]:
    rows = await session.execute(
        select(CollectionMembership, MCPServer)
        .join(MCPServer, MCPServer.id == CollectionMembership.server_id)
        .where(
            CollectionMembership.collection_id == collection_id,
            CollectionMembership.organization_id == organization_id,
        )
        .order_by(MCPServer.display_name, MCPServer.id)
        .limit(limit)
    )
    return [(membership, server) for membership, server in rows.all()]


async def list_addable_servers(
    session: AsyncSession, organization_id: UUID, collection_id: UUID, limit: int
) -> list[MCPServer]:
    member_ids = select(CollectionMembership.server_id).where(
        CollectionMembership.collection_id == collection_id
    )
    return list(
        (
            await session.scalars(
                select(MCPServer)
                .where(
                    MCPServer.organization_id == organization_id,
                    MCPServer.id.not_in(member_ids),
                )
                .order_by(MCPServer.display_name, MCPServer.id)
                .limit(limit)
            )
        ).all()
    )


async def list_collection_tool_rows(
    session: AsyncSession, organization_id: UUID, collection_id: UUID, limit: int, offset: int
) -> list[tuple[Tool, MCPServer]]:
    collection = await get_collection(session, organization_id, collection_id)
    if not collection.enabled:
        return []
    rows = await session.execute(
        select(Tool, MCPServer)
        .join(MCPServer, MCPServer.id == Tool.server_id)
        .join(CollectionMembership, CollectionMembership.server_id == Tool.server_id)
        .where(
            CollectionMembership.collection_id == collection_id,
            CollectionMembership.organization_id == organization_id,
            CollectionMembership.enabled.is_(True),
            MCPServer.enabled.is_(True),
            Tool.active.is_(True),
        )
        .order_by(Tool.name, Tool.server_id, Tool.id)
        .limit(limit)
        .offset(offset)
    )
    return [(tool, server) for tool, server in rows.all()]


async def remove_membership(
    session: AsyncSession, organization_id: UUID, collection_id: UUID, server_id: UUID
) -> None:
    membership = await session.get(CollectionMembership, (collection_id, server_id))
    if membership is None or membership.organization_id != organization_id:
        raise MissingResourceError("Collection membership not found.")
    await session.delete(membership)
    await session.commit()


async def list_collection_tools(
    session: AsyncSession, organization_id: UUID, collection_id: UUID, limit: int, offset: int
) -> list[Tool]:
    collection = await get_collection(session, organization_id, collection_id)
    if not collection.enabled:
        return []
    return list(
        (
            await session.scalars(
                select(Tool)
                .join(CollectionMembership, CollectionMembership.server_id == Tool.server_id)
                .where(
                    CollectionMembership.collection_id == collection_id,
                    CollectionMembership.organization_id == organization_id,
                    CollectionMembership.enabled.is_(True),
                    Tool.active.is_(True),
                )
                .order_by(Tool.name, Tool.server_id, Tool.id)
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )


async def list_publications(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    limit: int,
    offset: int,
) -> list[CollectionToolPublication]:
    await require_collection_update(session, current, collection_id)
    return list(
        (
            await session.scalars(
                select(CollectionToolPublication)
                .join(Collection, Collection.id == CollectionToolPublication.collection_id)
                .where(
                    CollectionToolPublication.collection_id == collection_id,
                    Collection.organization_id == current.require_organization_id(),
                )
                .order_by(CollectionToolPublication.published_name, CollectionToolPublication.id)
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )


async def list_publication_rows(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    limit: int,
    offset: int,
) -> list[tuple[CollectionToolPublication, Tool, MCPServer, bool]]:
    await require_collection_update(session, current, collection_id)
    rows = await session.execute(
        select(CollectionToolPublication, Tool, MCPServer, CollectionMembership.enabled)
        .join(Tool, Tool.id == CollectionToolPublication.tool_id)
        .join(MCPServer, MCPServer.id == CollectionToolPublication.server_id)
        .join(
            CollectionMembership,
            (CollectionMembership.collection_id == CollectionToolPublication.collection_id)
            & (CollectionMembership.server_id == CollectionToolPublication.server_id),
        )
        .join(Collection, Collection.id == CollectionToolPublication.collection_id)
        .where(
            CollectionToolPublication.collection_id == collection_id,
            Collection.organization_id == current.require_organization_id(),
        )
        .order_by(CollectionToolPublication.published_name, CollectionToolPublication.id)
        .limit(limit)
        .offset(offset)
    )
    return [
        (publication, tool, server, membership_enabled)
        for publication, tool, server, membership_enabled in rows.all()
    ]


async def list_unpublished_collection_tools(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    limit: int,
    offset: int,
) -> list[tuple[Tool, MCPServer]]:
    await require_collection_update(session, current, collection_id)
    rows = await session.execute(
        select(Tool, MCPServer)
        .join(MCPServer, MCPServer.id == Tool.server_id)
        .join(CollectionMembership, CollectionMembership.server_id == Tool.server_id)
        .where(
            CollectionMembership.collection_id == collection_id,
            CollectionMembership.organization_id == current.require_organization_id(),
            CollectionMembership.enabled.is_(True),
            Tool.active.is_(True),
            ~select(CollectionToolPublication.id)
            .where(
                CollectionToolPublication.collection_id == collection_id,
                CollectionToolPublication.tool_id == Tool.id,
            )
            .exists(),
        )
        .order_by(Tool.name, Tool.server_id, Tool.id)
        .limit(limit)
        .offset(offset)
    )
    return [(tool, server) for tool, server in rows.all()]


async def list_organization_tool_rows(
    session: AsyncSession, organization_id: UUID, limit: int, offset: int
) -> list[tuple[Tool, MCPServer]]:
    rows = await session.execute(
        select(Tool, MCPServer)
        .join(MCPServer, MCPServer.id == Tool.server_id)
        .where(MCPServer.organization_id == organization_id)
        .order_by(Tool.name, Tool.server_id, Tool.id)
        .limit(limit)
        .offset(offset)
    )
    return [(tool, server) for tool, server in rows.all()]


async def count_tool_publications(
    session: AsyncSession, organization_id: UUID, tool_ids: list[UUID]
) -> dict[UUID, int]:
    if not tool_ids:
        return {}
    rows = await session.execute(
        select(CollectionToolPublication.tool_id, func.count(CollectionToolPublication.id))
        .join(Collection, Collection.id == CollectionToolPublication.collection_id)
        .where(
            CollectionToolPublication.tool_id.in_(tool_ids),
            Collection.organization_id == organization_id,
        )
        .group_by(CollectionToolPublication.tool_id)
    )
    return {tool_id: count for tool_id, count in rows.all()}


def publication_exposure_issues(
    collection: Collection,
    membership_enabled: bool,
    tool: Tool,
    server: MCPServer,
    publication: CollectionToolPublication,
) -> tuple[str, ...]:
    """Explain why a publication is not currently exposed through MCP.

    Mirrors the gateway exposure predicate so the console reports the same
    conditions the gateway enforces.
    """
    issues: list[str] = []
    if not collection.enabled:
        issues.append("Collection is disabled.")
    if not publication.enabled:
        issues.append("Publication is disabled.")
    if not membership_enabled:
        issues.append("Server membership is disabled.")
    if not tool.active:
        issues.append("Tool is inactive in the latest discovery.")
    if not server.enabled:
        issues.append("Server is disabled.")
    if server.status != "ready":
        issues.append(f"Server status is {server.status}.")
    if server.transport != "streamable_http":
        issues.append("Server transport is not supported by the gateway.")
    return tuple(issues)


async def _ensure_publication_available(
    session: AsyncSession,
    collection_id: UUID,
    tool_id: UUID,
    published_name: str,
    *,
    publication_id: UUID | None = None,
) -> None:
    name_conflict = select(CollectionToolPublication.id).where(
        CollectionToolPublication.collection_id == collection_id,
        CollectionToolPublication.published_name == published_name,
    )
    if publication_id is not None:
        name_conflict = name_conflict.where(CollectionToolPublication.id != publication_id)
    if await session.scalar(name_conflict.limit(1)) is not None:
        raise DuplicateResourceError("That published name is already used in this collection.")
    if publication_id is None:
        tool_conflict = await session.scalar(
            select(CollectionToolPublication.id)
            .where(
                CollectionToolPublication.collection_id == collection_id,
                CollectionToolPublication.tool_id == tool_id,
            )
            .limit(1)
        )
        if tool_conflict is not None:
            raise DuplicateResourceError("This tool is already published in this collection.")


async def publish_tool(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    request: PublicationCreate,
) -> CollectionToolPublication:
    await require_collection_update(session, current, collection_id)
    row = await session.execute(
        select(Tool, CollectionMembership)
        .join(MCPServer, MCPServer.id == Tool.server_id)
        .join(
            CollectionMembership,
            (CollectionMembership.server_id == Tool.server_id)
            & (CollectionMembership.collection_id == collection_id),
        )
        .where(
            Tool.id == request.tool_id,
            MCPServer.organization_id == current.require_organization_id(),
        )
    )
    result = row.one_or_none()
    if result is None:
        raise MissingResourceError("Catalog tool not found in this collection.")
    tool, membership = result
    await _ensure_publication_available(session, collection_id, tool.id, request.published_name)
    publication = CollectionToolPublication(
        collection_id=collection_id,
        server_id=membership.server_id,
        tool_id=tool.id,
        enabled=request.enabled,
        published_name=request.published_name,
        description_override=request.description_override,
    )
    try:
        async with session.begin_nested():
            session.add(publication)
    except IntegrityError as error:
        raise DuplicateResourceError(
            "A publication already uses that tool or published name."
        ) from error
    await session.commit()
    await session.refresh(publication)
    return publication


async def update_publication(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    publication_id: UUID,
    request: PublicationUpdate,
) -> CollectionToolPublication:
    await require_collection_update(session, current, collection_id)
    publication = await session.scalar(
        select(CollectionToolPublication).where(
            CollectionToolPublication.id == publication_id,
            CollectionToolPublication.collection_id == collection_id,
        )
    )
    if publication is None:
        raise MissingResourceError("Tool publication not found.")
    updates = request.model_dump(exclude_unset=True)
    if updates.get("published_name") is not None:
        await _ensure_publication_available(
            session,
            collection_id,
            publication.tool_id,
            updates["published_name"],
            publication_id=publication.id,
        )
    try:
        async with session.begin_nested():
            for field, value in updates.items():
                setattr(publication, field, value)
    except IntegrityError as error:
        raise DuplicateResourceError("A publication already uses that published name.") from error
    await session.commit()
    await session.refresh(publication)
    return publication


async def read_publication(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    publication_id: UUID,
) -> tuple[CollectionToolPublication, Tool]:
    await require_collection_update(session, current, collection_id)
    row = await session.execute(
        select(CollectionToolPublication, Tool)
        .join(Tool, Tool.id == CollectionToolPublication.tool_id)
        .where(
            CollectionToolPublication.id == publication_id,
            CollectionToolPublication.collection_id == collection_id,
        )
    )
    result = row.one_or_none()
    if result is None:
        raise MissingResourceError("Tool publication not found.")
    return result


async def remove_publication(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    publication_id: UUID,
) -> None:
    await require_collection_update(session, current, collection_id)
    publication = await session.scalar(
        select(CollectionToolPublication).where(
            CollectionToolPublication.id == publication_id,
            CollectionToolPublication.collection_id == collection_id,
        )
    )
    if publication is None:
        raise MissingResourceError("Tool publication not found.")
    await session.delete(publication)
    await session.commit()
