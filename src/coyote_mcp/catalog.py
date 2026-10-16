from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import AuthenticatedPrincipal, authorize
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
)


class DuplicateResourceError(ValueError):
    pass


class MissingResourceError(LookupError):
    pass


class AuthorizationError(PermissionError):
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
    session.add(server)
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise DuplicateResourceError("A server with that name already exists.") from error
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
    session.add(collection)
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise DuplicateResourceError("A collection with that slug already exists.") from error
    await session.refresh(collection)
    return collection


async def update_collection(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    request: CollectionUpdate,
) -> Collection:
    collection = await get_collection(session, current.principal.organization_id, collection_id)
    if "collection:update" not in current.scopes:
        raise AuthorizationError("Insufficient permissions.")
    decision = await authorize(
        session,
        current.principal,
        "collection:update",
        collection,
        verified_group_ids=current.verified_group_ids,
        identity_provider_id=current.identity_provider_id,
    )
    if not decision.allowed:
        raise AuthorizationError("Insufficient permissions.")
    collection.exposure_mode = request.exposure_mode
    await session.commit()
    await session.refresh(collection)
    return collection


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
    await get_server(session, organization_id, request.server_id)
    membership = CollectionMembership(
        collection_id=collection_id,
        server_id=request.server_id,
        organization_id=organization_id,
        enabled=request.enabled,
    )
    session.add(membership)
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise DuplicateResourceError("That server is already a collection member.") from error
    await session.refresh(membership)
    return membership


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
    session: AsyncSession, organization_id: UUID, collection_id: UUID, limit: int, offset: int
) -> list[CollectionToolPublication]:
    await get_collection(session, organization_id, collection_id)
    return list(
        (
            await session.scalars(
                select(CollectionToolPublication)
                .join(Collection, Collection.id == CollectionToolPublication.collection_id)
                .where(
                    CollectionToolPublication.collection_id == collection_id,
                    Collection.organization_id == organization_id,
                )
                .order_by(CollectionToolPublication.published_name, CollectionToolPublication.id)
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )


async def publish_tool(
    session: AsyncSession,
    organization_id: UUID,
    collection_id: UUID,
    request: PublicationCreate,
) -> CollectionToolPublication:
    await get_collection(session, organization_id, collection_id)
    row = await session.execute(
        select(Tool, CollectionMembership)
        .join(MCPServer, MCPServer.id == Tool.server_id)
        .join(
            CollectionMembership,
            (CollectionMembership.server_id == Tool.server_id)
            & (CollectionMembership.collection_id == collection_id),
        )
        .where(Tool.id == request.tool_id, MCPServer.organization_id == organization_id)
    )
    result = row.one_or_none()
    if result is None:
        raise MissingResourceError("Catalog tool not found in this collection.")
    tool, membership = result
    publication = CollectionToolPublication(
        collection_id=collection_id,
        server_id=membership.server_id,
        tool_id=tool.id,
        enabled=request.enabled,
        published_name=request.published_name,
        description_override=request.description_override,
    )
    session.add(publication)
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise DuplicateResourceError(
            "A publication already uses that tool or published name."
        ) from error
    await session.refresh(publication)
    return publication


async def update_publication(
    session: AsyncSession,
    organization_id: UUID,
    collection_id: UUID,
    publication_id: UUID,
    request: PublicationUpdate,
) -> CollectionToolPublication:
    await get_collection(session, organization_id, collection_id)
    publication = await session.scalar(
        select(CollectionToolPublication).where(
            CollectionToolPublication.id == publication_id,
            CollectionToolPublication.collection_id == collection_id,
        )
    )
    if publication is None:
        raise MissingResourceError("Tool publication not found.")
    for field, value in request.model_dump(exclude_unset=True).items():
        setattr(publication, field, value)
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise DuplicateResourceError("A publication already uses that published name.") from error
    await session.refresh(publication)
    return publication


async def remove_publication(
    session: AsyncSession, organization_id: UUID, collection_id: UUID, publication_id: UUID
) -> None:
    await get_collection(session, organization_id, collection_id)
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
