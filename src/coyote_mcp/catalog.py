from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.models import Collection, CollectionMembership, MCPServer, Tool
from coyote_mcp.schemas import CollectionCreate, MembershipCreate, ServerCreate


class DuplicateResourceError(ValueError):
    pass


class MissingResourceError(LookupError):
    pass


async def create_server(session: AsyncSession, request: ServerCreate) -> MCPServer:
    server = MCPServer(
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


async def get_server(session: AsyncSession, server_id: UUID) -> MCPServer:
    server = await session.get(MCPServer, server_id)
    if server is None:
        raise MissingResourceError("Server not found.")
    return server


async def list_servers(session: AsyncSession, limit: int, offset: int) -> list[MCPServer]:
    return list(
        (
            await session.scalars(
                select(MCPServer).order_by(MCPServer.name).limit(limit).offset(offset)
            )
        ).all()
    )


async def list_server_tools(
    session: AsyncSession, server_id: UUID, limit: int, offset: int
) -> list[Tool]:
    await get_server(session, server_id)
    query = (
        select(Tool)
        .where(Tool.server_id == server_id)
        .order_by(Tool.name, Tool.id)
        .limit(limit)
        .offset(offset)
    )
    return list((await session.scalars(query)).all())


async def create_collection(session: AsyncSession, request: CollectionCreate) -> Collection:
    collection = Collection(
        slug=request.slug, display_name=request.display_name, description=request.description
    )
    session.add(collection)
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise DuplicateResourceError("A collection with that slug already exists.") from error
    await session.refresh(collection)
    return collection


async def get_collection(session: AsyncSession, collection_id: UUID) -> Collection:
    collection = await session.get(Collection, collection_id)
    if collection is None:
        raise MissingResourceError("Collection not found.")
    return collection


async def list_collections(session: AsyncSession, limit: int, offset: int) -> list[Collection]:
    query = select(Collection).order_by(Collection.slug).limit(limit).offset(offset)
    return list((await session.scalars(query)).all())


async def add_membership(
    session: AsyncSession, collection_id: UUID, request: MembershipCreate
) -> CollectionMembership:
    await get_collection(session, collection_id)
    await get_server(session, request.server_id)
    membership = CollectionMembership(
        collection_id=collection_id, server_id=request.server_id, enabled=request.enabled
    )
    session.add(membership)
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise DuplicateResourceError("That server is already a collection member.") from error
    await session.refresh(membership)
    return membership


async def remove_membership(session: AsyncSession, collection_id: UUID, server_id: UUID) -> None:
    membership = await session.get(CollectionMembership, (collection_id, server_id))
    if membership is None:
        raise MissingResourceError("Collection membership not found.")
    await session.delete(membership)
    await session.commit()


async def list_collection_tools(
    session: AsyncSession, collection_id: UUID, limit: int, offset: int
) -> list[Tool]:
    collection = await get_collection(session, collection_id)
    if not collection.enabled:
        return []
    query = (
        select(Tool)
        .join(CollectionMembership, CollectionMembership.server_id == Tool.server_id)
        .where(
            CollectionMembership.collection_id == collection_id,
            CollectionMembership.enabled.is_(True),
            Tool.active.is_(True),
        )
        .order_by(Tool.name, Tool.server_id, Tool.id)
        .limit(limit)
        .offset(offset)
    )
    return list((await session.scalars(query)).all())
