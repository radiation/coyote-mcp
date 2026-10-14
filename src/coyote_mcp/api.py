from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp import catalog
from coyote_mcp.db import get_session
from coyote_mcp.discovery import (
    DiscoveryService,
    SyncFailedError,
    SyncSupersededError,
    get_discovery_service,
)
from coyote_mcp.schemas import (
    CollectionCreate,
    CollectionDetailResponse,
    CollectionResponse,
    MembershipCreate,
    MembershipResponse,
    Page,
    ServerCreate,
    ServerResponse,
    ToolResponse,
)
from coyote_mcp.security import UnsafeEndpointError, validate_endpoint
from coyote_mcp.settings import Settings

router = APIRouter(prefix="/api/v1")
Session = Annotated[AsyncSession, Depends(get_session)]


def page(limit: int = 50, offset: int = 0) -> Page:
    return Page(limit=limit, offset=offset)


PageParams = Annotated[Page, Depends(page)]


def resource_not_found(error: catalog.MissingResourceError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


@router.post("/servers", response_model=ServerResponse, status_code=status.HTTP_201_CREATED)
async def register_server(request: ServerCreate, session: Session) -> ServerResponse:
    try:
        validate_endpoint(str(request.endpoint), Settings())
        return ServerResponse.model_validate(await catalog.create_server(session, request))
    except UnsafeEndpointError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)
        ) from error
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/servers", response_model=list[ServerResponse])
async def list_servers(page_params: PageParams, session: Session) -> list[ServerResponse]:
    servers = await catalog.list_servers(session, page_params.limit, page_params.offset)
    return [ServerResponse.model_validate(server) for server in servers]


@router.get("/servers/{server_id}", response_model=ServerResponse)
async def server_details(server_id: UUID, session: Session) -> ServerResponse:
    try:
        return ServerResponse.model_validate(await catalog.get_server(session, server_id))
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.post("/servers/{server_id}/sync", response_model=ServerResponse)
async def sync_server(server_id: UUID, session: Session) -> ServerResponse:
    try:
        server = await catalog.get_server(session, server_id)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    service: DiscoveryService = get_discovery_service(Settings())
    try:
        return ServerResponse.model_validate(await service.sync(session, server))
    except SyncFailedError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to synchronize the downstream server.",
        ) from error
    except SyncSupersededError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A newer synchronization request superseded this request.",
        ) from error


@router.get("/servers/{server_id}/tools", response_model=list[ToolResponse])
async def server_tools(
    server_id: UUID, page_params: PageParams, session: Session
) -> list[ToolResponse]:
    try:
        tools = await catalog.list_server_tools(
            session, server_id, page_params.limit, page_params.offset
        )
        return [ToolResponse.model_validate(tool) for tool in tools]
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.post("/collections", response_model=CollectionResponse, status_code=status.HTTP_201_CREATED)
async def create_collection(request: CollectionCreate, session: Session) -> CollectionResponse:
    try:
        return CollectionResponse.model_validate(await catalog.create_collection(session, request))
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/collections", response_model=list[CollectionResponse])
async def list_collections(page_params: PageParams, session: Session) -> list[CollectionResponse]:
    collections = await catalog.list_collections(session, page_params.limit, page_params.offset)
    return [CollectionResponse.model_validate(collection) for collection in collections]


@router.get("/collections/{collection_id}", response_model=CollectionDetailResponse)
async def collection_details(collection_id: UUID, session: Session) -> CollectionDetailResponse:
    try:
        collection = await catalog.get_collection(session, collection_id)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    memberships = await _get_memberships(collection_id, session)
    return CollectionDetailResponse(
        **CollectionResponse.model_validate(collection).model_dump(),
        memberships=memberships,
    )


async def _get_memberships(collection_id: UUID, session: AsyncSession) -> list[MembershipResponse]:
    from sqlalchemy import select

    from coyote_mcp.models import CollectionMembership

    memberships = await session.scalars(
        select(CollectionMembership)
        .where(CollectionMembership.collection_id == collection_id)
        .order_by(CollectionMembership.server_id)
    )
    return [MembershipResponse.model_validate(membership) for membership in memberships.all()]


@router.post(
    "/collections/{collection_id}/servers",
    response_model=MembershipResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_collection_server(
    collection_id: UUID, request: MembershipCreate, session: Session
) -> MembershipResponse:
    try:
        return MembershipResponse.model_validate(
            await catalog.add_membership(session, collection_id, request)
        )
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.delete(
    "/collections/{collection_id}/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_collection_server(collection_id: UUID, server_id: UUID, session: Session) -> None:
    try:
        await catalog.remove_membership(session, collection_id, server_id)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.get("/collections/{collection_id}/tools", response_model=list[ToolResponse])
async def collection_tools(
    collection_id: UUID, page_params: PageParams, session: Session
) -> list[ToolResponse]:
    try:
        tools = await catalog.list_collection_tools(
            session, collection_id, page_params.limit, page_params.offset
        )
        return [ToolResponse.model_validate(tool) for tool in tools]
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
