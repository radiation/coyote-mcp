from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp import catalog
from coyote_mcp.auth import AuthenticatedPrincipal, authorize, issue_pat
from coyote_mcp.db import get_session
from coyote_mcp.dependencies import current_principal
from coyote_mcp.discovery import (
    DiscoveryService,
    SyncFailedError,
    SyncSupersededError,
    get_discovery_service,
)
from coyote_mcp.models import CollectionMembership, PersonalAccessToken
from coyote_mcp.schemas import (
    CollectionCreate,
    CollectionDetailResponse,
    CollectionResponse,
    MembershipCreate,
    MembershipResponse,
    Page,
    PATCreate,
    PATCreatedResponse,
    PATResponse,
    ServerCreate,
    ServerResponse,
    ToolResponse,
)
from coyote_mcp.security import UnsafeEndpointError, validate_endpoint
from coyote_mcp.settings import Settings

router = APIRouter(prefix="/api/v1")
Session = Annotated[AsyncSession, Depends(get_session)]
Current = Annotated[AuthenticatedPrincipal, Depends(current_principal)]


def page(limit: int = 50, offset: int = 0) -> Page:
    return Page(limit=limit, offset=offset)


PageParams = Annotated[Page, Depends(page)]


def resource_not_found(error: catalog.MissingResourceError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")


async def require(
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    action: str,
    resource: object | None = None,
) -> None:
    if action not in current.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions."
        )
    context: dict[str, object] | None = (
        {"organization_id": current.principal.organization_id} if resource is None else None
    )
    decision = await authorize(session, current.principal, action, resource, context)
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions."
        )


@router.post("/servers", response_model=ServerResponse, status_code=status.HTTP_201_CREATED)
async def register_server(
    request: ServerCreate, session: Session, current: Current
) -> ServerResponse:
    await require(session, current, "server:create")
    try:
        validate_endpoint(str(request.endpoint), Settings())
        return ServerResponse.model_validate(
            await catalog.create_server(session, current.principal.organization_id, request)
        )
    except UnsafeEndpointError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)
        ) from error
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/servers", response_model=list[ServerResponse])
async def list_servers(
    page_params: PageParams, session: Session, current: Current
) -> list[ServerResponse]:
    await require(session, current, "server:read")
    servers = await catalog.list_servers(
        session, current.principal.organization_id, page_params.limit, page_params.offset
    )
    return [ServerResponse.model_validate(server) for server in servers]


@router.get("/servers/{server_id}", response_model=ServerResponse)
async def server_details(server_id: UUID, session: Session, current: Current) -> ServerResponse:
    try:
        server = await catalog.get_server(session, current.principal.organization_id, server_id)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    await require(session, current, "server:read", server)
    return ServerResponse.model_validate(server)


@router.post("/servers/{server_id}/sync", response_model=ServerResponse)
async def sync_server(server_id: UUID, session: Session, current: Current) -> ServerResponse:
    try:
        server = await catalog.get_server(session, current.principal.organization_id, server_id)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    await require(session, current, "server:sync", server)
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
    server_id: UUID, page_params: PageParams, session: Session, current: Current
) -> list[ToolResponse]:
    try:
        server = await catalog.get_server(session, current.principal.organization_id, server_id)
        await require(session, current, "tool:describe", server)
        tools = await catalog.list_server_tools(
            session,
            current.principal.organization_id,
            server_id,
            page_params.limit,
            page_params.offset,
        )
        return [ToolResponse.model_validate(tool) for tool in tools]
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.post("/collections", response_model=CollectionResponse, status_code=status.HTTP_201_CREATED)
async def create_collection(
    request: CollectionCreate, session: Session, current: Current
) -> CollectionResponse:
    await require(session, current, "collection:create")
    try:
        return CollectionResponse.model_validate(
            await catalog.create_collection(session, current.principal.organization_id, request)
        )
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/collections", response_model=list[CollectionResponse])
async def list_collections(
    page_params: PageParams, session: Session, current: Current
) -> list[CollectionResponse]:
    await require(session, current, "collection:read")
    collections = await catalog.list_collections(
        session, current.principal.organization_id, page_params.limit, page_params.offset
    )
    visible: list[CollectionResponse] = []
    for collection in collections:
        if (await authorize(session, current.principal, "collection:read", collection)).allowed:
            visible.append(CollectionResponse.model_validate(collection))
    return visible


@router.get("/collections/{collection_id}", response_model=CollectionDetailResponse)
async def collection_details(
    collection_id: UUID, session: Session, current: Current
) -> CollectionDetailResponse:
    try:
        collection = await catalog.get_collection(
            session, current.principal.organization_id, collection_id
        )
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    await require(session, current, "collection:read", collection)
    memberships = await _get_memberships(collection_id, current.principal.organization_id, session)
    return CollectionDetailResponse(
        **CollectionResponse.model_validate(collection).model_dump(), memberships=memberships
    )


async def _get_memberships(
    collection_id: UUID, organization_id: UUID, session: AsyncSession
) -> list[MembershipResponse]:
    memberships = await session.scalars(
        select(CollectionMembership)
        .where(
            CollectionMembership.collection_id == collection_id,
            CollectionMembership.organization_id == organization_id,
        )
        .order_by(CollectionMembership.server_id)
    )
    return [MembershipResponse.model_validate(membership) for membership in memberships.all()]


@router.post(
    "/collections/{collection_id}/servers",
    response_model=MembershipResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_collection_server(
    collection_id: UUID, request: MembershipCreate, session: Session, current: Current
) -> MembershipResponse:
    try:
        collection = await catalog.get_collection(
            session, current.principal.organization_id, collection_id
        )
        await require(session, current, "collection:manage_members", collection)
        return MembershipResponse.model_validate(
            await catalog.add_membership(
                session, current.principal.organization_id, collection_id, request
            )
        )
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.delete(
    "/collections/{collection_id}/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_collection_server(
    collection_id: UUID, server_id: UUID, session: Session, current: Current
) -> None:
    try:
        collection = await catalog.get_collection(
            session, current.principal.organization_id, collection_id
        )
        await require(session, current, "collection:manage_members", collection)
        await catalog.remove_membership(
            session, current.principal.organization_id, collection_id, server_id
        )
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.get("/collections/{collection_id}/tools", response_model=list[ToolResponse])
async def collection_tools(
    collection_id: UUID, page_params: PageParams, session: Session, current: Current
) -> list[ToolResponse]:
    try:
        collection = await catalog.get_collection(
            session, current.principal.organization_id, collection_id
        )
        await require(session, current, "tool:discover", collection)
        tools = await catalog.list_collection_tools(
            session,
            current.principal.organization_id,
            collection_id,
            page_params.limit,
            page_params.offset,
        )
        return [ToolResponse.model_validate(tool) for tool in tools]
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.get("/me/pats", response_model=list[PATResponse])
async def list_pats(session: Session, current: Current) -> list[PATResponse]:
    await require(session, current, "credential:create")
    tokens = await session.scalars(
        select(PersonalAccessToken)
        .where(PersonalAccessToken.principal_id == current.principal.id)
        .order_by(PersonalAccessToken.created_at)
    )
    return [PATResponse.model_validate(token) for token in tokens.all()]


@router.post("/me/pats", response_model=PATCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_pat(request: PATCreate, session: Session, current: Current) -> PATCreatedResponse:
    await require(session, current, "credential:create")
    try:
        token, plaintext = await issue_pat(
            session,
            current.principal,
            request.name,
            request.scopes,
            timedelta(seconds=request.lifetime_seconds),
            Settings(),
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)
        ) from error
    return PATCreatedResponse(**PATResponse.model_validate(token).model_dump(), token=plaintext)


@router.delete("/me/pats/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_pat(token_id: UUID, session: Session, current: Current) -> None:
    await require(session, current, "credential:revoke")
    token = await session.scalar(
        select(PersonalAccessToken).where(
            PersonalAccessToken.id == token_id,
            PersonalAccessToken.principal_id == current.principal.id,
        )
    )
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")
    token.revoked_at = datetime.now(UTC)
    await session.commit()
