from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp import catalog
from coyote_mcp.audit import AuditAction, AuditTargetType, record_principal_audit_event
from coyote_mcp.auth import (
    ROLE_PERMISSIONS,
    AuthenticatedPrincipal,
    authorize,
    effective_permissions,
    issue_pat,
)
from coyote_mcp.db import get_session
from coyote_mcp.dependencies import current_principal
from coyote_mcp.discovery import (
    SyncFailedError,
    SyncSupersededError,
)
from coyote_mcp.models import (
    Collection,
    CollectionMembership,
    ExternalGroup,
    GroupRoleMapping,
    OrganizationMembership,
    PersonalAccessToken,
    Principal,
    RoleAssignment,
)
from coyote_mcp.schemas import (
    CollectionCreate,
    CollectionDetailResponse,
    CollectionResponse,
    CollectionUpdate,
    ExternalGroupCreate,
    GroupRoleMappingCreate,
    MembershipCreate,
    MembershipResponse,
    Page,
    PATCreate,
    PATCreatedResponse,
    PATResponse,
    PrincipalResponse,
    PublicationCreate,
    PublicationResponse,
    PublicationUpdate,
    ServerCreate,
    ServerResponse,
    ServicePATCreate,
    ServicePrincipalCreate,
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
    if resource is None and current.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="An active organization is required."
        )
    context: dict[str, object] | None = (
        {"organization_id": current.require_organization_id()} if resource is None else None
    )
    decision = await authorize(
        session,
        current.principal,
        action,
        resource,
        context,
        current.verified_group_ids,
        current.credential_context,
    )
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
            await catalog.create_server(session, current.require_organization_id(), request)
        )
    except UnsafeEndpointError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)
        ) from error
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/servers", response_model=list[ServerResponse])
async def list_servers(
    page_params: PageParams, session: Session, current: Current
) -> list[ServerResponse]:
    await require(session, current, "server:read")
    servers = await catalog.list_servers(
        session, current.require_organization_id(), page_params.limit, page_params.offset
    )
    return [ServerResponse.model_validate(server) for server in servers]


@router.get("/servers/{server_id}", response_model=ServerResponse)
async def server_details(server_id: UUID, session: Session, current: Current) -> ServerResponse:
    try:
        server = await catalog.get_server(session, current.require_organization_id(), server_id)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    await require(session, current, "server:read", server)
    return ServerResponse.model_validate(server)


@router.post("/servers/{server_id}/sync", response_model=ServerResponse)
async def sync_server(server_id: UUID, session: Session, current: Current) -> ServerResponse:
    try:
        server = await catalog.get_server(session, current.require_organization_id(), server_id)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    await require(session, current, "server:sync", server)
    try:
        discovered = await catalog.discover_server(session, current, server)
        return ServerResponse.model_validate(discovered)
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
        server = await catalog.get_server(session, current.require_organization_id(), server_id)
        await require(session, current, "tool:describe", server)
        tools = await catalog.list_server_tools(
            session,
            current.require_organization_id(),
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
            await catalog.create_collection(session, current.require_organization_id(), request)
        )
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/collections", response_model=list[CollectionResponse])
async def list_collections(
    page_params: PageParams, session: Session, current: Current
) -> list[CollectionResponse]:
    await require(session, current, "collection:read")
    collections = await catalog.list_collections(
        session, current.require_organization_id(), page_params.limit, page_params.offset
    )
    visible: list[CollectionResponse] = []
    for collection in collections:
        if (
            await authorize(
                session,
                current.principal,
                "collection:read",
                collection,
                credential_context=current.credential_context,
            )
        ).allowed:
            visible.append(CollectionResponse.model_validate(collection))
    return visible


@router.get("/collections/{collection_id}", response_model=CollectionDetailResponse)
async def collection_details(
    collection_id: UUID, session: Session, current: Current
) -> CollectionDetailResponse:
    try:
        collection = await catalog.get_collection(
            session, current.require_organization_id(), collection_id
        )
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    await require(session, current, "collection:read", collection)
    memberships = await _get_memberships(collection_id, current.require_organization_id(), session)
    return CollectionDetailResponse(
        **CollectionResponse.model_validate(collection).model_dump(), memberships=memberships
    )


@router.patch("/collections/{collection_id}", response_model=CollectionResponse)
async def update_collection(
    collection_id: UUID, request: CollectionUpdate, session: Session, current: Current
) -> CollectionResponse:
    try:
        return CollectionResponse.model_validate(
            await catalog.update_collection(session, current, collection_id, request)
        )
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    except catalog.AuthorizationError as error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(error)) from error


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
            session, current.require_organization_id(), collection_id
        )
        await require(session, current, "collection:manage_members", collection)
        return MembershipResponse.model_validate(
            await catalog.add_membership(
                session, current.require_organization_id(), collection_id, request
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
            session, current.require_organization_id(), collection_id
        )
        await require(session, current, "collection:manage_members", collection)
        await catalog.remove_membership(
            session, current.require_organization_id(), collection_id, server_id
        )
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.get("/collections/{collection_id}/tools", response_model=list[ToolResponse])
async def collection_tools(
    collection_id: UUID, page_params: PageParams, session: Session, current: Current
) -> list[ToolResponse]:
    try:
        collection = await catalog.get_collection(
            session, current.require_organization_id(), collection_id
        )
        await require(session, current, "tool:discover", collection)
        tools = await catalog.list_collection_tools(
            session,
            current.require_organization_id(),
            collection_id,
            page_params.limit,
            page_params.offset,
        )
        return [ToolResponse.model_validate(tool) for tool in tools]
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.get("/collections/{collection_id}/publications", response_model=list[PublicationResponse])
async def collection_publications(
    collection_id: UUID, page_params: PageParams, session: Session, current: Current
) -> list[PublicationResponse]:
    try:
        collection = await catalog.get_collection(
            session, current.require_organization_id(), collection_id
        )
        await require(session, current, "collection:update", collection)
        publications = await catalog.list_publications(
            session, current, collection_id, page_params.limit, page_params.offset
        )
        return [PublicationResponse.model_validate(publication) for publication in publications]
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.post(
    "/collections/{collection_id}/publications",
    response_model=PublicationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def publish_collection_tool(
    collection_id: UUID, request: PublicationCreate, session: Session, current: Current
) -> PublicationResponse:
    try:
        collection = await catalog.get_collection(
            session, current.require_organization_id(), collection_id
        )
        await require(session, current, "collection:update", collection)
        publication = await catalog.publish_tool(session, current, collection_id, request)
        return PublicationResponse.model_validate(publication)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.patch(
    "/collections/{collection_id}/publications/{publication_id}", response_model=PublicationResponse
)
async def update_collection_publication(
    collection_id: UUID,
    publication_id: UUID,
    request: PublicationUpdate,
    session: Session,
    current: Current,
) -> PublicationResponse:
    try:
        collection = await catalog.get_collection(
            session, current.require_organization_id(), collection_id
        )
        await require(session, current, "collection:update", collection)
        publication = await catalog.update_publication(
            session, current, collection_id, publication_id, request
        )
        return PublicationResponse.model_validate(publication)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error
    except catalog.DuplicateResourceError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.delete(
    "/collections/{collection_id}/publications/{publication_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_collection_publication(
    collection_id: UUID, publication_id: UUID, session: Session, current: Current
) -> None:
    try:
        collection = await catalog.get_collection(
            session, current.require_organization_id(), collection_id
        )
        await require(session, current, "collection:update", collection)
        await catalog.remove_publication(session, current, collection_id, publication_id)
    except catalog.MissingResourceError as error:
        raise resource_not_found(error) from error


@router.get("/me/pats", response_model=list[PATResponse])
async def list_pats(session: Session, current: Current) -> list[PATResponse]:
    await require(session, current, "credential:create")
    tokens = await session.scalars(
        select(PersonalAccessToken)
        .where(
            PersonalAccessToken.principal_id == current.principal.id,
            PersonalAccessToken.organization_id == current.require_organization_id(),
        )
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
            current.require_organization_id(),
            request.name,
            request.scopes,
            timedelta(seconds=request.lifetime_seconds),
            Settings(),
            actor=current.principal,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)
        ) from error
    return PATCreatedResponse(**PATResponse.model_validate(token).model_dump(), token=plaintext)


@router.delete("/me/pats/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_pat(token_id: UUID, session: Session, current: Current) -> None:
    await require(session, current, "credential:revoke")
    token = await session.scalar(
        select(PersonalAccessToken).where(
            PersonalAccessToken.id == token_id,
            PersonalAccessToken.principal_id == current.principal.id,
            PersonalAccessToken.organization_id == current.require_organization_id(),
        )
    )
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
        await record_principal_audit_event(
            session,
            organization_id=current.require_organization_id(),
            actor=current.principal,
            action=AuditAction.CREDENTIAL_REVOKED,
            target_type=AuditTargetType.CREDENTIAL,
            target_id=token.id,
            metadata={"credential_kind": "pat"},
        )
    await session.commit()


async def require_identity_administrator(
    session: AsyncSession, current: AuthenticatedPrincipal
) -> None:
    await require(session, current, "policy:manage")


@router.get("/service-principals", response_model=list[PrincipalResponse])
async def list_service_principals(session: Session, current: Current) -> list[PrincipalResponse]:
    await require_identity_administrator(session, current)
    principals = await session.scalars(
        select(Principal)
        .join(OrganizationMembership, OrganizationMembership.principal_id == Principal.id)
        .where(
            OrganizationMembership.organization_id == current.require_organization_id(),
            Principal.identity_type == "service",
        )
        .order_by(Principal.identifier)
    )
    return [PrincipalResponse.model_validate(principal) for principal in principals]


@router.post(
    "/service-principals", response_model=PrincipalResponse, status_code=status.HTTP_201_CREATED
)
async def create_service_principal(
    request: ServicePrincipalCreate, session: Session, current: Current
) -> PrincipalResponse:
    await require_identity_administrator(session, current)
    actor_permissions = current.scopes & await effective_permissions(
        session,
        current.principal,
        current.require_organization_id(),
        current.verified_group_ids,
        current.credential_context,
    )
    requested_permissions = frozenset().union(*(ROLE_PERMISSIONS[role] for role in request.roles))
    if not requested_permissions.issubset(actor_permissions):
        raise HTTPException(status_code=403, detail="Cannot grant permissions you do not hold.")
    principal = Principal(
        identifier=request.identifier,
        display_name=request.display_name,
        identity_type="service",
    )
    session.add(principal)
    try:
        await session.flush()
        session.add(
            OrganizationMembership(
                organization_id=current.require_organization_id(), principal_id=principal.id
            )
        )
        session.add_all(
            [
                RoleAssignment(
                    organization_id=current.require_organization_id(),
                    principal_id=principal.id,
                    role=role,
                )
                for role in request.roles
            ]
        )
        await record_principal_audit_event(
            session,
            organization_id=current.require_organization_id(),
            actor=current.principal,
            action=AuditAction.PRINCIPAL_CREATED,
            target_type=AuditTargetType.PRINCIPAL,
            target_id=principal.id,
            metadata={"identity_type": "service", "role_count": len(request.roles)},
        )
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise HTTPException(status_code=409, detail="Service principal already exists.") from error
    await session.refresh(principal)
    return PrincipalResponse.model_validate(principal)


async def service_principal_or_404(
    session: AsyncSession, organization_id: UUID, principal_id: UUID
) -> Principal:
    principal = await session.scalar(
        select(Principal).where(
            Principal.id == principal_id,
            Principal.identity_type == "service",
        )
    )
    if principal is None:
        raise HTTPException(status_code=404, detail="Resource not found.")
    membership = await session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.principal_id == principal.id,
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.enabled.is_(True),
        )
    )
    if membership is None:
        raise HTTPException(status_code=404, detail="Resource not found.")
    return principal


@router.post("/service-principals/{principal_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_service_principal(principal_id: UUID, session: Session, current: Current) -> None:
    await require_identity_administrator(session, current)
    principal = await service_principal_or_404(
        session, current.require_organization_id(), principal_id
    )
    if principal.enabled:
        principal.enabled = False
        await record_principal_audit_event(
            session,
            organization_id=current.require_organization_id(),
            actor=current.principal,
            action=AuditAction.PRINCIPAL_DISABLED,
            target_type=AuditTargetType.PRINCIPAL,
            target_id=principal.id,
            metadata={"identity_type": "service"},
        )
    await session.commit()


@router.post(
    "/service-principals/{principal_id}/pats",
    response_model=PATCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def issue_service_pat(
    principal_id: UUID, request: ServicePATCreate, session: Session, current: Current
) -> PATCreatedResponse:
    await require_identity_administrator(session, current)
    principal = await service_principal_or_404(
        session, current.require_organization_id(), principal_id
    )
    actor_permissions = current.scopes & await effective_permissions(
        session,
        current.principal,
        current.require_organization_id(),
        current.verified_group_ids,
        current.credential_context,
    )
    if not request.scopes.issubset(actor_permissions):
        raise HTTPException(status_code=403, detail="Cannot issue broader credentials.")
    try:
        token, plaintext = await issue_pat(
            session,
            principal,
            current.require_organization_id(),
            request.name,
            request.scopes,
            timedelta(seconds=request.lifetime_seconds),
            Settings(),
            actor=current.principal,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return PATCreatedResponse(**PATResponse.model_validate(token).model_dump(), token=plaintext)


@router.delete(
    "/service-principals/{principal_id}/pats/{token_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def revoke_service_pat(
    principal_id: UUID, token_id: UUID, session: Session, current: Current
) -> None:
    await require_identity_administrator(session, current)
    await service_principal_or_404(session, current.require_organization_id(), principal_id)
    token = await session.scalar(
        select(PersonalAccessToken).where(
            PersonalAccessToken.id == token_id,
            PersonalAccessToken.principal_id == principal_id,
            PersonalAccessToken.organization_id == current.require_organization_id(),
        )
    )
    if token is None:
        raise HTTPException(status_code=404, detail="Resource not found.")
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
        await record_principal_audit_event(
            session,
            organization_id=current.require_organization_id(),
            actor=current.principal,
            action=AuditAction.CREDENTIAL_REVOKED,
            target_type=AuditTargetType.CREDENTIAL,
            target_id=token.id,
            metadata={"credential_kind": "pat"},
        )
    await session.commit()


@router.post("/external-groups", status_code=status.HTTP_201_CREATED)
async def create_external_group(
    request: ExternalGroupCreate, session: Session, current: Current
) -> dict[str, str]:
    await require_identity_administrator(session, current)
    group = ExternalGroup(
        organization_id=current.require_organization_id(),
        external_id=request.external_id,
        display_name=request.display_name,
    )
    session.add(group)
    try:
        await session.flush()
        await record_principal_audit_event(
            session,
            organization_id=current.require_organization_id(),
            actor=current.principal,
            action=AuditAction.GROUP_CREATED,
            target_type=AuditTargetType.POLICY,
            target_id=group.id,
        )
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise HTTPException(status_code=409, detail="External group already exists.") from error
    return {"id": str(group.id)}


@router.post("/external-groups/{group_id}/role-mappings", status_code=status.HTTP_201_CREATED)
async def create_group_role_mapping(
    group_id: UUID, request: GroupRoleMappingCreate, session: Session, current: Current
) -> dict[str, str]:
    await require_identity_administrator(session, current)
    group = await session.scalar(
        select(ExternalGroup).where(
            ExternalGroup.id == group_id,
            ExternalGroup.organization_id == current.require_organization_id(),
        )
    )
    if group is None:
        raise HTTPException(status_code=404, detail="Resource not found.")
    if request.collection_id is not None:
        collection = await session.get(Collection, request.collection_id)
        if collection is None or collection.organization_id != current.require_organization_id():
            raise HTTPException(status_code=404, detail="Resource not found.")
    mapping = GroupRoleMapping(
        organization_id=current.require_organization_id(),
        external_group_id=group.id,
        role=request.role,
        collection_id=request.collection_id,
    )
    session.add(mapping)
    try:
        await session.flush()
        await record_principal_audit_event(
            session,
            organization_id=current.require_organization_id(),
            actor=current.principal,
            action=AuditAction.ROLE_MAPPING_CREATED,
            target_type=AuditTargetType.POLICY,
            target_id=mapping.id,
            metadata={
                "role": mapping.role,
                "scope": "collection" if mapping.collection_id is not None else "organization",
            },
        )
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise HTTPException(status_code=409, detail="Group role mapping already exists.") from error
    return {"id": str(mapping.id)}
