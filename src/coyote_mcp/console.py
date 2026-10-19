from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import FormData

from coyote_mcp import catalog, connected_apps
from coyote_mcp.auth import (
    AuthenticatedPrincipal,
    OrganizationBootstrapError,
    authenticate_browser_session,
    authorize,
    authorized_collection_ids,
    available_organizations,
    create_initial_organization,
    csrf_token_for,
    csrf_token_valid,
    has_action_grant_in_organization,
    is_instance_administrator,
    select_active_organization,
)
from coyote_mcp.credentials import AUTH_POLICIES
from coyote_mcp.db import get_session
from coyote_mcp.discovery import SyncFailedError, SyncSupersededError
from coyote_mcp.downstream_oauth import PROVIDERS
from coyote_mcp.models import Collection, CollectionToolPublication, MCPServer, Organization, Tool
from coyote_mcp.schemas import (
    CollectionCreate,
    CollectionUpdate,
    OrganizationCreate,
    PublicationCreate,
    PublicationUpdate,
    ServerCreate,
    ServerUpdate,
)
from coyote_mcp.security import UnsafeEndpointError
from coyote_mcp.settings import Settings

router = APIRouter(prefix="/console", include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
Session = Annotated[AsyncSession, Depends(get_session)]
PAGE_SIZE = 25
MEMBERSHIP_LIMIT = 100
ADDABLE_SERVER_LIMIT = 100
PageQuery = Annotated[int, Query(ge=1, le=10_000)]


@dataclass(frozen=True)
class DashboardMetrics:
    servers: int
    ready_servers: int
    unavailable_servers: int
    active_tools: int
    collections: int
    enabled_publications: int


async def _browser_principal(request: Request, session: Session) -> AuthenticatedPrincipal | None:
    if request.headers.get("authorization") is not None:
        return None
    return await authenticate_browser_session(
        session, request.cookies.get(Settings().browser_session_cookie_name, "")
    )


async def _authorized(session: AsyncSession, current: AuthenticatedPrincipal, action: str) -> bool:
    if action not in current.scopes:
        return False
    decision = await authorize(
        session,
        current.principal,
        action,
        context={"organization_id": current.require_organization_id()},
        verified_group_ids=current.verified_group_ids,
        credential_context=current.credential_context,
    )
    return decision.allowed


def _context(
    request: Request,
    current: AuthenticatedPrincipal | None = None,
    **values: object,
) -> dict[str, object]:
    return {"request": request, "current": current, **values}


def _page_response(
    request: Request,
    page_name: str,
    context: dict[str, object],
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    template_name = (
        f"console/fragments/{page_name}_content.html"
        if request.headers.get("HX-Request") == "true"
        else f"console/{page_name}.html"
    )
    return templates.TemplateResponse(request, template_name, context, status_code=status_code)


def redacted_endpoint(endpoint: str) -> str:
    """Show only the scheme, host, and path of a downstream endpoint."""
    parts = urlsplit(endpoint)
    port = f":{parts.port}" if parts.port is not None else ""
    return f"{parts.scheme}://{parts.hostname or ''}{port}{parts.path}"


templates.env.filters["redacted_endpoint"] = redacted_endpoint


_CONSOLE_LOCATION_PATTERN = re.compile(r"/console(?:/[A-Za-z0-9_-]+)*")


def _see_other(location: str) -> RedirectResponse:
    # Only local console paths are valid redirect targets; anything else falls back to /console.
    if not _CONSOLE_LOCATION_PATTERN.fullmatch(location):
        location = "/console"
    return RedirectResponse(location, status_code=status.HTTP_303_SEE_OTHER)


def _render_access_required(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "console/login.html",
        _context(request, page_title="Sign in required"),
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


def _render_forbidden(request: Request, current: AuthenticatedPrincipal) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "console/error.html",
        _context(
            request,
            current,
            page_title="Access denied",
            error_title="Access denied",
            error_message="Your current roles do not permit access to this page.",
        ),
        status_code=status.HTTP_403_FORBIDDEN,
    )


async def _dashboard_metrics(session: AsyncSession, organization_id: UUID) -> DashboardMetrics:
    server_counts = (
        await session.execute(
            select(
                func.count(MCPServer.id),
                func.coalesce(func.sum(case((MCPServer.status == "ready", 1), else_=0)), 0),
            ).where(MCPServer.organization_id == organization_id)
        )
    ).one()
    servers = int(server_counts[0])
    ready_servers = int(server_counts[1])
    active_tools = int(
        await session.scalar(
            select(func.count(Tool.id))
            .join(MCPServer, Tool.server_id == MCPServer.id)
            .where(MCPServer.organization_id == organization_id, Tool.active.is_(True))
        )
        or 0
    )
    collections = int(
        await session.scalar(
            select(func.count(Collection.id)).where(Collection.organization_id == organization_id)
        )
        or 0
    )
    enabled_publications = int(
        await session.scalar(
            select(func.count(CollectionToolPublication.id))
            .join(Collection, CollectionToolPublication.collection_id == Collection.id)
            .where(
                Collection.organization_id == organization_id,
                CollectionToolPublication.enabled.is_(True),
            )
        )
        or 0
    )
    return DashboardMetrics(
        servers=servers,
        ready_servers=ready_servers,
        unavailable_servers=servers - ready_servers,
        active_tools=active_tools,
        collections=collections,
        enabled_publications=enabled_publications,
    )


@router.get("/login")
async def console_login(request: Request) -> Response:
    if request.query_params.get("start") == "1":
        return RedirectResponse("/auth/oidc/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "console/login.html", {"page_title": "Sign in"})


async def _select_organization_page(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    *,
    creation_error: str | None = None,
    response_status: int = status.HTTP_200_OK,
    auto_select: bool = True,
) -> Response:
    if current.browser_session is None:
        return _render_access_required(request)
    organizations = await available_organizations(session, current)
    if auto_select and len(organizations) == 1:
        await select_active_organization(session, current, organizations[0].id)
        return RedirectResponse("/console", status_code=status.HTTP_303_SEE_OTHER)
    csrf_token = csrf_token_for(current.browser_session, Settings())
    return templates.TemplateResponse(
        request,
        "console/select_organization.html",
        _context(
            request,
            current,
            page_title="Select organization",
            organizations=organizations,
            can_create_organization=await is_instance_administrator(session, current.principal),
            creation_error=creation_error,
            csrf_token=csrf_token,
        ),
        status_code=response_status,
    )


@router.get("/organizations")
async def organization_selection(request: Request, session: Session) -> Response:
    current = await _browser_principal(request, session)
    if current is None:
        return RedirectResponse("/console/login", status_code=status.HTTP_303_SEE_OTHER)
    return await _select_organization_page(request, session, current, auto_select=False)


@router.post("/organization")
async def select_organization(request: Request, session: Session) -> Response:
    current = await _browser_principal(request, session)
    if current is None or current.browser_session is None:
        return _render_access_required(request)
    form = await request.form()
    csrf_token = form.get("csrf_token")
    organization_value = form.get("organization_id")
    if not isinstance(csrf_token, str) or not csrf_token_valid(
        current.browser_session, csrf_token, Settings()
    ):
        return _render_forbidden(request, current)
    try:
        if not isinstance(organization_value, str):
            raise ValueError
        organization_id = UUID(organization_value)
    except ValueError:
        return _render_forbidden(request, current)
    if not await select_active_organization(session, current, organization_id):
        return _render_forbidden(request, current)
    return RedirectResponse("/console", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/organizations")
async def create_organization(request: Request, session: Session) -> Response:
    current = await _browser_principal(request, session)
    if current is None or current.browser_session is None:
        return _render_access_required(request)
    form = await request.form()
    csrf_token = form.get("csrf_token")
    if not isinstance(csrf_token, str) or not csrf_token_valid(
        current.browser_session, csrf_token, Settings()
    ):
        return _render_forbidden(request, current)
    slug = form.get("slug")
    display_name = form.get("display_name")
    if not isinstance(slug, str) or not isinstance(display_name, str):
        return await _select_organization_page(
            request,
            session,
            current,
            creation_error="Enter a valid organization slug and display name.",
            response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    try:
        organization_request = OrganizationCreate(slug=slug, display_name=display_name)
        await create_initial_organization(
            session,
            current,
            slug=organization_request.slug,
            display_name=organization_request.display_name,
        )
    except ValidationError:
        return await _select_organization_page(
            request,
            session,
            current,
            creation_error="Enter a valid organization slug and display name.",
            response_status=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except OrganizationBootstrapError as error:
        if error.category == "duplicate_slug":
            return await _select_organization_page(
                request,
                session,
                current,
                creation_error="An organization with this slug already exists.",
                response_status=status.HTTP_409_CONFLICT,
            )
        return _render_forbidden(request, current)
    return RedirectResponse("/console", status_code=status.HTTP_303_SEE_OTHER)


@router.get("", response_class=HTMLResponse)
async def overview(request: Request, session: Session) -> Response:
    current = await _browser_principal(request, session)
    if current is None:
        return RedirectResponse("/console/login", status_code=status.HTTP_303_SEE_OTHER)
    if current.organization_id is None:
        return await _select_organization_page(request, session, current)
    if not await _authorized(session, current, "server:read") or not await _authorized(
        session, current, "collection:read"
    ):
        return _render_forbidden(request, current)
    metrics = await _dashboard_metrics(session, current.require_organization_id())
    recent_servers = (
        await session.scalars(
            select(MCPServer)
            .where(MCPServer.organization_id == current.require_organization_id())
            .order_by(MCPServer.last_synced_at.desc(), MCPServer.name)
            .limit(5)
        )
    ).all()
    organization_name = await session.scalar(
        select(Organization.display_name).where(
            Organization.id == current.require_organization_id()
        )
    )
    return _page_response(
        request,
        "overview",
        _context(
            request,
            current,
            page_title="Overview",
            active_navigation="overview",
            metrics=metrics,
            recent_servers=recent_servers,
            organization_name=organization_name or "Organization",
        ),
    )


def _render_not_found(request: Request, current: AuthenticatedPrincipal) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "console/error.html",
        _context(
            request,
            current,
            page_title="Not found",
            error_title="Not found",
            error_message="The requested resource does not exist in the active organization.",
        ),
        status_code=status.HTTP_404_NOT_FOUND,
    )


async def _organization_name(session: AsyncSession, organization_id: UUID) -> str:
    name = await session.scalar(
        select(Organization.display_name).where(Organization.id == organization_id)
    )
    return name or "Organization"


async def _organization_principal(
    request: Request, session: AsyncSession
) -> AuthenticatedPrincipal | Response:
    """Authenticate and select an organization without an organization-wide permission check.

    Collection-scoped pages must authorize the specific collection in the service layer.
    """
    current = await _browser_principal(request, session)
    if current is None:
        return RedirectResponse("/console/login", status_code=status.HTTP_303_SEE_OTHER)
    if current.organization_id is None:
        return await _select_organization_page(request, session, current)
    return current


async def _page_principal(
    request: Request, session: AsyncSession, action: str
) -> AuthenticatedPrincipal | Response:
    current = await _organization_principal(request, session)
    if isinstance(current, Response):
        return current
    if not await _authorized(session, current, action):
        return _render_forbidden(request, current)
    return current


async def _write_request(
    request: Request, session: AsyncSession
) -> tuple[AuthenticatedPrincipal, FormData] | Response:
    current = await _browser_principal(request, session)
    if current is None or current.browser_session is None:
        return _render_access_required(request)
    form = await request.form()
    token = form.get("csrf_token")
    if (
        current.organization_id is None
        or not isinstance(token, str)
        or not csrf_token_valid(current.browser_session, token, Settings())
    ):
        return _render_forbidden(request, current)
    return current, form


def _csrf_token(current: AuthenticatedPrincipal) -> str:
    if current.browser_session is None:
        return ""
    return csrf_token_for(current.browser_session, Settings())


def _form_text(form: FormData, key: str) -> str:
    value = form.get(key)
    return value.strip() if isinstance(value, str) else ""


async def _server_form_response(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    *,
    server: MCPServer | None,
    values: dict[str, str],
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    return _page_response(
        request,
        "server_form",
        _context(
            request,
            current,
            page_title="Edit server" if server is not None else "Register server",
            active_navigation="servers",
            organization_name=await _organization_name(session, current.require_organization_id()),
            server=server,
            values=values,
            form_error=error,
            csrf_token=_csrf_token(current),
        ),
        status_code=status_code,
    )


async def _server_detail_response(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    server: MCPServer,
    page: int,
    *,
    action_error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    organization_id = current.require_organization_id()
    tools = await catalog.list_server_tools(
        session, organization_id, server.id, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE
    )
    return _page_response(
        request,
        "server_detail",
        _context(
            request,
            current,
            page_title=server.display_name,
            active_navigation="servers",
            organization_name=await _organization_name(session, organization_id),
            server=server,
            tools=tools[:PAGE_SIZE],
            page=page,
            has_next=len(tools) > PAGE_SIZE,
            can_update=await _authorized(session, current, "server:update"),
            can_sync=await _authorized(session, current, "server:sync"),
            action_error=action_error,
            csrf_token=_csrf_token(current),
        ),
        status_code=status_code,
    )


@router.get("/servers", response_class=HTMLResponse)
async def server_list(request: Request, session: Session, page: PageQuery = 1) -> Response:
    gate = await _page_principal(request, session, "server:read")
    if isinstance(gate, Response):
        return gate
    organization_id = gate.require_organization_id()
    servers = await catalog.list_servers(
        session, organization_id, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE
    )
    return _page_response(
        request,
        "server_list",
        _context(
            request,
            gate,
            page_title="MCP Servers",
            active_navigation="servers",
            organization_name=await _organization_name(session, organization_id),
            servers=servers[:PAGE_SIZE],
            page=page,
            has_next=len(servers) > PAGE_SIZE,
            can_create=await _authorized(session, gate, "server:create"),
        ),
    )


@router.get("/servers/new", response_class=HTMLResponse)
async def server_registration_form(request: Request, session: Session) -> Response:
    gate = await _page_principal(request, session, "server:create")
    if isinstance(gate, Response):
        return gate
    return await _server_form_response(request, session, gate, server=None, values={})


@router.post("/servers")
async def server_register(request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    values = {"name": _form_text(form, "name"), "display_name": _form_text(form, "display_name")}
    try:
        payload = ServerCreate.model_validate(
            {
                **values,
                "endpoint": _form_text(form, "endpoint"),
                "transport": "streamable_http",
            }
        )
        server = await catalog.register_server(session, current, payload)
    except ValidationError:
        return await _server_form_response(
            request,
            session,
            current,
            server=None,
            values=values,
            error="Enter a lowercase server name, a display name, and an HTTPS endpoint URL.",
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except UnsafeEndpointError as error:
        return await _server_form_response(
            request,
            session,
            current,
            server=None,
            values=values,
            error=str(error),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except catalog.DuplicateResourceError as error:
        return await _server_form_response(
            request,
            session,
            current,
            server=None,
            values=values,
            error=str(error),
            status_code=status.HTTP_409_CONFLICT,
        )
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/servers/" + str(server.id))


@router.get("/servers/{server_id}", response_class=HTMLResponse)
async def server_detail(
    server_id: UUID, request: Request, session: Session, page: PageQuery = 1
) -> Response:
    gate = await _page_principal(request, session, "server:read")
    if isinstance(gate, Response):
        return gate
    try:
        server = await catalog.read_server(session, gate, server_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, gate)
    except catalog.AuthorizationError:
        return _render_forbidden(request, gate)
    return await _server_detail_response(request, session, gate, server, page)


@router.get("/servers/{server_id}/edit", response_class=HTMLResponse)
async def server_edit_form(server_id: UUID, request: Request, session: Session) -> Response:
    gate = await _page_principal(request, session, "server:update")
    if isinstance(gate, Response):
        return gate
    try:
        server = await catalog.get_server(session, gate.require_organization_id(), server_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, gate)
    return await _server_form_response(
        request,
        session,
        gate,
        server=server,
        values={"display_name": server.display_name},
    )


@router.post("/servers/{server_id}/edit")
async def server_update(server_id: UUID, request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    try:
        server = await catalog.require_server_update(session, current, server_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    display_name = _form_text(form, "display_name")
    endpoint = _form_text(form, "endpoint")
    try:
        update = ServerUpdate.model_validate(
            {"display_name": display_name or None, "endpoint": endpoint or None}
        )
        await catalog.update_server(session, current, server_id, update)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    except (ValidationError, UnsafeEndpointError) as error:
        message = (
            str(error)
            if isinstance(error, UnsafeEndpointError)
            else "Enter a display name of up to 160 characters and a valid HTTPS endpoint URL."
        )
        return await _server_form_response(
            request,
            session,
            current,
            server=server,
            values={"display_name": display_name},
            error=message,
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    return _see_other("/console/servers/" + str(server_id))


@router.post("/servers/{server_id}/enabled")
async def server_set_enabled(server_id: UUID, request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    enabled = _form_text(form, "enabled")
    if enabled not in {"true", "false"}:
        return HTMLResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
    try:
        await catalog.set_server_enabled(session, current, server_id, enabled == "true")
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/servers/" + str(server_id))


@router.post("/servers/{server_id}/sync")
async def server_sync(server_id: UUID, request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, _ = result
    try:
        await catalog.synchronize_server(session, current, server_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    except SyncFailedError, SyncSupersededError, LookupError:
        # The failure is persisted on the server record and shown on its detail page.
        pass
    return _see_other("/console/servers/" + str(server_id))


@router.post("/servers/{server_id}/delete")
async def server_delete(server_id: UUID, request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, _ = result
    try:
        await catalog.delete_server(session, current, server_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    except catalog.ServerInUseError as error:
        try:
            server = await catalog.get_server(session, current.require_organization_id(), server_id)
        except catalog.MissingResourceError:
            return _render_not_found(request, current)
        return await _server_detail_response(
            request,
            session,
            current,
            server,
            1,
            action_error=str(error),
            status_code=status.HTTP_409_CONFLICT,
        )
    return RedirectResponse("/console/servers", status_code=status.HTTP_303_SEE_OTHER)


_PLACEHOLDER_PAGES = {
    "principals": ("Principals & Roles", "policy:manage"),
    "tokens": ("API Tokens", "credential:create"),
}


async def _collection_allows(
    session: AsyncSession, current: AuthenticatedPrincipal, collection: Collection, action: str
) -> bool:
    if action not in current.scopes:
        return False
    decision = await authorize(
        session,
        current.principal,
        action,
        collection,
        verified_group_ids=current.verified_group_ids,
        credential_context=current.credential_context,
    )
    return decision.allowed


async def _collection_form_response(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    *,
    collection: Collection | None,
    values: dict[str, str],
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    return _page_response(
        request,
        "collection_form",
        _context(
            request,
            current,
            page_title="Edit collection" if collection is not None else "Create collection",
            active_navigation="collections",
            organization_name=await _organization_name(session, current.require_organization_id()),
            collection=collection,
            values=values,
            form_error=error,
            csrf_token=_csrf_token(current),
        ),
        status_code=status_code,
    )


async def _collection_detail_response(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection: Collection,
    *,
    page: int,
    published_page: int,
    action_error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    organization_id = current.require_organization_id()
    can_update = await _collection_allows(session, current, collection, "collection:update")
    can_manage_members = await _collection_allows(
        session, current, collection, "collection:manage_members"
    )
    memberships = await catalog.list_collection_memberships(
        session, organization_id, collection.id, MEMBERSHIP_LIMIT + 1
    )
    available = await catalog.list_collection_tool_rows(
        session, organization_id, collection.id, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE
    )
    published: list[tuple[CollectionToolPublication, Tool, MCPServer, bool]] = []
    if can_update:
        published = await catalog.list_publication_rows(
            session,
            current,
            collection.id,
            PAGE_SIZE + 1,
            (published_page - 1) * PAGE_SIZE,
        )
    addable_servers: list[MCPServer] = []
    if can_manage_members:
        addable_servers = await catalog.list_addable_servers(
            session, organization_id, collection.id, ADDABLE_SERVER_LIMIT
        )
    return _page_response(
        request,
        "collection_detail",
        _context(
            request,
            current,
            page_title=collection.display_name,
            active_navigation="collections",
            organization_name=await _organization_name(session, organization_id),
            collection=collection,
            endpoint_url=(f"{str(request.base_url).rstrip('/')}/mcp/collections/{collection.slug}"),
            memberships=memberships[:MEMBERSHIP_LIMIT],
            membership_truncated=len(memberships) > MEMBERSHIP_LIMIT,
            addable_servers=addable_servers,
            available_tools=available[:PAGE_SIZE],
            page=page,
            has_next=len(available) > PAGE_SIZE,
            published_tools=published[:PAGE_SIZE],
            published_page=published_page,
            published_has_next=len(published) > PAGE_SIZE,
            can_update=can_update,
            can_manage_members=can_manage_members,
            action_error=action_error,
            csrf_token=_csrf_token(current),
        ),
        status_code=status_code,
    )


async def _collection_action_error(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    message: str,
    status_code: int,
) -> Response:
    try:
        collection = await catalog.read_collection(session, current, collection_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return await _collection_detail_response(
        request,
        session,
        current,
        collection,
        page=1,
        published_page=1,
        action_error=message,
        status_code=status_code,
    )


@router.get("/collections", response_class=HTMLResponse)
async def collection_list(request: Request, session: Session, page: PageQuery = 1) -> Response:
    gate = await _organization_principal(request, session)
    if isinstance(gate, Response):
        return gate
    organization_id = gate.require_organization_id()
    if not await has_action_grant_in_organization(
        session,
        gate.principal,
        "collection:read",
        organization_id,
        gate.verified_group_ids,
        credential_context=gate.credential_context,
    ):
        return _render_forbidden(request, gate)
    collections = await catalog.list_collections(
        session, organization_id, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE
    )
    readable_ids = await authorized_collection_ids(
        session,
        gate.principal,
        "collection:read",
        collections,
        gate.verified_group_ids,
        credential_context=gate.credential_context,
    )
    visible = [collection for collection in collections if collection.id in readable_ids]
    return _page_response(
        request,
        "collection_list",
        _context(
            request,
            gate,
            page_title="Collections",
            active_navigation="collections",
            organization_name=await _organization_name(session, organization_id),
            collections=visible[:PAGE_SIZE],
            page=page,
            has_next=len(collections) > PAGE_SIZE,
            can_create=await _authorized(session, gate, "collection:create"),
        ),
    )


@router.get("/collections/new", response_class=HTMLResponse)
async def collection_creation_form(request: Request, session: Session) -> Response:
    gate = await _page_principal(request, session, "collection:create")
    if isinstance(gate, Response):
        return gate
    return await _collection_form_response(
        request,
        session,
        gate,
        collection=None,
        values={"exposure_mode": "discovery"},
    )


@router.post("/collections")
async def collection_create(request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    values = {
        "slug": _form_text(form, "slug"),
        "display_name": _form_text(form, "display_name"),
        "description": _form_text(form, "description"),
        "exposure_mode": _form_text(form, "exposure_mode") or "discovery",
    }
    try:
        payload = CollectionCreate.model_validate(values)
        collection = await catalog.register_collection(session, current, payload)
    except ValidationError:
        return await _collection_form_response(
            request,
            session,
            current,
            collection=None,
            values=values,
            error=(
                "Enter a lowercase slug, a display name of up to 160 characters, "
                "a description of up to 1000 characters, and a supported exposure mode."
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except catalog.DuplicateResourceError as error:
        return await _collection_form_response(
            request,
            session,
            current,
            collection=None,
            values=values,
            error=str(error),
            status_code=status.HTTP_409_CONFLICT,
        )
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/collections/" + str(collection.id))


@router.get("/collections/{collection_id}", response_class=HTMLResponse)
async def collection_detail(
    collection_id: UUID,
    request: Request,
    session: Session,
    page: PageQuery = 1,
    published_page: PageQuery = 1,
) -> Response:
    gate = await _organization_principal(request, session)
    if isinstance(gate, Response):
        return gate
    try:
        collection = await catalog.read_collection(session, gate, collection_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, gate)
    except catalog.AuthorizationError:
        return _render_forbidden(request, gate)
    return await _collection_detail_response(
        request, session, gate, collection, page=page, published_page=published_page
    )


@router.get("/collections/{collection_id}/edit", response_class=HTMLResponse)
async def collection_edit_form(collection_id: UUID, request: Request, session: Session) -> Response:
    gate = await _organization_principal(request, session)
    if isinstance(gate, Response):
        return gate
    try:
        collection = await catalog.require_collection_update(session, gate, collection_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, gate)
    except catalog.AuthorizationError:
        return _render_forbidden(request, gate)
    return await _collection_form_response(
        request,
        session,
        gate,
        collection=collection,
        values={
            "display_name": collection.display_name,
            "description": collection.description,
            "exposure_mode": collection.exposure_mode,
        },
    )


@router.post("/collections/{collection_id}/edit")
async def collection_update(collection_id: UUID, request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    values = {
        "display_name": _form_text(form, "display_name"),
        "description": _form_text(form, "description"),
        "exposure_mode": _form_text(form, "exposure_mode"),
    }
    try:
        update = CollectionUpdate.model_validate(
            {
                "display_name": values["display_name"] or None,
                "description": values["description"],
                "exposure_mode": values["exposure_mode"] or None,
            }
        )
        await catalog.update_collection(session, current, collection_id, update)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    except ValidationError:
        try:
            collection = await catalog.require_collection_update(session, current, collection_id)
        except catalog.MissingResourceError:
            return _render_not_found(request, current)
        except catalog.AuthorizationError:
            return _render_forbidden(request, current)
        return await _collection_form_response(
            request,
            session,
            current,
            collection=collection,
            values=values,
            error=(
                "Enter a display name of up to 160 characters, a description of up to "
                "1000 characters, and a supported exposure mode."
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    return _see_other("/console/collections/" + str(collection_id))


@router.post("/collections/{collection_id}/enabled")
async def collection_set_enabled(
    collection_id: UUID, request: Request, session: Session
) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    enabled = _form_text(form, "enabled")
    if enabled not in {"true", "false"}:
        return HTMLResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
    try:
        await catalog.update_collection(
            session, current, collection_id, CollectionUpdate(enabled=enabled == "true")
        )
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/collections/" + str(collection_id))


@router.post("/collections/{collection_id}/servers")
async def collection_add_server(
    collection_id: UUID, request: Request, session: Session
) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    try:
        server_id = UUID(_form_text(form, "server_id"))
    except ValueError:
        return await _collection_action_error(
            request,
            session,
            current,
            collection_id,
            "Choose a server to add.",
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    try:
        await catalog.add_collection_member(session, current, collection_id, server_id)
    except catalog.MissingResourceError:
        return await _collection_action_error(
            request,
            session,
            current,
            collection_id,
            "Choose a server from this organization.",
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except catalog.DuplicateResourceError as error:
        return await _collection_action_error(
            request, session, current, collection_id, str(error), status.HTTP_409_CONFLICT
        )
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/collections/" + str(collection_id))


@router.post("/collections/{collection_id}/servers/{server_id}/remove")
async def collection_remove_server(
    collection_id: UUID, server_id: UUID, request: Request, session: Session
) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, _ = result
    try:
        await catalog.remove_collection_member(session, current, collection_id, server_id)
    except catalog.MissingResourceError:
        return await _collection_action_error(
            request,
            session,
            current,
            collection_id,
            "That server is no longer a member of this collection.",
            status.HTTP_404_NOT_FOUND,
        )
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/collections/" + str(collection_id))


TOOL_CHOICE_MESSAGE = "Choose a tool that is available in this collection."
PUBLISHED_NAME_MESSAGE = (
    "Enter a published name of up to 200 letters, digits, hyphens, or underscores, "
    "starting with a letter or digit."
)
PUBLICATION_FORM_MESSAGE = (
    "Enter a published name of up to 200 letters, digits, hyphens, or underscores, "
    "starting with a letter or digit, and a description override of up to 4096 characters."
)


def _suggest_published_name(tool_name: str) -> str:
    """Suggest a published name that satisfies the publication name pattern."""
    return re.sub(r"[^A-Za-z0-9_-]+", "-", tool_name).lstrip("-_")[:200]


def _publication_values(publication: CollectionToolPublication) -> dict[str, str]:
    return {
        "published_name": publication.published_name,
        "description_override": publication.description_override or "",
        "enabled": "true" if publication.enabled else "false",
    }


async def _publications_response(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection: Collection,
    *,
    page: int,
    published_page: int,
    action_error: str | None = None,
    draft: dict[str, str] | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    published = await catalog.list_publication_rows(
        session, current, collection.id, PAGE_SIZE + 1, (published_page - 1) * PAGE_SIZE
    )
    unpublished = await catalog.list_unpublished_collection_tools(
        session, current, collection.id, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE
    )
    published_rows = [
        (
            publication,
            tool,
            server,
            catalog.publication_exposure_issues(
                collection, membership_enabled, tool, server, publication
            ),
        )
        for publication, tool, server, membership_enabled in published[:PAGE_SIZE]
    ]
    unpublished_rows = [
        (
            tool,
            server,
            draft["published_name"]
            if draft is not None and draft["tool_id"] == str(tool.id)
            else _suggest_published_name(tool.name),
        )
        for tool, server in unpublished[:PAGE_SIZE]
    ]
    return _page_response(
        request,
        "collection_publications",
        _context(
            request,
            current,
            page_title="Publications",
            active_navigation="collections",
            organization_name=await _organization_name(session, current.require_organization_id()),
            collection=collection,
            published_rows=published_rows,
            published_page=published_page,
            published_has_next=len(published) > PAGE_SIZE,
            unpublished_rows=unpublished_rows,
            page=page,
            has_next=len(unpublished) > PAGE_SIZE,
            action_error=action_error,
            csrf_token=_csrf_token(current),
        ),
        status_code=status_code,
    )


async def _publications_action_error(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    message: str,
    status_code: int,
    *,
    draft: dict[str, str] | None = None,
) -> Response:
    try:
        collection = await catalog.require_collection_update(session, current, collection_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return await _publications_response(
        request,
        session,
        current,
        collection,
        page=1,
        published_page=1,
        action_error=message,
        draft=draft,
        status_code=status_code,
    )


async def _publication_form_response(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection: Collection,
    tool: Tool,
    publication: CollectionToolPublication,
    *,
    values: dict[str, str],
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    return _page_response(
        request,
        "publication_form",
        _context(
            request,
            current,
            page_title="Edit publication",
            active_navigation="collections",
            organization_name=await _organization_name(session, current.require_organization_id()),
            collection=collection,
            tool=tool,
            publication=publication,
            values=values,
            form_error=error,
            csrf_token=_csrf_token(current),
        ),
        status_code=status_code,
    )


async def _publication_edit_error(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    collection_id: UUID,
    publication_id: UUID,
    *,
    values: dict[str, str],
    message: str,
    status_code: int,
) -> Response:
    try:
        collection = await catalog.require_collection_update(session, current, collection_id)
        publication, tool = await catalog.read_publication(
            session, current, collection_id, publication_id
        )
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return await _publication_form_response(
        request,
        session,
        current,
        collection,
        tool,
        publication,
        values=values,
        error=message,
        status_code=status_code,
    )


@router.get("/tools", response_class=HTMLResponse)
async def tool_catalog(request: Request, session: Session, page: PageQuery = 1) -> Response:
    gate = await _page_principal(request, session, "server:read")
    if isinstance(gate, Response):
        return gate
    organization_id = gate.require_organization_id()
    rows = await catalog.list_organization_tool_rows(
        session, organization_id, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE
    )
    visible = rows[:PAGE_SIZE]
    can_view_publications = await _authorized(session, gate, "collection:update")
    publication_counts: dict[UUID, int] = {}
    if can_view_publications:
        publication_counts = await catalog.count_tool_publications(
            session, organization_id, [tool.id for tool, _ in visible]
        )
    return _page_response(
        request,
        "tool_catalog",
        _context(
            request,
            gate,
            page_title="Tool Catalog",
            active_navigation="tools",
            organization_name=await _organization_name(session, organization_id),
            tools=visible,
            publication_counts=publication_counts,
            can_view_publications=can_view_publications,
            page=page,
            has_next=len(rows) > PAGE_SIZE,
        ),
    )


@router.get("/collections/{collection_id}/publications", response_class=HTMLResponse)
async def collection_publications(
    collection_id: UUID,
    request: Request,
    session: Session,
    page: PageQuery = 1,
    published_page: PageQuery = 1,
) -> Response:
    gate = await _organization_principal(request, session)
    if isinstance(gate, Response):
        return gate
    try:
        collection = await catalog.require_collection_update(session, gate, collection_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, gate)
    except catalog.AuthorizationError:
        return _render_forbidden(request, gate)
    return await _publications_response(
        request, session, gate, collection, page=page, published_page=published_page
    )


@router.post("/collections/{collection_id}/publications")
async def publication_create(collection_id: UUID, request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    tool_text = _form_text(form, "tool_id")
    published_name = _form_text(form, "published_name")
    draft = {"tool_id": tool_text, "published_name": published_name}
    try:
        await catalog.require_collection_update(session, current, collection_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    try:
        tool_id = UUID(tool_text)
    except ValueError:
        return await _publications_action_error(
            request,
            session,
            current,
            collection_id,
            TOOL_CHOICE_MESSAGE,
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            draft=draft,
        )
    try:
        payload = PublicationCreate(tool_id=tool_id, published_name=published_name)
    except ValidationError:
        return await _publications_action_error(
            request,
            session,
            current,
            collection_id,
            PUBLISHED_NAME_MESSAGE,
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            draft=draft,
        )
    try:
        await catalog.publish_tool(session, current, collection_id, payload)
    except catalog.MissingResourceError:
        return await _publications_action_error(
            request,
            session,
            current,
            collection_id,
            TOOL_CHOICE_MESSAGE,
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            draft=draft,
        )
    except catalog.DuplicateResourceError as error:
        return await _publications_action_error(
            request,
            session,
            current,
            collection_id,
            str(error),
            status.HTTP_409_CONFLICT,
            draft=draft,
        )
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/collections/" + str(collection_id) + "/publications")


@router.get(
    "/collections/{collection_id}/publications/{publication_id}/edit",
    response_class=HTMLResponse,
)
async def publication_edit_form(
    collection_id: UUID, publication_id: UUID, request: Request, session: Session
) -> Response:
    gate = await _organization_principal(request, session)
    if isinstance(gate, Response):
        return gate
    try:
        collection = await catalog.require_collection_update(session, gate, collection_id)
        publication, tool = await catalog.read_publication(
            session, gate, collection_id, publication_id
        )
    except catalog.MissingResourceError:
        return _render_not_found(request, gate)
    except catalog.AuthorizationError:
        return _render_forbidden(request, gate)
    return await _publication_form_response(
        request,
        session,
        gate,
        collection,
        tool,
        publication,
        values=_publication_values(publication),
    )


@router.post("/collections/{collection_id}/publications/{publication_id}/edit")
async def publication_update(
    collection_id: UUID, publication_id: UUID, request: Request, session: Session
) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    values = {
        "published_name": _form_text(form, "published_name"),
        "description_override": _form_text(form, "description_override"),
        "enabled": _form_text(form, "enabled"),
    }
    try:
        update = PublicationUpdate.model_validate(
            {
                "published_name": values["published_name"],
                "description_override": values["description_override"] or None,
                "enabled": values["enabled"],
            }
        )
        await catalog.update_publication(session, current, collection_id, publication_id, update)
    except ValidationError:
        return await _publication_edit_error(
            request,
            session,
            current,
            collection_id,
            publication_id,
            values=values,
            message=PUBLICATION_FORM_MESSAGE,
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except catalog.DuplicateResourceError as error:
        return await _publication_edit_error(
            request,
            session,
            current,
            collection_id,
            publication_id,
            values=values,
            message=str(error),
            status_code=status.HTTP_409_CONFLICT,
        )
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/collections/" + str(collection_id) + "/publications")


@router.post("/collections/{collection_id}/publications/{publication_id}/remove")
async def publication_remove(
    collection_id: UUID, publication_id: UUID, request: Request, session: Session
) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, _ = result
    try:
        await catalog.remove_publication(session, current, collection_id, publication_id)
    except catalog.MissingResourceError:
        return await _publications_action_error(
            request,
            session,
            current,
            collection_id,
            "That tool is no longer published in this collection.",
            status.HTTP_404_NOT_FOUND,
        )
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/collections/" + str(collection_id) + "/publications")


async def _profile_response(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    *,
    notice: str | None = None,
    action_error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    try:
        apps = await connected_apps.list_connected_apps(session, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _page_response(
        request,
        "profile",
        _context(
            request,
            current,
            page_title="My Profile",
            active_navigation="profile",
            organization_name=await _organization_name(session, current.require_organization_id()),
            apps=apps,
            notice=notice,
            action_error=action_error,
            csrf_token=_csrf_token(current),
        ),
        status_code=status_code,
    )


@router.get("/profile", response_class=HTMLResponse)
async def my_profile(request: Request, session: Session) -> Response:
    current = await _organization_principal(request, session)
    if isinstance(current, Response):
        return current
    return await _profile_response(request, session, current)


@router.get("/connected-apps/callback", response_class=HTMLResponse)
async def connected_app_callback(
    request: Request,
    session: Session,
    state: Annotated[str | None, Query(max_length=256)] = None,
    code: Annotated[str | None, Query(max_length=4096)] = None,
    error: Annotated[str | None, Query(max_length=256)] = None,
) -> Response:
    current = await _organization_principal(request, session)
    if isinstance(current, Response):
        return current
    try:
        server_name = await connected_apps.complete_connection(
            session, Settings(), current, state=state, code=code, error=error
        )
    except connected_apps.ConnectedAppError as failure:
        return await _profile_response(
            request,
            session,
            current,
            action_error=str(failure),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return await _profile_response(request, session, current, notice=f"Connected {server_name}.")


@router.post("/connected-apps/{server_id}/connect")
async def connected_app_connect(server_id: UUID, request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, _ = result
    try:
        authorization_url = await connected_apps.start_connection(
            session, Settings(), current, server_id
        )
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    except connected_apps.ConnectedAppError as failure:
        return await _profile_response(
            request,
            session,
            current,
            action_error=str(failure),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    # The URL is built from validated provider endpoints and a single-use transaction.
    return RedirectResponse(authorization_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/connected-apps/{server_id}/disconnect")
async def connected_app_disconnect(server_id: UUID, request: Request, session: Session) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, _ = result
    try:
        await connected_apps.disconnect(session, Settings(), current, server_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _see_other("/console/profile")


async def _authentication_response(
    request: Request,
    session: AsyncSession,
    current: AuthenticatedPrincipal,
    server_id: UUID,
    *,
    action_error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    try:
        view = await connected_apps.get_server_authentication(session, current, server_id)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    return _page_response(
        request,
        "server_authentication",
        _context(
            request,
            current,
            page_title=f"Authentication: {view.server_name}",
            active_navigation="servers",
            organization_name=await _organization_name(session, current.require_organization_id()),
            view=view,
            auth_policies=sorted(AUTH_POLICIES),
            providers=sorted(PROVIDERS),
            action_error=action_error,
            csrf_token=_csrf_token(current),
        ),
        status_code=status_code,
    )


async def _authentication_mutation(
    request: Request,
    session: AsyncSession,
    server_id: UUID,
    mutation: Callable[[AuthenticatedPrincipal, FormData], Awaitable[None]],
) -> Response:
    result = await _write_request(request, session)
    if isinstance(result, Response):
        return result
    current, form = result
    try:
        await mutation(current, form)
    except catalog.MissingResourceError:
        return _render_not_found(request, current)
    except catalog.AuthorizationError:
        return _render_forbidden(request, current)
    except connected_apps.ConnectedAppError as failure:
        return await _authentication_response(
            request,
            session,
            current,
            server_id,
            action_error=str(failure),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    return _see_other(f"/console/servers/{server_id}/authentication")


@router.get("/servers/{server_id}/authentication", response_class=HTMLResponse)
async def server_authentication_page(
    server_id: UUID, request: Request, session: Session
) -> Response:
    gate = await _page_principal(request, session, "server:update")
    if isinstance(gate, Response):
        return gate
    return await _authentication_response(request, session, gate, server_id)


@router.post("/servers/{server_id}/authentication/policy")
async def server_authentication_policy(
    server_id: UUID, request: Request, session: Session
) -> Response:
    async def save(current: AuthenticatedPrincipal, form: FormData) -> None:
        await connected_apps.set_auth_policy(
            session, current, server_id, _form_text(form, "auth_policy")
        )

    return await _authentication_mutation(request, session, server_id, save)


@router.post("/servers/{server_id}/authentication/integration")
async def server_authentication_integration(
    server_id: UUID, request: Request, session: Session
) -> Response:
    async def save(current: AuthenticatedPrincipal, form: FormData) -> None:
        data = connected_apps.IntegrationInput(
            provider=_form_text(form, "provider"),
            client_id=_form_text(form, "client_id"),
            client_secret=_form_text(form, "client_secret") or None,
            scopes=_form_text(form, "scopes"),
            authorization_endpoint=_form_text(form, "authorization_endpoint"),
            token_endpoint=_form_text(form, "token_endpoint"),
            revocation_endpoint=_form_text(form, "revocation_endpoint"),
            account_endpoint=_form_text(form, "account_endpoint"),
            enabled=form.get("enabled") == "on",
        )
        await connected_apps.save_integration(session, Settings(), current, server_id, data)

    return await _authentication_mutation(request, session, server_id, save)


@router.post("/servers/{server_id}/authentication/integration/enabled")
async def server_authentication_integration_enabled(
    server_id: UUID, request: Request, session: Session
) -> Response:
    async def toggle(current: AuthenticatedPrincipal, form: FormData) -> None:
        enabled = _form_text(form, "enabled")
        if enabled not in {"true", "false"}:
            raise connected_apps.ConnectedAppError(
                "invalid_request", "Choose whether the integration is enabled."
            )
        await connected_apps.set_integration_enabled(
            session, Settings(), current, server_id, enabled == "true"
        )

    return await _authentication_mutation(request, session, server_id, toggle)


@router.post("/servers/{server_id}/authentication/shared-credential")
async def server_authentication_shared_credential(
    server_id: UUID, request: Request, session: Session
) -> Response:
    async def store(current: AuthenticatedPrincipal, form: FormData) -> None:
        await connected_apps.set_shared_credential(
            session, Settings(), current, server_id, _form_text(form, "credential_value")
        )

    return await _authentication_mutation(request, session, server_id, store)


@router.post("/servers/{server_id}/authentication/shared-credential/clear")
async def server_authentication_shared_credential_clear(
    server_id: UUID, request: Request, session: Session
) -> Response:
    async def clear(current: AuthenticatedPrincipal, form: FormData) -> None:
        await connected_apps.clear_shared_credential(session, current, server_id)

    return await _authentication_mutation(request, session, server_id, clear)


@router.get("/{page_name}", response_class=HTMLResponse)
async def placeholder(page_name: str, request: Request, session: Session) -> Response:
    page = _PLACEHOLDER_PAGES.get(page_name)
    if page is None:
        return HTMLResponse(status_code=status.HTTP_404_NOT_FOUND)
    current = await _browser_principal(request, session)
    if current is None:
        return RedirectResponse("/console/login", status_code=status.HTTP_303_SEE_OTHER)
    if current.organization_id is None:
        return await _select_organization_page(request, session, current)
    page_title, action = page
    if not await _authorized(session, current, action):
        return _render_forbidden(request, current)
    organization_name = await session.scalar(
        select(Organization.display_name).where(
            Organization.id == current.require_organization_id()
        )
    )
    return _page_response(
        request,
        "placeholder",
        _context(
            request,
            current,
            page_title=page_title,
            active_navigation=page_name,
            organization_name=organization_name or "Organization",
        ),
    )
