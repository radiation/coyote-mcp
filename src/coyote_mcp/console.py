from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import (
    AuthenticatedPrincipal,
    OrganizationBootstrapError,
    authenticate_browser_session,
    authorize,
    available_organizations,
    create_initial_organization,
    csrf_token_valid,
    is_instance_administrator,
    rotate_csrf_token,
    select_active_organization,
)
from coyote_mcp.db import get_session
from coyote_mcp.models import Collection, CollectionToolPublication, MCPServer, Organization, Tool
from coyote_mcp.schemas import OrganizationCreate
from coyote_mcp.settings import Settings

router = APIRouter(prefix="/console", include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
Session = Annotated[AsyncSession, Depends(get_session)]


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


def _page_response(request: Request, page_name: str, context: dict[str, object]) -> HTMLResponse:
    template_name = (
        f"console/fragments/{page_name}_content.html"
        if request.headers.get("HX-Request") == "true"
        else f"console/{page_name}.html"
    )
    return templates.TemplateResponse(request, template_name, context)


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
    csrf_token = await rotate_csrf_token(session, current.browser_session)
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
    if not isinstance(csrf_token, str) or not csrf_token_valid(current.browser_session, csrf_token):
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
    if not isinstance(csrf_token, str) or not csrf_token_valid(current.browser_session, csrf_token):
        return _render_forbidden(request, current)
    slug = form.get("slug")
    display_name = form.get("display_name")
    if not isinstance(slug, str) or not isinstance(display_name, str):
        return await _select_organization_page(
            request,
            session,
            current,
            creation_error="Enter a valid organization slug and display name.",
            response_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
            response_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
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


_PLACEHOLDER_PAGES = {
    "servers": ("MCP Servers", "server:read"),
    "collections": ("Collections", "collection:read"),
    "tools": ("Tool Catalog", "tool:describe"),
    "publications": ("Publications", "tool:describe"),
    "principals": ("Principals & Roles", "policy:manage"),
    "tokens": ("API Tokens", "credential:create"),
}


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
