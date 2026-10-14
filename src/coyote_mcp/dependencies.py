from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import (
    AuthenticatedPrincipal,
    authenticate_browser_session,
    authenticate_token,
    csrf_token_valid,
)
from coyote_mcp.db import get_session
from coyote_mcp.settings import Settings

bearer = HTTPBearer(auto_error=False)
Session = Annotated[AsyncSession, Depends(get_session)]


async def current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: Session,
) -> AuthenticatedPrincipal:
    if request.headers.get("authorization") is not None:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials."
            )
        authenticated = await authenticate_token(session, credentials.credentials)
        if authenticated is not None:
            return authenticated
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    browser_session = await authenticate_browser_session(
        session, request.cookies.get(Settings().browser_session_cookie_name, "")
    )
    if browser_session is not None:
        persisted_session = browser_session.browser_session
        if persisted_session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
            )
        if (
            request.url.path.startswith("/api/")
            and request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and not csrf_token_valid(persisted_session, request.headers.get("x-csrf-token"))
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed."
            )
        return browser_session
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")


async def reject_mcp_requests(request: Request) -> None:
    del request
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="MCP protocol operations are disabled until policy enforcement is available.",
    )
