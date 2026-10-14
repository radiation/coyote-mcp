from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.auth import AuthenticatedPrincipal, authenticate_token
from coyote_mcp.db import get_session

bearer = HTTPBearer(auto_error=False)
Session = Annotated[AsyncSession, Depends(get_session)]


async def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: Session,
) -> AuthenticatedPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    authenticated = await authenticate_token(session, credentials.credentials)
    if authenticated is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    return authenticated


async def reject_mcp_requests(request: Request) -> None:
    del request
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="MCP protocol operations are disabled until policy enforcement is available.",
    )
