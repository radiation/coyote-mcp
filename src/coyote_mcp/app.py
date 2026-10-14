from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastmcp import FastMCP
from pydantic import BaseModel

from coyote_mcp.api import router as api_router
from coyote_mcp.oidc import router as oidc_router
from coyote_mcp.settings import Settings


class HealthResponse(BaseModel):
    status: str


mcp = FastMCP("coyote-mcp")


@mcp.tool
async def gateway_info() -> str:
    """Describe this gateway prototype (not yet a secured tool router)."""
    return "coyote-mcp prototype: registration, authorization and routing are not yet enabled"


mcp_app = mcp.http_app(path="/")
app = FastAPI(title="coyote-mcp", lifespan=mcp_app.lifespan)
settings = Settings()


@app.middleware("http")
async def block_unsecured_mcp(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    if request.url.path.startswith("/mcp"):
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "MCP protocol operations are disabled until policy enforcement is available."
                )
            },
        )
    return await call_next(request)


app.mount("/mcp", mcp_app)
app.include_router(api_router)
app.include_router(oidc_router)


@app.get("/", include_in_schema=False)
async def landing() -> dict[str, str]:
    return {"status": "coyote-mcp"}


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")
