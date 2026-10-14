from fastapi import FastAPI
from fastmcp import FastMCP
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str


mcp = FastMCP("coyote-mcp")


@mcp.tool
async def gateway_info() -> str:
    """Describe this gateway prototype (not yet a secured tool router)."""
    return "coyote-mcp prototype: registration, authorization and routing are not yet enabled"


mcp_app = mcp.http_app(path="/")
app = FastAPI(title="coyote-mcp", lifespan=mcp_app.lifespan)
app.mount("/mcp", mcp_app)


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")
