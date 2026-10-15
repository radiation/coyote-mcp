from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

mock_mcp = FastMCP("coyote-smoke-mock")


@mock_mcp.tool
def echo(message: str) -> dict[str, str]:
    """Return the supplied message."""
    return {"message": message}


@mock_mcp.tool
def add(left: int, right: int) -> dict[str, int]:
    """Add two integers."""
    return {"sum": left + right}


@mock_mcp.tool
def fail() -> None:
    """Return a deterministic downstream tool error."""
    raise ToolError("Smoke mock failure.")


if __name__ == "__main__":
    mock_mcp.run(transport="streamable-http", host="0.0.0.0", port=8001, path="/mcp")
