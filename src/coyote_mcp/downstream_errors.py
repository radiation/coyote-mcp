"""Fail-closed error type shared by the credential broker, discovery, and gateway.

This module has no coyote_mcp imports so that low-level modules can depend on it without
creating import cycles.
"""

import json


class DownstreamAuthorizationError(RuntimeError):
    """Fail-closed credential resolution error.

    ``str(error)`` is a compact JSON document suitable for an MCP tool error. It never
    contains token material, client secrets, or upstream response bodies.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(json.dumps({"error": code, "message": message}, separators=(",", ":")))
