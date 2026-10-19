import ipaddress
import re
import secrets
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import Any

from starlette.datastructures import Headers, MutableHeaders

RequestID = ContextVar[str | None]("request_id", default=None)

_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ASGIReceive = Callable[[], Awaitable[dict[str, Any]]]
_ASGISend = Callable[[dict[str, Any]], Awaitable[None]]
_ASGIApp = Callable[[dict[str, Any], _ASGIReceive, _ASGISend], Awaitable[None]]


def is_trusted_proxy(client_host: str | None, networks: tuple[str, ...]) -> bool:
    if client_host is None:
        return False
    try:
        address = ipaddress.ip_address(client_host)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network) for network in networks)


def request_id() -> str | None:
    return RequestID.get()


class TrustedProxyHeadersMiddleware:
    """Accept only forwarded scheme information supplied by a configured proxy."""

    def __init__(self, app: _ASGIApp, trusted_proxy_networks: tuple[str, ...]) -> None:
        self.app = app
        self.trusted_proxy_networks = trusted_proxy_networks

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: _ASGIReceive,
        send: _ASGISend,
    ) -> None:
        if scope["type"] == "http" and is_trusted_proxy(
            scope.get("client", (None,))[0], self.trusted_proxy_networks
        ):
            forwarded_proto = Headers(scope=scope).get("x-forwarded-proto")
            if forwarded_proto in {"http", "https"}:
                scope["scheme"] = forwarded_proto
        await self.app(scope, receive, send)


class RequestIDMiddleware:
    def __init__(self, app: _ASGIApp, trusted_proxy_networks: tuple[str, ...]) -> None:
        self.app = app
        self.trusted_proxy_networks = trusted_proxy_networks

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: _ASGIReceive,
        send: _ASGISend,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_host = scope.get("client", (None,))[0]
        supplied = Headers(scope=scope).get("x-request-id")
        value = (
            supplied
            if is_trusted_proxy(client_host, self.trusted_proxy_networks)
            and supplied is not None
            and _REQUEST_ID_PATTERN.fullmatch(supplied)
            else secrets.token_urlsafe(18)
        )
        scope.setdefault("state", {})["request_id"] = value
        token = RequestID.set(value)

        async def send_with_request_id(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = value
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            RequestID.reset(token)
