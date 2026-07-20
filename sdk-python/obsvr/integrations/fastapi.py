"""FastAPI / ASGI integration — a per-request SIGNED obsvr execution span.

Unlike an OTel tracing middleware, this emits obsvr's own signed, chainable
execution-span event (via obsvr.span), so an HTTP request is part of the same
tamper-evident record as the LLM calls it makes. Pure ASGI: works with FastAPI,
Starlette, or any ASGI app, and imports neither at module load (the optional
`fastapi` extra just pins a compatible Starlette for users who want it).

Usage:
    from fastapi import FastAPI
    from obsvr.integrations.fastapi import ObsvrASGIMiddleware
    app = FastAPI()
    app.add_middleware(ObsvrASGIMiddleware)

    # or wrap any ASGI app directly:
    app = ObsvrASGIMiddleware(app)
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict

from ..span import span

Scope = Dict[str, Any]
Receive = Callable[[], Awaitable[Dict[str, Any]]]
Send = Callable[[Dict[str, Any]], Awaitable[None]]


class ObsvrASGIMiddleware:
    """ASGI middleware emitting one signed execution span per HTTP request,
    attributed with method, path, and response status. Non-HTTP scopes
    (websocket, lifespan) pass through untouched."""

    def __init__(self, app: Callable, span_name: str = "http.request") -> None:
        self.app = app
        self.span_name = span_name

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Mutated in place; obsvr.span copies the attributes dict at span exit,
        # so a status set during the request is captured on the emitted event.
        attrs: Dict[str, Any] = {
            "http.method": scope.get("method"),
            "http.target": scope.get("path"),
        }

        async def send_wrapper(message: Dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                attrs["http.status_code"] = message.get("status")
            await send(message)

        with span(self.span_name, "chain", attrs):
            await self.app(scope, receive, send_wrapper)


def instrument_fastapi(app: Any, span_name: str = "http.request") -> Any:
    """Convenience: add ObsvrASGIMiddleware to a FastAPI/Starlette app and return
    it. Equivalent to app.add_middleware(ObsvrASGIMiddleware, span_name=...)."""
    app.add_middleware(ObsvrASGIMiddleware, span_name=span_name)
    return app
