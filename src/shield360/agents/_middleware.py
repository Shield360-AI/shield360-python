"""
ASGI and WSGI middleware for the agent passport verifier.

Each sets the check result on the request (ASGI: ``scope["state"]["shield360_agent"]``,
so ``request.state.shield360_agent`` in Starlette/FastAPI, and ``scope["shield360_agent"]``;
WSGI: ``environ["shield360.agent"]``) and answers 403
``{"error": "agent_not_allowed", "reason": ...}`` only when the result is blocked.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Iterable


def _forbidden_body(reason: Any) -> bytes:
    return json.dumps({"error": "agent_not_allowed", "reason": reason}).encode()


class AgentVerifierASGIMiddleware:
    """``app = AgentVerifierASGIMiddleware(app, verifier)``.

    FastAPI/Starlette: ``app.add_middleware(AgentVerifierASGIMiddleware, verifier=verifier)``.
    """

    def __init__(self, app, verifier: Any):
        self.app = app
        self.verifier = verifier

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        # check() may fetch keys or the policy; keep it off the event loop.
        result = await asyncio.to_thread(
            lambda: self.verifier.check(
                list(scope.get("headers") or []),
                False,
                # The path as sent (signatures cover it encoded), else the decoded one.
                (scope.get("raw_path") or b"").decode("latin-1") or scope.get("path"),
                scope.get("method"),
                query=scope.get("query_string") or None,
                scheme=scope.get("scheme"),
            )
        )
        state = scope.get("state")
        if isinstance(state, dict):
            state["shield360_agent"] = result
        else:
            scope["state"] = {"shield360_agent": result}
        scope["shield360_agent"] = result
        if not result.blocked:
            await self.app(scope, receive, send)
            return
        body = _forbidden_body(result.reason)
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"application/json; charset=utf-8"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


class AgentVerifierWSGIMiddleware:
    """``app.wsgi_app = AgentVerifierWSGIMiddleware(app.wsgi_app, verifier)`` (Flask) or any WSGI app."""

    def __init__(self, app, verifier: Any):
        self.app = app
        self.verifier = verifier

    def __call__(self, environ, start_response: Callable) -> Iterable[bytes]:
        result = self.verifier.check(environ, route=environ.get("PATH_INFO"), method=environ.get("REQUEST_METHOD"))
        environ["shield360.agent"] = result
        if not result.blocked:
            return self.app(environ, start_response)
        body = _forbidden_body(result.reason)
        start_response("403 Forbidden", [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]
