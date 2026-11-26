"""Framework middleware: WSGI and ASGI, with thin adapters for Flask and
Django (FastAPI and Starlette take the ASGI middleware as it is). Each
answers decoy paths first (README "Deception"), records the request's inputs
(query, params, body, cookies, the contract's input headers) in the request's
context, runs the virtual patches before the handler, and maps the block
error to the contract's 403.

None of these needs a framework installed. While RASP is not active each
passes the request straight through.
"""

from __future__ import annotations

import contextvars
import inspect
import io
import json
import re
import sys
from typing import Any, Awaitable, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple, Union
from urllib.parse import quote

from shield360.rasp._capture import capture_body, capture_request, lower_headers, run_virtual_patches
from shield360.rasp._context import RaspContext, current_context, event_route_of, reset_context, set_context
from shield360.rasp._deception import RULE_HIT, RULE_SUSPICIOUS, decode_target, match_decoy, suspicious_table
from shield360.rasp._engine import deception_config, deception_mode, is_active, report_deception
from shield360.rasp._hooks import response as _response
from shield360.rasp._normalize import flatten
from shield360.rasp._types import RaspBlockedError, block_answer
# SHIELD: AI attack agents — the before-handler check, the scoring, the tripwire and the deter answer (README "AI attack agents").
from shield360.rasp._agents import agents_after, agents_before, agents_decoy, check_tripwire, decoy_verdict
from shield360.rasp._edge_context import VERDICT_HEADER

MAX_READ = 1024 * 1024
BODY_METHODS = frozenset(("POST", "PUT", "PATCH", "DELETE"))
_BLOCK_HEADERS = (("Content-Type", "application/json"), ("Cache-Control", "no-store"))
_NOT_FOUND = b"Not Found"


def is_rasp_blocked(e: Any) -> bool:
    return isinstance(e, RaspBlockedError)


def blocked_body_bytes(e: RaspBlockedError) -> bytes:
    return block_answer(e)[3]


class _TripwirePage(str):
    """SHIELD: AI attack agents — a decoy hit answered with the LLM tripwire page (the page's HTML)."""


def _status_code(status: Any) -> int:
    try:
        return int(str(status).split(" ", 1)[0])
    except (TypeError, ValueError):
        return 0


def _outer_captured() -> bool:
    """SHIELD: an outer Shield360 middleware (the zero-code start's, say) already captured this request."""
    ctx = current_context()
    return ctx is not None and ctx.in_request


def _content_length(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _no_body(headers: Mapping[str, Any], http_version: Any = None) -> bool:
    """The request has no body, or an empty one: a known, empty body, so the
    body rules run. A zero length, or on HTTP/1.x no length and no chunked
    transfer (as body parsers judge it). HTTP/2 and later frame a body without
    either header, so there only an explicit zero length counts."""
    length = headers.get("content-length")
    if length is not None:
        return _content_length(length) == 0
    version = str(http_version or "1.1").upper()
    if version.startswith("HTTP/"):
        version = version[5:]
    if not version.startswith(("1.", "0.")) and version not in ("1", "0"):
        return False
    return not headers.get("transfer-encoding")


# ---- deception ---------------------------------------------------------------

# What deception made of a request: let it through (None), answer the decoy
# with the app's not-found (_HIT), or answer the block error.
_HIT = "hit"
Deceived = Union[None, str, RaspBlockedError]


Target = Tuple[str, Optional[bytes]]


def _deceive(
    framework: str,
    method: str,
    target: Callable[[], Target],
    ip: Optional[str],
    headers: Optional[Mapping[str, Any]] = None,
    verdict: Optional[List[str]] = None,
) -> Deceived:
    """README "Deception": runs before anything else the middleware does.
    ``target`` gives the request path as received (for the event route) and
    its bytes decoded once (None: an invalid escape, which hits nothing).
    ``verdict``, when given, receives the signed X-Shield360-Verdict a decoy
    hit's 404 carries (SHIELD: decoy and trap verdicts).
    Fail open: any error lets the request through."""
    try:
        # SHIELD: AI attack agents — the tripwire URL is answered first (README "AI attack agents").
        trip = check_tripwire(framework, method, target()[0], ip, headers)
        if trip is True:
            return _HIT
        if isinstance(trip, RaspBlockedError):
            return trip
        d = deception_config()
        if d is None:
            return None
        path, decoded = target()
        decoy = match_decoy(decoded, d.paths)
        if decoy is not None:
            mode = deception_mode(d.action)
            if mode is None:
                return None
            suspicious_table().mark(ip, d.ttl_seconds)
            report_deception(RULE_HIT, mode, framework, method, decoy, path)
            # SHIELD: decoy and trap verdicts — behind Edge, the 404 tells every Edge to block the client, in monitor too.
            if verdict is not None:
                v = decoy_verdict(method, path, ip, headers, d.ttl_seconds)
                if v:
                    verdict.append(v)
            # SHIELD: AI attack agents — a decoy hit adds to the behavior score; the 404 may carry the tripwire page.
            page = agents_decoy(framework, method, path, ip, headers)
            return _TripwirePage(page) if page else _HIT
        if not suspicious_table().is_suspicious(ip):
            return None
        mode = deception_mode(d.action)
        if mode is None:
            return None
        e = report_deception(RULE_SUSPICIOUS, mode, framework, method, event_route_of(path), path)
        return e if mode == "block" else None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _raw_uri_target(environ: Mapping[str, Any]) -> Optional[Target]:
    """``RAW_URI`` / ``REQUEST_URI`` (the target as the client sent it, mount
    prefix included) decoded once, when the server gives one."""
    raw = environ.get("RAW_URI") or environ.get("REQUEST_URI")
    if isinstance(raw, str) and raw.startswith("/"):
        path = raw.split("?", 1)[0]
        return path, decode_target(path.encode("latin-1"))
    return None


def _environ_target(environ: Mapping[str, Any]) -> Target:
    """The path the client sent: the raw URI, else ``SCRIPT_NAME`` +
    ``PATH_INFO`` as the server already decoded them (latin-1 text of the
    bytes, PEP 3333), never decoded again."""
    raw = _raw_uri_target(environ)
    if raw is not None:
        return raw
    path = f"{environ.get('SCRIPT_NAME', '')}{environ.get('PATH_INFO', '')}" or "/"
    return path, path.encode("latin-1")


def _django_target(request: Any) -> Target:
    """The raw URI, else Django's decoded ``request.path`` (script prefix
    included; text under both WSGI and ASGI), never decoded again."""
    raw = _raw_uri_target(request.META)
    if raw is not None:
        return raw
    path = str(request.path or "/")
    return path, path.encode("utf-8", "surrogateescape")


def _asgi_target(scope: Mapping[str, Any]) -> Target:
    """The path the client sent: ``raw_path`` decoded once, else ``path`` as
    the server decoded it. A ``root_path`` the server left out of them is put
    back in front (servers differ on whether ``path`` carries it)."""
    root = scope.get("root_path")
    root = root.rstrip("/") if isinstance(root, str) else ""
    raw_path = scope.get("raw_path")
    if isinstance(raw_path, (bytes, bytearray)) and raw_path.startswith(b"/"):
        raw = bytes(raw_path).split(b"?", 1)[0]
        prefix = quote(root, safe="/!$&'()*+,;=:@~").encode("ascii")
        if prefix and raw != prefix and not raw.startswith(prefix + b"/"):
            raw = prefix + raw
        return raw.decode("latin-1"), decode_target(raw)
    path = str(scope.get("path") or "/")
    if root and path != root and not path.startswith(root + "/"):
        path = root + path
    return path, path.encode("utf-8", "surrogateescape")


def _carry_headers(e: RaspBlockedError, ctx: Optional[RaspContext]) -> None:
    """SHIELD: protection triangle — the verdict RASP set for a request blocked before it reached the app, on its error."""
    try:
        if ctx is not None and ctx.response_headers:
            e.response_headers = list(ctx.response_headers)  # type: ignore[attr-defined]
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def _error_headers(e: RaspBlockedError) -> List[Tuple[str, str]]:
    """The response headers a block error carries (see ``_carry_headers``)."""
    h = getattr(e, "response_headers", None)
    return list(h) if isinstance(h, list) else []


def _begin(
    make: Callable[[], RaspContext],
    body: Callable[[], Optional[Tuple[Any, Optional[str]]]],
    headers: Optional[Mapping[str, Any]] = None,
):
    """Starts a request context. Returns ``(ctx, None)``, ``(None, error)`` when
    a virtual patch blocks, or ``(None, None)`` when capture failed (fail open).
    A blocked request's error carries the response headers RASP set for it
    (the verdict for Edge), for the 403."""
    ctx: Optional[RaspContext] = None
    try:
        ctx = make()
        run_virtual_patches(ctx)
        b = body()
        if b is not None and b[0] is not None:
            capture_body(ctx, b[0], b[1])
            run_virtual_patches(ctx)
        # SHIELD: AI attack agents — once the inputs are known: a marked client is deterred here.
        if headers is not None:
            agents_before(ctx, headers)
        return ctx, None
    except RaspBlockedError as e:
        _carry_headers(e, ctx)
        return None, e
    except Exception:  # pylint: disable=broad-exception-caught
        return None, None


# ---- WSGI --------------------------------------------------------------------


def _environ_headers(environ: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in environ.items():
        if isinstance(k, str) and k.startswith("HTTP_") and isinstance(v, str):
            out[k[5:].replace("_", "-").lower()] = v
    for k, name in (("CONTENT_TYPE", "content-type"), ("CONTENT_LENGTH", "content-length")):
        if environ.get(k):
            out[name] = str(environ[k])
    return out


def _environ_url(environ: Mapping[str, Any]) -> str:
    raw = environ.get("RAW_URI") or environ.get("REQUEST_URI")
    if isinstance(raw, str) and raw.startswith("/"):
        query = environ.get("QUERY_STRING") or ""
        # SHIELD: some servers (Werkzeug's test client) put the path alone in RAW_URI.
        return f"{raw}?{query}" if query and "?" not in raw else raw
    path = f"{environ.get('SCRIPT_NAME', '')}{environ.get('PATH_INFO', '')}" or "/"
    try:
        # PEP 3333: the path arrives as latin-1 text of the original bytes.
        path = path.encode("latin-1").decode("utf-8", "replace")
    except UnicodeError:
        pass
    query = environ.get("QUERY_STRING") or ""
    return f"{path}?{query}" if query else path


def _ip_of(v: Any) -> Optional[str]:
    """The client address as the server reports it (WSGI ``REMOTE_ADDR``, ASGI
    ``scope["client"]``), never read from ``X-Forwarded-For``."""
    return v if isinstance(v, str) and v else None


def _asgi_client(scope: Mapping[str, Any]) -> Optional[str]:
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client:
        return _ip_of(client[0])
    return None


def _capture_environ(environ: Mapping[str, Any], framework: str, read_body: Callable[[], Optional[bytes]]):
    headers = _environ_headers(environ)
    method = str(environ.get("REQUEST_METHOD") or "GET").upper()

    def body() -> Optional[Tuple[Any, Optional[str]]]:
        if _no_body(headers, environ.get("SERVER_PROTOCOL")):
            return b"", headers.get("content-type")
        if method not in BODY_METHODS or not 0 < _content_length(headers.get("content-length")) <= MAX_READ:
            return None
        data = read_body()
        return (data, headers.get("content-type")) if data is not None else None

    return _begin(
        lambda: capture_request(framework, method, _environ_url(environ), headers, ip=_ip_of(environ.get("REMOTE_ADDR"))),
        body,
        headers,
    )


def _wsgi_blocked(start_response: Callable, e: RaspBlockedError, exc_info: Any = None) -> List[bytes]:
    status, reason, base, body = block_answer(e)
    headers = base + [("Content-Length", str(len(body)))] + _error_headers(e)
    if exc_info is not None:
        start_response(f"{status} {reason}", headers, exc_info)
    else:
        start_response(f"{status} {reason}", headers)
    return [body]


def _wsgi_with_verdict(start_response: Callable, verdict: List[str]) -> Callable:
    """SHIELD: decoy and trap verdicts — a start_response that adds a decoy hit's verdict, when there is one."""
    if not verdict:
        return start_response

    def sr(status: str, headers: List[Tuple[str, str]], exc_info: Any = None) -> Any:
        h = [x for x in headers if x[0].lower() != VERDICT_HEADER.lower()] + [(VERDICT_HEADER, verdict[0])]
        return start_response(status, h) if exc_info is None else start_response(status, h, exc_info)

    return sr


def _asgi_with_verdict(send: Callable, verdict: List[str]) -> Callable:
    """SHIELD: decoy and trap verdicts — an ASGI send that adds a decoy hit's verdict to the response start, when there is one."""
    if not verdict:
        return send

    async def wrapped(message: Dict[str, Any]) -> None:
        if message.get("type") == "http.response.start":
            name = VERDICT_HEADER.lower().encode("latin-1")
            headers = [h for h in (message.get("headers") or []) if bytes(h[0]).lower() != name]
            message = {**message, "headers": headers + [(name, verdict[0].encode("latin-1"))]}
        await send(message)

    return wrapped


def _wsgi_page(start_response: Callable, page: str) -> List[bytes]:
    """SHIELD: AI attack agents — the decoy 404 with the LLM tripwire page."""
    body = page.encode("utf-8")
    start_response(
        "404 Not Found",
        [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store"), ("Content-Length", str(len(body)))],
    )
    return [body]


class _ScopedResponse:
    """The app's response iterable, iterated in the request's context; a block
    error raised while the body is produced becomes the 403 when no header has
    gone out yet, else ends the response. An HTML body goes to the response
    hook's reflected-XSS check (monitor only) as it passes."""

    def __init__(
        self, result: Iterable[bytes], cv: contextvars.Context, start_response: Callable, headers: Optional[Dict[str, Any]] = None
    ):
        self._result = result
        self._cv = cv
        self._start_response = start_response
        self._headers = headers if headers is not None else {}
        self._body: Optional[_response.ResponseBody] = None
        self._began = False

    def _seen(self, chunk: Any) -> None:
        if not self._began:
            self._began = True
            self._body = self._cv.run(_response.begin, self._headers.get("content-type"))
        if self._body is not None:
            self._body.add(chunk)

    def __iter__(self) -> Iterator[bytes]:
        try:
            it = self._cv.run(iter, self._result)
        except RaspBlockedError as e:
            yield from self._blocked(e)
            return
        while True:
            try:
                chunk = self._cv.run(next, it)
            except StopIteration:
                self._seen(b"")
                if self._body is not None:
                    self._cv.run(self._body.finish)
                return
            except RaspBlockedError as e:
                yield from self._blocked(e)
                return
            self._seen(chunk)
            yield chunk

    def _blocked(self, e: RaspBlockedError) -> Iterator[bytes]:
        try:
            body = _wsgi_blocked(self._start_response, e, sys.exc_info())
        except Exception:  # pylint: disable=broad-exception-caught
            return  # the headers are already out: end the response
        yield from body

    def close(self) -> None:
        close = getattr(self._result, "close", None)
        if callable(close):
            self._cv.run(close)


def wsgi_not_found(environ: Dict[str, Any], start_response: Callable) -> Iterable[bytes]:  # pylint: disable=unused-argument
    """A plain ``404 Not Found`` (text ``Not Found``): what a decoy gets from
    a WSGI app that has no not-found response of its own to reuse."""
    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(_NOT_FOUND)))])
    return [_NOT_FOUND]


class RaspWSGIMiddleware:
    """Any WSGI app: ``application = RaspWSGIMiddleware(application)``.

    A body of at most 1 MiB with a Content-Length is read before the app
    runs (and handed to the app unchanged), so virtual patches that read the
    body run before the handler too.

    A decoy path (README "Deception") never reaches the app: it gets
    ``not_found``, a WSGI app that answers the app's own 404 (default: a
    plain ``404 Not Found``; ``rasp_flask`` passes Flask's).
    """

    def __init__(self, app: Callable, framework: str = "wsgi", not_found: Optional[Callable] = None):
        self.app = app
        self.framework = framework
        self.not_found = not_found or wsgi_not_found

    def __call__(self, environ: Dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        if not is_active() or _outer_captured():
            return self.app(environ, start_response)
        verdict: List[str] = []
        deceived = _deceive(
            self.framework,
            str(environ.get("REQUEST_METHOD") or "GET").upper(),
            lambda: _environ_target(environ),
            _ip_of(environ.get("REMOTE_ADDR")),
            _environ_headers(environ),
            verdict,
        )
        if isinstance(deceived, _TripwirePage):
            return _wsgi_page(_wsgi_with_verdict(start_response, verdict), deceived)
        if deceived is _HIT:
            return self.not_found(environ, _wsgi_with_verdict(start_response, verdict))
        if isinstance(deceived, RaspBlockedError):
            return _wsgi_blocked(start_response, deceived)

        def read_body() -> Optional[bytes]:
            stream = environ.get("wsgi.input")
            if stream is None:
                return None
            data = stream.read(_content_length(environ.get("CONTENT_LENGTH")))
            environ["wsgi.input"] = io.BytesIO(data)
            return data

        ctx, blocked = _capture_environ(environ, self.framework, read_body)
        if blocked is not None:
            return _wsgi_blocked(start_response, blocked)
        if ctx is None:
            return self.app(environ, start_response)
        cv = contextvars.copy_context()
        cv.run(set_context, ctx)
        seen: Dict[str, Any] = {}

        def start(status: str, headers: Any, *exc_info: Any) -> Any:
            seen["content-type"] = _response.content_type_of(headers)
            # SHIELD: AI attack agents — scored before the headers go out, so a mark's verdict goes with them.
            agents_after(ctx, _status_code(status))
            # SHIELD: protection triangle — the verdict for Edge, when RASP detected something in this request.
            if ctx.response_headers:
                headers = list(headers) + list(ctx.response_headers)
            return start_response(status, headers, *exc_info)

        try:
            result = cv.run(self.app, environ, start)
        except RaspBlockedError as e:
            return _wsgi_blocked(lambda s, h, *x: start_response(s, list(h) + list(ctx.response_headers), *x), e, sys.exc_info())
        return _ScopedResponse(result, cv, start_response, seen)


# ---- ASGI --------------------------------------------------------------------


async def _read_asgi_body(receive: Callable[[], Awaitable[Dict[str, Any]]], messages: List[Dict[str, Any]]) -> Optional[bytes]:
    """Reads the body (keeping every message for the app). None when it is over 1 MiB or the client left."""
    chunks: List[bytes] = []
    total = 0
    while True:
        message = await receive()
        messages.append(message)
        if message.get("type") != "http.request":
            return None
        chunk = message.get("body") or b""
        total += len(chunk)
        if total > MAX_READ:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _asgi_headers(headers: Iterable[Tuple[str, str]]) -> List[Tuple[bytes, bytes]]:
    return [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers]


async def _asgi_blocked(send: Callable, e: RaspBlockedError, ctx: Optional[RaspContext] = None) -> None:
    status, _, base, body = block_answer(e)
    headers = _asgi_headers(base) + [(b"content-length", str(len(body)).encode())]
    # SHIELD: protection triangle — the verdict for Edge, when RASP detected something in this request.
    headers += _asgi_headers(ctx.response_headers if ctx is not None else _error_headers(e))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def _asgi_text(send: Callable, status: int, body: bytes, content_type: str) -> None:
    headers = [(b"content-type", content_type.encode()), (b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _is_a(obj: Any, module: str, name: str) -> bool:
    """Whether ``obj`` is an instance of ``module.name``, by its class's MRO:
    instrumentation (OpenTelemetry's) swaps the module's attribute for a subclass."""
    return any(c.__module__ == module and c.__name__ == name for c in type(obj).__mro__)


def _starlette_app(*apps: Any) -> Any:
    """The Starlette (or FastAPI) application among ``apps``."""
    return next((a for a in apps if a is not None and _is_a(a, "starlette.applications", "Starlette")), None)


def _is_fastapi(app: Any, framework: str) -> bool:
    return _is_a(app, "fastapi.applications", "FastAPI") if app is not None else framework == "fastapi"


async def _starlette_not_found(app: Any, scope: Dict[str, Any], receive: Callable, send: Callable) -> bool:
    """Answers with the app's own handler for a 404 (a status handler, else the
    HTTPException handler, as Starlette looks them up; FastAPI registers its
    ``{"detail": "Not Found"}`` one there). False when there is none."""
    from starlette.exceptions import HTTPException
    from starlette.requests import Request

    handlers = getattr(app, "exception_handlers", None)
    if not isinstance(handlers, dict):
        return False
    handler = handlers.get(404) or next((handlers[c] for c in HTTPException.__mro__ if c in handlers), None)
    if handler is None:
        return False
    scope = dict(scope)
    scope.setdefault("app", app)
    request, exc = Request(scope, receive), HTTPException(status_code=404)
    if inspect.iscoroutinefunction(handler):
        response = await handler(request, exc)
    else:
        from starlette.concurrency import run_in_threadpool

        response = await run_in_threadpool(handler, request, exc)
    await response(scope, receive, send)
    return True


def _asgi_route(scope: Mapping[str, Any]) -> Optional[str]:
    """SHIELD: AI attack agents — the route template Starlette or FastAPI matched (``scope["route"].path``), if any."""
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) and path.startswith("/") else None


class RaspASGIMiddleware:
    """Any ASGI app: ``app = RaspASGIMiddleware(app)``.

    FastAPI / Starlette: ``app.add_middleware(RaspASGIMiddleware, framework="fastapi")``.
    The body (at most 1 MiB) is read before the app runs and replayed to it.

    A decoy path (README "Deception") never reaches the app: a Starlette or
    FastAPI app answers it with its own 404 handler (FastAPI's default is
    ``{"detail": "Not Found"}``, Starlette's the text ``Not Found``); any
    other ASGI app gets a plain ``404`` with the text ``Not Found``, or
    ``not_found`` (an ASGI app) when given.
    """

    def __init__(self, app: Callable, framework: str = "asgi", not_found: Optional[Callable] = None):
        self.app = app
        self.framework = framework
        self.not_found = not_found

    async def _not_found(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if self.not_found is not None:
            await self.not_found(scope, receive, send)
            return
        app = _starlette_app(scope.get("app"), self.app)
        started: List[bool] = []

        async def tracked(message: Dict[str, Any]) -> None:
            started.append(True)
            await send(message)

        if app is not None:
            try:
                if await _starlette_not_found(app, scope, receive, tracked):
                    return
            except Exception:  # pylint: disable=broad-exception-caught
                if started:
                    return  # the handler failed after it began answering
        if _is_fastapi(app, self.framework):
            await _asgi_text(send, 404, b'{"detail":"Not Found"}', "application/json")
        else:
            await _asgi_text(send, 404, _NOT_FOUND, "text/plain; charset=utf-8")

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http" or not is_active() or _outer_captured():
            await self.app(scope, receive, send)
            return
        method = str(scope.get("method") or "GET").upper()
        verdict: List[str] = []
        deceived = _deceive(
            self.framework, method, lambda: _asgi_target(scope), _asgi_client(scope), lower_headers(scope.get("headers") or []), verdict
        )
        if isinstance(deceived, _TripwirePage):
            await _asgi_text(_asgi_with_verdict(send, verdict), 404, deceived.encode("utf-8"), "text/html; charset=utf-8")
            return
        if deceived is _HIT:
            await self._not_found(scope, receive, _asgi_with_verdict(send, verdict))
            return
        if isinstance(deceived, RaspBlockedError):
            await _asgi_blocked(send, deceived)
            return
        messages: List[Dict[str, Any]] = []
        ctx: Optional[RaspContext] = None
        try:
            headers = lower_headers(scope.get("headers") or [])
            method = str(scope.get("method") or "GET").upper()
            raw_path = scope.get("raw_path")
            path = raw_path.decode("latin-1") if isinstance(raw_path, (bytes, bytearray)) else str(scope.get("path") or "/")
            query = scope.get("query_string") or b""
            query = query.decode("latin-1") if isinstance(query, (bytes, bytearray)) else str(query)
            url = f"{path}?{query}" if query else path
            ctx = capture_request(self.framework, method, url, headers, ip=_asgi_client(scope))
            run_virtual_patches(ctx)
            ct = headers.get("content-type")
            if method in BODY_METHODS and _content_length(headers.get("content-length")) <= MAX_READ:
                body = await _read_asgi_body(receive, messages)
                if body is not None:
                    capture_body(ctx, body, ct if isinstance(ct, str) else None)
                    run_virtual_patches(ctx)
            elif _no_body(headers, scope.get("http_version")):
                capture_body(ctx, b"", ct if isinstance(ct, str) else None)
                run_virtual_patches(ctx)
            # SHIELD: AI attack agents — the route Starlette matched (it updates the scope), read when the app answers.
            ctx.route_later = lambda: _asgi_route(scope)
            agents_before(ctx, headers)
        except RaspBlockedError as e:
            await _asgi_blocked(send, e, ctx)
            return
        except Exception:  # pylint: disable=broad-exception-caught
            ctx = None

        async def replay() -> Dict[str, Any]:
            if messages:
                return messages.pop(0)
            return await receive()

        if ctx is None:
            await self.app(scope, replay, send)
            return
        state = {"started": False, "done": False}
        body: List[Optional[_response.ResponseBody]] = [None]

        async def tracked(message: Dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                state["started"] = True
                # SHIELD: AI attack agents — scored before the headers go out, so a mark's verdict goes with them.
                agents_after(ctx, message.get("status") or 0)
                body[0] = _response.begin(_response.content_type_of(message.get("headers") or []))
                # SHIELD: protection triangle — the verdict for Edge, when RASP detected something in this request.
                if ctx.response_headers:
                    message = dict(message)
                    message["headers"] = list(message.get("headers") or []) + _asgi_headers(ctx.response_headers)
            elif message.get("type") == "http.response.body":
                if body[0] is not None:
                    body[0].add(message.get("body") or b"")
                if not message.get("more_body", False):
                    state["done"] = True
                    if body[0] is not None:
                        body[0].finish()
            await send(message)

        token = set_context(ctx)
        try:
            await self.app(scope, replay, tracked)
        except RaspBlockedError as e:
            if not state["started"]:
                await _asgi_blocked(send, e, ctx)
            elif not state["done"]:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            reset_context(token)


# ---- Flask -------------------------------------------------------------------

_FLASK_PARAM = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>")


def _flask_blocked(e: RaspBlockedError):
    status, _, headers, body = block_answer(e)
    return json.loads(body), status, {k: v for k, v in headers if k != "Content-Type"}


def _flask_before_request() -> None:
    try:
        from flask import request

        ctx = current_context()
        if ctx is None or not ctx.in_request:
            return
        rule = getattr(request, "url_rule", None)
        if rule is not None and isinstance(getattr(rule, "rule", None), str):
            ctx.route = _FLASK_PARAM.sub(r":\1", rule.rule)
        if isinstance(getattr(request, "view_args", None), dict):
            flatten(ctx.inputs, request.view_args, "params")
    except Exception:  # pylint: disable=broad-exception-caught
        pass


_FLASK_DECOY = "shield360.rasp.decoy"


def _flask_decoy(endpoint: Any, values: Any) -> None:  # pylint: disable=unused-argument
    """The first URL value preprocessor: a decoy raises Werkzeug's ``NotFound``
    before any of the app's hooks or its view, so Flask answers it with the
    app's own 404 (its ``errorhandler(404)``, else Werkzeug's page)."""
    from flask import request

    if request.environ.get(_FLASK_DECOY):
        from werkzeug.exceptions import NotFound

        raise NotFound()


def _flask_not_found(wsgi_app: Callable) -> Callable:
    def not_found(environ: Dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        environ[_FLASK_DECOY] = True
        return wsgi_app(environ, start_response)

    return not_found


def rasp_flask(app: Any) -> Any:
    """Flask: ``rasp_flask(app)``. Wraps ``app.wsgi_app``, records the route
    and path parameters before each view, and answers the block error from a
    view with the 403 (Flask would otherwise turn it into a 500). A decoy path
    gets the app's own 404 and never reaches a view."""
    if getattr(app, "_shield360_rasp", False):  # SHIELD: once per app (the zero-code start may have done it)
        return app
    app._shield360_rasp = True  # pylint: disable=protected-access
    # Flask answers a decoy only when the hook is in place; else the plain 404, never the view.
    not_found = None
    preprocessors = getattr(app, "url_value_preprocessors", None)
    if isinstance(preprocessors, dict):
        preprocessors.setdefault(None, []).insert(0, _flask_decoy)
        not_found = _flask_not_found(app.wsgi_app)
    app.wsgi_app = RaspWSGIMiddleware(app.wsgi_app, framework="flask", not_found=not_found)
    app.register_error_handler(RaspBlockedError, _flask_blocked)
    app.before_request(_flask_before_request)
    return app


# ---- Django ------------------------------------------------------------------


def _django_blocked(e: RaspBlockedError) -> Any:
    from django.http import JsonResponse

    status, _, headers, body = block_answer(e)
    response = JsonResponse(json.loads(body), status=status)
    for k, v in headers[1:] + _error_headers(e):
        response[k] = v
    return response


def _django_not_found(request: Any) -> Any:
    """Raises what Django raises for an unknown URL, so its 404 handling
    (``handler404``, or the debug page with ``DEBUG``) answers the decoy: the
    resolver's own ``Resolver404``, or ``Http404`` when the decoy resolves."""
    from django.http import Http404

    try:
        from django.urls import Resolver404, get_resolver
    except ImportError:
        raise Http404() from None
    try:
        get_resolver(getattr(request, "urlconf", None)).resolve(request.path_info)
    except Resolver404:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    raise Http404()


class _ScopedIter:
    """An iterator advanced inside a given context (a streamed Django body)."""

    def __init__(self, content: Iterable[Any], cv: contextvars.Context):
        self._cv = cv
        self._content = content
        self._it: Optional[Iterator[Any]] = None

    def __iter__(self) -> "_ScopedIter":
        return self

    def __next__(self) -> Any:
        if self._it is None:
            self._it = self._cv.run(iter, self._content)
        return self._cv.run(next, self._it)

    def close(self) -> None:
        close = getattr(self._content, "close", None)
        if callable(close):
            self._cv.run(close)


async def _scoped_async_iter(content: Any, ctx: RaspContext) -> Any:
    """An async streamed body iterated with the request's context set (and reset when it ends or closes)."""
    token = set_context(ctx)
    try:
        async for chunk in content:
            yield chunk
    finally:
        try:
            reset_context(token)
        except ValueError:
            pass  # closed from another context: that context never saw the token


class RaspDjangoMiddleware:
    """Django: add ``"shield360.rasp.RaspDjangoMiddleware"`` to ``MIDDLEWARE``.

    Records the request (a body of at most 1 MiB), runs the virtual patches,
    adds the route and path parameters once the URL is resolved, and maps the
    block error from a view to the 403.
    """

    sync_capable = True
    async_capable = False

    def __init__(self, get_response: Callable):
        self.get_response = get_response

    def __call__(self, request: Any) -> Any:
        if not is_active() or _outer_captured():
            return self.get_response(request)
        meta = request.META
        method = str(meta.get("REQUEST_METHOD") or "GET").upper()
        verdict: List[str] = []
        deceived = _deceive("django", method, lambda: _django_target(request), _ip_of(meta.get("REMOTE_ADDR")), _environ_headers(meta), verdict)
        if isinstance(deceived, _TripwirePage):
            from django.http import HttpResponse

            page = HttpResponse(str(deceived), status=404, content_type="text/html; charset=utf-8")
            page["Cache-Control"] = "no-store"
            if verdict:
                page[VERDICT_HEADER] = verdict[0]
            return page
        if deceived is _HIT:
            if not verdict:
                _django_not_found(request)
            # SHIELD: decoy and trap verdicts — Django's own 404 response for the decoy, with the verdict on it.
            try:
                _django_not_found(request)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                from django.core.handlers.exception import response_for_exception

                resp = response_for_exception(request, exc)
                resp[VERDICT_HEADER] = verdict[0]
                return resp
        if isinstance(deceived, RaspBlockedError):
            return _django_blocked(deceived)
        ctx, blocked = _capture_environ(meta, "django", lambda: request.body)
        if blocked is not None:
            return _django_blocked(blocked)
        if ctx is None:
            return self.get_response(request)
        # The request runs in a context of its own, never the worker thread's,
        # so nothing it sets outlives it; a streamed body is produced in the same
        # context (Django iterates it after this returns).
        cv = contextvars.copy_context()
        cv.run(set_context, ctx)
        response = cv.run(self.get_response, request)
        # SHIELD: AI attack agents — Django's signed-in user, then the score before the headers are copied.
        try:
            user = getattr(request, "user", None)
            if (
                ctx.user is None
                and user is not None
                and getattr(user, "is_authenticated", False)
                and getattr(user, "pk", None) is not None
            ):
                ctx.user = str(user.pk)[:128]
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        cv.run(agents_after, ctx, getattr(response, "status_code", 0))
        # SHIELD: protection triangle — the verdict for Edge, when RASP detected something in this request.
        try:
            for k, v in ctx.response_headers:
                response[k] = v
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        if not getattr(response, "streaming", False):
            try:
                body = cv.run(_response.begin, response.get("Content-Type"))
                if body is not None:
                    body.add(response.content)
                    cv.run(body.finish)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        elif getattr(response, "streaming", False):
            try:
                content = response.streaming_content
                if getattr(response, "is_async", False):
                    response.streaming_content = _scoped_async_iter(content, ctx)
                else:
                    response.streaming_content = _ScopedIter(content, cv)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        return response

    def process_view(self, request: Any, view_func: Any, view_args: Any, view_kwargs: Any) -> None:
        try:
            ctx = current_context()
            if ctx is None or not ctx.in_request:
                return None
            match = getattr(request, "resolver_match", None)
            route = getattr(match, "route", None)
            if isinstance(route, str) and route:
                ctx.route = "/" + _FLASK_PARAM.sub(r":\1", route).lstrip("/")
            if isinstance(view_kwargs, dict):
                flatten(ctx.inputs, view_kwargs, "params")
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return None

    def process_exception(self, request: Any, exception: BaseException) -> Any:
        if isinstance(exception, RaspBlockedError):
            return _django_blocked(exception)
        return None


# ---- a body the app read itself ----------------------------------------------


def record_request_body(body: Any, content_type: Optional[str] = None) -> None:
    """Adds a body the app read itself to the current request's inputs and
    runs the virtual patches that read the body. Raises the block error when
    one blocks; otherwise never raises."""
    if not is_active():
        return
    ctx = current_context()
    # A body counted empty (the request had none as far as the middleware
    # knew) still takes the body the app read: its inputs reach the built-in
    # checks. The custom body phase already ran and does not run again.
    if ctx is None or not ctx.in_request or (ctx.vp is not None and ctx.vp.body_known and not ctx.vp.body_empty):
        return
    try:
        ctx.late = None
        capture_body(ctx, body, content_type)
        run_virtual_patches(ctx)
    except RaspBlockedError:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        pass
