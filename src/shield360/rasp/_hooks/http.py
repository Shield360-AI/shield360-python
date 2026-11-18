"""Outbound HTTP sink hook (README "SSRF"): requests are checked for SSRF
and for hosts outside ``allow.outboundHosts`` before anything is sent, and
again against the addresses the connection actually resolves (DNS
rebinding: the contract's "``socket.getaddrinfo`` inside the call"). The
Shield360 and OTLP hosts are always allowed.

Covered, each when the app imports it: ``urllib.request``
(``OpenerDirector.open``, so ``urlopen``), ``http.client``
(``HTTPConnection.putrequest``, with the resolution check at ``connect``),
``requests`` (``Session.send``) and ``httpx`` (``Client.send`` and
``AsyncClient.send``). A high-level call checks its URL once and opens a
scope for the rest of the call: the ``http.client`` request ``requests``
makes underneath is part of it and is not checked again, while a redirect
to another URL is. Inside the scope, ``socket.getaddrinfo`` and asyncio's
``loop.getaddrinfo`` run the SSRF check on the addresses they return for the
call's host before the connection is made.

Gaps: an event loop whose ``getaddrinfo`` cannot be wrapped (uvloop) gets
the URL check only, and so do pooled ``urllib3`` calls made without
``requests``.
"""

from __future__ import annotations

import contextvars
import inspect
import re
import weakref
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from shield360.rasp import _detect, _engine
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._engine import allow_lists
from shield360.rasp._hooks import _imports
from shield360.rasp._hooks._wrap import Entry, argument, in_check, restore, run_check, strongest, wrap
from shield360.rasp._types import Finding, RaspInput

_TAG = "rasp.http"
_entries: List[Entry] = []
_installed = False
_always: List[str] = []
_ABSOLUTE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")


class _Scope:  # pylint: disable=too-few-public-methods
    """One outbound call in progress: its URL, host, inputs (for the resolution check) and sink."""

    __slots__ = ("url", "host", "inputs", "sink", "checked")

    def __init__(self, url: str, host: str, inputs: List[RaspInput], sink: str):
        self.url = url
        self.host = host
        self.inputs = inputs
        self.sink = sink
        self.checked: List[frozenset] = []


_scope: contextvars.ContextVar[Optional[_Scope]] = contextvars.ContextVar("shield360_rasp_outbound", default=None)
# http.client connections with a request checked, waiting for their connect: the URL, host and
# sink, and a weak reference to the context it was checked in (no inputs are held here; they are
# read from that context at connect). Dropped by the connect, by the next request, and by close.
_pending: "weakref.WeakKeyDictionary[Any, Tuple[_Scope, Any]]" = weakref.WeakKeyDictionary()


def _host_of(url: str) -> str:
    raw = _detect.raw_url(url)
    return raw["host"] if raw else ""


def check_url(sink: str, url: str) -> _Scope:
    """The URL checks (outbound allow-list, SSRF without addresses). Raises the
    block error; returns the scope the resolution check uses."""
    seen: Dict[str, List[RaspInput]] = {}

    def run() -> Optional[Finding]:
        ctx = current_context()
        inputs = list(inputs_of(ctx)) if ctx is not None else []
        seen["inputs"] = inputs
        # Both, the stronger decision wins: an outbound finding in monitor mode must not hide an SSRF that blocks.
        return strongest(_detect.detect_outbound(url, allow_lists()["outbound_hosts"], _always), _detect.detect_ssrf(url, inputs, []))

    run_check(sink, run)
    host = _host_of(url)
    inputs = seen.get("inputs") or []
    # An IP literal was judged as written; there is nothing to resolve.
    keep = inputs if host and not _detect.is_ip_literal(host) else []
    return _Scope(url, host, keep, sink)


def _resolved(scope: Optional[_Scope], host: Any, result: Any) -> None:
    """After a resolution inside an outbound call: the SSRF check on the addresses, once per distinct answer."""
    if scope is None or not scope.inputs:
        return
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    if not isinstance(host, str) or host.lower().strip("[]") != scope.host:
        return
    try:
        addresses = frozenset(str(ai[4][0]) for ai in result)
    except Exception:  # pylint: disable=broad-exception-caught
        return
    if not addresses or addresses in scope.checked:
        return
    scope.checked.append(addresses)
    run_check(scope.sink, lambda: _detect.detect_ssrf(scope.url, scope.inputs, sorted(addresses)))


def _enter(entry: Entry, sink: str, url_of: Callable[[Sequence[Any], Dict[str, Any]], Any], args: Any, kwargs: Any) -> Any:
    """Checks a high-level call's URL and opens its scope; None when nothing is to be done."""
    if not entry.on or in_check() or not _engine.is_active():
        return None
    try:
        url = url_of(args[1:] if entry.bound else args, kwargs)
        url = str(url) if url is not None else None
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    if not url:
        return None
    outer = _scope.get()
    if outer is not None and outer.url == url:
        return None
    return _scope.set(check_url(sink, url))


UrlOf = Callable[[Sequence[Any], Dict[str, Any]], Any]


def _outbound(sink: str, url_of: UrlOf) -> Callable[[Callable[..., Any], Entry], Callable[..., Any]]:
    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):

            async def outbound_async(*args: Any, **kwargs: Any) -> Any:
                token = _enter(entry, sink, url_of, args, kwargs)
                try:
                    return await fn(*args, **kwargs)
                finally:
                    if token is not None:
                        _scope.reset(token)

            return outbound_async

        def outbound(*args: Any, **kwargs: Any) -> Any:
            token = _enter(entry, sink, url_of, args, kwargs)
            try:
                return fn(*args, **kwargs)
            finally:
                if token is not None:
                    _scope.reset(token)

        return outbound

    return build


def connection_url(conn: Any, path: Any) -> Optional[str]:
    """The URL an ``http.client`` connection is about to request."""
    if not isinstance(path, str):
        return None
    if _ABSOLUTE.match(path):
        return path  # absolute form, through a proxy
    tunnel = getattr(conn, "_tunnel_host", None)
    host = tunnel or getattr(conn, "host", None)
    if not isinstance(host, str) or not host:
        return None
    port = getattr(conn, "_tunnel_port", None) if tunnel else getattr(conn, "port", None)
    https = getattr(conn, "default_port", 80) == 443
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    shown = f":{port}" if port and port != (443 if https else 80) else ""
    return f"{'https' if https else 'http'}://{authority}{shown}{path if path.startswith('/') else '/' + path}"


def _putrequest(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
    def putrequest(self: Any, *args: Any, **kwargs: Any) -> Any:
        # Whatever an earlier request on this connection left belongs to that request.
        _pending.pop(self, None)
        if entry.on and _scope.get() is None and not in_check() and _engine.is_active():
            url = None
            try:
                url = connection_url(self, argument(args, kwargs, 1, "url"))
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            if url:
                scope = check_url("http.client.HTTPConnection.request", url)
                if scope.inputs and getattr(self, "sock", None) is None:
                    try:
                        ctx = current_context()
                        if ctx is not None:
                            _pending[self] = (_Scope(scope.url, scope.host, [], scope.sink), weakref.ref(ctx))
                    except TypeError:
                        pass
        return fn(self, *args, **kwargs)

    return putrequest


def _connect(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
    def connect(self: Any, *args: Any, **kwargs: Any) -> Any:
        held = _pending.pop(self, None)
        ctx = current_context()
        # Only in the context the request was checked in: inputs never reach another request or a worker.
        if held is None or not entry.on or ctx is None or held[1]() is not ctx or _scope.get() is not None:
            return fn(self, *args, **kwargs)
        scope = held[0]
        try:
            scope.inputs = list(inputs_of(ctx))
        except Exception:  # pylint: disable=broad-exception-caught
            return fn(self, *args, **kwargs)
        token = _scope.set(scope)
        try:
            return fn(self, *args, **kwargs)
        finally:
            _scope.reset(token)

    return connect


def _close(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:  # pylint: disable=unused-argument
    def close(self: Any, *args: Any, **kwargs: Any) -> Any:
        _pending.pop(self, None)
        return fn(self, *args, **kwargs)

    return close


def _getaddrinfo(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(fn):

        async def getaddrinfo_async(*args: Any, **kwargs: Any) -> Any:
            result = await fn(*args, **kwargs)
            if entry.on:
                values = args[1:] if entry.bound else args
                _resolved(_scope.get(), argument(values, kwargs, 0, "host"), result)
            return result

        return getaddrinfo_async

    def getaddrinfo(*args: Any, **kwargs: Any) -> Any:
        result = fn(*args, **kwargs)
        if entry.on:
            _resolved(_scope.get(), argument(args, kwargs, 0, "host"), result)
        return result

    return getaddrinfo


def _add(entry: Optional[Entry]) -> None:
    if entry is not None and entry not in _entries:
        _entries.append(entry)


def _request_url(args: Sequence[Any], kwargs: Dict[str, Any]) -> Any:
    first = argument(args, kwargs, 0, "fullurl", "request")
    return first if isinstance(first, str) else getattr(first, "full_url", None)


def _send_url(args: Sequence[Any], kwargs: Dict[str, Any]) -> Any:
    return getattr(argument(args, kwargs, 0, "request"), "url", None)


def _patch_urllib(module: Any) -> None:
    opener = getattr(module, "OpenerDirector", None)
    if isinstance(opener, type):
        _add(wrap(opener, "open", _outbound("urllib.request.urlopen", _request_url)))


def _patch_http_client(module: Any) -> None:
    conn = getattr(module, "HTTPConnection", None)
    if isinstance(conn, type):
        _add(wrap(conn, "putrequest", _putrequest))
        _add(wrap(conn, "connect", _connect))
        _add(wrap(conn, "close", _close))


def _patch_requests(module: Any) -> None:
    session = getattr(module, "Session", None)
    if isinstance(session, type):
        _add(wrap(session, "send", _outbound("requests.Session.send", _send_url)))


def _patch_httpx(module: Any) -> None:
    for name, sink in (("Client", "httpx.Client.send"), ("AsyncClient", "httpx.AsyncClient.send")):
        cls = getattr(module, name, None)
        if isinstance(cls, type):
            _add(wrap(cls, "send", _outbound(sink, _send_url)))
            # send follows redirects itself; each hop goes out through _send_single_request
            # (httpx 0.18 to 0.28), checked when its URL differs from the call's.
            _add(wrap(cls, "_send_single_request", _outbound(sink, _send_url)))


def _patch_socket(module: Any) -> None:
    _add(wrap(module, "getaddrinfo", _getaddrinfo))


def _patch_asyncio(module: Any) -> None:
    loop = getattr(module, "BaseEventLoop", None)
    if isinstance(loop, type):
        _add(wrap(loop, "getaddrinfo", _getaddrinfo))


_PATCHES = (
    ("socket", _patch_socket),
    ("asyncio.base_events", _patch_asyncio),
    ("http.client", _patch_http_client),
    ("urllib.request", _patch_urllib),
    ("requests.sessions", _patch_requests),
    ("httpx", _patch_httpx),
)


def install_http_hooks(always_allowed_hosts: Sequence[str] = ()) -> bool:
    """Wraps the HTTP clients the app has loaded, and the others when it loads
    them. Idempotent (a second call only updates the always-allowed hosts); never raises."""
    global _installed
    _always[:] = [h.lower() for h in always_allowed_hosts if isinstance(h, str) and h]
    if _installed:
        return True
    try:
        _installed = True
        for name, patch in _PATCHES:
            _imports.when_imported(name, _TAG, patch)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        uninstall_http_hooks()
        return False


def uninstall_http_hooks() -> None:
    """Switches every wrapper off and puts the originals back where RASP's wrapper is on top. Idempotent."""
    global _installed
    _installed = False
    _imports.forget(_TAG)
    for entry in reversed(_entries):
        restore(entry)
    _entries.clear()
    _pending.clear()
