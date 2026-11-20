"""The RASP context of the request (or worker job) being served, kept in a
context variable. Inputs live here, in memory, for the life of the request
only; nothing in this file sends or stores them anywhere else."""

from __future__ import annotations

import contextvars
import inspect
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from shield360.rasp._types import RaspInput


@dataclass
class VpState:
    """Virtual-patch state: the request as the rules see it."""

    req: Any
    body_known: bool = False
    # How many of the context's inputs were known before the body: head rules see only these.
    head_inputs: Optional[int] = None
    # The known body is empty (none, or counted empty): record_request_body still adds a body the app read.
    body_empty: bool = False
    ran_head: bool = False
    ran_body: bool = False


@dataclass
class RaspContext:
    inputs: List[RaspInput] = field(default_factory=list)
    # Parsed body and query trees (for nosql_injection).
    trees: List[Any] = field(default_factory=list)
    in_request: bool = False
    method: Optional[str] = None
    path: Optional[str] = None
    # The route template when the framework knows it.
    route: Optional[str] = None
    framework: Optional[str] = None
    # The client address as the framework reports it (custom rules' ``request.ip``).
    ip: Optional[str] = None
    # Custom-rule state for this request (``_custom_rules.CustomRuleState``).
    rules: Any = None
    vp: Optional[VpState] = None
    # Captures a body that became readable after the middleware ran. Called
    # when a sink reads the inputs, until it reports the body was found
    # (returns other than False).
    late: Optional[Callable[[], Optional[bool]]] = None
    # SHIELD: protection triangle — Edge's verified context, and response headers for Edge (the verdict).
    edge: Optional[Dict[str, Any]] = None
    response_headers: List[Tuple[str, str]] = field(default_factory=list)
    verdict_sent: bool = False
    # SHIELD: uploads — the files this request carries, inspected (_upload.py); never their content.
    uploads: List[Any] = field(default_factory=list)


_current: contextvars.ContextVar[Optional[RaspContext]] = contextvars.ContextVar("shield360_rasp_context", default=None)


def current_context() -> Optional[RaspContext]:
    return _current.get()


def set_context(ctx: Optional[RaspContext]) -> contextvars.Token:
    """Makes ctx current for the rest of this context (thread or task). Returns the token to reset."""
    return _current.set(ctx)


def reset_context(token: contextvars.Token) -> None:
    _current.reset(token)


def new_context(**init: Any) -> RaspContext:
    return RaspContext(**init)


def inputs_of(ctx: RaspContext) -> List[RaspInput]:
    """The context's inputs, after any late body capture. Sinks call this
    rather than reading ``inputs`` directly. A virtual patch matched by the
    late body raises the block error from here."""
    late = ctx.late
    if late is not None:
        ctx.late = None
        if late() is False:
            ctx.late = late
    return ctx.inputs


def _run_with(ctx: RaspContext, fn: Callable[..., Any], args: Any, kwargs: Any) -> Any:
    if inspect.iscoroutinefunction(fn):

        async def scoped():
            token = _current.set(ctx)
            try:
                return await fn(*args, **kwargs)
            finally:
                _current.reset(token)

        return scoped()
    token = _current.set(ctx)
    try:
        return fn(*args, **kwargs)
    finally:
        _current.reset(token)


def run_in_rasp_scope(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Runs fn in a fresh context that is not a request (a worker acting on a
    model's answer). A coroutine function gives back a coroutine that runs in
    the scope when awaited."""
    return _run_with(new_context(), fn, args, kwargs)


def run_with_inputs(inputs: Iterable[Any], fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Runs fn with a context holding the given inputs (workers, tests).
    Each input is a ``RaspInput``, a ``(value, key, source)`` tuple or a dict
    with those keys."""
    items: List[RaspInput] = []
    for i in inputs:
        if isinstance(i, RaspInput):
            items.append(i)
        elif isinstance(i, dict):
            items.append(RaspInput(str(i.get("value", "")), str(i.get("key", "")), str(i.get("source", "request"))))
        else:
            items.append(RaspInput(*i))
    return _run_with(new_context(inputs=items), fn, args, kwargs)


_ID_SEGMENT = re.compile(
    r"(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?=[0-9a-f]*\d)[0-9a-f]{8,})",
    re.IGNORECASE | re.ASCII,
)


def route_of(path: str) -> str:
    """Route fallback: all-digit, UUID and hex (8+, with a digit) segments become ``:id``."""
    return "/".join(":id" if _ID_SEGMENT.fullmatch(s) else s for s in path.split("?")[0].split("/"))


_KEPT_SEGMENT = re.compile(r"[a-z][a-z_.-]{0,15}|v[0-9]{1,2}", re.ASCII)


def event_route_of(path: str) -> str:
    """The route every event carries when the framework gave no template
    (README "Event route"): the route fallback, then every segment that is not
    a short lower-case word (or an API version such as ``v2``) becomes ``:id``,
    so a token, name or other value in the path never reaches an event."""
    return "/".join(s if s in ("", ":id") or _KEPT_SEGMENT.fullmatch(s) else ":id" for s in route_of(path).split("/"))
