"""Request capture shared by every framework middleware: turns a request into
the context's inputs (README "Sources of untrusted input") and runs the
virtual patches. Inputs stay in memory, in the request's context only."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union
from urllib.parse import parse_qsl

from opentelemetry import trace

from shield360.rasp._context import RaspContext, VpState, current_context, new_context, reset_context, set_context
from shield360.rasp._custom_rules import custom_finding, match_request_rules, request_subject
from shield360.rasp._engine import current_application_name, custom_rules, handle_finding, remote_config, virtual_patches
from shield360.rasp._normalize import MAX_RAW_BODY, add_input, flatten, parse_cookies
from shield360.rasp._vpatch import MAX_VP_TEXT, VpRequest, match_virtual_patches
from shield360.rasp._edge_context import CONTEXT_HEADER, REQUEST_ID_HEADER, verify_edge_context
from shield360.otel.edge_request import REQUEST_ID_HEADER as EDGE_REQUEST_ID_HEADER, request_id_of, tag_server_span, trace_id_of

# Headers the contract treats as input (OpenRASP's headerInjection).
INPUT_HEADERS = ("user-agent", "referer", "x-forwarded-for")
VP_SINK = "server.request"
_MAX_FORM = 1024 * 1024

Headers = Dict[str, Union[str, List[str]]]


def _header(h: Mapping[str, Any], name: str) -> str:
    v = h.get(name)
    if v is None:
        return ""
    return ", ".join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v)


def _split_url(url: str) -> Tuple[str, str]:
    q = url.find("?")
    h = url.find("#")
    end = h if h >= 0 else len(url)
    if 0 <= q < end:
        return url[:q], url[q + 1 : end]
    return url[:end], ""


def _text(v: Any) -> str:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode("latin-1")
    return str(v)


def lower_headers(h: Any) -> Headers:
    """Lower-cases header names. Takes a mapping, or (name, value) pairs as
    ASGI sends them (bytes are read as latin-1); repeated names become lists."""
    out: Headers = {}
    if not h:
        return out
    items = h.items() if isinstance(h, Mapping) else h
    try:
        for k, v in items:
            if v is None:
                continue
            name = _text(k).lower()
            value: Union[str, List[str]] = [_text(x) for x in v] if isinstance(v, (list, tuple)) else _text(v)
            prev = out.get(name)
            if prev is None:
                out[name] = value
            else:
                merged = prev if isinstance(prev, list) else [prev]
                out[name] = merged + (value if isinstance(value, list) else [value])
    except Exception:  # pylint: disable=broad-exception-caught
        return out
    return out


def capture_request(
    framework: str,
    method: str,
    url: str,
    headers: Headers,
    query: Any = None,
    params: Any = None,
    route: Optional[str] = None,
    ip: Optional[str] = None,
) -> RaspContext:
    """Builds the request's context: query, params, cookies, the input headers.
    ``url`` is the path and query as received (``/a/b?x=1``); ``headers`` have
    lower-case names; ``query`` is the parsed query when the framework has
    one (else it is parsed from ``url``); ``ip`` is the client address as the
    framework reports it (custom rules' ``request.ip``)."""
    path, raw_query = _split_url(url or "/")
    ctx = new_context(in_request=True, method=method, path=path, route=route, framework=framework)
    if isinstance(ip, str) and ip:
        ctx.ip = ip
    inputs = ctx.inputs
    if isinstance(query, (dict, list)):
        flatten(inputs, query, "query")
        ctx.trees.append(query)
    elif raw_query:
        tree: Dict[str, Union[str, List[str]]] = {}
        for k, v in parse_qsl(raw_query, keep_blank_values=True):
            add_input(inputs, v, f"query.{k}")
            prev = tree.get(k)
            tree[k] = v if prev is None else (prev + [v] if isinstance(prev, list) else [prev, v])
        ctx.trees.append(tree)
    if isinstance(params, (dict, list)):
        flatten(inputs, params, "params")
    cookie = _header(headers, "cookie")
    for name, value in parse_cookies(cookie):
        add_input(inputs, value, f"cookie.{name}")
    for h in INPUT_HEADERS:
        v = _header(headers, h)
        if v:
            add_input(inputs, v, f"header.{h}")
    ctx.vp = VpState(req=VpRequest(method=method, path=path, query=raw_query, headers=headers, cookie=cookie, body=""))
    # SHIELD: protection triangle — Edge's signed context, verified (never trusted unverified).
    edge_value = _header(headers, CONTEXT_HEADER)
    if edge_value:
        remote = remote_config()
        keys = remote.edge_keys if remote else []
        ctx.edge = verify_edge_context(keys, edge_value, method, path, _header(headers, REQUEST_ID_HEADER) or None)
    # SHIELD: request correlation — Edge's request id and the trace for the app's log lines and server span (otel/edge_request.py).
    ctx.request_id = (ctx.edge or {}).get("rid") or request_id_of(_header(headers, EDGE_REQUEST_ID_HEADER))
    ctx.trace_id = trace_id_of(_header(headers, "traceparent"))
    tag_server_span(trace.get_current_span(), ctx.request_id)
    return ctx


def capture_body(ctx: RaspContext, body: Any, content_type: Optional[str] = None) -> None:
    """Adds the body to the context: string leaves of a parsed body
    (``body.a.b``), form fields, or the raw text when it is text, unparsed and
    at most 8 KiB. Also gives the virtual patches the body text."""
    if body is None:
        return
    if ctx.vp is not None and ctx.vp.head_inputs is None:
        ctx.vp.head_inputs = len(ctx.inputs)
    ct = (content_type or "").lower()
    raw = ""
    if isinstance(body, (str, bytes, bytearray, memoryview)):
        raw = body if isinstance(body, str) else bytes(body).decode("utf-8", "replace")
        parsed: Any = None
        if "json" in ct:
            try:
                parsed = json.loads(raw)
            except Exception:  # pylint: disable=broad-exception-caught
                parsed = None
        elif "application/x-www-form-urlencoded" in ct:
            parsed = dict(parse_qsl(raw[:_MAX_FORM], keep_blank_values=True))
        if isinstance(parsed, (dict, list)):
            flatten(ctx.inputs, parsed, "body")
            ctx.trees.append(parsed)
        elif len(raw) <= MAX_RAW_BODY:
            add_input(ctx.inputs, raw, "body")
    elif isinstance(body, (dict, list)):
        flatten(ctx.inputs, body, "body")
        ctx.trees.append(body)
        try:
            raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        except Exception:  # pylint: disable=broad-exception-caught
            raw = ""
    if ctx.vp is not None:
        ctx.vp.req.body = raw[:MAX_VP_TEXT]
        ctx.vp.body_known = True
        ctx.vp.body_empty = raw == ""


def run_virtual_patches(ctx: RaspContext) -> None:
    """Runs the virtual patches the request can be judged by so far: rules
    that do not read the body at once, rules that do once the body is known.
    Each rule set runs once. Raises the block error when a blocking rule
    matches; any other failure lets the request through."""
    vp = ctx.vp
    if vp is None:
        return
    phases = []
    if not vp.ran_head:
        vp.ran_head = True
        phases.append("head")
    if vp.body_known and not vp.ran_body:
        vp.ran_body = True
        phases.append("body")
    if not phases:
        return
    # The middleware runs this before it makes ctx current: findings judged here
    # (custom finding rules read the request) must see this request's context.
    token = set_context(ctx) if current_context() is not ctx else None
    try:
        for phase in phases:
            try:
                finding = match_virtual_patches(vp.req, virtual_patches(), phase)
            except Exception:  # pylint: disable=broad-exception-caught
                finding = None
            # A monitored match is reported and the next phase still runs; a blocked one raises.
            if finding:
                handle_finding(finding, VP_SINK, framework=ctx.framework, route=ctx.route, method=ctx.method, path=ctx.path)
            run_request_rules(ctx, phase)
    finally:
        if token is not None:
            reset_context(token)


def run_request_rules(ctx: RaspContext, phase: str) -> None:
    """Custom request rules (README "Custom rules"): each match is reported in
    order; the first that blocks raises the block error. Any other failure
    lets the request through."""
    try:
        rules = custom_rules()
        if not rules:
            return
        # Head rules see only the inputs known before the body, even when the
        # body was captured before the head was judged.
        head = ctx.vp.head_inputs if ctx.vp is not None and phase == "head" else None
        inputs = ctx.inputs[:head] if head is not None else None
        matches = match_request_rules(rules, ctx, phase, request_subject(ctx, current_application_name(), inputs))
    except Exception:  # pylint: disable=broad-exception-caught
        return
    for m in matches:
        handle_finding(
            custom_finding(m.rule, m.input), VP_SINK, framework=ctx.framework, route=ctx.route, method=ctx.method, path=ctx.path
        )


def capture_later(ctx: RaspContext, read: Callable[[], Optional[Tuple[Any, Optional[str]]]]) -> None:
    """Sets up late body capture: when a sink first reads the inputs, a body
    that became readable after the middleware ran is captured and judged.
    ``read`` returns ``(body, content_type)``, or None while there is none."""
    if ctx.vp is not None and ctx.vp.body_known:
        return

    def late() -> Optional[bool]:
        try:
            b = read()
            if not b or b[0] is None:
                return False
            capture_body(ctx, b[0], b[1])
        except Exception:  # pylint: disable=broad-exception-caught
            return True
        run_virtual_patches(ctx)
        return True

    ctx.late = late
