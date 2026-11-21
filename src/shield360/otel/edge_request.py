"""
SHIELD: request correlation — Shield360 Edge's request id and the trace id on
everything the app records while it serves that request, so Shield360 joins
the app's log lines and spans to Edge's record of the request, even when the
app does not trace. The TypeScript SDK does the same (otel/edge-request.ts).

Edge's id is taken from its signed context header when the app verified one
(``rasp/_edge_context.py``), else from the request's ``X-Request-Id`` (Edge
always sends its own there; a client's value never reaches the app under that
name). It goes on:

- the app's server span, as ``shield360.edge.request_id`` (the RASP capture
  tags the span active when the request is captured);
- every record the Shield360 log handler sends (``app_logs.py``), with the
  trace id as ``shield360.edge.trace_id`` when no span is active;
- every ``logging`` record that passes ``EdgeRequestFilter``, as
  ``record.shield360_request_id`` and ``record.shield360_trace_id``, for the
  app's own formatters (``%(shield360_request_id)s``).

Only an id-shaped value is used: letters, digits, ``.``, ``_`` and ``-``, 8 to
128 characters.
"""

import logging
import re
import threading
from collections import OrderedDict
from typing import Any, Dict, Optional

from opentelemetry import trace

EDGE_REQUEST_ID_ATTR = "shield360.edge.request_id"
EDGE_TRACE_ID_ATTR = "shield360.edge.trace_id"
REQUEST_ID_HEADER = "x-request-id"

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")
_MAX_TRACES = 5000
_by_trace: "OrderedDict[str, str]" = OrderedDict()
_lock = threading.Lock()


def request_id_of(value: Any) -> Optional[str]:
    """An id-shaped request id, or None."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return value if isinstance(value, str) and _REQUEST_ID.match(value) else None


def trace_id_of(traceparent: Any) -> Optional[str]:
    """The trace id in a W3C traceparent, or None."""
    m = _TRACEPARENT.match(traceparent) if isinstance(traceparent, str) else None
    return m.group(1) if m and m.group(1) != "0" * 32 else None


def tag_server_span(span: Any, request_id: Optional[str]) -> None:
    """Records the request id on the request's server span and remembers it for the span's trace."""
    if span is None or not request_id:
        return
    try:
        sc = span.get_span_context()
        if not sc or not sc.is_valid:
            return
        span.set_attribute(EDGE_REQUEST_ID_ATTR, request_id)
        key = format(sc.trace_id, "032x")
        with _lock:
            _by_trace[key] = request_id
            _by_trace.move_to_end(key)
            while len(_by_trace) > _MAX_TRACES:
                _by_trace.popitem(last=False)
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def current_edge_ids() -> Dict[str, Any]:
    """Edge's request id and the trace id for what the app is doing now (either may be None)."""
    from shield360.rasp._context import current_context  # pylint: disable=import-outside-toplevel

    ctx = current_context()
    sc = trace.get_current_span().get_span_context()
    active = bool(sc and sc.is_valid)
    trace_id = format(sc.trace_id, "032x") if active else None
    edge = getattr(ctx, "edge", None) if ctx else None
    request_id = (edge or {}).get("rid") or (getattr(ctx, "request_id", None) if ctx else None)
    if not request_id and trace_id:
        with _lock:
            request_id = _by_trace.get(trace_id)
    if not active:
        trace_id = trace_id_of((edge or {}).get("tp")) or (getattr(ctx, "trace_id", None) if ctx else None)
    return {"request_id": request_id, "trace_id": trace_id, "span_active": active}


class EdgeRequestFilter(logging.Filter):
    """Adds ``shield360_request_id`` and ``shield360_trace_id`` ("" when unknown) to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            ids = current_edge_ids()
            record.shield360_request_id = ids["request_id"] or ""
            record.shield360_trace_id = ids["trace_id"] or ""
        except Exception:  # pylint: disable=broad-exception-caught
            record.shield360_request_id = record.shield360_trace_id = ""
        return True


def reset() -> None:
    """Test hook."""
    with _lock:
        _by_trace.clear()
