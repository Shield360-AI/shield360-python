"""SHIELD: security event trace ids — the W3C trace and span of the request
this code runs in, as attributes under ``prefix`` (``shield360.rasp.`` or
``shield360.ai_security.``), so the console's replay opens the event's own
trace. Empty outside a span or without tracing. Ids only, never a value."""

from __future__ import annotations

from typing import Any


def trace_attrs(prefix: str) -> dict[str, str]:
    try:
        from opentelemetry import trace

        ctx = trace.get_current_span().get_span_context()
        if not ctx.is_valid:
            return {}
        return {f"{prefix}trace_id": format(ctx.trace_id, "032x"), f"{prefix}span_id": format(ctx.span_id, "016x")}
    except Exception:  # noqa: BLE001 — reporting never breaks a call
        return {}


def without_trace(attrs: dict[str, Any], prefix: str) -> dict[str, Any]:
    """The attributes without the ids: a folded or merged repeat stands for several requests."""
    return {k: v for k, v in attrs.items() if k not in (f"{prefix}trace_id", f"{prefix}span_id")}
