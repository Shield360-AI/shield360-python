"""
User feedback: what one of your application's users thought of an AI
response, sent to Shield360 (``POST /api/feedback``) against the trace that
produced it.

Call it from your server, with the environment's API key, never from a
browser. It never raises: anything wrong (no trace, no URL or key, a bad
score, the network) returns ``False``.

Shield360 keeps the score, ids, application and release. The comment is kept
only when your organisation's Data retention setting stores end users' free
text (with secrets and personal data masked); ``user_id`` and ``tenant_id``
are kept only as a keyed hash.
"""

import logging
import os
import re

from opentelemetry import trace as _trace

logger = logging.getLogger(__name__)

_TRACE_ID = re.compile(r"^[0-9a-fA-F]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-fA-F]{16}$")
_INVALID_TRACE = "0" * 32
_INVALID_SPAN = "0" * 16

_defaults = {"app": None, "release": None}


def configure_feedback(app=None, release=None):
    """Set by ``init``: the application and release every rating names."""
    _defaults["app"] = app or None
    _defaults["release"] = release or None


def get_current_trace_id():
    """The active span's trace id as 32 hex characters, or None outside a trace."""
    try:
        ctx = _trace.get_current_span().get_span_context()
        if not ctx or not ctx.trace_id:
            return None
        value = format(ctx.trace_id, "032x")
        return None if value == _INVALID_TRACE else value
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def get_current_span_id():
    """The active span's id as 16 hex characters, or None outside a trace."""
    try:
        ctx = _trace.get_current_span().get_span_context()
        if not ctx or not ctx.span_id:
            return None
        value = format(ctx.span_id, "016x")
        return None if value == _INVALID_SPAN else value
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _valid_score(score, scale):
    if isinstance(score, bool) or not isinstance(score, int):
        return False
    if scale == "thumbs":
        return score in (1, -1)
    if scale == "stars":
        return 1 <= score <= 5
    if scale is not None:
        return False
    return score == -1 or 1 <= score <= 5


def feedback(
    score,
    trace_id=None,
    span_id=None,
    comment=None,
    scale=None,
    user_id=None,
    tenant_id=None,
    metadata=None,
    feedback_id=None,
    url=None,
    api_key=None,
    timeout=5.0,
):
    """
    Send one rating. Returns whether Shield360 accepted it; never raises.

    Args:
        score: 1 or -1 (thumbs), or 1 to 5 (stars; pass ``scale="stars"``
            for a one-star rating, since 1 alone is a thumbs up).
        trace_id: The trace rated. Defaults to the active span's trace.
        span_id: The span rated, when it was one call in the trace.
        comment: What the user wrote. Kept only when your organisation
            stores end users' free text.
        scale: "thumbs" or "stars".
        user_id / tenant_id: Your end user and their tenant; stored only as a
            keyed hash.
        metadata: A flat dict of up to 20 short values.
        feedback_id: Your own id for this rating; sending it again replaces
            the earlier rating.
        url / api_key: Default to what ``init`` was given, then
            SHIELD360_URL / SHIELD360_API_KEY.
        timeout: Seconds to wait for Shield360.
    """
    try:
        # pylint: disable=import-outside-toplevel
        import requests
        from shield360._config import Shield360Config

        trace_id = (trace_id or get_current_trace_id() or "").lower()
        if not _TRACE_ID.match(trace_id) or trace_id == _INVALID_TRACE:
            return False
        if span_id and not _SPAN_ID.match(str(span_id)):
            return False
        if not _valid_score(score, scale):
            return False

        base = (
            url
            or getattr(Shield360Config, "shield360_url", None)
            or os.getenv("SHIELD360_URL")
            or ""
        )
        key = (
            api_key
            or getattr(Shield360Config, "shield360_api_key", None)
            or os.getenv("SHIELD360_API_KEY")
            or ""
        )
        base = str(base).strip().rstrip("/")
        key = str(key).strip()
        if not base or not key:
            return False

        body = {"traceId": trace_id, "score": score}
        optional = {
            "spanId": str(span_id).lower() if span_id else None,
            "scale": scale,
            "comment": comment,
            "userId": user_id,
            "tenantId": tenant_id,
            "metadata": metadata,
            "feedbackId": feedback_id,
            "app": _defaults["app"]
            or getattr(Shield360Config, "application_name", None),
            "release": _defaults["release"],
        }
        body.update({k: v for k, v in optional.items() if v})

        response = requests.post(
            f"{base}/api/feedback",
            json=body,
            headers={"Authorization": f"Bearer {key}"},
            timeout=timeout,
        )
        return 200 <= response.status_code < 300
    except Exception as error:  # pylint: disable=broad-exception-caught
        logger.debug("shield360 feedback not sent: %s", type(error).__name__)
        return False
