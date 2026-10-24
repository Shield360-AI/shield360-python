"""
Shield Protect -- enforcement APIs, kept apart from the tracing APIs.

    protect_tool(name, ...)            decorate a function the agent may call:
                                       its arguments are checked before it
                                       runs, an optional authorize step is
                                       asked, and its result is checked before
                                       it is returned. In enforced mode every
                                       failure refuses the call.
    authorize_with_shield360(target)   ask Shield360's decision service about a
                                       model or a destination, as the agent
                                       (SHIELD360_AGENT_TOKEN).
    protect_readiness()                what this process can claim.

``shield360.trace``, ``shield360.start_trace`` and the instrumentations
record; these refuse.

Must stay in sync with: sdk/typescript/src/protect/index.ts
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import os
from typing import Any, Awaitable, Callable, Dict, Optional, Union

from opentelemetry import trace as otel_trace

from shield360._config import Shield360Config
from shield360.guard._base import GuardAction, GuardDeniedError, GuardPhase
from shield360.guard._pipeline import Pipeline
from shield360.protect._mode import (
    PROTECT_MODES,
    ProtectDeniedError,
    ProtectError,
    ProtectReadinessError,
    ResolvedProtect,
    current_protect_mode,
    protect_readiness,
    refuses,
    resolve_protect,
    resolve_protect_mode,
)

logger = logging.getLogger(__name__)

__all__ = [
    "protect_tool",
    "authorize_with_shield360",
    "protect_readiness",
    "canonical_json",
    "ProtectError",
    "ProtectDeniedError",
    "ProtectReadinessError",
    "ResolvedProtect",
    "resolve_protect",
    "resolve_protect_mode",
    "PROTECT_MODES",
]

_MAX_DESCRIBED = 1_000_000


def canonical_json(value: Any, depth: int = 0) -> str:
    """Canonical JSON: keys sorted, so the same call reads the same. Unserialisable values become their repr."""
    if depth > 32:
        return '"…"'
    if isinstance(value, dict):
        items = sorted((str(k), v) for k, v in value.items())
        return "{" + ",".join(f"{json.dumps(k)}:{canonical_json(v, depth + 1)}" for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v, depth + 1) for v in value) + "]"
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps(repr(value))


def _record(tool: str, phase: str, outcome: str, reason: str) -> None:
    try:
        span = otel_trace.get_current_span()
        if span is not None and span.is_recording():
            span.add_event(
                "shield360.protect.decision",
                {
                    "shield360.protect.tool": tool,
                    "shield360.protect.phase": phase,
                    "shield360.protect.outcome": outcome,
                    "shield360.protect.reason": (reason or "")[:500],
                },
            )
    except Exception:  # recording never changes a decision
        pass


def finding_stops(mode: Optional[str], denied: bool) -> bool:
    """Whether a deny finding stops the call under ``mode``. Legacy (None) stops; observe and warn do not; enforced does."""
    if not denied:
        return False
    if mode is None:
        return True
    return refuses(mode)


def _evaluate_text(pipeline: Pipeline, text: str, phase: str, tool: str, mode: Optional[str]) -> None:
    if not text:
        return
    bound = pipeline.scan_bound()
    if refuses(mode) and 0 < bound < len(text):
        _record(tool, phase, "deny", f"input of {len(text)} characters is over the {bound}-character scan bound")
        raise ProtectDeniedError(
            "oversized",
            f"Shield360 Protect refused {tool}: {len(text)} characters is more than its guards scan ({bound}); send less.",
        )
    try:
        result = pipeline.evaluate(text, phase=phase)
    except Exception as exc:
        if refuses(mode):
            _record(tool, phase, "deny", f"guard failed: {exc}")
            raise ProtectDeniedError(
                "guard_failed",
                f"Shield360 Protect refused {tool}: a guard failed and enforced mode does not run unchecked calls.",
            ) from exc
        raise
    denied = result.action == GuardAction.DENY
    if not denied:
        _record(tool, phase, "allow", str(result.action.value))
        return
    if finding_stops(mode, True):
        _record(tool, phase, "deny", result.explanation)
        raise GuardDeniedError(result)
    _record(tool, phase, "observed", result.explanation)
    if mode == "warn":
        logger.warning("Shield360 Protect (warn mode): %s would have been refused at %s: %s", tool, phase, result.explanation)


Verdict = Dict[str, Any]
Authorize = Callable[..., Union[Verdict, Awaitable[Verdict]]]


def protect_tool(
    name: str,
    *,
    pipeline: Optional[Pipeline] = None,
    mode: Optional[str] = None,
    describe_args: Optional[Callable[..., str]] = None,
    describe_result: Optional[Callable[[Any], str]] = None,
    authorize: Optional[Authorize] = None,
):
    """Decorate a function as a protected tool (sync or async; the wrapper matches).

    ``authorize(*args, **kwargs)`` returns ``{"allow": bool, "reason": str}``;
    a refusal, an exception or a non-boolean answer refuses the call in
    enforced mode: the call never runs on an answer it did not get.
    """

    def _describe_args(*args: Any, **kwargs: Any) -> str:
        if describe_args:
            return describe_args(*args, **kwargs)
        return canonical_json({"args": list(args), "kwargs": kwargs})[:_MAX_DESCRIBED]

    def _describe_result(result: Any) -> str:
        if describe_result:
            return describe_result(result)
        return canonical_json(result)[:_MAX_DESCRIBED]

    def _before(args: Any, kwargs: Any):
        effective_mode = mode if mode is not None else current_protect_mode()
        effective_pipeline = pipeline if pipeline is not None else getattr(Shield360Config, "guard_pipeline", None)
        if effective_pipeline is None and refuses(effective_mode):
            raise ProtectDeniedError(
                "guard_failed",
                f"Shield360 Protect refused {name}: enforced mode has no guard pipeline; pass guards to init() or to protect_tool().",
            )
        if effective_pipeline is not None:
            _evaluate_text(effective_pipeline, _describe_args(*args, **kwargs), GuardPhase.PREFLIGHT.value, name, effective_mode)
        return effective_mode, effective_pipeline

    def _after_authorize(effective_mode: Optional[str], verdict: Any, failed: Optional[BaseException]) -> None:
        if failed is not None:
            _record(name, "authorize", "deny" if refuses(effective_mode) else "observed", f"authorize failed: {failed}")
            if refuses(effective_mode):
                raise ProtectDeniedError(
                    "authorize_failed",
                    f"Shield360 Protect refused {name}: the authorization check failed "
                    "and enforced mode does not run unchecked calls.",
                ) from failed
            return
        allowed = isinstance(verdict, dict) and verdict.get("allow") is True
        reason = verdict.get("reason", "") if isinstance(verdict, dict) else ""
        outcome = "allow" if allowed else ("deny" if finding_stops(effective_mode, True) else "observed")
        _record(name, "authorize", outcome, str(reason))
        if not allowed and finding_stops(effective_mode, True):
            raise ProtectDeniedError("not_authorized", f"Shield360 Protect refused {name}: {reason or 'not authorized'}.")

    def _after(effective_mode: Optional[str], effective_pipeline: Optional[Pipeline], result: Any) -> Any:
        if effective_pipeline is not None:
            _evaluate_text(effective_pipeline, _describe_result(result), GuardPhase.POSTFLIGHT.value, name, effective_mode)
        return result

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                effective_mode, effective_pipeline = _before(args, kwargs)
                if authorize is not None:
                    verdict, failed = None, None
                    try:
                        verdict = authorize(*args, **kwargs)
                        if inspect.isawaitable(verdict):
                            verdict = await verdict
                    except Exception as exc:  # pylint: disable=broad-exception-caught
                        failed = exc
                    _after_authorize(effective_mode, verdict, failed)
                return _after(effective_mode, effective_pipeline, await fn(*args, **kwargs))

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            effective_mode, effective_pipeline = _before(args, kwargs)
            if authorize is not None:
                verdict, failed = None, None
                try:
                    verdict = authorize(*args, **kwargs)
                    if inspect.isawaitable(verdict):
                        raise TypeError("an async authorize step needs an async tool")
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    failed = exc
                _after_authorize(effective_mode, verdict, failed)
            return _after(effective_mode, effective_pipeline, fn(*args, **kwargs))

        return sync_wrapper

    return decorate


# ---------------------------------------------------------------------------
# Shield360's decision service
# ---------------------------------------------------------------------------


def authorize_with_shield360(
    target: Dict[str, Any],
    *,
    agent_token: Optional[str] = None,
    url: Optional[str] = None,
    on_behalf_of: Optional[str] = None,
    environment: Optional[str] = None,
    timeout: float = 5.0,
    post: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Ask Shield360 whether this agent may make a model call or reach a host.

    ``target`` is ``{"kind": "model", "model": ...}`` or
    ``{"kind": "destination", "host": ..., "method": ...}`` (POST
    /api/agent-authorization/check). The agent's token decides the agent and
    its environment. An answer that did not arrive is ``allow: False`` with
    the reason: a caller in enforced mode treats it as a refusal, never a
    verdict in the agent's favour.
    """
    token = agent_token if agent_token is not None else os.environ.get("SHIELD360_AGENT_TOKEN", "")
    base = (url or getattr(Shield360Config, "shield360_url", None) or os.environ.get("SHIELD360_URL") or "").rstrip("/")
    if not token or not base:
        return {"allow": False, "reason": "shield360_not_configured"}
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    if on_behalf_of:
        headers["X-Shield360-On-Behalf-Of"] = on_behalf_of
    if environment:
        headers["X-Shield360-Environment"] = environment
    try:
        if post is None:
            import requests  # pylint: disable=import-outside-toplevel

            post = requests.post
        response = post(f"{base}/api/agent-authorization/check", json=target, headers=headers, timeout=timeout)
        status = getattr(response, "status_code", 0)
        if status != 200:
            return {"allow": False, "reason": f"check_http_{status}"}
        body = response.json()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {"allow": False, "reason": f"check_unreachable: {exc}"}
    return {
        "allow": body.get("outcome") == "allow",
        "reason": body.get("reason", "unknown"),
        "outcome": body.get("outcome"),
        "message": body.get("message"),
        "policy_version": body.get("policyVersion"),
        "decision_id": body.get("decisionId"),
    }
