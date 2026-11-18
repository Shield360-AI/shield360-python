"""Budget check: ask Shield360 whether this app may spend on a model call.

    shield360.budgets.check(model="gpt-4o", estimated_cost_usd=0.02)
      -> BudgetCheckResult(allowed, action, code, reason, ...)

The answer comes from the platform's ``GET /api/budgets/decision``, the one
spend decision every Shield360 enforcement point uses, asked with the
environment's API key and this app's service name. App budgets (Costs ->
Budgets, "App") and project budgets with enforcement rules apply.

It does not call the platform on every request. Like the CLI's proxy and
hooks (cli/internal/spenddecision), a decision is reused for the ttlSeconds
the platform sets (60 s by default) while the estimated cost of the calls
checked with it fits in its ``headroomUsd``, the spend left before any limit
turns stricter.

It never raises. When no decision can be read it fails open (allowed) by
default; closed when ``fail_closed`` is set here or on the client
(SHIELD360_BUDGET_FAIL_CLOSED=1), or when the last decision read said
failClosed (a budget with a block rule that asks for it). A failed read is
not retried for a few seconds.

``setup_auto_budget_check()`` (``init(budget_check=True)`` or
SHIELD360_BUDGET_CHECK=1) checks before each call to a provider the SDK knows
and raises BudgetExceededError when a budget refuses it.

Must stay in sync with: sdk/typescript/src/budgets/index.ts and auto.ts
"""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

ACTIONS = ("allow", "warn", "throttle", "block")
DEFAULT_TTL = 60.0
MAX_TTL = 600.0
UNAVAILABLE_BACKOFF = 5.0
MAX_SUBJECT = 256

UNAVAILABLE_REASON = (
    "Shield360 could not check the budget for this AI call, and this app is set to wait "
    "until it can. Try again shortly. [budget_unavailable]"
)


def _env_flag(name: str) -> bool:
    return (os.getenv(name) or "").strip().lower() in ("1", "true", "yes")


def _clean(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value and len(value) <= MAX_SUBJECT else None


def _positive(value: Any) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    return v if v > 0 and math.isfinite(v) else 0.0


@dataclass
class BudgetCheckResult:
    """The decision for one call."""

    allowed: bool
    action: str
    code: str
    reason: str = ""
    limit: Optional[Dict[str, str]] = None
    headroom_usd: Optional[float] = None
    cached: bool = False
    unavailable: bool = False


class BudgetExceededError(Exception):
    """Raised by the automatic pre-call check when a budget refuses the call."""

    def __init__(self, result: BudgetCheckResult):
        super().__init__(result.reason or f"Shield360 budget refused this AI call. [{result.code}]")
        self.result = result


@dataclass
class _Entry:
    decision: Dict[str, Any]
    fetched_at: float
    ttl: float
    spent: float = 0.0


@dataclass
class BudgetClient:
    """Fetches and caches decisions. Defaults come from ``shield360.init()`` and the environment."""

    url: Optional[str] = None
    api_key: Optional[str] = None
    app: Optional[str] = None
    fail_closed: Optional[bool] = None
    timeout: float = 3.0
    http_get: Optional[Callable[..., Any]] = None
    now: Callable[[], float] = time.monotonic
    _cache: Dict[str, _Entry] = field(default_factory=dict, init=False, repr=False)
    _unavailable_until: Dict[str, float] = field(default_factory=dict, init=False, repr=False)
    _calls: Dict[str, List[float]] = field(default_factory=dict, init=False, repr=False)
    _fail_closed_hint: bool = field(default=False, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    # ------------------------------------------------------------ settings

    def _creds(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        from shield360._config import Shield360Config

        url = self.url or getattr(Shield360Config, "shield360_url", None) or os.getenv("SHIELD360_URL")
        key = self.api_key or getattr(Shield360Config, "shield360_api_key", None) or os.getenv("SHIELD360_API_KEY")
        app = self.app or getattr(Shield360Config, "application_name", None)
        return url, key, app

    def _closed(self, fail_closed: Optional[bool]) -> bool:
        if fail_closed is not None:
            return fail_closed
        if self.fail_closed is not None:
            return self.fail_closed or self._fail_closed_hint
        return _env_flag("SHIELD360_BUDGET_FAIL_CLOSED") or self._fail_closed_hint

    def reset(self) -> None:
        """Forget cached decisions."""
        with self._lock:
            self._cache.clear()
            self._unavailable_until.clear()
            self._calls.clear()
            self._fail_closed_hint = False

    # -------------------------------------------------------------- check

    def check(
        self,
        app: Optional[str] = None,
        model: Optional[str] = None,
        estimated_cost_usd: Optional[float] = None,
        fail_closed: Optional[bool] = None,
    ) -> BudgetCheckResult:
        """The decision for one call. Never raises."""
        try:
            return self._check(app, model, estimated_cost_usd, fail_closed)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.debug("Budget check failed", exc_info=True)
            return self._unavailable(fail_closed)

    def _unavailable(self, fail_closed: Optional[bool]) -> BudgetCheckResult:
        closed = self._closed(fail_closed)
        return BudgetCheckResult(
            allowed=not closed,
            action="block" if closed else "allow",
            code="budget_unavailable",
            reason=UNAVAILABLE_REASON if closed else "",
            unavailable=True,
        )

    def _check(self, app, model, estimated_cost_usd, fail_closed) -> BudgetCheckResult:
        url, key, default_app = self._creds()
        app = _clean(app) or _clean(default_app)
        model = _clean(model)
        cost = _positive(estimated_cost_usd)
        if not app or not url or not key:
            return self._unavailable(fail_closed)
        cache_key = f"{app}\0{model or ''}".lower()
        now = self.now()
        with self._lock:
            hit = self._cache.get(cache_key)
            if hit and now - hit.fetched_at < hit.ttl and self._fits(hit, cost):
                hit.spent += cost
                return self._result(cache_key, hit.decision, cached=True)
            if self._unavailable_until.get(cache_key, 0) > now:
                return self._unavailable(fail_closed)
        decision = self._fetch(url, key, app, model, cost)
        with self._lock:
            if decision is None:
                self._unavailable_until[cache_key] = self.now() + UNAVAILABLE_BACKOFF
                return self._unavailable(fail_closed)
            self._unavailable_until.pop(cache_key, None)
            self._fail_closed_hint = decision.get("failClosed") is True
            ttl_s = decision.get("ttlSeconds")
            ttl = min(float(ttl_s), MAX_TTL) if isinstance(ttl_s, (int, float)) and ttl_s > 0 else DEFAULT_TTL
            self._cache[cache_key] = _Entry(decision=decision, fetched_at=self.now(), ttl=ttl, spent=cost)
            return self._result(cache_key, decision, cached=False)

    @staticmethod
    def _fits(entry: _Entry, cost: float) -> bool:
        headroom = entry.decision.get("headroomUsd")
        return not isinstance(headroom, (int, float)) or entry.spent + cost <= headroom

    def _fetch(self, url: str, key: str, app: str, model: Optional[str], cost: float) -> Optional[Dict[str, Any]]:
        query = {"app": app}
        if model:
            query["model"] = model
        if cost > 0:
            query["cost"] = f"{cost:.6f}"
        endpoint = f"{url.rstrip('/')}/api/budgets/decision?{urlencode(query)}"
        get = self.http_get
        if get is None:
            import requests  # pylint: disable=import-outside-toplevel

            get = requests.get
        try:
            res = get(endpoint, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"}, timeout=self.timeout)
            if getattr(res, "status_code", 500) >= 300:
                return None
            body = res.json()
        except Exception:  # pylint: disable=broad-exception-caught
            return None
        if not isinstance(body, dict) or body.get("action") not in ACTIONS:
            return None
        return body

    def _throttled(self, cache_key: str, rpm: int) -> bool:
        now = self.now()
        recent = [t for t in self._calls.get(cache_key, []) if now - t < 60.0]
        if len(recent) >= rpm:
            self._calls[cache_key] = recent
            return True
        recent.append(now)
        self._calls[cache_key] = recent
        return False

    def _result(self, cache_key: str, d: Dict[str, Any], cached: bool) -> BudgetCheckResult:
        action = d.get("action") if d.get("action") in ACTIONS else "allow"
        allowed = action in ("allow", "warn")
        if action == "throttle":
            throttle = d.get("throttle") or {}
            try:
                rpm = max(1, int(throttle.get("requestsPerMinute") or 1))
            except (TypeError, ValueError):
                rpm = 1
            allowed = not self._throttled(cache_key, rpm)
        limit = d.get("limit")
        headroom = d.get("headroomUsd")
        return BudgetCheckResult(
            allowed=allowed,
            action=action,
            code=d.get("code") if isinstance(d.get("code"), str) else f"budget_{'ok' if action == 'allow' else action}",
            reason=d.get("reason") if isinstance(d.get("reason"), str) else "",
            limit=(
                {"id": str(limit.get("id", "")), "name": str(limit.get("name", "")), "scope": str(limit.get("scope", ""))}
                if isinstance(limit, dict)
                else None
            ),
            headroom_usd=float(headroom) if isinstance(headroom, (int, float)) and math.isfinite(headroom) else None,
            cached=cached,
            unavailable=False,
        )


_default: Optional[BudgetClient] = None


def default_client() -> BudgetClient:
    """The process's client, built from init()'s URL, API key and application name."""
    global _default  # pylint: disable=global-statement
    if _default is None:
        _default = BudgetClient()
    return _default


def configure(**kwargs: Any) -> BudgetClient:
    """Replace the process's client (init(budget_check=...) and tests)."""
    global _default  # pylint: disable=global-statement
    _default = BudgetClient(**kwargs)
    return _default


def check(
    app: Optional[str] = None,
    model: Optional[str] = None,
    estimated_cost_usd: Optional[float] = None,
    fail_closed: Optional[bool] = None,
) -> BudgetCheckResult:
    """``shield360.budgets.check()`` with the process's client. Never raises."""
    return default_client().check(app=app, model=model, estimated_cost_usd=estimated_cost_usd, fail_closed=fail_closed)


def reset() -> None:
    default_client().reset()


# --------------------------------------------------------------- automatic


def _model_of(kwargs: Dict[str, Any]) -> Optional[str]:
    for key in ("model", "model_id", "modelId"):
        value = kwargs.get(key)
        if isinstance(value, str):
            return value
    return None


def _make_sync_wrapper(client: BudgetClient):
    def _budget_wrapper(wrapped, instance, args, kwargs):  # pylint: disable=unused-argument
        result = client.check(model=_model_of(kwargs))
        if not result.allowed:
            raise BudgetExceededError(result)
        if result.action == "warn" and result.reason:
            logger.warning("%s", result.reason)
        return wrapped(*args, **kwargs)

    return _budget_wrapper


def _make_async_wrapper(client: BudgetClient):
    async def _budget_wrapper(wrapped, instance, args, kwargs):  # pylint: disable=unused-argument
        import asyncio  # pylint: disable=import-outside-toplevel

        # The check may make one short request; keep it off the event loop.
        result = await asyncio.get_running_loop().run_in_executor(None, lambda: client.check(model=_model_of(kwargs)))
        if not result.allowed:
            raise BudgetExceededError(result)
        if result.action == "warn" and result.reason:
            logger.warning("%s", result.reason)
        return await wrapped(*args, **kwargs)

    return _budget_wrapper


def setup_auto_budget_check(client: Optional[BudgetClient] = None, methods=None) -> List[str]:
    """Wrap the providers the auto-guards know with the budget check. Returns the packages wrapped."""
    from wrapt import wrap_function_wrapper  # pylint: disable=import-outside-toplevel
    from shield360.guard._integration import GUARDED_METHODS, _is_async_method  # pylint: disable=import-outside-toplevel

    client = client or default_client()
    wrapped: List[str] = []
    for entry in methods if methods is not None else GUARDED_METHODS:
        module_path, class_method = entry[0], entry[1]
        try:
            wrapper = _make_async_wrapper(client) if _is_async_method(module_path, class_method) else _make_sync_wrapper(client)
            wrap_function_wrapper(module_path, class_method, wrapper)
            package = module_path.split(".", maxsplit=1)[0]
            if package not in wrapped:
                wrapped.append(package)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.debug("Could not wrap %s.%s with the budget check", module_path, class_method)
    if wrapped:
        logger.info("Budget check: wrapped %d provider package(s): %s", len(wrapped), ", ".join(wrapped))
    return wrapped
