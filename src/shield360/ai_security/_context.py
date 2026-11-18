"""What the AI security checks know about the request in progress.

The signed-in end user's roles and attributes (tool permissions) and the
identifiers of other tenants that reached the model's context (cross-tenant
output check). The end customer itself is the one set with
``shield360.customer(...)`` / ``set_customer()``. Scoped with contextvars, so
concurrent requests (threads with copied contexts, asyncio tasks) never see
each other's state. Bounded: at most 2000 identifiers per request.

Must stay in sync with: sdk/typescript/src/ai-security/context.ts
"""

from __future__ import annotations

import contextvars
import re
from contextlib import ContextDecorator
from typing import Any, Dict, Iterable, List, Optional

from shield360._customer import customer as _customer_scope, get_customer

_MAX_IDENTIFIERS = 2000

_state: contextvars.ContextVar = contextvars.ContextVar("shield360_ai_security_request", default=None)
_fallback: Dict[str, Any] = {"user": None, "foreign": {}}


def _current() -> Dict[str, Any]:
    s = _state.get()
    return s if s is not None else _fallback


def _clean_user(roles: Any = None, attributes: Any = None) -> Dict[str, Any]:
    clean_roles = (
        [r for r in (roles or []) if isinstance(r, str) and 0 < len(r) <= 128][:100] if isinstance(roles, (list, tuple, set)) else []
    )
    attrs: Dict[str, str] = {}
    if isinstance(attributes, dict):
        for k, v in list(attributes.items())[:100]:
            if isinstance(v, (str, int, float, bool)):
                attrs[str(k)] = str(v)[:256]
    return {"roles": clean_roles, "attributes": attrs}


class end_user(ContextDecorator):  # pylint: disable=invalid-name
    """One request for this end user: the customer (tenant, user) for
    attribution, roles and attributes for tool permissions. Identifiers of
    other tenants seen inside are forgotten on exit.

        with shield360.ai_security.end_user(tenant_id="acme", user_id="u1", roles=["agent"]):
            ...
    """

    def __init__(self, tenant_id: Any = None, user_id: Any = None, roles: Any = None, attributes: Any = None):
        self._state = {"user": _clean_user(roles, attributes), "foreign": {}}
        self._customer = _customer_scope(tenant_id, user_id) if tenant_id is not None else None
        self._tokens: List[Any] = []

    def __enter__(self):
        if self._customer is not None:
            self._customer.__enter__()
        self._tokens.append(_state.set({"user": self._state["user"], "foreign": {}}))
        return self

    def __exit__(self, *exc):
        _state.reset(self._tokens.pop())
        if self._customer is not None:
            self._customer.__exit__(*exc)
        return False


def set_end_user(roles: Any = None, attributes: Any = None) -> None:
    """The process-wide end user (scripts, single-user workers)."""
    global _fallback  # pylint: disable=global-statement
    _fallback = {"user": _clean_user(roles, attributes), "foreign": {}}


def get_end_user() -> Optional[Dict[str, Any]]:
    return _current()["user"]


def current_tenant() -> Optional[str]:
    c = get_customer()
    return c.get("tenant_id") if c else None


def remember_foreign_identifiers(tenant_id: str, identifiers: Iterable[str]) -> None:
    foreign = _current()["foreign"]
    for raw in identifiers:
        if len(foreign) >= _MAX_IDENTIFIERS:
            return
        ident = str(raw).strip().lower()
        if 4 <= len(ident) <= 200:
            foreign[ident] = tenant_id


def foreign_identifiers() -> Dict[str, str]:
    return _current()["foreign"]


def reset_request_state() -> None:
    global _fallback  # pylint: disable=global-statement
    _fallback = {"user": None, "foreign": {}}


_ID_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE),
    re.compile(r"\b[A-Z]{2,6}-?[0-9]{4,}\b"),
    re.compile(r"(?<![0-9])[0-9]{6,}(?![0-9])"),
]


def identifiers_in(text: str, limit: int = 200) -> List[str]:
    """Distinctive identifiers: e-mail addresses, UUIDs, record ids, long numbers."""
    out: List[str] = []
    seen = set()
    if not text:
        return out
    sample = text[:100_000]
    for rx in _ID_PATTERNS:
        for m in rx.finditer(sample):
            if len(out) >= limit:
                return out
            if m.group(0) not in seen:
                seen.add(m.group(0))
                out.append(m.group(0))
    return out
