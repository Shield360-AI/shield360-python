"""Cost per end customer.

SaaS builders tag each AI call with their own customer (tenant) and,
optionally, the end user inside that tenant, so Shield360 can show cost and
margin per end customer.

``shield360.set_customer()`` sets a process-wide default;
``with shield360.customer(...)`` scopes a customer to a block through
contextvars (so it follows asyncio tasks) and wins over the default.
``CustomerSpanProcessor`` stamps every span started while a customer is in
effect, so one processor covers every instrumentation.

The SDK never hashes. Ids are sent as given: Shield360 stores user ids only as
a keyed hash on its side, and keeps tenant ids as given unless the
organisation opts to hash them.
"""

import contextvars
import math
from contextlib import ContextDecorator
from typing import Any, Dict, Optional

from opentelemetry.sdk.trace import SpanProcessor

from shield360.semcov import SemanticConvention

ATTR_CUSTOMER_TENANT_ID = SemanticConvention.SHIELD360_CUSTOMER_TENANT_ID
ATTR_CUSTOMER_USER_ID = SemanticConvention.SHIELD360_CUSTOMER_USER_ID

_MAX_ID_LENGTH = 256

# Sentinel: no customer scoped here, so the process-wide default applies.
_UNSET = object()
# The scoped customer: _UNSET, None ("no customer here") or a validated dict.
_scoped: contextvars.ContextVar = contextvars.ContextVar(
    "shield360_customer", default=_UNSET
)
_default: Optional[Dict[str, str]] = None


def _is_control(char: str) -> bool:
    code = ord(char)
    return code <= 0x1F or 0x7F <= code <= 0x9F


def normalise_customer_id(value: Any) -> Optional[str]:
    """A valid id, or None.

    Strings and finite numbers are accepted, trimmed, 1-256 characters, with no
    control characters. Never raises, never logs the value.
    """
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, str):
            text = value
        elif isinstance(value, int):
            text = str(value)
        elif isinstance(value, float) and math.isfinite(value):
            text = repr(value)
        else:
            return None
        text = text.strip()
        if not 1 <= len(text) <= _MAX_ID_LENGTH:
            return None
        if any(_is_control(c) for c in text):
            return None
        return text
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def normalise_customer(tenant_id: Any, user_id: Any = None) -> Optional[Dict[str, str]]:
    """A validated customer dict, or None.

    A user is only attributable inside a tenant, so a user id without a valid
    tenant id is dropped with it.
    """
    tenant = normalise_customer_id(tenant_id)
    if tenant is None:
        return None
    user = normalise_customer_id(user_id) if user_id is not None else None
    return {"tenant_id": tenant, "user_id": user} if user else {"tenant_id": tenant}


def set_customer(tenant_id: Any = None, user_id: Any = None) -> None:
    """Set the process-wide default customer.

    ``tenant_id=None`` clears it. An invalid tenant id also clears it, so calls
    are never attributed to the wrong customer.
    """
    global _default  # pylint: disable=global-statement
    _default = normalise_customer(tenant_id, user_id)


def _current() -> Optional[Dict[str, str]]:
    scoped = _scoped.get()
    return _default if scoped is _UNSET else scoped


def get_customer() -> Optional[Dict[str, str]]:
    """The customer in effect here (scoped, else the default), or None."""
    current = _current()
    return dict(current) if current else None


class customer(ContextDecorator):  # pylint: disable=invalid-name
    """Attribute every span started inside the block to this customer.

    Works as a context manager or decorator, and with asyncio (contextvars).
    Nested blocks override; the scoped customer wins over the default. A
    ``None`` or invalid tenant id means no customer inside the block.

        with shield360.customer(tenant_id="acme", user_id="u1"):
            client.chat.completions.create(...)
    """

    def __init__(self, tenant_id: Any = None, user_id: Any = None):
        self._customer = normalise_customer(tenant_id, user_id)
        self._tokens = []

    def __enter__(self):
        self._tokens.append(_scoped.set(self._customer))
        return self

    def __exit__(self, *exc):
        _scoped.reset(self._tokens.pop())
        return False


class CustomerSpanProcessor(SpanProcessor):
    """Stamps shield360.customer.tenant_id / user_id on every span started
    while a customer is in effect.

    A span that already carries a tenant id (set by the caller) is left alone,
    so explicit attributes are never mixed with ours.
    """

    def on_start(self, span, parent_context=None):
        try:
            current = _current()
            if not current:
                return
            attributes = getattr(span, "attributes", None) or {}
            if ATTR_CUSTOMER_TENANT_ID in attributes:
                return
            span.set_attribute(ATTR_CUSTOMER_TENANT_ID, current["tenant_id"])
            if current.get("user_id"):
                span.set_attribute(ATTR_CUSTOMER_USER_ID, current["user_id"])
        except Exception:  # pylint: disable=broad-exception-caught
            # Never break span creation.
            pass

    def on_end(self, span):
        pass

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis: int = 30000):
        return True
