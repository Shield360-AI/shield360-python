"""Passive IAST: the slot a check's detectors write a vulnerability into
(README "Passive IAST"). ``_engine.check`` arms a slot for one check when
passive IAST is on and the check is sampled; the detectors in ``_detect.py``
call ``note_vulnerability`` with a rule from ``_iast_rules.py``, which runs
only while a slot is armed. Unarmed, the cost is one context-variable read
per detector call. The slot lives in a context variable, so a check on one
thread or task never sees another's."""

from __future__ import annotations

import contextvars
from typing import Any, Callable, Optional, Tuple

from shield360.rasp._iast_rules import Vuln


class IastSlot:
    __slots__ = ("prev", "vuln", "closed")

    def __init__(self, prev: Optional["IastSlot"]):
        self.prev = prev
        self.vuln: Optional[Vuln] = None
        self.closed = False


_current: contextvars.ContextVar[Optional[IastSlot]] = contextvars.ContextVar("shield360_rasp_iast_slot", default=None)


def arm_iast_slot() -> IastSlot:
    """Arms a slot for the check about to run (nested checks keep their own)."""
    slot = IastSlot(_current.get())
    _current.set(slot)
    return slot


def close_iast_slot(slot: IastSlot) -> Optional[Vuln]:
    """Disarms a slot; returns the vulnerability noted in it, once. Idempotent."""
    if slot.closed:
        return None
    slot.closed = True
    if _current.get() is slot:
        _current.set(slot.prev)
    return slot.vuln


def iast_armed() -> bool:
    """Whether a slot is armed for the running check."""
    return _current.get() is not None


def note_vulnerability(rule: Callable[[], Optional[Vuln]]) -> None:
    """Runs a vulnerability rule when a slot is armed and keeps its first
    result. Never raises: a rule that fails is ignored."""
    slot = _current.get()
    if slot is None or slot.vuln is not None:
        return
    try:
        slot.vuln = rule()
    except Exception:  # pylint: disable=broad-exception-caught
        pass  # passive IAST never breaks a check


def capture_vulnerability(fn: Callable[[], Any]) -> Tuple[Any, Optional[Vuln]]:
    """Runs fn with a slot armed; returns what it returned and the vulnerability noted (tests, conformance)."""
    slot = arm_iast_slot()
    try:
        result = fn()
        return result, close_iast_slot(slot)
    finally:
        close_iast_slot(slot)
